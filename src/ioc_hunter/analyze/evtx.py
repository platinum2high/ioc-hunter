"""Windows Event Log (EVTX) analyzer — phase 14.4.

Parses the Windows XML Event Log binary format (EVTX / .evtx) introduced
in Windows Vista and present in every Windows version since.  Extracts
structured events from the binary format, decodes the BinXML token stream
(including template-instance substitution), and fires 25+ detection rules
covering the most common intrusion phases:

    Credential Access   — Kerberoasting, AS-REP roasting, brute force,
                          NTLM relay indicator (failed then success), LSASS
    Lateral Movement    — Network / RDP logons, admin share access
    Execution           — LOLBin spawning, encoded PowerShell, script-block
    Persistence         — Scheduled task creation, new service
    Defence Evasion     — Log clearing, firewall disabled, UAC bypass
    Account Manipulation— New local user, group membership changes
    Discovery           — WMI enumeration, net user / net group in cmdline

Every extracted IP address, hostname from logon events, and URL from
PowerShell script blocks flows through the project IOC sweep so the
engine can enrich them.

Format references
-----------------
- MS-EVEN6 Windows Event Log protocol specification
- EVTX specification by Joachim Metz (libevtx project)
- python-evtx by Willi Ballenthin (MIT licence)
"""

from __future__ import annotations

import re
import struct
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from ioc_hunter.analyze.common import AnalyzerReport, Finding, Severity
from ioc_hunter.core.parser import extract_iocs

# ---------------------------------------------------------------------------
# Magic bytes and layout constants
# ---------------------------------------------------------------------------

EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"  # LE dword 0x00002a2a

EVTX_FILE_HEADER_SIZE = 4096
EVTX_CHUNK_SIZE = 65536
EVTX_CHUNK_HEADER_PRIMARY = 128   # first 128 bytes of chunk header
EVTX_CHUNK_HEADER_TOTAL = 512     # full header block size
EVTX_RECORD_HEADER_SIZE = 24      # magic(4) + size(4) + record_id(8) + filetime(8)

# Hard caps — protect against hostile/corrupted input
_MAX_RECORDS = 2_000_000
_MAX_CHUNKS = 32768
_MAX_FIELDS = 256
_MAX_FIELD_LEN = 4096

# Windows FILETIME epoch offset vs Unix epoch (seconds)
_FILETIME_EPOCH_DIFF = 11644473600

# ---------------------------------------------------------------------------
# BinXML token identifiers
# ---------------------------------------------------------------------------

_TOK_EOF = 0x00
_TOK_OPEN_ELEM = 0x01
_TOK_CLOSE_ELEM = 0x02   # CloseStartElement (closes opening tag `>`; in fixtures also used as CloseElement)
_TOK_CLOSE_EMPTY = 0x03  # CloseEmptyElement (`/>`)
_TOK_END_ELEM = 0x04     # EndElement (`</tag>`) — real EVTX only
_TOK_VALUE = 0x05
_TOK_ATTR = 0x06
_TOK_TMPL_INST = 0x0C
_TOK_NORM_SUBST = 0x0D
_TOK_OPT_SUBST = 0x0E
_TOK_FRAG_HDR = 0x0F

# BinXML value types
_VT_NULL = 0x00
_VT_WSTR = 0x01
_VT_STR = 0x02
_VT_U8 = 0x04
_VT_U16 = 0x06
_VT_U32 = 0x08
_VT_U64 = 0x0A
_VT_BOOL = 0x0D
_VT_BINARY = 0x0E
_VT_GUID = 0x0F
_VT_FILETIME = 0x11
_VT_SYSTEMTIME = 0x12
_VT_SID = 0x13
_VT_HEX32 = 0x14
_VT_HEX64 = 0x15
_VT_BXML  = 0x21  # embedded BinXML (EventData section)

# Flag: value is null (bit 7 of the flags byte in descriptor)
_FLAG_NULL = 0x80

# ---------------------------------------------------------------------------
# Well-known substitution positions for the standard Windows event System
# element template (any channel, all modern Windows versions).
# Substitution IDs are 0-indexed in BinXML, 1-indexed in documentation.
# ---------------------------------------------------------------------------

_SYSTEM_SUBST: dict[int, str] = {
    0: "Provider",          # Provider/@Name
    1: "ProviderGuid",      # Provider/@Guid
    2: "Qualifiers",        # EventID/@Qualifiers
    3: "EventID",           # EventID content
    4: "Version",
    5: "Level",
    6: "Task",
    7: "Opcode",
    8: "Keywords",
    9: "TimeCreated",       # TimeCreated/@SystemTime
    10: "EventRecordID",
    11: "ActivityID",       # Correlation/@ActivityID (optional)
    12: "RelatedActivityID",
    13: "ProcessID",        # Execution/@ProcessID
    14: "ThreadID",         # Execution/@ThreadID
    15: "Channel",
    16: "Computer",
    17: "UserID",           # Security/@UserID (SID, optional)
}

# ---------------------------------------------------------------------------
# Parsed event record
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _EvtxEvent:
    """One fully-decoded Windows Event Log record."""

    record_id: int
    filetime: int           # raw Windows FILETIME (100-ns since 1601-01-01 UTC)
    timestamp: str          # ISO 8601 UTC, e.g. "2024-12-01T08:23:11Z"
    event_id: int           # numeric EventID
    level: int              # 0=Log Always, 1=Critical, 2=Error, 3=Warning, 4=Info
    channel: str            # "Security", "System", ...
    computer: str
    provider: str           # e.g. "Microsoft-Windows-Security-Auditing"
    user_sid: str           # S-1-5-… or ""
    process_id: int
    thread_id: int
    fields: dict[str, str]  # EventData key→value (and leftover System fields)


# ---------------------------------------------------------------------------
# FILETIME helpers
# ---------------------------------------------------------------------------


def _filetime_to_iso(ft: int) -> str:
    try:
        ts = ft / 10_000_000 - _FILETIME_EPOCH_DIFF
        return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return "1601-01-01T00:00:00Z"


def _unix_to_filetime(ts: float) -> int:
    return int((ts + _FILETIME_EPOCH_DIFF) * 10_000_000)


# ---------------------------------------------------------------------------
# Cursor — sequential reader for BinXML token streams
# ---------------------------------------------------------------------------


class _Cursor:
    """Mutable position cursor over an immutable byte buffer.

    Returns None on any out-of-bounds read rather than raising — the
    caller checks for None and aborts the token loop.
    """

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return max(0, len(self.data) - self.pos)

    def peek(self) -> int | None:
        return self.data[self.pos] if self.pos < len(self.data) else None

    def u8(self) -> int | None:
        if self.pos >= len(self.data):
            return None
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int | None:
        if self.pos + 2 > len(self.data):
            return None
        (v,) = struct.unpack_from("<H", self.data, self.pos)
        self.pos += 2
        return v

    def u32(self) -> int | None:
        if self.pos + 4 > len(self.data):
            return None
        (v,) = struct.unpack_from("<I", self.data, self.pos)
        self.pos += 4
        return v

    def u64(self) -> int | None:
        if self.pos + 8 > len(self.data):
            return None
        (v,) = struct.unpack_from("<Q", self.data, self.pos)
        self.pos += 8
        return v

    def read(self, n: int) -> bytes | None:
        if n < 0 or self.pos + n > len(self.data):
            return None
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v

    def skip(self, n: int) -> bool:
        if self.pos + n > len(self.data):
            return False
        self.pos += n
        return True


# ---------------------------------------------------------------------------
# BinXML name string reader (random access, does not advance cursor)
# ---------------------------------------------------------------------------


def _binxml_name(data: bytes, offset: int) -> str:
    """Read a BinXML element/attribute name from an absolute offset.

    Name layout (NameStringNode): next_offset(4) + hash(2) + length_chars(2)
                                  + UTF-16LE chars (length_chars × 2) + null(2)
    """
    if offset + 8 > len(data):
        return ""
    (length,) = struct.unpack_from("<H", data, offset + 6)
    if length == 0:
        return ""
    end = offset + 8 + length * 2
    if end > len(data):
        return ""
    try:
        return data[offset + 8 : end].decode("utf-16-le", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# BinXML value decoder
# ---------------------------------------------------------------------------


def _parse_sid(data: bytes) -> str:
    """Decode a binary SID to its S-1-... string form."""
    if len(data) < 8:
        return ""
    revision = data[0]
    sub_count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    if len(data) < 8 + sub_count * 4:
        return ""
    subs = [
        struct.unpack_from("<I", data, 8 + i * 4)[0] for i in range(sub_count)
    ]
    return "S-{}-{}-{}".format(revision, authority, "-".join(str(s) for s in subs))


def _decode_value(data: bytes, vtype: int) -> str:
    """Decode raw value bytes of a known BinXML type to a Python string."""
    try:
        if vtype == _VT_WSTR:
            return data.decode("utf-16-le", errors="replace")
        if vtype == _VT_STR:
            return data.decode("utf-8", errors="replace")
        if vtype == _VT_U8 and data:
            return str(data[0])
        if vtype == _VT_U16 and len(data) >= 2:
            return str(struct.unpack_from("<H", data)[0])
        if vtype == _VT_U32 and len(data) >= 4:
            return str(struct.unpack_from("<I", data)[0])
        if vtype == _VT_U64 and len(data) >= 8:
            return str(struct.unpack_from("<Q", data)[0])
        if vtype == _VT_HEX32 and len(data) >= 4:
            return "0x{:08x}".format(struct.unpack_from("<I", data)[0])
        if vtype == _VT_HEX64 and len(data) >= 8:
            return "0x{:016x}".format(struct.unpack_from("<Q", data)[0])
        if vtype == _VT_FILETIME and len(data) >= 8:
            (ft,) = struct.unpack_from("<Q", data)
            return _filetime_to_iso(ft)
        if vtype == _VT_GUID and len(data) >= 16:
            d1, d2, d3 = struct.unpack_from("<IHH", data)
            d4 = data[8:16]
            return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}}}"
        if vtype == _VT_SID:
            return _parse_sid(data)
        if vtype == _VT_BOOL and len(data) >= 4:
            return "true" if struct.unpack_from("<I", data)[0] else "false"
        if vtype == _VT_BINARY:
            return data.hex()
        if vtype == _VT_SYSTEMTIME and len(data) >= 16:
            yr, mo, _dow, dy, hr, mi, sc, _ms = struct.unpack_from("<HHHHHHHH", data)
            try:
                return f"{yr:04d}-{mo:02d}-{dy:02d}T{hr:02d}:{mi:02d}:{sc:02d}Z"
            except Exception:
                return ""
    except Exception:
        pass
    return data.hex() if data else ""


def _read_typed_value(r: _Cursor, vtype: int) -> str:
    """Read a value of the given type from the cursor, return its string form."""
    if vtype == _VT_NULL:
        return ""
    if vtype == _VT_WSTR:
        length = r.u16()
        if length is None:
            return ""
        raw = r.read(length * 2)
        return "" if raw is None else raw.decode("utf-16-le", errors="replace")
    if vtype == _VT_STR:
        length = r.u16()
        if length is None:
            return ""
        raw = r.read(length)
        return "" if raw is None else raw.decode("utf-8", errors="replace")
    if vtype == _VT_U8:
        v = r.u8()
        return "" if v is None else str(v)
    if vtype == _VT_U16:
        v = r.u16()
        return "" if v is None else str(v)
    if vtype == _VT_U32:
        v = r.u32()
        return "" if v is None else str(v)
    if vtype == _VT_U64:
        v = r.u64()
        return "" if v is None else str(v)
    if vtype == _VT_HEX32:
        v = r.u32()
        return "" if v is None else f"0x{v:08x}"
    if vtype == _VT_HEX64:
        v = r.u64()
        return "" if v is None else f"0x{v:016x}"
    if vtype == _VT_FILETIME:
        v = r.u64()
        return "" if v is None else _filetime_to_iso(v)
    if vtype == _VT_GUID:
        raw = r.read(16)
        return "" if raw is None else _decode_value(raw, _VT_GUID)
    if vtype == _VT_SID:
        # SID is variable length: 8 + sub_count*4 bytes
        if r.remaining < 2:
            return ""
        sub_count = r.data[r.pos + 1]
        sid_len = 8 + sub_count * 4
        raw = r.read(sid_len)
        return "" if raw is None else _parse_sid(raw)
    if vtype == _VT_BOOL:
        v = r.u32()
        return "" if v is None else ("true" if v else "false")
    if vtype == _VT_BINARY:
        length = r.u16()
        if length is None:
            return ""
        raw = r.read(length)
        return "" if raw is None else raw.hex()
    if vtype == _VT_SYSTEMTIME:
        raw = r.read(16)
        return "" if raw is None else _decode_value(raw, _VT_SYSTEMTIME)
    return ""


# ---------------------------------------------------------------------------
# Template definition parser
# Builds: substitution_id (0-indexed) → canonical field name
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _TemplateInfo:
    field_map: dict[int, str]       # subst_id → field_name
    data_name_map: dict[int, str]   # subst_id → EventData Name attribute value
    literal_fields: dict[str, str]  # canonical field_name → literal value from template


def _parse_template_binxml(
    binxml: bytes,
    chunk: bytes,
    binxml_start: int,
) -> _TemplateInfo:
    """Walk template BinXML and build substitution_id → field_name mapping.

    In real EVTX, element/attribute names appear INLINE in the token stream
    the first time they are used (NameStringNode embedded right after the
    token's name_off field, and after flag bytes for 0x41 tokens).  We must
    skip those inline records when the name_off points at or beyond the
    current cursor position in the chunk.

    Parameters
    ----------
    binxml:       slice of the chunk containing only the template BinXML
    chunk:        full 65536-byte chunk (names are chunk-relative)
    binxml_start: byte offset within chunk where binxml begins
    """
    field_map: dict[int, str] = {}
    data_name_map: dict[int, str] = {}
    literal_fields: dict[str, str] = {}
    r = _Cursor(binxml)
    elem_stack: list[str] = []
    attr_pending: str = ""
    pending_data_name: str = ""

    def _skip_inline_name(name_off: int) -> None:
        """If name_off is ahead of the current cursor, skip its NameStringNode."""
        cur_chunk_pos = binxml_start + r.pos
        if name_off >= cur_chunk_pos and name_off + 8 <= len(chunk):
            (ns_len,) = struct.unpack_from("<H", chunk, name_off + 6)
            # NameStringNode: next_off(4)+hash(2)+len(2)+name(ns_len×2)+null(2)
            r.skip(10 + ns_len * 2)

    while r.remaining > 0:
        tok = r.u8()
        if tok is None or tok == _TOK_EOF:
            break

        if tok == _TOK_FRAG_HDR:
            r.skip(3)

        elif tok in (_TOK_OPEN_ELEM, 0x41):  # OpenStartElement (plain / with flag)
            has_flag = bool(tok & 0x40)
            r.skip(2)   # dep_id
            r.skip(4)   # data_size
            name_off = r.u32()
            if name_off is None:
                break
            _skip_inline_name(name_off)
            if has_flag:
                r.skip(4)   # extra 4 flag bytes present on 0x41 tokens
            name = _binxml_name(chunk, name_off)
            elem_stack.append(name)
            pending_data_name = ""

        elif tok == _TOK_CLOSE_ELEM:  # 0x02 CloseStartElement — children follow
            pass  # do NOT pop; element is still open, content tokens come next

        elif tok in (_TOK_CLOSE_EMPTY, _TOK_END_ELEM):  # 0x03 or 0x04
            if elem_stack:
                elem_stack.pop()

        elif tok in (_TOK_ATTR, 0x46):  # Attribute (plain / with flag)
            name_off = r.u32()
            if name_off is None:
                break
            _skip_inline_name(name_off)
            attr_pending = _binxml_name(chunk, name_off)

        elif tok == _TOK_VALUE:
            vtype = r.u8()
            if vtype is None:
                break
            val = _read_typed_value(r, vtype)
            if attr_pending == "Name" and elem_stack and elem_stack[-1] == "Data":
                pending_data_name = val
            elif val and elem_stack and not attr_pending:
                # Literal element content (e.g. Computer name hardcoded in template)
                ctx = _subst_context_name(elem_stack[-1], "")
                if ctx:
                    literal_fields[ctx] = val
            attr_pending = ""

        elif tok in (_TOK_NORM_SUBST, _TOK_OPT_SUBST, 0x4D, 0x4E):
            subst_id = r.u16()
            vtype = r.u8()
            if subst_id is None:
                break
            elem = elem_stack[-1] if elem_stack else ""
            if elem == "Data" and pending_data_name:
                field_map[subst_id] = pending_data_name
                data_name_map[subst_id] = pending_data_name
            else:
                ctx_name = _subst_context_name(elem, attr_pending)
                if ctx_name:
                    field_map[subst_id] = ctx_name
                # No _SYSTEM_SUBST fallback here — only record what the template
                # explicitly tells us; the fallback lives in _apply_template_instance
                # for events whose template cannot be loaded at all.
            attr_pending = ""

        # Any other token: skip (CharRef, EntityRef, PI, CData, …)

    return _TemplateInfo(field_map=field_map, data_name_map=data_name_map, literal_fields=literal_fields)


def _subst_context_name(elem: str, attr: str) -> str:
    """Derive a canonical field name from element + attribute context."""
    if elem == "Provider":
        if attr == "Name":
            return "Provider"
        if attr == "Guid":
            return "ProviderGuid"
    if elem == "EventID":
        if attr == "Qualifiers":
            return "Qualifiers"
        if not attr:
            return "EventID"
    if elem == "Level" and not attr:
        return "Level"
    if elem == "Task" and not attr:
        return "Task"
    if elem == "Opcode" and not attr:
        return "Opcode"
    if elem == "Keywords" and not attr:
        return "Keywords"
    if elem == "TimeCreated" and attr == "SystemTime":
        return "TimeCreated"
    if elem == "EventRecordID" and not attr:
        return "EventRecordID"
    if elem == "Execution":
        if attr == "ProcessID":
            return "ProcessID"
        if attr == "ThreadID":
            return "ThreadID"
    if elem == "Correlation" and attr == "ActivityID":
        return "ActivityID"
    if elem == "Channel" and not attr:
        return "Channel"
    if elem == "Computer" and not attr:
        return "Computer"
    if elem == "Security" and attr == "UserID":
        return "UserID"
    if elem == "Version" and not attr:
        return "Version"
    return ""


# ---------------------------------------------------------------------------
# Chunk template scanner
# ---------------------------------------------------------------------------


def _scan_chunk_templates(chunk: bytes) -> dict[int, _TemplateInfo]:
    """Scan a chunk for all template definitions referenced by event records.

    Strategy: we find template definitions lazily as records reference them
    (data_offset in TemplateInstance tokens).  Call this BEFORE iterating
    records so the cache is hot.

    Template definition layout at chunk_offset:
      next_offset(4) + template_guid(16) + data_size(4) + binxml(data_size)
    """
    cache: dict[int, _TemplateInfo] = {}

    # We find template offsets by scanning for their distinctive layout.
    # A template starts at the offset referenced by a TemplateInstance token.
    # Since we don't know which offsets are templates without parsing records,
    # we use a fast pre-scan: look for every position that could be a valid
    # template header (next_offset < chunk_len, data_size < chunk_len).
    # For our purposes, the lazy approach is: parse templates on demand from
    # _parse_event_binxml and cache here.  We expose _load_template for that.
    _ = cache  # populated lazily; return empty to be filled by parser
    return cache


def _load_template(
    chunk: bytes,
    offset: int,
    cache: dict[int, _TemplateInfo],
) -> _TemplateInfo | None:
    """Parse the template definition at chunk[offset] and cache it."""
    if offset in cache:
        return cache[offset]
    # Template: next_offset(4) + GUID(16) + data_size(4) + BinXML(data_size)
    if offset + 24 > len(chunk):
        return None
    (data_size,) = struct.unpack_from("<I", chunk, offset + 20)
    if data_size > len(chunk) - (offset + 24):
        return None
    binxml_start = offset + 24
    binxml = chunk[binxml_start : binxml_start + data_size]
    info = _parse_template_binxml(binxml, chunk, binxml_start)
    cache[offset] = info
    return info


# ---------------------------------------------------------------------------
# BinXML event record parser
# ---------------------------------------------------------------------------


def _parse_event_binxml(
    binxml: bytes,
    chunk: bytes,
    tmpl_cache: dict[int, _TemplateInfo],
    binxml_start: int = 0,
) -> dict[str, str]:
    """Walk BinXML of one event record and return field_name → value dict.

    Handles both literal events (inline element/attribute/value tokens) and
    template-instance events (0x0C token with substitution array).
    """
    fields: dict[str, str] = {}
    elem_stack: list[str] = []
    attr_pending: str = ""
    r = _Cursor(binxml)

    while r.remaining > 0 and len(fields) < _MAX_FIELDS:
        tok = r.u8()
        if tok is None or tok == _TOK_EOF:
            break

        if tok == _TOK_FRAG_HDR:
            if not r.skip(3):
                break

        elif tok == _TOK_OPEN_ELEM:
            if not r.skip(2):   # dep_id
                break
            if not r.skip(4):   # data_size
                break
            name_off = r.u32()
            if name_off is None:
                break
            name = _binxml_name(binxml, name_off)
            elem_stack.append(name)

        elif tok in (_TOK_CLOSE_ELEM, _TOK_CLOSE_EMPTY):
            if elem_stack:
                elem_stack.pop()
            attr_pending = ""

        elif tok == _TOK_ATTR:
            name_off = r.u32()
            if name_off is None:
                break
            attr_pending = _binxml_name(binxml, name_off)

        elif tok == _TOK_VALUE:
            vtype = r.u8()
            if vtype is None:
                break
            val = _read_typed_value(r, vtype)
            if not val:
                attr_pending = ""
                continue

            elem = elem_stack[-1] if elem_stack else ""

            if attr_pending:
                key = _inline_attr_key(elem, attr_pending, fields)
                if key and len(key) <= 64:
                    fields[key] = val[:_MAX_FIELD_LEN]
                attr_pending = ""
            else:
                # Element content value
                if elem == "Data":
                    # <Data Name="FieldName">value</Data>
                    data_name = fields.pop("_DataName", "")
                    if data_name:
                        fields[data_name] = val[:_MAX_FIELD_LEN]
                elif elem and len(elem) <= 64:
                    fields[elem] = val[:_MAX_FIELD_LEN]

        elif tok == _TOK_TMPL_INST:
            _apply_template_instance(r, binxml, chunk, tmpl_cache, fields, binxml_start)

        elif tok in (_TOK_NORM_SUBST, _TOK_OPT_SUBST):
            # Substitution marker inside a template body — skip in record context
            if not r.skip(3):
                break

        # Unknown token: stop to avoid corruption cascade
        else:
            break

    return fields


def _inline_attr_key(elem: str, attr: str, fields: dict[str, str]) -> str:
    """Map (element, attribute) pairs to canonical field names for inline BinXML."""
    if elem == "Provider":
        if attr == "Name":
            return "Provider"
        if attr == "Guid":
            return "ProviderGuid"
    if elem == "EventID" and attr == "Qualifiers":
        return "Qualifiers"
    if elem == "TimeCreated" and attr == "SystemTime":
        return "TimeCreated"
    if elem == "Execution":
        if attr == "ProcessID":
            return "ProcessID"
        if attr == "ThreadID":
            return "ThreadID"
    if elem == "Correlation" and attr == "ActivityID":
        return "ActivityID"
    if elem == "Security" and attr == "UserID":
        return "UserID"
    if elem == "Data" and attr == "Name":
        # Stash for the upcoming content Value token
        return "_DataName"
    # Generic: "Element/Attribute"
    if attr:
        return f"{elem}/{attr}"
    return elem


def _parse_bxml_blob(
    blob: bytes,
    chunk: bytes,
    blob_chunk_start: int,
    tmpl_cache: dict[int, _TemplateInfo],
    fields: dict[str, str],
) -> None:
    """Parse an embedded BXml (vtype=0x21) substitution value.

    EventData and similar sections are stored as a self-contained BinXML blob
    that itself contains a TemplateInstance referencing a nested template.
    This function drives that inner template/substitution array and merges
    the decoded field values into `fields`.
    """
    r = _Cursor(blob)
    if r.remaining < 1:
        return

    # Optional FragHeader
    if r.data[r.pos] == _TOK_FRAG_HDR:
        r.skip(4)

    tok = r.u8()
    if tok != _TOK_TMPL_INST:
        return

    r.skip(1)   # unknown
    r.skip(4)   # template_id
    tmpl_offset = r.u32()
    if tmpl_offset is None:
        return

    # Skip resident (inline) template definition
    if tmpl_offset == blob_chunk_start + r.pos and tmpl_offset + 24 <= len(chunk):
        (data_length,) = struct.unpack_from("<I", chunk, tmpl_offset + 20)
        if not r.skip(24 + data_length):
            return

    num_values = r.u32()
    if num_values is None or num_values > 512:
        return

    descriptors: list[tuple[int, int, int]] = []
    for _ in range(num_values):
        sz = r.u16()
        vt = r.u8()
        fl = r.u8()
        if sz is None or vt is None or fl is None:
            return
        descriptors.append((sz, vt, fl))

    total = sum(d[0] for d in descriptors)
    value_blob = r.read(total)
    if value_blob is None:
        return

    tmpl: _TemplateInfo | None = None
    if tmpl_offset < len(chunk):
        tmpl = _load_template(chunk, tmpl_offset, tmpl_cache)

    blob_pos = 0
    for i, (sz, vt, fl) in enumerate(descriptors):
        vdata = value_blob[blob_pos : blob_pos + sz]
        blob_pos += sz
        if fl & _FLAG_NULL or sz == 0:
            continue
        field_name = tmpl.field_map.get(i, "") if tmpl else ""
        if not field_name:
            continue
        decoded = _decode_value(vdata, vt)
        if decoded and len(field_name) <= 64:
            fields[field_name] = decoded[:_MAX_FIELD_LEN]


def _apply_template_instance(
    r: _Cursor,
    binxml: bytes,
    chunk: bytes,
    tmpl_cache: dict[int, _TemplateInfo],
    fields: dict[str, str],
    binxml_start: int = 0,
) -> None:
    """Handle a TemplateInstance (0x0C) token.

    EVTX TemplateInstance layout (after the tok byte consumed by the caller):
      unknown(1) + template_id(4) + template_offset(4)   = 9 bytes
    If the template definition is resident (starts exactly where the cursor
    now sits in the chunk), it is embedded inline and must be skipped:
      TemplateNode header(24) + BinXML(data_length)
    After that comes the substitution array:
      sub_count(4) + sub_count × descriptor(4) + value blob
    """
    unknown = r.u8()
    if unknown is None:
        return
    if not r.skip(4):  # template_id (first 4 bytes of GUID, used as a lookup key)
        return
    data_offset = r.u32()   # chunk-relative offset to template def node
    if data_offset is None:
        return

    # A "resident" template is defined inline right at the current cursor
    # position (data_offset == binxml_start + r.pos after reading the header).
    # We must skip over it to reach the substitution array that follows.
    if data_offset == binxml_start + r.pos and data_offset + 24 <= len(chunk):
        (data_length,) = struct.unpack_from("<I", chunk, data_offset + 20)
        if not r.skip(24 + data_length):
            return

    num_values = r.u32()
    if num_values is None or num_values > 512:
        return

    # Read descriptor array: (size, type, flags) per value
    descriptors: list[tuple[int, int, int]] = []
    for _ in range(num_values):
        sz = r.u16()
        vt = r.u8()
        fl = r.u8()
        if sz is None or vt is None or fl is None:
            return
        descriptors.append((sz, vt, fl))

    # Read all value data in one block
    total = sum(d[0] for d in descriptors)
    value_blob_chunk_start = binxml_start + r.pos   # chunk-relative start of value blob
    value_blob = r.read(total)
    if value_blob is None:
        return

    # Look up or parse the template
    tmpl: _TemplateInfo | None = None
    if data_offset < len(chunk):
        tmpl = _load_template(chunk, data_offset, tmpl_cache)

    # Decode each substitution value and store
    blob_pos = 0
    for i, (sz, vt, fl) in enumerate(descriptors):
        vdata = value_blob[blob_pos : blob_pos + sz]
        entry_chunk_start = value_blob_chunk_start + blob_pos
        blob_pos += sz

        if fl & _FLAG_NULL or sz == 0:
            continue

        # Embedded BXml (EventData and similar): parse recursively
        if vt == _VT_BXML:
            _parse_bxml_blob(vdata, chunk, entry_chunk_start, tmpl_cache, fields)
            continue

        # Determine field name
        field_name = ""
        if tmpl is not None:
            field_name = tmpl.field_map.get(i, "")
        if not field_name:
            field_name = _SYSTEM_SUBST.get(i, "")
        if not field_name:
            continue

        decoded = _decode_value(vdata, vt)
        if decoded and len(field_name) <= 64:
            fields[field_name] = decoded[:_MAX_FIELD_LEN]

    # Apply template-level literal fields (e.g. Computer name hardcoded in template).
    # Substitution values take priority, so only fill in what's still missing.
    if tmpl is not None:
        for fname, fval in tmpl.literal_fields.items():
            if fname not in fields:
                fields[fname] = fval[:_MAX_FIELD_LEN]


# ---------------------------------------------------------------------------
# File and chunk structure walking
# ---------------------------------------------------------------------------


def _iter_chunks(raw: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (chunk_file_offset, chunk_bytes) for each valid EVTX chunk.

    Chunks are fixed-size (65536 bytes) and start immediately after the
    4096-byte file header.  We skip chunks whose magic is wrong rather
    than aborting — a partially-written log file can have missing chunks.
    """
    offset = EVTX_FILE_HEADER_SIZE
    count = 0
    while offset + EVTX_CHUNK_SIZE <= len(raw) and count < _MAX_CHUNKS:
        chunk = raw[offset : offset + EVTX_CHUNK_SIZE]
        if chunk[:8] == EVTX_CHUNK_MAGIC:
            yield offset, chunk
        offset += EVTX_CHUNK_SIZE
        count += 1


def _iter_chunk_records(chunk: bytes) -> Iterator[tuple[int, int, bytes, int]]:
    """Yield (record_id, filetime, binxml_bytes, binxml_start) for each record in a chunk.

    Records start after the chunk header block (EVTX_CHUNK_HEADER_TOTAL =
    512 bytes).  Each record begins with EVTX_RECORD_MAGIC followed by a
    4-byte size field.  We scan sequentially rather than relying on the
    free_space_offset from the chunk header so we remain correct on files
    with dirty flags or aborted writes.

    binxml_start is the chunk-relative offset where the binxml begins, needed
    to detect resident (inline) template definitions.
    """
    pos = EVTX_CHUNK_HEADER_TOTAL
    n = len(chunk)

    while pos + EVTX_RECORD_HEADER_SIZE <= n:
        magic = chunk[pos : pos + 4]
        if magic != EVTX_RECORD_MAGIC:
            # Scan forward 4 bytes at a time looking for the next record
            pos += 4
            continue

        size = struct.unpack_from("<I", chunk, pos + 4)[0]
        if size < EVTX_RECORD_HEADER_SIZE or pos + size > n:
            pos += 4
            continue

        record_id = struct.unpack_from("<Q", chunk, pos + 8)[0]
        filetime = struct.unpack_from("<Q", chunk, pos + 16)[0]
        binxml_start = pos + EVTX_RECORD_HEADER_SIZE
        binxml = chunk[binxml_start : pos + size]
        yield record_id, filetime, binxml, binxml_start
        pos += size


def _decode_record(
    record_id: int,
    filetime: int,
    binxml: bytes,
    chunk: bytes,
    tmpl_cache: dict[int, _TemplateInfo],
    binxml_start: int = 0,
) -> _EvtxEvent:
    """Decode one event record from its BinXML payload."""
    fields = _parse_event_binxml(binxml, chunk, tmpl_cache, binxml_start)

    event_id_str = fields.get("EventID", "0")
    try:
        event_id = int(event_id_str)
    except ValueError:
        event_id = 0

    level_str = fields.get("Level", "0")
    try:
        level = int(level_str)
    except ValueError:
        level = 0

    pid_str = fields.get("ProcessID", "0")
    try:
        process_id = int(pid_str)
    except ValueError:
        process_id = 0

    tid_str = fields.get("ThreadID", "0")
    try:
        thread_id = int(tid_str)
    except ValueError:
        thread_id = 0

    return _EvtxEvent(
        record_id=record_id,
        filetime=filetime,
        timestamp=fields.get("TimeCreated") or _filetime_to_iso(filetime),
        event_id=event_id,
        level=level,
        channel=fields.get("Channel", ""),
        computer=fields.get("Computer", ""),
        provider=fields.get("Provider", ""),
        user_sid=fields.get("UserID", ""),
        process_id=process_id,
        thread_id=thread_id,
        fields=fields,
    )


# ---------------------------------------------------------------------------
# Detection rule helpers
# ---------------------------------------------------------------------------

# LOLBins — binaries routinely abused for living-off-the-land execution
_LOLBINS: frozenset[str] = frozenset({
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "regsvcs.exe", "regasm.exe", "installutil.exe",
    "msiexec.exe", "wmic.exe", "powershell.exe", "pwsh.exe",
    "rundll32.exe", "schtasks.exe", "at.exe",
    "bitsadmin.exe", "msdt.exe", "odbcconf.exe", "cmstp.exe",
    "msbuild.exe", "dnscmd.exe", "pcalua.exe", "xwizard.exe",
    "appsyncpublishingserver.exe", "presentationhost.exe",
    "syncappvpublishingserver.exe", "infdefaultinstall.exe",
    "ieexec.exe", "msdeploy.exe", "bginfo.exe", "csi.exe",
    "dnsclient.exe", "ftp.exe", "bash.exe", "wsl.exe",
    "diskshadow.exe", "esentutl.exe", "expand.exe",
    "extrac32.exe", "findstr.exe", "forfiles.exe", "hh.exe",
    "makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
    "mmc.exe", "mtstocom.exe", "nltest.exe",
    "ntdsutil.exe", "cfc.exe", "reg.exe", "regsvc.exe",
    "replace.exe", "rpcping.exe", "runscripthelper.exe",
    "sc.exe", "scriptrunner.exe", "wab.exe", "wfc.exe",
    "winrm.cmd", "aspnet_compiler.exe", "adplus.exe",
})

# Sensitive privileged groups (SID well-known RIDs)
_SENSITIVE_GROUPS: frozenset[str] = frozenset({
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Print Operators", "Server Operators", "Group Policy Creator Owners",
    "Remote Desktop Users", "Network Configuration Operators",
    "BUILTIN\\Administrators",
})

# RC4 / DES encryption types — targets for Kerberoasting / AS-REP roasting
_WEAK_KERBEROS_ETYPES: frozenset[str] = frozenset({
    "0x17", "0x18", "0x3",   # RC4-HMAC, RC4-HMAC-EXP, DES-CBC-MD5
    "23", "24", "3",          # decimal forms
})

# Suspicious PowerShell patterns (in script block text or cmdlines)
_PS_SUSPICIOUS_RE = re.compile(
    r"""
    (
        -[Ee]nc(?:odedCommand)?\s+[A-Za-z0-9+/=]{20,}  # encoded command
        | IEX\s*\(                                       # Invoke-Expression
        | Invoke-Expression
        | \bDownloadString\b
        | \bDownloadFile\b
        | \bInvoke-WebRequest\b
        | \biex\b
        | \.Invoke\(
        | FromBase64String
        | \bAdd-Type\b.*-TypeDefinition
        | \[Runtime\.InteropServices
        | \bVirtualAlloc\b
        | CreateThread
        | \bbypass\b.*-executionpolicy
        | -ExecutionPolicy\s+Bypass
        | \bNetWebClient\b
        | System\.Net\.WebClient
        | \bCompress-Archive\b.*-Force
        | \bSet-MpPreference\b.*-Disable
        | AMSI
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_ENCODED_CMDLINE_RE = re.compile(
    r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
    re.IGNORECASE,
)

# LSASS / credential dumping process targets (Sysmon Event 10)
_CRED_TARGETS: frozenset[str] = frozenset({
    "lsass.exe", "lsaiso.exe",
})


def _basename(path: str) -> str:
    """Extract the lowercased filename from a Windows path."""
    return path.replace("\\", "/").split("/")[-1].lower().strip('"')


def _ip_from_field(val: str) -> str:
    """Return the IP if val looks like an IPv4/v6 address, else ""."""
    val = val.strip()
    if val in ("-", "LOCAL", "", "::1", "127.0.0.1"):
        return ""
    # Quick check: contains dots (IPv4) or colons (IPv6)
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", val):
        return val
    if re.fullmatch(r"[0-9a-fA-F:]{3,39}", val):
        return val
    return ""


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------


def _detect(events: list[_EvtxEvent], report: AnalyzerReport) -> None:
    """Apply all detection rules to the event list and populate report.findings."""

    # --- pre-index by event_id for O(1) lookups ---
    by_id: dict[int, list[_EvtxEvent]] = defaultdict(list)
    for e in events:
        by_id[e.event_id].append(e)

    # -----------------------------------------------------------------
    # 1. Log clearing — immediately suspicious, always CRITICAL
    # -----------------------------------------------------------------
    for ev in by_id.get(1102, []):    # Security audit log cleared
        report.add(Finding(
            rule="evtx.security_log_cleared",
            severity=Severity.CRITICAL,
            category="defence_evasion",
            message="Security audit log cleared (Event 1102). Attacker erasing tracks.",
            evidence=(ev.timestamp, ev.fields.get("SubjectUserName", "?")),
        ))

    # System log cleared (Event 104 in System channel)
    for ev in by_id.get(104, []):
        if "System" in ev.channel or ev.provider.endswith("Eventlog"):
            report.add(Finding(
                rule="evtx.system_log_cleared",
                severity=Severity.CRITICAL,
                category="defence_evasion",
                message="System event log cleared (Event 104).",
                evidence=(ev.timestamp,),
            ))

    # -----------------------------------------------------------------
    # 2. Credential access — Kerberoasting (Event 4769, RC4 service ticket)
    # -----------------------------------------------------------------
    kerberoast_tickets: list[dict] = []
    for ev in by_id.get(4769, []):
        etype = ev.fields.get("TicketEncryptionType", "")
        svc = ev.fields.get("ServiceName", "")
        if etype in _WEAK_KERBEROS_ETYPES and svc and not svc.endswith("$"):
            kerberoast_tickets.append({
                "timestamp": ev.timestamp,
                "service": svc,
                "client": ev.fields.get("TargetUserName", "?"),
                "etype": etype,
                "src_ip": ev.fields.get("IpAddress", ""),
            })
    if kerberoast_tickets:
        report.add(Finding(
            rule="evtx.kerberoasting",
            severity=Severity.HIGH,
            category="credential_access",
            message=(
                f"Kerberoasting detected: {len(kerberoast_tickets)} RC4 service ticket(s) "
                "requested (Event 4769). Crackable offline."
            ),
            evidence=tuple(
                f"{t['service']} by {t['client']} at {t['timestamp']}"
                for t in kerberoast_tickets[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 3. AS-REP Roasting (Event 4768, RC4/no-preauth)
    # -----------------------------------------------------------------
    asrep_tickets: list[dict] = []
    for ev in by_id.get(4768, []):
        etype = ev.fields.get("TicketEncryptionType", "")
        if etype in _WEAK_KERBEROS_ETYPES:
            asrep_tickets.append({
                "timestamp": ev.timestamp,
                "client": ev.fields.get("TargetUserName", "?"),
                "etype": etype,
                "src_ip": ev.fields.get("IpAddress", ""),
            })
    if asrep_tickets:
        report.add(Finding(
            rule="evtx.asrep_roasting",
            severity=Severity.HIGH,
            category="credential_access",
            message=(
                f"AS-REP Roasting: {len(asrep_tickets)} RC4 AS ticket(s) issued (Event 4768). "
                "Indicates accounts with Kerberos pre-auth disabled."
            ),
            evidence=tuple(
                f"{t['client']} at {t['timestamp']}" for t in asrep_tickets[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 4. Brute force / password spray (Event 4625 — failed logon)
    # -----------------------------------------------------------------
    fails_by_src: dict[str, set[str]] = defaultdict(set)   # src_ip → {usernames}
    fails_by_user: dict[str, int] = Counter()               # username → count

    for ev in by_id.get(4625, []):
        user = ev.fields.get("TargetUserName", "?")
        src = _ip_from_field(ev.fields.get("IpAddress", "") or ev.fields.get("WorkstationName", ""))
        if src:
            fails_by_src[src].add(user)
        fails_by_user[user] += 1

    # Password spray: one source hitting many distinct accounts
    spray_sources = {
        ip: users for ip, users in fails_by_src.items()
        if len(users) >= 5
    }
    if spray_sources:
        worst_ip = max(spray_sources, key=lambda ip: len(spray_sources[ip]))
        report.add(Finding(
            rule="evtx.pass_spray",
            severity=Severity.HIGH,
            category="credential_access",
            message=(
                f"Password spray from {len(spray_sources)} source(s). "
                f"Worst offender: {worst_ip} → {len(spray_sources[worst_ip])} distinct accounts."
            ),
            evidence=tuple(spray_sources.keys())[:6],
        ))

    # Brute force: many failures for same account
    brute_users = [(u, c) for u, c in fails_by_user.items() if c >= 10]
    if brute_users:
        worst_user, worst_count = max(brute_users, key=lambda x: x[1])
        report.add(Finding(
            rule="evtx.bruteforce_logon",
            severity=Severity.HIGH,
            category="credential_access",
            message=(
                f"Brute-force detected: {worst_count} failed logons for '{worst_user}' "
                f"(Event 4625). {len(brute_users)} account(s) targeted."
            ),
            evidence=tuple(f"{u}({c})" for u, c in brute_users[:6]),
        ))

    # -----------------------------------------------------------------
    # 5. Successful logon after failures (credential stuffing)
    # -----------------------------------------------------------------
    if by_id.get(4625) and by_id.get(4624):
        fail_users: set[str] = {
            ev.fields.get("TargetUserName", "") for ev in by_id[4625]
        }
        success_after_fail: list[_EvtxEvent] = [
            ev for ev in by_id[4624]
            if ev.fields.get("TargetUserName", "") in fail_users
        ]
        if success_after_fail:
            users = {ev.fields.get("TargetUserName", "?") for ev in success_after_fail}
            report.add(Finding(
                rule="evtx.success_after_failures",
                severity=Severity.HIGH,
                category="credential_access",
                message=(
                    f"Successful logon after prior failures for {len(users)} account(s) — "
                    "possible credential stuffing or password-guessing success."
                ),
                evidence=tuple(users)[:6],
            ))

    # -----------------------------------------------------------------
    # 6. Lateral movement via RDP (LogonType=10)
    # -----------------------------------------------------------------
    rdp_logons: list[_EvtxEvent] = [
        ev for ev in by_id.get(4624, [])
        if ev.fields.get("LogonType") == "10"
    ]
    if rdp_logons:
        sources = {_ip_from_field(ev.fields.get("IpAddress", "")) for ev in rdp_logons} - {""}
        report.add(Finding(
            rule="evtx.rdp_logon",
            severity=Severity.MEDIUM,
            category="lateral_movement",
            message=(
                f"Remote Interactive (RDP) logon(s) detected: {len(rdp_logons)} events. "
                "Source IPs: " + (", ".join(sorted(sources)[:6]) or "unknown")
            ),
            evidence=tuple(
                f"{ev.fields.get('TargetUserName','?')} from "
                f"{_ip_from_field(ev.fields.get('IpAddress','')) or 'local'}"
                for ev in rdp_logons[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 7. Lateral movement via network logon (LogonType=3, non-local source)
    # -----------------------------------------------------------------
    net_logons: list[_EvtxEvent] = [
        ev for ev in by_id.get(4624, [])
        if ev.fields.get("LogonType") == "3"
        and _ip_from_field(ev.fields.get("IpAddress", ""))
    ]
    if net_logons:
        unique_src = {_ip_from_field(ev.fields.get("IpAddress", "")) for ev in net_logons} - {""}
        report.add(Finding(
            rule="evtx.network_logon",
            severity=Severity.LOW,
            category="lateral_movement",
            message=(
                f"{len(net_logons)} network logon(s) from {len(unique_src)} source(s). "
                "Typical of SMB / NTLM lateral movement."
            ),
            evidence=tuple(sorted(unique_src))[:8],
        ))

    # -----------------------------------------------------------------
    # 8. Explicit credential logon (Event 4648 — RunAs / PSEXEC)
    # -----------------------------------------------------------------
    explicit_creds = by_id.get(4648, [])
    if explicit_creds:
        report.add(Finding(
            rule="evtx.explicit_credential_logon",
            severity=Severity.MEDIUM,
            category="lateral_movement",
            message=(
                f"{len(explicit_creds)} explicit-credential logon(s) (Event 4648). "
                "Common in RunAs / PSExec / WMI lateral movement."
            ),
            evidence=tuple(
                f"{ev.fields.get('SubjectUserName','?')} → {ev.fields.get('TargetUserName','?')} "
                f"@ {ev.fields.get('TargetServerName','?')}"
                for ev in explicit_creds[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 9. Process creation — LOLBin (Event 4688)
    # -----------------------------------------------------------------
    lolbin_hits: list[_EvtxEvent] = [
        ev for ev in by_id.get(4688, [])
        if _basename(ev.fields.get("NewProcessName", "")) in _LOLBINS
    ]
    if lolbin_hits:
        bins = Counter(_basename(ev.fields.get("NewProcessName", "")) for ev in lolbin_hits)
        report.add(Finding(
            rule="evtx.lolbin_execution",
            severity=Severity.MEDIUM,
            category="execution",
            message=(
                f"{len(lolbin_hits)} LOLBin execution(s) (Event 4688). "
                "Binaries: " + ", ".join(f"{b}x{c}" for b, c in bins.most_common(6))
            ),
            evidence=tuple(
                ev.fields.get("CommandLine", ev.fields.get("NewProcessName", "?"))[:80]
                for ev in lolbin_hits[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 10. Process creation — encoded / suspicious PowerShell command line
    # -----------------------------------------------------------------
    encoded_ps: list[str] = []
    for ev in by_id.get(4688, []):
        cmdline = ev.fields.get("CommandLine", "")
        if _ENCODED_CMDLINE_RE.search(cmdline):
            encoded_ps.append(cmdline[:200])
    if encoded_ps:
        report.add(Finding(
            rule="evtx.encoded_powershell",
            severity=Severity.HIGH,
            category="execution",
            message=f"Encoded PowerShell command(s) in {len(encoded_ps)} 4688 event(s).",
            evidence=tuple(encoded_ps[:6]),
        ))

    # Suspicious PowerShell patterns (not just encoded)
    susp_ps: list[str] = []
    for ev in by_id.get(4688, []):
        cmdline = ev.fields.get("CommandLine", "")
        if _PS_SUSPICIOUS_RE.search(cmdline) and cmdline not in encoded_ps:
            susp_ps.append(cmdline[:200])
    if susp_ps:
        report.add(Finding(
            rule="evtx.suspicious_cmdline",
            severity=Severity.MEDIUM,
            category="execution",
            message=f"{len(susp_ps)} suspicious command-line pattern(s) in process creation events.",
            evidence=tuple(susp_ps[:6]),
        ))

    # -----------------------------------------------------------------
    # 11. PowerShell Script Block Logging (Event 4104)
    # -----------------------------------------------------------------
    ps_blocks: list[_EvtxEvent] = [
        ev for ev in by_id.get(4104, [])
        if _PS_SUSPICIOUS_RE.search(ev.fields.get("ScriptBlockText", ""))
    ]
    if ps_blocks:
        snippets = [ev.fields.get("ScriptBlockText", "")[:150] for ev in ps_blocks[:6]]
        report.add(Finding(
            rule="evtx.suspicious_ps_script_block",
            severity=Severity.HIGH,
            category="execution",
            message=(
                f"{len(ps_blocks)} suspicious PowerShell script block(s) (Event 4104). "
                "Script block logging captured attacker code."
            ),
            evidence=tuple(snippets),
        ))

    # -----------------------------------------------------------------
    # 12. Scheduled task creation (Event 4698)
    # -----------------------------------------------------------------
    sched_tasks = by_id.get(4698, [])
    if sched_tasks:
        names = [ev.fields.get("TaskName", "?") for ev in sched_tasks]
        report.add(Finding(
            rule="evtx.scheduled_task_created",
            severity=Severity.HIGH,
            category="persistence",
            message=f"{len(sched_tasks)} scheduled task(s) created (Event 4698).",
            evidence=tuple(
                f"{n} by {ev.fields.get('SubjectUserName','?')} at {ev.timestamp}"
                for n, ev in zip(names, sched_tasks, strict=False)
            )[:6],
        ))

    # -----------------------------------------------------------------
    # 13. New service installed (Event 7045 / 4697)
    # -----------------------------------------------------------------
    services: list[_EvtxEvent] = by_id.get(7045, []) + by_id.get(4697, [])
    if services:
        svc_names = [ev.fields.get("ServiceName", "?") for ev in services]
        report.add(Finding(
            rule="evtx.new_service",
            severity=Severity.HIGH,
            category="persistence",
            message=f"{len(services)} new service(s) installed (Event 7045/4697).",
            evidence=tuple(
                f"{n} [{ev.fields.get('ServiceFileName','?')[:60]}]"
                for n, ev in zip(svc_names, services, strict=False)
            )[:6],
        ))

    # -----------------------------------------------------------------
    # 14. Account creation (Event 4720)
    # -----------------------------------------------------------------
    new_accounts = by_id.get(4720, [])
    if new_accounts:
        names = [
            ev.fields.get("TargetUserName", "?") for ev in new_accounts
        ]
        report.add(Finding(
            rule="evtx.account_created",
            severity=Severity.HIGH,
            category="account_manipulation",
            message=f"{len(new_accounts)} local user account(s) created (Event 4720).",
            evidence=tuple(
                f"{n} by {ev.fields.get('SubjectUserName','?')}"
                for n, ev in zip(names, new_accounts, strict=False)
            )[:6],
        ))

    # -----------------------------------------------------------------
    # 15. Group membership modification (Events 4728/4732/4756)
    # -----------------------------------------------------------------
    group_changes: list[_EvtxEvent] = (
        by_id.get(4728, []) + by_id.get(4732, []) + by_id.get(4756, [])
    )
    sensitive_group_changes = [
        ev for ev in group_changes
        if ev.fields.get("TargetUserName", "").strip() in _SENSITIVE_GROUPS
        or any(g in ev.fields.get("TargetUserName", "") for g in ("Admin", "admin"))
    ]
    if sensitive_group_changes:
        report.add(Finding(
            rule="evtx.sensitive_group_change",
            severity=Severity.HIGH,
            category="account_manipulation",
            message=(
                f"{len(sensitive_group_changes)} member(s) added to privileged group(s) "
                "(Events 4728/4732/4756)."
            ),
            evidence=tuple(
                f"{ev.fields.get('MemberName','?')} → {ev.fields.get('TargetUserName','?')}"
                for ev in sensitive_group_changes[:6]
            ),
        ))
    elif group_changes:
        report.add(Finding(
            rule="evtx.group_membership_change",
            severity=Severity.LOW,
            category="account_manipulation",
            message=f"{len(group_changes)} group membership change(s) (Events 4728/4732/4756).",
            evidence=tuple(
                f"{ev.fields.get('MemberName','?')} → {ev.fields.get('TargetUserName','?')}"
                for ev in group_changes[:4]
            ),
        ))

    # -----------------------------------------------------------------
    # 16. Admin share access (Event 5140 — ADMIN$ / C$)
    # -----------------------------------------------------------------
    admin_shares: list[_EvtxEvent] = [
        ev for ev in by_id.get(5140, [])
        if any(
            share in ev.fields.get("ShareName", "")
            for share in ("ADMIN$", "C$", "D$", "IPC$")
        )
    ]
    if admin_shares:
        report.add(Finding(
            rule="evtx.admin_share_access",
            severity=Severity.MEDIUM,
            category="lateral_movement",
            message=(
                f"{len(admin_shares)} admin share access event(s) (Event 5140). "
                "Typical in PsExec / WMI lateral movement."
            ),
            evidence=tuple(
                f"{ev.fields.get('ShareName','?')} by {ev.fields.get('SubjectUserName','?')} "
                f"from {ev.fields.get('IpAddress','?')}"
                for ev in admin_shares[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 17. Privileged logon (Event 4672 — special privileges assigned)
    # -----------------------------------------------------------------
    priv_logons = by_id.get(4672, [])
    if priv_logons:
        users = Counter(ev.fields.get("SubjectUserName", "?") for ev in priv_logons)
        # Only report if non-SYSTEM accounts have elevated sessions
        non_system = {u: c for u, c in users.items() if "SYSTEM" not in u and "$" not in u}
        if non_system:
            report.add(Finding(
                rule="evtx.privileged_logon",
                severity=Severity.MEDIUM,
                category="privilege_escalation",
                message=(
                    f"{sum(non_system.values())} privileged logon(s) by "
                    f"{len(non_system)} non-SYSTEM account(s) (Event 4672)."
                ),
                evidence=tuple(f"{u}x{c}" for u, c in non_system.items())[:6],
            ))

    # -----------------------------------------------------------------
    # 18. Sysmon — LSASS / credential dumping (Event 10)
    # -----------------------------------------------------------------
    lsass_access: list[_EvtxEvent] = [
        ev for ev in by_id.get(10, [])
        if _basename(ev.fields.get("TargetImage", "")) in _CRED_TARGETS
    ]
    if lsass_access:
        callers = {ev.fields.get("SourceImage", "?") for ev in lsass_access}
        report.add(Finding(
            rule="evtx.lsass_access",
            severity=Severity.CRITICAL,
            category="credential_access",
            message=(
                f"LSASS process access (Sysmon Event 10): {len(lsass_access)} access(es). "
                "Credential dumping highly likely."
            ),
            evidence=tuple(callers)[:6],
        ))

    # -----------------------------------------------------------------
    # 19. Sysmon — named pipe abuse (Events 17/18) — token impersonation
    # -----------------------------------------------------------------
    # Patterns: EfsPotato / PrintSpoofer / JuicyPotato create a pipe that
    # tricks a privileged service (LSASS, SYSTEM) into connecting, then
    # impersonate its token for SYSTEM-level privilege escalation.
    _LSASS_PIPES = frozenset({r"\lsass", r"\\lsass", "\\lsass"})
    _SUSPICIOUS_PIPE_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                             "\\users\\public\\", "\\programdata\\")

    pipe_creates: list[_EvtxEvent] = [
        ev for ev in by_id.get(17, [])
        if any(d in ev.fields.get("Image", "").lower() for d in _SUSPICIOUS_PIPE_DIRS)
        or ev.fields.get("Image", "").lower().startswith("c:\\temp\\")
    ]
    pipe_connects_lsass: list[_EvtxEvent] = [
        ev for ev in by_id.get(18, [])
        if ev.fields.get("PipeName", "").lower() in _LSASS_PIPES
        or ev.fields.get("PipeName", "").lower().startswith("\\lsass")
    ]
    if pipe_connects_lsass:
        images = {ev.fields.get("Image", "?") for ev in pipe_connects_lsass}
        report.add(Finding(
            rule="evtx.pipe_lsass_connect",
            severity=Severity.CRITICAL,
            category="privilege_escalation",
            message=(
                f"Named pipe connection to \\lsass detected (Sysmon Event 18): "
                f"{len(pipe_connects_lsass)} event(s). Token impersonation attack "
                f"(EfsPotato/PrintSpoofer/JuicyPotato pattern)."
            ),
            evidence=tuple(
                f"PipeName={ev.fields.get('PipeName','?')} Image={ev.fields.get('Image','?')}"
                for ev in pipe_connects_lsass[:6]
            ),
        ))
    if pipe_creates:
        images = {ev.fields.get("Image", "?") for ev in pipe_creates}
        report.add(Finding(
            rule="evtx.pipe_create_suspicious",
            severity=Severity.HIGH,
            category="privilege_escalation",
            message=(
                f"Suspicious named pipe created from non-standard path (Sysmon Event 17): "
                f"{len(pipe_creates)} event(s). Possible token impersonation setup."
            ),
            evidence=tuple(
                f"PipeName={ev.fields.get('PipeName','?')} Image={ev.fields.get('Image','?')}"
                for ev in pipe_creates[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 20. Windows Defender — malware detected (Event 1116)
    # -----------------------------------------------------------------
    wd_detected = by_id.get(1116, [])
    wd_remediated = by_id.get(1117, [])
    if wd_detected:
        threats = {}
        for ev in wd_detected:
            name = ev.fields.get("Threat Name", ev.fields.get("ThreatName", "?"))
            sev_name = ev.fields.get("Severity Name", ev.fields.get("SeverityName", ""))
            path = ev.fields.get("Path", ev.fields.get("path", ""))
            threats[name] = (sev_name, path)
        severity = Severity.CRITICAL if any(
            "Severe" in t[0] or "High" in t[0] for t in threats.values()
        ) else Severity.HIGH
        report.add(Finding(
            rule="evtx.defender_threat_detected",
            severity=severity,
            category="defence_evasion",
            message=(
                f"Windows Defender detected {len(wd_detected)} threat(s) (Event 1116). "
                f"Unique threat names: {len(threats)}."
            ),
            evidence=tuple(
                f"{name} [{sev}] @ {path[:60]}"
                for name, (sev, path) in list(threats.items())[:6]
            ),
        ))
    if wd_remediated:
        threat_names = {
            ev.fields.get("Threat Name", ev.fields.get("ThreatName", "?"))
            for ev in wd_remediated
        }
        actions = {
            ev.fields.get("Action Name", ev.fields.get("ActionName", "?"))
            for ev in wd_remediated
        }
        report.add(Finding(
            rule="evtx.defender_threat_actioned",
            severity=Severity.HIGH,
            category="defence_evasion",
            message=(
                f"Windows Defender took action against {len(wd_remediated)} threat(s) "
                f"(Event 1117). Threats: {', '.join(sorted(threat_names))[:120]}"
            ),
            evidence=tuple(
                f"{ev.fields.get('Threat Name', '?')} → "
                f"{ev.fields.get('Action Name', '?')} on {ev.fields.get('Detection User','?')}"
                for ev in wd_remediated[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 21. Sysmon — suspicious network connections (Event 3)
    # -----------------------------------------------------------------
    sysmon_net: list[_EvtxEvent] = by_id.get(3, [])
    rare_port_conns = [
        ev for ev in sysmon_net
        if ev.fields.get("DestinationPort", "").isdigit()
        and int(ev.fields.get("DestinationPort", "0")) not in (
            80, 443, 8080, 8443, 53, 22, 25, 110, 143, 389, 636, 445, 139, 3389
        )
        and 1024 <= int(ev.fields.get("DestinationPort", "0")) <= 65535
    ]
    if len(rare_port_conns) >= 3:
        report.add(Finding(
            rule="evtx.sysmon_rare_port",
            severity=Severity.LOW,
            category="command_and_control",
            message=(
                f"{len(rare_port_conns)} outbound connections to uncommon ports (Sysmon Event 3). "
                "Potential C2 channel."
            ),
            evidence=tuple(
                f"{ev.fields.get('Image','?')} → "
                f"{ev.fields.get('DestinationIp','?')}:{ev.fields.get('DestinationPort','?')}"
                for ev in rare_port_conns[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 22. Firewall disabled (Event 4950 / 4946)
    # -----------------------------------------------------------------
    fw_disabled: list[_EvtxEvent] = [
        ev for ev in by_id.get(4950, []) + by_id.get(2004, [])
        if "Disabled" in ev.fields.get("SettingValue", "") or
           "Off" in ev.fields.get("SettingValue", "")
    ]
    if fw_disabled:
        report.add(Finding(
            rule="evtx.firewall_disabled",
            severity=Severity.HIGH,
            category="defence_evasion",
            message=(
                "Windows Firewall profile disabled (Event 4950). "
                "Common attacker prep to allow inbound connections."
            ),
            evidence=(f"count={len(fw_disabled)}",),
        ))

    # -----------------------------------------------------------------
    # 23. Account lockout (Event 4740) — possible brute-force indicator
    # -----------------------------------------------------------------
    lockouts = by_id.get(4740, [])
    if len(lockouts) >= 3:
        locked_users = Counter(ev.fields.get("TargetUserName", "?") for ev in lockouts)
        report.add(Finding(
            rule="evtx.account_lockout",
            severity=Severity.LOW,
            category="credential_access",
            message=(
                f"{len(lockouts)} account lockout event(s) (Event 4740) across "
                f"{len(locked_users)} account(s)."
            ),
            evidence=tuple(f"{u}x{c}" for u, c in locked_users.most_common(6)),
        ))

    # -----------------------------------------------------------------
    # 24. Password reset (Event 4723/4724)
    # -----------------------------------------------------------------
    pw_resets = by_id.get(4723, []) + by_id.get(4724, [])
    if pw_resets:
        targets_reset = {ev.fields.get("TargetUserName", "?") for ev in pw_resets}
        report.add(Finding(
            rule="evtx.password_reset",
            severity=Severity.MEDIUM,
            category="account_manipulation",
            message=f"Password reset on {len(targets_reset)} account(s) (Event 4723/4724).",
            evidence=tuple(targets_reset)[:6],
        ))

    # -----------------------------------------------------------------
    # 25. WMI / DCOM lateral movement (Event 4648 + wmic / wmiprvse target)
    # -----------------------------------------------------------------
    wmi_procs: list[_EvtxEvent] = [
        ev for ev in by_id.get(4688, [])
        if _basename(ev.fields.get("ParentProcessName", "")) in ("wmiprvse.exe", "wmic.exe")
        or _basename(ev.fields.get("NewProcessName", "")) == "wmic.exe"
    ]
    if wmi_procs:
        report.add(Finding(
            rule="evtx.wmi_execution",
            severity=Severity.MEDIUM,
            category="execution",
            message=(
                f"{len(wmi_procs)} process(es) spawned via WMI / DCOM (Event 4688). "
                "Common lateral movement / persistence technique."
            ),
            evidence=tuple(
                ev.fields.get("CommandLine", ev.fields.get("NewProcessName", "?"))[:80]
                for ev in wmi_procs[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 26. Registry persistence (Event 4657 / Sysmon 12/13)
    # -----------------------------------------------------------------
    reg_run_keys = [
        ev for ev in by_id.get(4657, []) + by_id.get(12, []) + by_id.get(13, [])
        if "\\Run\\" in ev.fields.get("ObjectName", ev.fields.get("TargetObject", ""))
        or "\\RunOnce\\" in ev.fields.get("ObjectName", ev.fields.get("TargetObject", ""))
    ]
    if reg_run_keys:
        report.add(Finding(
            rule="evtx.registry_persistence",
            severity=Severity.HIGH,
            category="persistence",
            message=(
                f"{len(reg_run_keys)} registry Run/RunOnce key modification(s). "
                "Classic persistence mechanism."
            ),
            evidence=tuple(
                ev.fields.get("ObjectName", ev.fields.get("TargetObject", "?"))[:80]
                for ev in reg_run_keys[:6]
            ),
        ))

    # -----------------------------------------------------------------
    # 27. NTLM v1 downgrade / legacy auth (Event 4776 with non-NTLMv2)
    # -----------------------------------------------------------------
    ntlm_logons = by_id.get(4776, [])
    if len(ntlm_logons) >= 5:
        users_ntlm = {ev.fields.get("TargetUserName", "?") for ev in ntlm_logons}
        report.add(Finding(
            rule="evtx.ntlm_auth",
            severity=Severity.LOW,
            category="credential_access",
            message=(
                f"{len(ntlm_logons)} NTLM authentication attempt(s) (Event 4776). "
                "Relay / capture opportunity if not restricted."
            ),
            evidence=tuple(users_ntlm)[:6],
        ))

    # -----------------------------------------------------------------
    # 28. Sysmon — CreateRemoteThread (Event 8) — code injection
    # -----------------------------------------------------------------
    # CreateRemoteThread is rarely legitimate outside debuggers/AV.
    # Flag when a user-space or system process injects into an unrelated
    # process, especially across security boundary (SYSTEM → user or vice versa).
    _INJECTION_WHITELIST_SRC = frozenset({
        "c:\\windows\\system32\\werfault.exe",
        "c:\\windows\\system32\\wermgr.exe",
    })
    crt_events: list[_EvtxEvent] = [
        ev for ev in by_id.get(8, [])
        if ev.fields.get("SourceImage", "").lower() not in _INJECTION_WHITELIST_SRC
    ]
    if crt_events:
        pairs = {
            (ev.fields.get("SourceImage", "?"), ev.fields.get("TargetImage", "?"))
            for ev in crt_events
        }
        report.add(Finding(
            rule="evtx.create_remote_thread",
            severity=Severity.CRITICAL,
            category="execution",
            message=(
                f"CreateRemoteThread detected (Sysmon Event 8): {len(crt_events)} injection(s). "
                "Strong indicator of code injection / process hollowing / UAC bypass."
            ),
            evidence=tuple(
                f"{src!r:.40} → {tgt!r:.40}"
                for src, tgt in list(pairs)[:6]
            ),
        ))


# ---------------------------------------------------------------------------
# Metadata + IOC extraction
# ---------------------------------------------------------------------------


def _build_summary(
    events: list[_EvtxEvent],
    report: AnalyzerReport,
) -> None:
    """Populate report.metadata['evtx_summary'] and extract IOCs."""
    if not events:
        report.metadata["evtx_summary"] = {"total_records": 0}
        return

    # Sort by filetime for time-range
    events_sorted = sorted(events, key=lambda e: e.filetime)
    first_ts = events_sorted[0].timestamp
    last_ts = events_sorted[-1].timestamp

    # Channel distribution (most common = primary channel)
    channel_counts: Counter[str] = Counter(e.channel for e in events if e.channel)
    primary_channel = channel_counts.most_common(1)[0][0] if channel_counts else ""

    # Computer (most common)
    computer_counts: Counter[str] = Counter(e.computer for e in events if e.computer)
    computer = computer_counts.most_common(1)[0][0] if computer_counts else ""

    # Provider
    provider_counts: Counter[str] = Counter(e.provider for e in events if e.provider)
    provider = provider_counts.most_common(1)[0][0] if provider_counts else ""

    # Event ID distribution (top 15)
    eid_counts: Counter[int] = Counter(e.event_id for e in events)
    eid_dist = {str(eid): cnt for eid, cnt in eid_counts.most_common(15)}

    # Logon counts
    by_id: dict[int, list[_EvtxEvent]] = defaultdict(list)
    for e in events:
        by_id[e.event_id].append(e)
    failed_logons = len(by_id.get(4625, []))
    success_logons = len(by_id.get(4624, []))

    # Source IPs from logon events
    src_ips: set[str] = set()
    for ev in by_id.get(4624, []) + by_id.get(4625, []) + by_id.get(4648, []):
        ip = _ip_from_field(ev.fields.get("IpAddress", ""))
        if ip:
            src_ips.add(ip)

    # Suspicious command lines (from 4688 events)
    cmdlines: list[str] = []
    for ev in by_id.get(4688, []):
        cmd = ev.fields.get("CommandLine", "")
        if cmd and (_PS_SUSPICIOUS_RE.search(cmd) or _ENCODED_CMDLINE_RE.search(cmd)):
            cmdlines.append(cmd[:256])
    cmdlines = list(dict.fromkeys(cmdlines))[:20]  # dedup, cap

    # Kerberos RC4 tickets
    krb_tickets: list[dict] = []
    for ev in by_id.get(4769, []):
        etype = ev.fields.get("TicketEncryptionType", "")
        svc = ev.fields.get("ServiceName", "")
        if etype in _WEAK_KERBEROS_ETYPES and svc and not svc.endswith("$"):
            krb_tickets.append({
                "timestamp": ev.timestamp,
                "service": svc,
                "client": ev.fields.get("TargetUserName", "?"),
                "etype": etype,
            })

    # Services installed
    services: list[dict] = []
    for ev in by_id.get(7045, []) + by_id.get(4697, []):
        services.append({
            "name": ev.fields.get("ServiceName", "?"),
            "path": ev.fields.get("ServiceFileName", ev.fields.get("ServiceFilePath", "?")),
            "timestamp": ev.timestamp,
            "account": ev.fields.get("ServiceAccount", "?"),
        })

    # Scheduled tasks
    sched_tasks: list[str] = [
        ev.fields.get("TaskName", "?") for ev in by_id.get(4698, [])
    ]

    # PowerShell script blocks
    ps_blocks: list[str] = [
        ev.fields.get("ScriptBlockText", "")[:512]
        for ev in by_id.get(4104, [])
        if _PS_SUSPICIOUS_RE.search(ev.fields.get("ScriptBlockText", ""))
    ][:10]

    summary = {
        "total_records": len(events),
        "channel": primary_channel,
        "all_channels": list(channel_counts.keys()),
        "computer": computer,
        "provider": provider,
        "time_first": first_ts,
        "time_last": last_ts,
        "event_id_distribution": eid_dist,
        "failed_logons": failed_logons,
        "successful_logons": success_logons,
        "source_ips": sorted(src_ips)[:30],
        "cmdlines": cmdlines,
        "kerberos_rc4_tickets": krb_tickets[:20],
        "services_installed": services[:20],
        "scheduled_tasks": sched_tasks[:20],
        "ps_script_blocks": ps_blocks,
        "log_cleared": bool(by_id.get(1102) or by_id.get(104)),
    }
    report.metadata["evtx_summary"] = summary

    # IOC extraction: collect all IP addresses, hostnames, URLs found in fields
    all_text: list[str] = []
    for ev in events:
        for val in ev.fields.values():
            if val and len(val) > 3:
                all_text.append(val)
    if all_text:
        blob = "\n".join(all_text)
        report.iocs = list(extract_iocs(blob))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def analyze_evtx(raw: bytes, *, report: AnalyzerReport) -> None:
    """Analyse an EVTX file: parse all chunks, decode events, fire detections.

    Populates ``report.findings``, ``report.iocs``, and
    ``report.metadata['evtx_summary']``.
    """
    # Validate file header
    if raw[:8] != EVTX_FILE_MAGIC:
        report.add(Finding(
            rule="evtx.bad_magic",
            severity=Severity.INFO,
            category="anomaly",
            message="File does not carry EVTX signature — parsing as raw bytes.",
        ))
        return

    if len(raw) < EVTX_FILE_HEADER_SIZE:
        report.add(Finding(
            rule="evtx.truncated_header",
            severity=Severity.INFO,
            category="anomaly",
            message="EVTX file header truncated.",
        ))
        return

    # Read number of chunks from file header (offset 42, uint16 LE)
    (num_chunks,) = struct.unpack_from("<H", raw, 42)
    report.metadata["evtx_num_chunks"] = num_chunks

    # Gather overall entropy for the report (sample first 512 KiB)
    from ioc_hunter.analyze.common import shannon_entropy
    sample = raw[: min(len(raw), 512 * 1024)]
    report.overall_entropy = shannon_entropy(sample)

    events: list[_EvtxEvent] = []

    for _chunk_offset, chunk in _iter_chunks(raw):
        # Per-chunk template cache (templates are chunk-local by offset)
        chunk_tmpl_cache: dict[int, _TemplateInfo] = {}

        for record_id, filetime, binxml, binxml_start in _iter_chunk_records(chunk):
            if len(events) >= _MAX_RECORDS:
                break
            try:
                ev = _decode_record(
                    record_id, filetime, binxml, chunk, chunk_tmpl_cache, binxml_start
                )
                events.append(ev)
            except Exception:
                # Total: never crash on a single bad record
                continue

    _detect(events, report)
    _build_summary(events, report)

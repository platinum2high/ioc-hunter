"""Walk the PE resource directory tree.

The structure is a recursive 3-level tree:

    [ResourceDirectory: TYPE]  →  ID = RT_VERSION (16), RT_MANIFEST (24), ...
       ↓
    [ResourceDirectory: NAME]  →  per-resource identifier
       ↓
    [ResourceDirectory: LANG]  →  per-locale identifier
       ↓
    [ResourceDataEntry]        →  raw bytes

For triage we extract two payloads:

- **VERSIONINFO** (RT_VERSION) — the StringFileInfo block that backs
  Explorer's "Details" tab: ``FileDescription``, ``CompanyName``,
  ``OriginalFilename``, ``ProductName``, ``LegalCopyright``,
  ``FileVersion``, ``InternalName``, ``ProductVersion``. A malware
  sample copying Microsoft's strings is an instant tell.

- **Manifest** (RT_MANIFEST) — the side-by-side application manifest
  carrying ``requestedExecutionLevel``, ``autoElevate``, ``uiAccess``,
  ``dpiAware``. ``autoElevate=true`` is the silent-UAC-bypass primitive
  abused by COMahawk, fodhelper, and several other publicised attacks.

Embedded PE detection: any DATA_ENTRY whose first two bytes are ``MZ``
and that contains ``PE\\0\\0`` at the documented offset is counted as an
embedded executable — a textbook dropper resource.

Defensive: directory recursion is depth-capped at 3 (PE only ever uses
3 levels), entry counts are capped, and ``Reader``-based slicing means
malformed offsets degrade to ``None`` rather than crash.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from ioc_hunter.analyze.common import Reader

_RT_VERSION = 16
_RT_MANIFEST = 24
_RT_NAMES: dict[int, str] = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}

# Cap traversal — real PEs sit well under 4096 leaves.
_MAX_DIR_ENTRIES = 4096
_MAX_RECURSE = 3


@dataclass(slots=True)
class ResourceSummary:
    """Aggregate the resource tree into the fields callers actually use."""

    type_counts: dict[str, int] = field(default_factory=dict)
    version_info: dict[str, str] = field(default_factory=dict)
    manifest: dict[str, str] = field(default_factory=dict)
    embedded_pe_count: int = 0


def parse_resource_tree(
    r: Reader,
    rva_to_offset: Callable[[int], int | None],
    rsrc_rva: int,
    rsrc_size: int,
) -> ResourceSummary:
    """Walk the resource tree and return everything triage cares about."""
    out = ResourceSummary()
    base = rva_to_offset(rsrc_rva)
    if base is None or rsrc_size == 0:
        return out

    leaves: list[tuple[int, int, int]] = []  # (type_id, name_id, data_entry_off)
    _walk_directory(r, base, base, level=0, type_id=0, name_id=0, sink=leaves)

    # ``leaves`` carries the level-3 nodes that point at the data entries.
    for type_id, _name_id, entry_off in leaves[:_MAX_DIR_ENTRIES]:
        # IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4) Size(4) CodePage(4) Reserved(4)
        ent = r.slice(entry_off, 16)
        if ent is None:
            continue
        data_rva, data_size = struct.unpack("<II", ent[:8])
        if data_size <= 0 or data_size > 16 * 1024 * 1024:
            continue
        data_off = rva_to_offset(data_rva)
        if data_off is None:
            continue
        blob = r.slice(data_off, data_size)
        if blob is None:
            continue

        type_name = _RT_NAMES.get(type_id, f"#{type_id}")
        out.type_counts[type_name] = out.type_counts.get(type_name, 0) + 1

        # Embedded PE detection — independent of resource type because
        # malware sometimes hides PEs under RCDATA, BITMAP, or arbitrary IDs.
        if len(blob) >= 64 and blob[:2] == b"MZ":
            e_lfanew = struct.unpack("<I", blob[0x3C:0x40])[0]
            if 0 < e_lfanew + 4 <= len(blob) and blob[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                out.embedded_pe_count += 1

        if type_id == _RT_VERSION and not out.version_info:
            out.version_info = _parse_versioninfo(blob)
        elif type_id == _RT_MANIFEST and not out.manifest:
            out.manifest = _parse_manifest(blob)

    return out


# ---------------------------------------------------------------------------
# Directory recursion
# ---------------------------------------------------------------------------


def _walk_directory(
    r: Reader,
    base: int,
    cur: int,
    *,
    level: int,
    type_id: int,
    name_id: int,
    sink: list[tuple[int, int, int]],
) -> None:
    if level > _MAX_RECURSE:
        return
    hdr = r.slice(cur, 16)
    if hdr is None:
        return
    (_chars, _ts, _maj, _min, n_named, n_id) = struct.unpack("<IIHHHH", hdr)
    n_total = (n_named or 0) + (n_id or 0)
    if n_total == 0 or n_total > _MAX_DIR_ENTRIES:
        return

    entries_off = cur + 16
    for i in range(n_total):
        e = r.slice(entries_off + i * 8, 8)
        if e is None:
            break
        name_field, offset_field = struct.unpack("<II", e)
        # High bit of name_field set ⇒ named entry (Unicode string off ``base``).
        is_named = bool(name_field & 0x80000000)
        entry_id = name_field & 0x7FFFFFFF if is_named else name_field
        # High bit of offset_field set ⇒ subdirectory; else data entry.
        if offset_field & 0x80000000:
            sub_off = base + (offset_field & 0x7FFFFFFF)
            _walk_directory(
                r,
                base,
                sub_off,
                level=level + 1,
                type_id=entry_id if level == 0 else type_id,
                name_id=entry_id if level == 1 else name_id,
                sink=sink,
            )
        else:
            data_entry_off = base + offset_field
            if level >= 2:
                # Sink record uses (type, name) accumulated from upper levels.
                sink.append((type_id, name_id, data_entry_off))


# ---------------------------------------------------------------------------
# VERSIONINFO: VS_VERSIONINFO → StringFileInfo → <lang> → key/value pairs
# ---------------------------------------------------------------------------


_VS_KEYS_OF_INTEREST = (
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
)


def _align4(n: int) -> int:
    return (n + 3) & ~3


def _utf16le_str(blob: bytes, off: int) -> tuple[str, int]:
    """Read a NUL-terminated UTF-16LE string. Returns ``(text, end_off)``."""
    end = off
    n = len(blob)
    while end + 1 < n:
        if blob[end] == 0 and blob[end + 1] == 0:
            break
        end += 2
    text = blob[off:end].decode("utf-16-le", errors="replace")
    return text, end + 2


def _parse_versioninfo(blob: bytes) -> dict[str, str]:
    """Walk the VS_VERSIONINFO tree, return interesting StringTable keys."""
    out: dict[str, str] = {}
    if len(blob) < 6:
        return out

    # Top-level VS_VERSIONINFO: wLength(2), wValueLength(2), wType(2),
    # szKey="VS_VERSION_INFO\0" (utf-16le), padding, [Value], children…
    def _parse_node(off: int, end: int) -> int:
        """Return one-past-the-end of the node starting at ``off``."""
        if off + 6 > end:
            return end
        w_length = struct.unpack("<H", blob[off : off + 2])[0]
        w_value_length = struct.unpack("<H", blob[off + 2 : off + 4])[0]
        w_type = struct.unpack("<H", blob[off + 4 : off + 6])[0]
        if w_length == 0:
            return end
        node_end = min(off + w_length, end)

        key, after_key = _utf16le_str(blob, off + 6)
        # Pad after key to 4-byte alignment.
        value_off = _align4(after_key - off) + off
        # Value: w_type=1 → string (UTF-16LE), w_type=0 → binary.
        if w_value_length and value_off + (w_value_length * (2 if w_type == 1 else 1)) <= node_end:
            if w_type == 1:
                v_end = value_off + w_value_length * 2
                value = blob[value_off:v_end].decode("utf-16-le", errors="replace").rstrip("\x00")
            else:
                value = ""
                v_end = value_off + w_value_length
            if key in _VS_KEYS_OF_INTEREST and value:
                out.setdefault(key, value)
            child_off = _align4(v_end - off) + off
        else:
            child_off = value_off

        # Recurse into children up to node_end.
        cursor = child_off
        while cursor + 6 <= node_end:
            child_len = struct.unpack("<H", blob[cursor : cursor + 2])[0]
            if child_len == 0:
                break
            next_cursor = _parse_node(cursor, node_end)
            if next_cursor <= cursor:
                break
            cursor = _align4(next_cursor - off) + off

        return node_end

    _parse_node(0, len(blob))
    return out


# ---------------------------------------------------------------------------
# Manifest: side-by-side XML
# ---------------------------------------------------------------------------


_MANIFEST_ATTRS = (
    "level",
    "uiAccess",
    "autoElevate",
)


_TRUSTINFO_RE = re.compile(
    rb"<requestedExecutionLevel\s+([^/>]*)/?>",
    re.IGNORECASE,
)
_ATTR_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')


def _parse_manifest(blob: bytes) -> dict[str, str]:
    """Pull a few attributes out of the XML manifest by regex.

    Side-by-side manifests are tiny XML blobs that the OS reads
    permissively, so a regex extraction matches what Windows does.
    Real XML parsing would be overkill for the keys we want.
    """
    out: dict[str, str] = {}
    m = _TRUSTINFO_RE.search(blob)
    if m:
        for am in _ATTR_RE.finditer(m.group(1)):
            k = am.group(1).decode("ascii", errors="ignore")
            v = am.group(2).decode("utf-8", errors="replace")
            if k == "level":
                out["requestedExecutionLevel"] = v
            elif k in _MANIFEST_ATTRS:
                out[k] = v
    # Pick up dpiAware / longPathAware / heapType as a small bonus.
    for tag in (b"dpiAware", b"longPathAware", b"heapType"):
        rx = re.compile(rb"<" + tag + rb">([^<]+)</" + tag + rb">", re.IGNORECASE)
        rm = rx.search(blob)
        if rm:
            out[tag.decode("ascii")] = rm.group(1).decode("ascii", errors="replace").strip()
    return out

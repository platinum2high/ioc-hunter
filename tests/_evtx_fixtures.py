"""Byte-level EVTX fixture builder.

All EVTX containers are constructed from scratch using documented binary
layouts so the tests pin the parser against the specification rather than
against whatever a third-party tool emits.

Fixture events use *literal* BinXML (direct OpenStartElement / Attribute /
Value tokens, no TemplateInstance).  This is valid per the spec and simpler
to generate.  A separate set of fixtures exercises TemplateInstance-based
events (the common real-world form).
"""

from __future__ import annotations

import struct
import time

# ---------------------------------------------------------------------------
# BinXML literal builder
# ---------------------------------------------------------------------------

class _BinXmlBuilder:
    """Build a literal BinXML fragment (no templates) byte by byte.

    Design: names are stored in a separate section at the END of the BinXML
    blob.  All token bytes are accumulated in ``_tokens``; name references
    leave 4-byte placeholder slots that are patched with the correct absolute
    offsets in ``build()``.  This means the sequential token stream never
    contains embedded name data — the parser reads tokens from the start and
    uses the name_offset to jump (random-access) to the name section.
    """

    def __init__(self) -> None:
        self._tokens = bytearray()               # sequential token stream
        self._name_data = bytearray()            # name strings (appended at end)
        self._name_cache: dict[str, int] = {}    # name → offset in name_data
        self._patches: list[tuple[int, str]] = []  # (slot_pos_in_tokens, name)

    # -------- internal helpers ----------------------------------------

    def _schedule_name(self, name: str) -> None:
        """Reserve the name for the name section if not already scheduled."""
        if name not in self._name_cache:
            # offset -1 = not yet assigned; will be set in build()
            self._name_cache[name] = -1

    def _slot(self) -> int:
        """Append a 4-byte placeholder and return its position in _tokens."""
        pos = len(self._tokens)
        self._tokens.extend(b"\x00\x00\x00\x00")
        return pos

    # -------- token emitters ------------------------------------------

    def frag_header(self) -> _BinXmlBuilder:
        self._tokens.extend(b"\x0f\x01\x01\x00")   # FragHeader v1.1, flags=0
        return self

    def open_elem(self, name: str) -> _BinXmlBuilder:
        self._tokens.extend(b"\x01")                # OpenStartElement token
        self._tokens.extend(struct.pack("<H", 0))   # dep_id = 0
        self._tokens.extend(struct.pack("<I", 0))   # data_size = 0
        slot = self._slot()
        self._schedule_name(name)
        self._patches.append((slot, name))
        return self

    def close_elem(self) -> _BinXmlBuilder:
        self._tokens.extend(b"\x02")
        return self

    def close_empty(self) -> _BinXmlBuilder:
        self._tokens.extend(b"\x03")
        return self

    def attr(self, name: str) -> _BinXmlBuilder:
        self._tokens.extend(b"\x06")                # Attribute token
        slot = self._slot()
        self._schedule_name(name)
        self._patches.append((slot, name))
        return self

    def val_wstr(self, s: str) -> _BinXmlBuilder:
        enc = s.encode("utf-16-le")
        self._tokens.extend(b"\x05\x01")            # Value + WString
        self._tokens.extend(struct.pack("<H", len(s)))
        self._tokens.extend(enc)
        return self

    def val_u16(self, v: int) -> _BinXmlBuilder:
        self._tokens.extend(b"\x05\x06")            # Value + UInt16
        self._tokens.extend(struct.pack("<H", v))
        return self

    def val_u32(self, v: int) -> _BinXmlBuilder:
        self._tokens.extend(b"\x05\x08")            # Value + UInt32
        self._tokens.extend(struct.pack("<I", v))
        return self

    def val_filetime(self, unix_ts: float) -> _BinXmlBuilder:
        ft = int((unix_ts + 11644473600) * 10_000_000)
        self._tokens.extend(b"\x05\x11")            # Value + FILETIME
        self._tokens.extend(struct.pack("<Q", ft))
        return self

    def val_hex32(self, v: int) -> _BinXmlBuilder:
        self._tokens.extend(b"\x05\x14")            # Value + HexInt32
        self._tokens.extend(struct.pack("<I", v))
        return self

    def eof(self) -> _BinXmlBuilder:
        self._tokens.extend(b"\x00")
        return self

    def build(self) -> bytes:
        """Finalise: assign name offsets (= token_size + name_data offset)
        and patch the token stream, then return tokens + name_data."""
        tok_size = len(self._tokens)

        # Assign absolute offsets for all names
        for name in self._name_cache:
            off_in_names = len(self._name_data)
            self._name_cache[name] = tok_size + off_in_names
            enc = name.encode("utf-16-le")
            # name layout (NameStringNode): next_off(4) + hash(2) + length(2) + chars + null(2)
            self._name_data.extend(struct.pack("<IHH", 0, 0, len(name)))
            self._name_data.extend(enc)
            self._name_data.extend(b"\x00\x00")

        # Patch slots in token stream
        for slot_pos, name in self._patches:
            struct.pack_into("<I", self._tokens, slot_pos, self._name_cache[name])

        return bytes(self._tokens) + bytes(self._name_data)


# ---------------------------------------------------------------------------
# Standard event template: build literal BinXML for a Windows event
# ---------------------------------------------------------------------------

def make_event_binxml(
    *,
    event_id: int,
    level: int = 4,
    channel: str = "Security",
    computer: str = "WIN-DC01",
    provider: str = "Microsoft-Windows-Security-Auditing",
    unix_ts: float | None = None,
    record_id: int = 1,
    process_id: int = 4,
    thread_id: int = 8,
    data_fields: dict[str, str] | None = None,
) -> bytes:
    """Build a literal BinXML blob for an event record.

    The XML structure mirrors a standard Windows event:
        <Event>
          <System>
            <Provider Name="…"/>
            <EventID>N</EventID>
            <Level>N</Level>
            <TimeCreated SystemTime="FILETIME"/>
            <EventRecordID>N</EventRecordID>
            <Execution ProcessID="N" ThreadID="N"/>
            <Channel>…</Channel>
            <Computer>…</Computer>
          </System>
          <EventData>
            <Data Name="FieldKey">FieldValue</Data>
            …
          </EventData>
        </Event>
    """
    if unix_ts is None:
        unix_ts = time.time()
    if data_fields is None:
        data_fields = {}

    b = _BinXmlBuilder()
    (
        b.frag_header()
        .open_elem("Event")
            .open_elem("System")
                .open_elem("Provider")
                    .attr("Name").val_wstr(provider)
                .close_empty()
                .open_elem("EventID").val_u16(event_id).close_elem()
                .open_elem("Level").val_u16(level).close_elem()
                .open_elem("TimeCreated")
                    .attr("SystemTime").val_filetime(unix_ts)
                .close_empty()
                .open_elem("EventRecordID").val_u32(record_id).close_elem()
                .open_elem("Execution")
                    .attr("ProcessID").val_u32(process_id)
                    .attr("ThreadID").val_u32(thread_id)
                .close_empty()
                .open_elem("Channel").val_wstr(channel).close_elem()
                .open_elem("Computer").val_wstr(computer).close_elem()
            .close_elem()  # /System
    )
    if data_fields:
        b.open_elem("EventData")
        for key, val in data_fields.items():
            b.open_elem("Data").attr("Name").val_wstr(key).val_wstr(val).close_elem()
        b.close_elem()  # /EventData
    b.close_elem()  # /Event
    b.eof()
    return b.build()


# ---------------------------------------------------------------------------
# EVTX container builders
# ---------------------------------------------------------------------------

_EVTX_FILE_MAGIC = b"ElfFile\x00"
_EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
_EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"

_FILE_HEADER_SIZE = 4096
_CHUNK_SIZE = 65536
_CHUNK_HEADER_SIZE = 512
_RECORD_HEADER_SIZE = 24   # magic(4) + size(4) + record_id(8) + filetime(8)

_FILETIME_EPOCH_DIFF = 11644473600


def _unix_to_filetime(ts: float) -> int:
    return int((ts + _FILETIME_EPOCH_DIFF) * 10_000_000)


def _build_record(
    record_id: int,
    unix_ts: float,
    binxml: bytes,
) -> bytes:
    """Wrap BinXML in a 24-byte event record header."""
    total = _RECORD_HEADER_SIZE + len(binxml)
    ft = _unix_to_filetime(unix_ts)
    hdr = _EVTX_RECORD_MAGIC
    hdr += struct.pack("<I", total)
    hdr += struct.pack("<Q", record_id)
    hdr += struct.pack("<Q", ft)
    return hdr + binxml


def _build_chunk(records: list[bytes]) -> bytes:
    """Wrap a list of record bytes into an EVTX chunk (65536 bytes)."""
    body = bytearray()
    for rec in records:
        body.extend(rec)

    # Chunk header (512 bytes)
    hdr = bytearray(512)
    hdr[:8] = _EVTX_CHUNK_MAGIC
    first_num = 1
    last_num = len(records)
    struct.pack_into("<Q", hdr, 8, first_num)
    struct.pack_into("<Q", hdr, 16, last_num)
    struct.pack_into("<Q", hdr, 24, first_num)   # first event record ID
    struct.pack_into("<Q", hdr, 32, last_num)    # last event record ID
    struct.pack_into("<I", hdr, 40, 128)         # header size (primary part)
    last_data_offset = _CHUNK_HEADER_SIZE + len(body) - len(records[-1]) if records else _CHUNK_HEADER_SIZE
    free_space_offset = _CHUNK_HEADER_SIZE + len(body)
    struct.pack_into("<I", hdr, 44, last_data_offset)
    struct.pack_into("<I", hdr, 48, free_space_offset)

    # Pad chunk to 65536
    chunk = bytes(hdr) + bytes(body)
    padding = _CHUNK_SIZE - len(chunk)
    chunk = chunk[:_CHUNK_SIZE] if padding < 0 else chunk + b"\x00" * padding
    return chunk


def _build_file_header(num_chunks: int) -> bytes:
    """Build a 4096-byte EVTX file header."""
    hdr = bytearray(4096)
    hdr[:8] = _EVTX_FILE_MAGIC
    struct.pack_into("<Q", hdr, 8, 0)            # FirstChunkNumber
    struct.pack_into("<Q", hdr, 16, max(0, num_chunks - 1))  # LastChunkNumber
    struct.pack_into("<Q", hdr, 24, 1)           # NextRecordIdentifier
    struct.pack_into("<I", hdr, 32, 128)         # HeaderBlockSize
    struct.pack_into("<H", hdr, 36, 1)           # MinorVersion
    struct.pack_into("<H", hdr, 38, 3)           # MajorVersion
    struct.pack_into("<H", hdr, 40, 0x1000)      # HeaderBlockSize (file)
    struct.pack_into("<H", hdr, 42, num_chunks)  # NumberOfChunks
    return bytes(hdr)


def build_evtx(event_specs: list[tuple[int, dict]]) -> bytes:
    """Build a complete EVTX file from a list of (unix_ts, event_kwargs) tuples.

    ``event_kwargs`` is passed directly to ``make_event_binxml``.
    All events land in a single chunk (up to ~60 KiB of records).
    """
    records: list[bytes] = []
    for i, (unix_ts, kwargs) in enumerate(event_specs):
        binxml = make_event_binxml(unix_ts=unix_ts, record_id=i + 1, **kwargs)
        rec = _build_record(i + 1, unix_ts, binxml)
        records.append(rec)

    chunk = _build_chunk(records)
    file_hdr = _build_file_header(num_chunks=1)
    return file_hdr + chunk


# ---------------------------------------------------------------------------
# Pre-built scenario fixtures
# ---------------------------------------------------------------------------

def _ts(offset_seconds: float = 0) -> float:
    """Deterministic timestamp: 2024-06-01 00:00:00 UTC + offset."""
    # 2024-06-01 00:00:00 UTC = 1717200000
    return 1717200000.0 + offset_seconds


def build_kerberoasting_evtx() -> bytes:
    """EVTX with 4769 events using RC4 encryption (T1558.003)."""
    specs = [
        (_ts(i * 5), {
            "event_id": 4769,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "svc_sql",
                "ServiceName": f"MSSQLSvc/sql{i:02d}.corp.local:1433",
                "TicketEncryptionType": "0x17",
                "IpAddress": "192.168.10.50",
            },
        })
        for i in range(3)
    ]
    return build_evtx(specs)


def build_asrep_evtx() -> bytes:
    """EVTX with 4768 events using RC4 (T1558.004)."""
    specs = [
        (_ts(i * 10), {
            "event_id": 4768,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": f"nopreauth_user{i}",
                "TicketEncryptionType": "0x17",
                "IpAddress": "192.168.10.60",
            },
        })
        for i in range(2)
    ]
    return build_evtx(specs)


def build_bruteforce_evtx(fail_count: int = 12) -> bytes:
    """EVTX with many 4625 (failed logon) events for the same account."""
    specs = [
        (_ts(i * 2), {
            "event_id": 4625,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "Administrator",
                "LogonType": "3",
                "IpAddress": "10.10.10.99",
                "FailureReason": "%%2313",
            },
        })
        for i in range(fail_count)
    ]
    return build_evtx(specs)


def build_password_spray_evtx(user_count: int = 7) -> bytes:
    """EVTX with 4625 failures from one source IP targeting many users."""
    specs = [
        (_ts(i * 3), {
            "event_id": 4625,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": f"user{i:03d}",
                "LogonType": "3",
                "IpAddress": "172.16.0.200",
                "FailureReason": "%%2313",
            },
        })
        for i in range(user_count)
    ]
    return build_evtx(specs)


def build_log_cleared_evtx() -> bytes:
    """EVTX with event 1102 (Security log cleared)."""
    specs = [
        (_ts(0), {
            "event_id": 4624,
            "channel": "Security",
            "data_fields": {"TargetUserName": "admin"},
        }),
        (_ts(100), {
            "event_id": 1102,
            "channel": "Security",
            "provider": "Microsoft-Windows-Eventlog",
            "data_fields": {
                "SubjectUserName": "admin",
                "SubjectDomainName": "CORP",
            },
        }),
    ]
    return build_evtx(specs)


def build_lolbin_evtx() -> bytes:
    """EVTX with 4688 events spawning LOLBins and encoded PowerShell."""
    specs = [
        (_ts(0), {
            "event_id": 4688,
            "channel": "Security",
            "data_fields": {
                "SubjectUserName": "user1",
                "NewProcessName": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -decode payload.b64 payload.exe",
            },
        }),
        (_ts(10), {
            "event_id": 4688,
            "channel": "Security",
            "data_fields": {
                "SubjectUserName": "user1",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": (
                    "powershell.exe -NoP -NonI -W Hidden "
                    "-enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
                ),
            },
        }),
    ]
    return build_evtx(specs)


def build_rdp_logon_evtx() -> bytes:
    """EVTX with 4624 event for RDP logon (LogonType=10)."""
    specs = [
        (_ts(0), {
            "event_id": 4624,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "sysadmin",
                "LogonType": "10",
                "IpAddress": "203.0.113.5",
                "WorkstationName": "ATTACKER-PC",
            },
        }),
    ]
    return build_evtx(specs)


def build_new_service_evtx() -> bytes:
    """EVTX with Event 7045 (new service installed)."""
    specs = [
        (_ts(0), {
            "event_id": 7045,
            "channel": "System",
            "provider": "Service Control Manager",
            "data_fields": {
                "ServiceName": "WindowsDefenderUpdate",
                "ServiceFileName": "C:\\Users\\Public\\svc.exe",
                "ServiceType": "16",
                "ServiceAccount": "LocalSystem",
            },
        }),
    ]
    return build_evtx(specs)


def build_scheduled_task_evtx() -> bytes:
    """EVTX with Event 4698 (scheduled task created)."""
    specs = [
        (_ts(0), {
            "event_id": 4698,
            "channel": "Security",
            "data_fields": {
                "SubjectUserName": "attacker",
                "TaskName": "\\Microsoft\\Windows\\Telemetry\\Update",
                "TaskContent": "<Actions><Exec><Command>C:\\temp\\beacon.exe</Command></Exec></Actions>",
            },
        }),
    ]
    return build_evtx(specs)


def build_new_account_evtx() -> bytes:
    """EVTX with Event 4720 (new local account)."""
    specs = [
        (_ts(0), {
            "event_id": 4720,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "hacker123",
                "SubjectUserName": "attacker",
                "SubjectDomainName": "CORP",
            },
        }),
    ]
    return build_evtx(specs)


def build_success_after_fail_evtx() -> bytes:
    """EVTX: multiple 4625 failures followed by 4624 success for same user."""
    specs = [
        (_ts(i * 5), {
            "event_id": 4625,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "admin",
                "IpAddress": "10.0.0.99",
                "LogonType": "3",
            },
        })
        for i in range(5)
    ] + [
        (_ts(30), {
            "event_id": 4624,
            "channel": "Security",
            "data_fields": {
                "TargetUserName": "admin",
                "IpAddress": "10.0.0.99",
                "LogonType": "3",
            },
        }),
    ]
    return build_evtx(specs)


def build_explicit_cred_evtx() -> bytes:
    """EVTX with Event 4648 (explicit credential logon = RunAs / PSExec)."""
    specs = [
        (_ts(0), {
            "event_id": 4648,
            "channel": "Security",
            "data_fields": {
                "SubjectUserName": "user1",
                "TargetUserName": "Administrator",
                "TargetServerName": "\\\\DC01",
            },
        }),
    ]
    return build_evtx(specs)


def build_admin_share_evtx() -> bytes:
    """EVTX with Event 5140 (network share access to ADMIN$)."""
    specs = [
        (_ts(0), {
            "event_id": 5140,
            "channel": "Security",
            "data_fields": {
                "SubjectUserName": "attacker",
                "ShareName": "\\\\*\\ADMIN$",
                "IpAddress": "192.168.100.200",
            },
        }),
    ]
    return build_evtx(specs)


def build_sensitive_group_evtx() -> bytes:
    """EVTX with Event 4728 (member added to Domain Admins)."""
    specs = [
        (_ts(0), {
            "event_id": 4728,
            "channel": "Security",
            "data_fields": {
                "MemberName": "CN=hacker123,DC=corp,DC=local",
                "TargetUserName": "Domain Admins",
                "SubjectUserName": "attacker",
            },
        }),
    ]
    return build_evtx(specs)


def build_minimal_evtx(event_id: int = 4624) -> bytes:
    """Single-event EVTX for basic parser smoke tests."""
    specs = [
        (_ts(0), {
            "event_id": event_id,
            "channel": "Security",
            "computer": "TESTPC",
            "provider": "Microsoft-Windows-Security-Auditing",
            "data_fields": {"TargetUserName": "testuser"},
        }),
    ]
    return build_evtx(specs)


def build_multi_channel_evtx() -> bytes:
    """EVTX with events from multiple channels."""
    specs = [
        (_ts(0), {"event_id": 4624, "channel": "Security",
                  "data_fields": {"TargetUserName": "alice"}}),
        (_ts(1), {"event_id": 7045, "channel": "System",
                  "provider": "Service Control Manager",
                  "data_fields": {"ServiceName": "malware_svc",
                                  "ServiceFileName": "C:\\evil.exe"}}),
        (_ts(2), {"event_id": 4698, "channel": "Security",
                  "data_fields": {"TaskName": "\\backdoor",
                                  "SubjectUserName": "alice"}}),
    ]
    return build_evtx(specs)

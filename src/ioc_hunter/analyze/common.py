"""Shared building blocks for the binary analyzers.

This module is the toolbox every format-specific analyzer (PE / ELF /
Mach-O) draws from. It owns:

- the dataclasses every report carries: ``Finding``, ``Section``,
  ``Import``, ``AnalyzerReport``;
- a defensive ``Reader`` that wraps the raw bytes — every offset read
  goes through it and returns ``None`` on bounds violation instead of
  crashing on a truncated/lying header;
- entropy math (Shannon, in bits/byte, 0..8);
- ASCII + UTF-16LE string extraction with sane caps so a 50 MiB blob
  doesn't materialise 50 MiB of Python strings;
- IOC sweep that reuses the project-wide ``extract_iocs`` parser so the
  same defang/refang rules apply that the rest of the CLI relies on;
- a packer signature table (UPX, MPRESS, ASPack, PECompact, FSG, Themida,
  VMProtect, Petite, Enigma) shared between PE and ELF;
- suspicious-API tables grouped by behaviour (process injection,
  anti-debug, anti-VM, persistence, network, crypto, info-stealer)
  consumed by ``heuristics.py``.

Design rule: everything that touches user-supplied bytes is total —
i.e. never raises on malformed input. Bad files yield a degraded
report, not a stack trace. That is what lets us safely point the
analyser at random samples from a malware feed.
"""

from __future__ import annotations

import math
import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from ioc_hunter.core.parser import extract_iocs
from ioc_hunter.core.types import IOC

# ---------------------------------------------------------------------------
# Hard caps. Picked to survive obviously hostile input while still letting
# real-world samples (multi-MB packed installers) analyse fully.
# ---------------------------------------------------------------------------

#: Largest file we will ever ingest. Bigger files are truncated to this and a
#: warning is emitted — the analyser still runs, but on a prefix.
MAX_FILE_BYTES = 256 * 1024 * 1024  # 256 MiB

#: Largest number of PE sections / ELF sections / Mach-O segments we will walk.
#: Real binaries have <50; values in the thousands are a malformed-header tell.
MAX_SECTIONS = 96

#: Cap on imported DLL/dylib entries we materialise.
MAX_IMPORT_LIBS = 256

#: Cap on imported symbol names per library.
MAX_IMPORT_SYMBOLS_PER_LIB = 4096

#: Cap on extracted strings.
MAX_STRINGS = 20_000

#: Minimum printable-character run we treat as a "string".
MIN_STRING_LEN = 6

#: Drop strings longer than this — pathological packers embed megabytes of
#: random ASCII; nothing useful for IOC extraction lives past ~1 KiB.
MAX_STRING_LEN = 1024


# ---------------------------------------------------------------------------
# Public enums + dataclasses
# ---------------------------------------------------------------------------


class FileFormat(StrEnum):
    """Recognised binary container formats."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    MACHO_FAT = "macho_fat"
    PDF = "pdf"
    OOXML = "ooxml"  # ZIP-based Office (.docx, .docm, .xlsm, .pptm, ...)
    OLE = "ole"  # Compound File Binary (.doc, .xls, .ppt, .msi, vbaProject.bin)
    RTF = "rtf"  # Rich Text Format — usually carries OLE exploit objects
    UNKNOWN = "unknown"


class Severity(IntEnum):
    """Finding severity ladder. Numeric so we can max() across findings."""

    INFO = 10
    LOW = 30
    MEDIUM = 50
    HIGH = 70
    CRITICAL = 90


class Verdict(StrEnum):
    """Final synthesised verdict for the binary as a whole."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation about the binary worth surfacing.

    `category` groups related findings ("injection", "anti_debug", ...)
    so the renderer can colour them; `evidence` is the concrete artefact
    that triggered the rule (an API name, a section, ...).
    `mitre` carries ATT&CK technique IDs ("T1055", "T1027.002") populated
    by ``attack_map.tag_findings`` after the report is built.
    """

    rule: str
    severity: Severity
    category: str
    message: str
    evidence: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Section:
    """One section/segment from any binary format."""

    name: str
    virtual_size: int
    raw_size: int
    file_offset: int
    entropy: float
    flags: str = ""  # human-readable permission string e.g. "RX", "RW"


@dataclass(frozen=True, slots=True)
class Import:
    """One imported library and its referenced symbols."""

    library: str
    symbols: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Export:
    name: str
    ordinal: int | None = None


@dataclass(slots=True)
class AnalyzerReport:
    """Everything one analyser knows about one file.

    Format-specific extras live in ``metadata`` so we don't need a new
    dataclass for every quirk (Rich header, TLS callbacks, Mach-O UUID,
    ELF interpreter, ...).
    """

    path: str
    format: FileFormat
    file_size: int
    truncated: bool
    md5: str
    sha1: str
    sha256: str

    architecture: str = ""
    bitness: int = 0  # 32 or 64; 0 means unknown
    entry_point: int = 0
    timestamp: int = 0
    compiler: str = ""

    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    exports: list[Export] = field(default_factory=list)
    linked_libraries: list[str] = field(default_factory=list)

    overall_entropy: float = 0.0
    has_overlay: bool = False
    overlay_size: int = 0
    overlay_entropy: float = 0.0

    is_signed: bool = False
    is_stripped: bool = False
    is_packed: bool = False
    detected_packer: str = ""

    # Cross-format pivot identifiers populated by the dedicated modules.
    # All optional; empty string ⇒ "not present / not parsed".
    imphash: str = ""  # PE only — Mandiant industry-standard pivot
    signer_cn: str = ""  # PE Authenticode / Mach-O CodeDirectory
    issuer_cn: str = ""  # PE Authenticode only
    build_id: str = ""  # ELF GNU build-id hex (or Go .note.go.buildid)
    version_info: dict[str, str] = field(default_factory=dict)  # PE VERSIONINFO keys
    manifest: dict[str, str] = field(default_factory=dict)  # PE Manifest keys
    entitlements: list[str] = field(default_factory=list)  # Mach-O entitlement keys

    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        """Synthesise a verdict from the maximum finding severity."""
        if not self.findings:
            return Verdict.CLEAN
        worst = max(f.severity for f in self.findings)
        if worst >= Severity.HIGH:
            return Verdict.MALICIOUS
        if worst >= Severity.MEDIUM:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    def confidence(self) -> float:
        """A crude 0..1 confidence in the verdict. Combines the count and
        severity of findings — more, higher-severity hits ⇒ more confident.
        Intentionally simple; the user reads the findings, the number is
        decoration."""
        if not self.findings:
            return 1.0
        # 0..1 contribution per finding, weighted by severity.
        total = sum(f.severity / 100.0 for f in self.findings)
        return min(1.0, total / 3.0)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# ---------------------------------------------------------------------------
# Defensive reader. Wraps a `bytes` blob and refuses to read past the end.
# ---------------------------------------------------------------------------


class Reader:
    """A bounds-checked view of the raw file bytes.

    Every header-walking routine in the format modules goes through this
    so a malformed file produces ``None`` rather than an ``IndexError``
    or ``struct.error``. The Reader does NOT mutate state — there is no
    cursor — because format walkers jump around the file constantly
    (RVA→offset translation, follow tables, etc) and a stateful cursor
    just becomes a footgun.
    """

    __slots__ = ("data", "size")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

    def slice(self, offset: int, length: int) -> bytes | None:
        """Return ``data[offset:offset+length]`` or ``None`` on OOB."""
        if offset < 0 or length < 0:
            return None
        end = offset + length
        if end > self.size:
            return None
        return self.data[offset:end]

    def u8(self, offset: int) -> int | None:
        buf = self.slice(offset, 1)
        return buf[0] if buf else None

    def u16(self, offset: int, little: bool = True) -> int | None:
        buf = self.slice(offset, 2)
        if buf is None:
            return None
        return struct.unpack("<H" if little else ">H", buf)[0]

    def u32(self, offset: int, little: bool = True) -> int | None:
        buf = self.slice(offset, 4)
        if buf is None:
            return None
        return struct.unpack("<I" if little else ">I", buf)[0]

    def u64(self, offset: int, little: bool = True) -> int | None:
        buf = self.slice(offset, 8)
        if buf is None:
            return None
        return struct.unpack("<Q" if little else ">Q", buf)[0]

    def cstr(self, offset: int, max_len: int = 256) -> str | None:
        """Read a C string starting at ``offset`` (NUL-terminated, ASCII)."""
        if offset < 0 or offset >= self.size:
            return None
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = min(offset + max_len, self.size)
        try:
            return self.data[offset:end].decode("ascii", errors="replace")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte (0..8).

    Empty input returns 0.0 by convention. Packed/encrypted payloads
    cluster around 7.5-8.0; English text around 4.0-5.0; native code
    around 5.5-6.5.
    """
    if not data:
        return 0.0
    # bytes.count is C-fast; faster than collections.Counter for raw bytes.
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------


_ASCII_PRINTABLE = re.compile(rb"[\x20-\x7E]{%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))


def extract_ascii_strings(data: bytes, *, cap: int = MAX_STRINGS) -> list[str]:
    """Pull printable ASCII runs of length ≥ ``MIN_STRING_LEN``."""
    out: list[str] = []
    for m in _ASCII_PRINTABLE.finditer(data):
        out.append(m.group().decode("ascii", errors="replace"))
        if len(out) >= cap:
            break
    return out


def extract_utf16le_strings(data: bytes, *, cap: int = MAX_STRINGS) -> list[str]:
    """Pull printable UTF-16LE runs.

    Strategy: every other byte must be 0x00 (high byte of a BMP printable
    code point) and the low byte must be printable ASCII. We scan in
    ``bytes`` to avoid materialising a giant decoded string.

    Performance: this routine is linear in ``len(data)`` — we never
    rewind ``i`` after the inner accept loop. A non-rewinding scanner
    is the only safe shape for a SOC tool that may face hundreds of MB
    of input; a naive O(n²) approach blows up on packed payloads.
    """
    out: list[str] = []
    n = len(data)
    i = 0
    while i + 1 < n and len(out) < cap:
        # Fast skip: every UTF-16LE printable starts with (low, 0x00).
        if data[i + 1] != 0 or not 0x20 <= data[i] <= 0x7E:
            i += 1
            continue
        chars: list[int] = []
        while i + 1 < n and data[i + 1] == 0 and 0x20 <= data[i] <= 0x7E:
            chars.append(data[i])
            i += 2
            if len(chars) >= MAX_STRING_LEN:
                break
        if len(chars) >= MIN_STRING_LEN:
            out.append(bytes(chars).decode("ascii", errors="replace"))
        # Linear: ``i`` already advanced past the run we tried. Even if
        # it was too short to save, we do NOT rewind — that would make
        # the worst case quadratic.
    return out


def extract_all_strings(data: bytes, *, cap: int = MAX_STRINGS) -> list[str]:
    """ASCII + UTF-16LE strings, deduplicated, capped."""
    seen: set[str] = set()
    out: list[str] = []
    remaining = cap
    for s in extract_ascii_strings(data, cap=remaining):
        if s not in seen:
            seen.add(s)
            out.append(s)
    remaining = cap - len(out)
    if remaining > 0:
        for s in extract_utf16le_strings(data, cap=remaining):
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out[:cap]


def sweep_iocs(strings: Iterable[str]) -> list[IOC]:
    """Extract IOCs from a sequence of strings via the project parser.

    We pass each string through the same ``extract_iocs`` the rest of
    the engine uses — so behaviour around defanging, host extraction
    from URLs, and dedup is identical to the CLI.
    """
    # Joining with a delimiter the parser will not match across (a newline)
    # avoids materialising a giant single string when there are tens of
    # thousands of strings.
    blob = "\n".join(strings)
    if not blob:
        return []
    return list(extract_iocs(blob))


# ---------------------------------------------------------------------------
# Packer signatures. Heuristic — see packer_match() for ranking.
# Each entry: (label, bytes-pattern, where-to-look).
# ``where``: "section_name", "entry", "anywhere".
# ---------------------------------------------------------------------------


_PACKER_SIGS: tuple[tuple[str, bytes, str], ...] = (
    # Section-name based
    ("UPX", b"UPX0", "section_name"),
    ("UPX", b"UPX1", "section_name"),
    ("UPX", b"UPX2", "section_name"),
    ("UPX", b"UPX!", "anywhere"),
    ("ASPack", b".aspack", "section_name"),
    ("ASPack", b".adata", "section_name"),
    ("MPRESS", b".MPRESS1", "section_name"),
    ("MPRESS", b".MPRESS2", "section_name"),
    ("PECompact", b"PEC2", "section_name"),
    ("PECompact", b"PECompact2", "anywhere"),
    ("FSG", b"FSG!", "anywhere"),
    ("Themida", b".themida", "section_name"),
    ("Themida", b"Themida", "anywhere"),
    ("VMProtect", b".vmp0", "section_name"),
    ("VMProtect", b".vmp1", "section_name"),
    ("VMProtect", b".vmp2", "section_name"),
    ("Petite", b".petite", "section_name"),
    ("Enigma", b".enigma1", "section_name"),
    ("Enigma", b".enigma2", "section_name"),
    ("ConfuserEx", b"ConfusedByAttribute", "anywhere"),
    ("Obsidium", b".obsidium", "section_name"),
    ("Yoda", b"yC", "section_name"),
)


def packer_match(
    section_names: Iterable[str],
    raw: bytes,
) -> str | None:
    """Return the packer label if a signature matches, else None.

    ``raw`` is the file head (we only need the first ~1 MiB for
    ``anywhere`` patterns — packers stamp themselves near the start).
    """
    head = raw[: 1024 * 1024]
    names = set(section_names)
    for label, pattern, where in _PACKER_SIGS:
        if where == "section_name":
            try:
                name = pattern.decode("ascii")
            except UnicodeDecodeError:
                continue
            if any(name == n or name in n for n in names):
                return label
        elif where == "anywhere" and pattern in head:
            return label
    return None


# ---------------------------------------------------------------------------
# Suspicious-API tables. Read by heuristics.py to flag behaviour combos.
# Tables are intentionally narrow — high-precision over high-recall — so a
# match is meaningful when we surface it on the LinkedIn-ready screenshot.
# ---------------------------------------------------------------------------


#: Classic process-injection toolkit. Hitting ≥3 of these in one PE = textbook
#: injector. Plain copies have at most one ("VirtualAlloc" for malloc-style).
WIN_INJECTION_APIS: frozenset[str] = frozenset(
    {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "GetThreadContext",
        "NtMapViewOfSection",
        "ZwMapViewOfSection",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "OpenProcess",
        "NtOpenProcess",
        "ResumeThread",
        "SuspendThread",
        "WriteFileEx",
    }
)


WIN_ANTI_DEBUG_APIS: frozenset[str] = frozenset(
    {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "DebugActiveProcess",
        "ZwQueryInformationProcess",
        "ZwSetInformationThread",
        "FindWindowA",
        "FindWindowW",
        "GetTickCount",
        "QueryPerformanceCounter",
        "NtClose",
    }
)


WIN_ANTI_VM_APIS: frozenset[str] = frozenset(
    {
        "CPUID",
        "GetSystemFirmwareTable",
        "EnumSystemFirmwareTables",
        "GetAdaptersInfo",  # MAC OUI sandbox detection
        "GetVolumeInformationW",
        "GetVolumeInformationA",
        "GlobalMemoryStatusEx",
    }
)


WIN_PERSISTENCE_APIS: frozenset[str] = frozenset(
    {
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "CreateServiceA",
        "CreateServiceW",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "StartServiceA",
        "StartServiceW",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "ITaskScheduler",  # COM CLSID often shows in strings, not imports
        "CreateFileMappingW",
    }
)


WIN_NETWORK_APIS: frozenset[str] = frozenset(
    {
        "InternetOpenA",
        "InternetOpenW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "InternetConnectA",
        "InternetConnectW",
        "InternetReadFile",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "URLDownloadToCacheFileA",
        "URLDownloadToCacheFileW",
        "socket",
        "WSAStartup",
        "WSASocketA",
        "WSASocketW",
        "connect",
        "send",
        "recv",
        "gethostbyname",
        "getaddrinfo",
        "DnsQuery_A",
        "DnsQuery_W",
    }
)


WIN_CRYPTO_APIS: frozenset[str] = frozenset(
    {
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CryptHashData",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptGenKey",
        "CryptImportKey",
        "CryptExportKey",
        "CryptDeriveKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptGenerateSymmetricKey",
    }
)


WIN_INFOSTEALER_APIS: frozenset[str] = frozenset(
    {
        "GetClipboardData",
        "OpenClipboard",
        "EmptyClipboard",
        "SetClipboardData",
        "GetAsyncKeyState",  # keylogger
        "GetKeyState",
        "RegisterRawInputDevices",
        "BitBlt",  # screenshot
        "CreateCompatibleBitmap",
        "GetDC",
        "GetForegroundWindow",
        "GetWindowTextA",
        "GetWindowTextW",
        "EnumWindows",
        "CryptUnprotectData",  # DPAPI unpacking (browser creds)
    }
)


#: ELF/Mach-O posix-side suspicious symbols.
POSIX_SUSPICIOUS_SYMBOLS: frozenset[str] = frozenset(
    {
        "ptrace",
        "system",
        "popen",
        "execve",
        "execv",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "dlopen",
        "dlsym",
        "mprotect",
        "mmap",
        "fork",
        "vfork",
        "clone",
        "kill",
        "setuid",
        "setgid",
        "chmod",
        "chown",
        # network
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "send",
        "recv",
        "sendto",
        "recvfrom",
        "getaddrinfo",
        "gethostbyname",
        "inet_pton",
        # crypto
        "EVP_EncryptInit_ex",
        "EVP_DecryptInit_ex",
        "AES_encrypt",
        "RSA_public_encrypt",
        # macOS specifics
        "task_for_pid",
        "mach_vm_write",
        "mach_vm_read",
        "vm_protect",
        "thread_create_running",
        "_dyld_register_func_for_add_image",
    }
)


# ---------------------------------------------------------------------------
# Small helpers reused across format modules.
# ---------------------------------------------------------------------------


def humanize_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} GiB"


def chunks(data: bytes, n: int) -> Iterator[bytes]:
    """Yield consecutive ``n``-byte chunks of ``data``."""
    for i in range(0, len(data), n):
        yield data[i : i + n]

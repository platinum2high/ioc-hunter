"""VBA module decompressor + behavioural heuristics.

Every macro-enabled Office document — both legacy CFB (.doc / .xls) and
modern OOXML (.docm / .xlsm / .pptm) — ships its macros as a
**vbaProject** storage with one stream per code module. Inside each
module stream, the actual VBA source sits behind a small
``PerformanceCache`` prefix and is encoded with Microsoft's
``CompressedAtom`` format ([MS-OVBA] §2.4.1).

This module:

1. **Decompresses CompressedAtom**. The algorithm is a tiny
   LZ-style scheme. Each chunk packs up to 4 KiB of plaintext; tokens
   are either literal bytes or copy tokens whose offset/length bit
   split widens as the chunk fills (so early bytes can only reference
   a 4-wide window, later bytes the full 12-bit space). Implementing
   it correctly is load-bearing — get the bit split wrong and the
   output looks like ``Sub`` followed by garbage that won't trigger
   any rule.

2. **Walks a vbaProject CFB** for every plausible module stream,
   skipping the binary ``PerformanceCache`` prefix by scanning for the
   compressed-atom signature byte (``0x01``) followed by a chunk
   header with the spec's signature bit set.

3. **Runs source-level heuristics** on the decoded text. Tier ladder:

   - Auto-exec subs (``AutoOpen``, ``Workbook_Open``,
     ``Document_Open``, …) → HIGH, ATT&CK T1204.002.
   - Suspicious COM bridges (``WScript.Shell``, ``MSXML2.XMLHTTP``,
     ``ADODB.Stream``, …) → HIGH, T1059.005.
   - Process-spawn targets (``cmd``, ``powershell``, ``mshta``,
     ``rundll32``, ``regsvr32``, ``certutil``) → HIGH, T1218.
   - PowerShell encoded-command markers (``-enc``,
     ``FromBase64String``) → CRITICAL, T1027 + T1059.001.
   - Chr() / StrReverse / Hex2Dec obfuscation density →
     MEDIUM, T1027.

Reference:
  https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    Finding,
    Severity,
)
from ioc_hunter.analyze.ole import OleContainer

# ---------------------------------------------------------------------------
# CompressedAtom constants
# ---------------------------------------------------------------------------

#: First byte of every valid CompressedAtom — the "signature byte".
COMPRESSED_SIGNATURE = 0x01

#: Maximum decompressed bytes per chunk (the chunk is sized to fit in
#: 12 bits → 4096 byte ceiling).
MAX_CHUNK_DECOMPRESSED = 4096

#: We cap total decompressed output per stream. Real VBA modules are
#: <100 KiB; multi-MB output is a malformed-chunk loop.
MAX_DECOMPRESSED_BYTES = 4 * 1024 * 1024


@dataclass(slots=True)
class VbaModule:
    """One decompressed VBA module."""

    name: str
    raw_size: int
    decompressed: bytes = b""
    text: str = ""
    decode_error: str = ""
    auto_exec_subs: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Heuristic tables
# ---------------------------------------------------------------------------

# Sub names that fire automatically when the document is opened / closed /
# activated. The match is anchored on ``Sub <name>`` or ``Function <name>``
# (case-insensitive). One hit is enough to flag the doc.
_AUTO_EXEC_SUBS: tuple[str, ...] = (
    "AutoOpen",
    "AutoClose",
    "AutoExec",
    "AutoNew",
    "AutoExit",
    "Auto_Open",
    "Auto_Close",
    "Document_Open",
    "Document_Close",
    "Document_New",
    "Workbook_Open",
    "Workbook_Close",
    "Workbook_Activate",
    "Workbook_BeforeClose",
    "Worksheet_Activate",
    "Worksheet_BeforeDoubleClick",
)

# Suspicious COM bridges + win32 calls. Hit count matters — a single
# CreateObject can be benign but in combination with auto-exec it isn't.
_SUSPICIOUS_APIS: tuple[str, ...] = (
    "WScript.Shell",
    "Shell.Application",
    "MSXML2.XMLHTTP",
    "MSXML2.ServerXMLHTTP",
    "Microsoft.XMLHTTP",
    "WinHttp.WinHttpRequest",
    "ADODB.Stream",
    "ADODB.Connection",
    "Scripting.FileSystemObject",
    "InternetExplorer.Application",
    "URLDownloadToFile",
    "URLDownloadToFileA",
    "ShellExecute",
    "ShellExecuteA",
    "VirtualAlloc",
    "CreateThread",
    "WriteProcessMemory",
)

# Living-off-the-land binaries (LOLBins) spawned from VBA.
_LOLBINS: tuple[str, ...] = (
    "cmd.exe",
    "cmd /c",
    "cmd /k",
    "powershell",
    "pwsh",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "schtasks",
    "wscript.exe",
    "cscript.exe",
    "msbuild.exe",
    "installutil.exe",
    "wmic.exe",
    "ftp.exe",
)

# Tokens that almost always mean "PowerShell encoded blob inbound".
_ENCODED_POWERSHELL_TOKENS: tuple[str, ...] = (
    "-enc",
    "-EncodedCommand",
    "FromBase64String",
    "[Convert]::FromBase64",
    "::FromBase64String",
    "-noprofile",
    "-windowstyle hidden",
    "-w hidden",
    "iex(",
    "Invoke-Expression",
    "DownloadString",
    "DownloadFile",
)

# Counts of these primitive obfuscation helpers signal hand-rolled
# decoders. Singletons are noise; density is the real signal.
_OBFUSCATION_PRIMITIVES = re.compile(
    rb"\b(Chr|ChrW|ChrB|StrReverse|Hex2Dec|StrConv|Asc|AscW)\s*\(",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public entry — drive from an OleContainer (works for vbaProject.bin
# extracted from OOXML and for legacy CFB Office docs alike).
# ---------------------------------------------------------------------------


def analyze_vba_project(container: OleContainer, *, report: AnalyzerReport) -> None:
    """Walk a CFB looking for VBA modules, decompress each, emit findings.

    ``container`` must already be parsed (``ole.parse_cfb``). Idempotent —
    calling twice just re-records the same findings.
    """
    modules = extract_vba_modules(container)
    report.metadata["vba_module_count"] = len(modules)
    report.metadata["vba_modules"] = [
        {
            "name": m.name,
            "raw_size": m.raw_size,
            "decompressed_size": len(m.decompressed),
            "auto_exec": m.auto_exec_subs,
            "decode_error": m.decode_error,
        }
        for m in modules
    ]

    if not modules:
        return

    all_text = b"\n".join(m.decompressed for m in modules)
    report.metadata["vba_decoded_blob"] = all_text

    _emit_vba_findings(modules, all_text, report)


# ---------------------------------------------------------------------------
# Module extraction
# ---------------------------------------------------------------------------


# Streams we never treat as modules. Decoding ``dir`` is doable but we
# already get sub names from each individual module.
_NON_MODULE_NAMES = {"dir", "_VBA_PROJECT", "PROJECT", "PROJECTwm", "ProjectLcid"}


def extract_vba_modules(container: OleContainer) -> list[VbaModule]:
    out: list[VbaModule] = []
    for path, body in container.streams.items():
        leaf = path.rsplit("/", 1)[-1]
        # Only look inside a "VBA" storage to keep noise down.
        if "VBA/" not in path and "VBA\\" not in path:
            continue
        if leaf in _NON_MODULE_NAMES:
            continue
        decompressed, err = decompress_module_stream(body)
        if decompressed is None:
            # No CompressedAtom found inside; not a module.
            continue
        text = decompressed.decode("latin-1", "replace")
        autos = _detect_auto_exec_subs(text)
        out.append(
            VbaModule(
                name=leaf,
                raw_size=len(body),
                decompressed=decompressed,
                text=text,
                decode_error=err,
                auto_exec_subs=autos,
            )
        )
    return out


def decompress_module_stream(body: bytes) -> tuple[bytes | None, str]:
    """Locate the CompressedAtom inside a module stream and decode it.

    Module streams start with a PerformanceCache (compiled p-code) whose
    length is recorded in the project's ``dir`` stream. Rather than parse
    ``dir`` we scan forward for ``0x01`` followed by a valid first chunk
    header (signature bit set, chunk type compressed, plausible size).
    First hit wins — false positives are bounded because the chunk
    header validation is strict.
    """
    for start in range(len(body) - 3):
        if body[start] != COMPRESSED_SIGNATURE:
            continue
        if not _looks_like_chunk_header(body, start + 1):
            continue
        decoded, err = decompress_compressed_atom(body[start:])
        if decoded:
            return decoded, err
    return None, "no CompressedAtom signature found"


def _looks_like_chunk_header(body: bytes, off: int) -> bool:
    if off + 2 > len(body):
        return False
    header = body[off] | (body[off + 1] << 8)
    sig_bit = (header >> 15) & 0x1
    chunk_type = (header >> 12) & 0x7
    size_minus_three = header & 0x0FFF
    # Spec: signature bit must be 1; type must be 0b011 (compressed) or
    # 0b000 (uncompressed); chunk total length must fit the remaining bytes.
    if sig_bit != 1:
        return False
    if chunk_type not in (0b011, 0b000):
        return False
    total_chunk_len = size_minus_three + 3
    return total_chunk_len <= MAX_CHUNK_DECOMPRESSED + 2


# ---------------------------------------------------------------------------
# CompressedAtom decompressor — [MS-OVBA] §2.4.1
# ---------------------------------------------------------------------------


def decompress_compressed_atom(data: bytes) -> tuple[bytes, str]:
    """Decompress a CompressedAtom blob. Returns (decoded, error_msg).

    A non-empty error message means the decode stopped early; whatever
    we managed to produce is still returned. Total output is capped at
    ``MAX_DECOMPRESSED_BYTES`` regardless of what the input claims.
    """
    if not data or data[0] != COMPRESSED_SIGNATURE:
        return b"", "missing signature byte"

    out = bytearray()
    cursor = 1
    while cursor < len(data) and len(out) < MAX_DECOMPRESSED_BYTES:
        if cursor + 2 > len(data):
            return bytes(out), "truncated chunk header"
        header = data[cursor] | (data[cursor + 1] << 8)
        sig_bit = (header >> 15) & 0x1
        chunk_type = (header >> 12) & 0x7
        size_minus_three = header & 0x0FFF
        chunk_total = size_minus_three + 3  # incl. 2-byte header
        if sig_bit != 1:
            return bytes(out), "chunk signature bit clear"
        chunk_body_end = cursor + chunk_total
        if chunk_body_end > len(data):
            return bytes(out), "chunk extends past stream"

        body = data[cursor + 2 : chunk_body_end]
        cursor = chunk_body_end

        if chunk_type == 0b000:
            # Uncompressed chunk: body is up to 4 KiB plaintext.
            out.extend(body[:MAX_CHUNK_DECOMPRESSED])
            continue
        if chunk_type != 0b011:
            return bytes(out), f"unknown chunk type {chunk_type}"

        chunk_start = len(out)
        body_cursor = 0
        body_len = len(body)
        while body_cursor < body_len and len(out) - chunk_start < MAX_CHUNK_DECOMPRESSED:
            flag = body[body_cursor]
            body_cursor += 1
            for j in range(8):
                if body_cursor >= body_len:
                    break
                if (flag >> j) & 1 == 0:
                    out.append(body[body_cursor])
                    body_cursor += 1
                else:
                    if body_cursor + 2 > body_len:
                        return bytes(out), "truncated copy token"
                    token = body[body_cursor] | (body[body_cursor + 1] << 8)
                    body_cursor += 2
                    difference = len(out) - chunk_start
                    bit_count = max(_ceil_log2(difference), 4)
                    length_mask = 0xFFFF >> bit_count
                    offset_mask = (~length_mask) & 0xFFFF
                    length = (token & length_mask) + 3
                    raw_offset = (token & offset_mask) >> (16 - bit_count)
                    offset = raw_offset + 1
                    src = len(out) - offset
                    if src < chunk_start or offset == 0:
                        return bytes(out), "copy token out of range"
                    for _ in range(length):
                        out.append(out[src])
                        src += 1
                    if len(out) - chunk_start >= MAX_CHUNK_DECOMPRESSED:
                        break
        # End of one chunk's token stream.

    return bytes(out), ""


def _ceil_log2(n: int) -> int:
    if n <= 1:
        return 0
    return (n - 1).bit_length()


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------


def _detect_auto_exec_subs(text: str) -> list[str]:
    found: list[str] = []
    lowered = text.lower()
    for name in _AUTO_EXEC_SUBS:
        # Match ``Sub <name>`` or ``Function <name>``, case-insensitive.
        pattern = rf"\b(sub|function)\s+{re.escape(name).lower()}\b"
        if re.search(pattern, lowered):
            found.append(name)
    return found


def _emit_vba_findings(modules: list[VbaModule], all_text: bytes, report: AnalyzerReport) -> None:
    text_blob = all_text.decode("latin-1", "replace")
    lowered = text_blob.lower()

    auto_exec_all = sorted({sub for m in modules for sub in m.auto_exec_subs})
    if auto_exec_all:
        report.add(
            Finding(
                rule="vba.auto_exec",
                severity=Severity.HIGH,
                category="document",
                message=f"VBA project defines auto-exec sub(s): {', '.join(auto_exec_all)}. "
                "These run automatically when the document is opened or closed.",
                evidence=tuple(auto_exec_all),
            )
        )

    hit_apis = [api for api in _SUSPICIOUS_APIS if api.lower() in lowered]
    if hit_apis:
        report.add(
            Finding(
                rule="vba.suspicious_api",
                severity=Severity.HIGH,
                category="document",
                message=f"VBA references {len(hit_apis)} suspicious COM / Win32 API(s).",
                evidence=tuple(hit_apis[:8]),
            )
        )

    hit_lolbins = [b for b in _LOLBINS if b.lower() in lowered]
    if hit_lolbins:
        report.add(
            Finding(
                rule="vba.lolbin_spawn",
                severity=Severity.HIGH,
                category="document",
                message=f"VBA references living-off-the-land binaries: {', '.join(hit_lolbins[:6])}.",
                evidence=tuple(hit_lolbins[:6]),
            )
        )

    hit_ps = [tok for tok in _ENCODED_POWERSHELL_TOKENS if tok.lower() in lowered]
    if hit_ps:
        report.add(
            Finding(
                rule="vba.encoded_powershell",
                severity=Severity.CRITICAL,
                category="document",
                message="VBA carries PowerShell-encoded-command primitives — "
                "near-certain malicious dropper pattern.",
                evidence=tuple(hit_ps[:6]),
            )
        )

    obf_count = len(_OBFUSCATION_PRIMITIVES.findall(all_text))
    if obf_count >= 20:
        report.add(
            Finding(
                rule="vba.obfuscation_density",
                severity=Severity.MEDIUM,
                category="document",
                message=f"High density of obfuscation primitives "
                f"(Chr/StrReverse/Asc): {obf_count} calls — "
                "hand-rolled decoder pattern.",
                evidence=(f"{obf_count} primitive calls",),
            )
        )
    elif obf_count >= 5:
        report.add(
            Finding(
                rule="vba.obfuscation_present",
                severity=Severity.LOW,
                category="document",
                message=f"Obfuscation primitives present ({obf_count} calls).",
                evidence=(f"{obf_count} primitive calls",),
            )
        )

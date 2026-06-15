"""Scan a binary body for embedded payloads and known shellcode markers.

Modern droppers and self-extracting installers hide a second-stage
payload by concatenating it onto the carrier. This module finds the
common cases:

- An additional ``MZ``+``PE\\0\\0`` PE at a non-zero offset.
- An additional ``\\x7fELF`` header.
- A Mach-O magic at a non-zero offset (handled separately from the
  fat container we already recognise at offset 0).
- ZIP (``PK\\x03\\x04``), 7-Zip (``7z\\xBC\\xAF\\x27\\x1C``), RAR
  (``Rar!\\x1A\\x07``), gzip (``\\x1F\\x8B``) — archives sitting in
  the body.

It also looks for a small, high-precision list of known shellcode /
loader prologues:

- msfvenom x64 reverse-shell prologue ``\\xfc\\x48\\x83\\xe4\\xf0`` —
  the canonical reverse-shell stub the Metasploit Framework emits.
- msfvenom x86 kernel32 hash-resolution prologue ``\\xfc\\xe8\\x82``.
- Donut loader marker ``\\xe8\\x00\\x00\\x00\\x00\\x59`` followed by
  the Donut config tag string.
- Cobalt Strike beacon config marker ``\\x00\\x01\\x00\\x01\\x00\\x02``
  preceded by a 4-byte XOR-decodable hint (we check only one
  candidate key, 0x69 / 0x2E — narrow but high-confidence).

All scans run on the analysed buffer in O(n) via ``bytes.find``. They
emit findings into the report rather than raising.
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.common import AnalyzerReport, Finding, Severity

# ---------------------------------------------------------------------------
# Embedded artefact scanner
# ---------------------------------------------------------------------------


def scan_embedded(raw: bytes, report: AnalyzerReport) -> None:
    """Emit findings for non-trivial embedded payloads in ``raw``.

    ``report`` is mutated in place. The carrier file's own header at
    offset 0 is **not** counted — we only want additional payloads.
    Mach-O slices already known via the fat-binary header are
    excluded so a universal binary doesn't trip ``embedded.macho``.
    """
    n = len(raw)
    if n < 16:
        return
    # Known fat-slice offsets (Mach-O universal binary): the dispatcher
    # stashes these in metadata. They are legitimate, not "embedded".
    fat_slice_offsets: set[int] = set()
    for s in report.metadata.get("fat_slices", []) or ():
        if isinstance(s, dict) and isinstance(s.get("offset"), int):
            fat_slice_offsets.add(s["offset"])

    # ---- Embedded PE: every additional "MZ" with a valid PE\0\0 at +e_lfanew.
    pe_offsets = _find_embedded_pe(raw)
    if pe_offsets:
        report.add(
            Finding(
                rule="embedded.pe",
                severity=Severity.HIGH,
                category="dropper",
                message=f"Embedded PE payload(s) at offset(s) {', '.join(f'0x{o:x}' for o in pe_offsets[:6])}.",
                evidence=tuple(f"0x{o:x}" for o in pe_offsets[:8]),
            )
        )

    # ---- Embedded ELF / Mach-O at non-zero offsets.
    elf_offsets = _find_all(raw, b"\x7fELF", skip_first_byte=True)
    if elf_offsets:
        report.add(
            Finding(
                rule="embedded.elf",
                severity=Severity.HIGH,
                category="dropper",
                message=f"Embedded ELF at offset(s) {', '.join(f'0x{o:x}' for o in elf_offsets[:6])}.",
                evidence=tuple(f"0x{o:x}" for o in elf_offsets[:8]),
            )
        )

    macho_offsets: list[int] = []
    for magic in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        macho_offsets.extend(
            o for o in _find_all(raw, magic, skip_first_byte=True) if o not in fat_slice_offsets
        )
    if macho_offsets:
        report.add(
            Finding(
                rule="embedded.macho",
                severity=Severity.HIGH,
                category="dropper",
                message=f"Embedded Mach-O at offset(s) {', '.join(f'0x{o:x}' for o in macho_offsets[:6])}.",
                evidence=tuple(f"0x{o:x}" for o in macho_offsets[:8]),
            )
        )

    # ---- Archives.
    archive_hits: list[tuple[str, int]] = []
    for label, sig in (
        ("ZIP", b"PK\x03\x04"),
        ("7z", b"7z\xbc\xaf\x27\x1c"),
        ("RAR", b"Rar!\x1a\x07"),
        ("gzip", b"\x1f\x8b\x08"),
    ):
        for off in _find_all(raw, sig, skip_first_byte=False)[:4]:
            archive_hits.append((label, off))
    if archive_hits:
        rendered = ", ".join(f"{lbl}@0x{off:x}" for lbl, off in archive_hits[:6])
        report.add(
            Finding(
                rule="embedded.archive",
                severity=Severity.MEDIUM,
                category="dropper",
                message=f"Archive container(s) embedded: {rendered}.",
                evidence=tuple(f"{lbl}@0x{off:x}" for lbl, off in archive_hits[:8]),
            )
        )


def _find_all(data: bytes, sig: bytes, *, skip_first_byte: bool, cap: int = 16) -> list[int]:
    """Return up to ``cap`` byte-offsets where ``sig`` occurs in ``data``.

    ``skip_first_byte``: when True, an occurrence at offset 0 is
    excluded — used for embedded-magic scans where the carrier's own
    header sits at 0 and is not what we mean by "embedded".
    """
    out: list[int] = []
    start = 1 if skip_first_byte else 0
    pos = data.find(sig, start)
    while pos != -1 and len(out) < cap:
        out.append(pos)
        pos = data.find(sig, pos + len(sig))
    return out


def _find_embedded_pe(data: bytes) -> list[int]:
    """Return offsets of embedded PE images (additional, not the carrier)."""
    out: list[int] = []
    n = len(data)
    # Start at offset 1 to skip the carrier's own MZ if present.
    pos = data.find(b"MZ", 1)
    while pos != -1 and len(out) < 8:
        if pos + 0x40 < n:
            e_lfanew = struct.unpack("<I", data[pos + 0x3C : pos + 0x40])[0]
            sig_off = pos + e_lfanew
            if (
                0 < e_lfanew < 0x100000
                and sig_off + 4 <= n
                and data[sig_off : sig_off + 4] == b"PE\x00\x00"
            ):
                out.append(pos)
        pos = data.find(b"MZ", pos + 2)
    return out


# ---------------------------------------------------------------------------
# Shellcode / loader markers
# ---------------------------------------------------------------------------


_SHELLCODE_PATTERNS: tuple[tuple[str, bytes, str, str, Severity], ...] = (
    # (rule, pattern, category, message, severity)
    (
        "shellcode.msfvenom_x64",
        b"\xfc\x48\x83\xe4\xf0\xe8",
        "shellcode",
        "msfvenom x64 reverse-shell prologue (fc 48 83 e4 f0 e8).",
        Severity.HIGH,
    ),
    (
        "shellcode.msfvenom_x86_hash",
        b"\xfc\xe8\x82\x00\x00\x00",
        "shellcode",
        "msfvenom x86 kernel32 hash-resolution prologue (fc e8 82 00 00 00).",
        Severity.HIGH,
    ),
    (
        "shellcode.metasploit_egghunter",
        b"\x66\x81\xca\xff\x0f\x42\x52\x6a",
        "shellcode",
        "Metasploit egghunter shellcode marker.",
        Severity.HIGH,
    ),
    (
        "shellcode.donut_loader",
        b"\xe8\x00\x00\x00\x00\x59\x49\x89\xc8",
        "shellcode",
        "Donut loader prologue (call $+5 / pop / mov r8).",
        Severity.HIGH,
    ),
    (
        "shellcode.go_buildid_marker",
        b'\xff Go build ID: "',
        "compiler",
        "Go runtime build-id marker (Go-compiled binary).",
        Severity.INFO,
    ),
    (
        "shellcode.upx_signature",
        b"$Info: This file is packed with the UPX",
        "packer",
        "UPX self-identification string.",
        Severity.LOW,
    ),
)


def scan_shellcode_markers(raw: bytes, report: AnalyzerReport) -> None:
    """Apply the high-precision shellcode/loader pattern table."""
    # Search the first 16 MiB — that covers any realistic stub placement.
    head = raw[: 16 * 1024 * 1024]
    for rule, pattern, category, message, sev in _SHELLCODE_PATTERNS:
        off = head.find(pattern)
        if off != -1:
            report.add(
                Finding(
                    rule=rule,
                    severity=sev,
                    category=category,
                    message=f"{message} (offset 0x{off:x})",
                    evidence=(f"0x{off:x}",),
                )
            )


# ---------------------------------------------------------------------------
# Cobalt Strike beacon config marker (narrow XOR scan)
# ---------------------------------------------------------------------------


_CS_CONFIG_MARKER = b"\x00\x01\x00\x01\x00\x02\x00\x04"
# Known stable XOR keys reported in public analyses of CS beacon configs.
_CS_KEYS = (0x69, 0x2E)


def scan_cobalt_strike(raw: bytes, report: AnalyzerReport) -> None:
    """Look for the Cobalt Strike beacon config marker.

    The CS beacon config is XOR-encoded with a fixed 1-byte key against
    a SEQUENCE of TLV (tag, type, length, value) entries. The first
    bytes of the decoded blob are an unambiguous ``tag=0x0001
    type=0x0001 length=0x0002`` ⇒ the bytes ``00 01 00 01 00 02 00 04``.

    We check the body in two cheap passes per candidate XOR key. Hits
    are not very common in benign binaries — high precision.
    """
    head = raw[: 16 * 1024 * 1024]
    # Untouched (already-decoded / hand-staged builds).
    off = head.find(_CS_CONFIG_MARKER)
    if off != -1:
        report.add(
            Finding(
                rule="c2.cobalt_strike_beacon_marker",
                severity=Severity.CRITICAL,
                category="c2",
                message=f"Cobalt Strike beacon config marker found at 0x{off:x}.",
                evidence=(f"0x{off:x}",),
            )
        )
        return
    # XOR-encoded variant. ``bytes.translate`` with a per-key lookup table
    # is far faster than per-byte Python work but still allocates ~16 MiB
    # per try. Use it only when nothing benign already matched, and only
    # for the two well-known keys.
    for key in _CS_KEYS:
        target = bytes(b ^ key for b in _CS_CONFIG_MARKER)
        off = head.find(target)
        if off != -1:
            report.add(
                Finding(
                    rule="c2.cobalt_strike_xor_marker",
                    severity=Severity.CRITICAL,
                    category="c2",
                    message=f"Cobalt Strike XOR-{key:#04x} beacon marker at 0x{off:x}.",
                    evidence=(f"0x{off:x}",),
                )
            )
            return

"""Magic-byte dispatcher.

Given a path, identify the binary format from its first few bytes and
hand off to the right analyser. This module also owns the side
concerns common to every format:

- streaming file hashes (md5/sha1/sha256) over the full file even when
  the analysed buffer is truncated to ``MAX_FILE_BYTES``;
- string extraction + IOC sweep (ASCII + UTF-16LE);
- running the cross-cutting heuristics pass.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ioc_hunter.analyze.attack_map import tag_findings
from ioc_hunter.analyze.common import (
    MAX_FILE_BYTES,
    MAX_STRINGS,
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
    extract_all_strings,
    sweep_iocs,
)
from ioc_hunter.analyze.elf import analyze_elf
from ioc_hunter.analyze.embedded import (
    scan_cobalt_strike,
    scan_embedded,
    scan_shellcode_markers,
)
from ioc_hunter.analyze.heuristics import apply_heuristics
from ioc_hunter.analyze.macho import (
    FAT_CIGAM,
    FAT_CIGAM_64,
    FAT_MAGIC,
    FAT_MAGIC_64,
    MH_CIGAM,
    MH_CIGAM_64,
    MH_MAGIC,
    MH_MAGIC_64,
    analyze_macho,
    parse_fat_header,
)
from ioc_hunter.analyze.pdf import analyze_pdf
from ioc_hunter.analyze.pe import analyze_pe

_CHUNK = 1024 * 1024  # 1 MiB streaming-hash chunk


def detect_format(head: bytes) -> FileFormat:
    """Identify the container format from the first 16 bytes.

    Returns ``FileFormat.UNKNOWN`` for anything we can't route. The
    caller is responsible for deciding how loudly to complain.
    """
    if len(head) < 4:
        return FileFormat.UNKNOWN
    if head[:2] == b"MZ":
        return FileFormat.PE
    if head[:4] == b"\x7fELF":
        return FileFormat.ELF
    if head[:5] == b"%PDF-":
        return FileFormat.PDF
    magic = int.from_bytes(head[:4], "little")
    if magic in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64):
        return FileFormat.MACHO
    if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        return FileFormat.MACHO_FAT
    return FileFormat.UNKNOWN


def _stream_read_and_hash(path: Path) -> tuple[bytes, bool, str, str, str]:
    """Read up to ``MAX_FILE_BYTES`` and stream-hash the full file.

    Returns (analysis_buf, truncated, md5_hex, sha1_hex, sha256_hex).
    Hashes always reflect the whole file on disk; truncation only
    affects the buffer we hand to the analyser.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    buf = bytearray()
    truncated = False
    with path.open("rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            if len(buf) < MAX_FILE_BYTES:
                room = MAX_FILE_BYTES - len(buf)
                if len(chunk) <= room:
                    buf.extend(chunk)
                else:
                    buf.extend(chunk[:room])
                    truncated = True
            else:
                truncated = True
    return bytes(buf), truncated, md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def analyze(path: str | Path, *, want_strings: bool = True) -> AnalyzerReport:
    """Entry point used by the CLI and the engine.

    Reads the file, identifies its format, runs the right analyser,
    then layers the universal post-processing (strings → IOCs,
    heuristics, verdict).

    ``want_strings`` lets callers opt out of materialising the (often
    large) strings list when they only care about the verdict. IOCs
    are still extracted regardless because that's the whole point of
    the analyser.
    """
    p = Path(path)
    raw, truncated, md5, sha1, sha256 = _stream_read_and_hash(p)

    head = raw[:16]
    fmt = detect_format(head)

    report = AnalyzerReport(
        path=str(p),
        format=fmt,
        file_size=len(raw),
        truncated=truncated,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )

    if truncated:
        report.add(
            Finding(
                rule="analyzer.truncated",
                severity=Severity.INFO,
                category="anomaly",
                message=f"File analysed only over first {MAX_FILE_BYTES:,} bytes "
                "(hashes still reflect the full file).",
            )
        )

    if fmt == FileFormat.PE:
        analyze_pe(raw, report=report)
    elif fmt == FileFormat.ELF:
        analyze_elf(raw, report=report)
    elif fmt == FileFormat.PDF:
        analyze_pdf(raw, report=report)
    elif fmt == FileFormat.MACHO:
        analyze_macho(raw, report=report, slice_offset=0)
    elif fmt == FileFormat.MACHO_FAT:
        slices = parse_fat_header(raw) or []
        report.metadata["fat_slices"] = [
            {"cputype": ct, "cpusubtype": cs, "offset": off, "size": sz}
            for ct, cs, off, sz in slices
        ]
        if slices:
            # Analyse the first slice fully; record the rest as metadata.
            _, _, off, _ = slices[0]
            analyze_macho(raw, report=report, slice_offset=off)
            report.format = FileFormat.MACHO_FAT
        else:
            report.add(
                Finding(
                    rule="macho.bad_fat",
                    severity=Severity.MEDIUM,
                    category="anomaly",
                    message="Universal binary header malformed.",
                )
            )
    else:
        report.add(
            Finding(
                rule="analyzer.unknown_format",
                severity=Severity.INFO,
                category="anomaly",
                message="Unrecognised container — falling back to strings + IOC sweep only.",
            )
        )

    # ---- Strings + IOC sweep -- always run; cheap on the buffer we have ---
    # PDFs hide IOCs inside FlateDecode'd JavaScript bodies; analyze_pdf
    # stashes them in `pdf_decoded_blob` so we can fold them into the sweep.
    pdf_blob = report.metadata.pop("pdf_decoded_blob", b"")
    sweep_buf = raw + b"\n" + pdf_blob if pdf_blob else raw
    strings = extract_all_strings(sweep_buf, cap=MAX_STRINGS)
    iocs = sweep_iocs(strings)
    report.iocs = iocs
    if want_strings:
        report.strings = strings

    # ---- Embedded payload + shellcode + C2 markers ------------------------
    scan_embedded(raw, report)
    scan_shellcode_markers(raw, report)
    scan_cobalt_strike(raw, report)

    # ---- Behavioural heuristics --------------------------------------------
    apply_heuristics(report)

    # ---- ATT&CK technique tagging (last so it covers every finding) -------
    tag_findings(report)

    return report

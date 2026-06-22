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

from ioc_hunter.analyze.archive import MAX_TOTAL_BYTES as _ARCHIVE_BUDGET
from ioc_hunter.analyze.archive import analyze_archive, is_tar
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
from ioc_hunter.analyze.ole import CFB_SIGNATURE, analyze_ole
from ioc_hunter.analyze.ooxml import analyze_ooxml
from ioc_hunter.analyze.pcap import analyze_pcap
from ioc_hunter.analyze.pcap_parse import detect_pcap_format
from ioc_hunter.analyze.pdf import analyze_pdf
from ioc_hunter.analyze.pe import analyze_pe
from ioc_hunter.analyze.rtf import analyze_rtf, is_rtf

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
    if head[:8] == CFB_SIGNATURE:
        return FileFormat.OLE
    if head[:2] == b"PK" and head[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08"):
        # Could be an OOXML document or a plain ZIP — the dispatcher decides
        # by content (``is_ooxml``); default to OOXML here.
        return FileFormat.OOXML
    if is_rtf(head):
        return FileFormat.RTF
    if detect_pcap_format(head):
        return FileFormat.PCAP
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        return FileFormat.ARCHIVE
    magic = int.from_bytes(head[:4], "little")
    if magic in (MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64):
        return FileFormat.MACHO
    if magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        return FileFormat.MACHO_FAT
    return FileFormat.UNKNOWN


def _is_ooxml_document(raw: bytes) -> bool:
    """True only for a genuine OOXML document (``[Content_Types].xml`` +
    an Office part tree), not just any ZIP.

    A bare ``is_ooxml`` is only a PK magic check, so it can't tell a real
    ``.docx`` from ``malware.zip``. We open the central directory and look
    for the OOXML skeleton; everything else (plain ZIP, JAR, ODF, APK)
    falls through to the recursive archive analyser.
    """
    import zipfile
    from io import BytesIO

    try:
        with zipfile.ZipFile(BytesIO(raw)) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError, EOFError):
        return False
    if "[Content_Types].xml" not in names:
        return False
    return any(n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names)


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
    report = _build_report(
        raw, label=str(p), truncated=truncated, md5=md5, sha1=sha1, sha256=sha256
    )
    _run(raw, report, depth=0, want_strings=want_strings, budget=None)
    return report


def analyze_bytes(
    raw: bytes,
    *,
    label: str = "<member>",
    want_strings: bool = False,
    depth: int = 0,
    budget: list[int] | None = None,
) -> AnalyzerReport:
    """Analyse an in-memory buffer (used to recurse into archive members).

    Hashes reflect the full member; analysis runs on the first
    ``MAX_FILE_BYTES``. ``depth`` / ``budget`` thread the archive
    recursion guards down the tree.
    """
    truncated = len(raw) > MAX_FILE_BYTES
    buf = raw[:MAX_FILE_BYTES] if truncated else raw
    report = _build_report(
        buf,
        label=label,
        truncated=truncated,
        md5=hashlib.md5(raw).hexdigest(),
        sha1=hashlib.sha1(raw).hexdigest(),
        sha256=hashlib.sha256(raw).hexdigest(),
        file_size=len(raw),
    )
    _run(buf, report, depth=depth, want_strings=want_strings, budget=budget)
    return report


def _build_report(
    raw: bytes,
    *,
    label: str,
    truncated: bool,
    md5: str,
    sha1: str,
    sha256: str,
    file_size: int | None = None,
) -> AnalyzerReport:
    report = AnalyzerReport(
        path=label,
        format=detect_format(raw[:16]),
        file_size=file_size if file_size is not None else len(raw),
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
    return report


def _run(
    raw: bytes,
    report: AnalyzerReport,
    *,
    depth: int,
    want_strings: bool,
    budget: list[int] | None,
) -> None:
    """Dispatch to the right analyser and layer the universal passes."""
    fmt = report.format

    if fmt == FileFormat.PE:
        analyze_pe(raw, report=report)
    elif fmt == FileFormat.ELF:
        analyze_elf(raw, report=report)
    elif fmt == FileFormat.PDF:
        analyze_pdf(raw, report=report)
    elif fmt == FileFormat.OOXML:
        # PK container — an Office doc if it has the OOXML skeleton, else a
        # plain ZIP (or JAR / ODF / APK) we recurse into.
        if _is_ooxml_document(raw):
            analyze_ooxml(raw, report=report)
        else:
            report.format = FileFormat.ARCHIVE
            _run_archive(raw, report, depth=depth, budget=budget)
    elif fmt == FileFormat.OLE:
        analyze_ole(raw, report=report)
    elif fmt == FileFormat.RTF:
        analyze_rtf(raw, report=report)
    elif fmt == FileFormat.PCAP:
        analyze_pcap(raw, report=report)
    elif fmt == FileFormat.ARCHIVE:
        _run_archive(raw, report, depth=depth, budget=budget)
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
    elif is_tar(raw):
        # tar's magic lives at offset 257 so detect_format can't see it.
        report.format = FileFormat.ARCHIVE
        _run_archive(raw, report, depth=depth, budget=budget)
    else:
        report.add(
            Finding(
                rule="analyzer.unknown_format",
                severity=Severity.INFO,
                category="anomaly",
                message="Unrecognised container — falling back to strings + IOC sweep only.",
            )
        )

    # For archives the container bytes are compressed noise plus member
    # filenames; sweeping them yields junk "IOCs" (filenames parsed as
    # domains) and redundant embedded-ZIP hits. The real IOCs/findings come
    # from the per-member recursion, already merged into the report, so we
    # skip the container-level passes here.
    if report.format != FileFormat.ARCHIVE:
        # ---- Strings + IOC sweep — PDFs (FlateDecode JS), OOXML (decoded VBA
        # + embedded payloads), and OLE (decoded VBA) stash extra bytes in
        # `pdf_decoded_blob` so they flow into the IOC sweep here.
        pdf_blob = report.metadata.pop("pdf_decoded_blob", b"")
        sweep_buf = raw + b"\n" + pdf_blob if pdf_blob else raw
        strings = extract_all_strings(sweep_buf, cap=MAX_STRINGS)
        report.iocs = sweep_iocs(strings)
        if want_strings:
            report.strings = strings

        # ---- Embedded payload + shellcode + C2 markers --------------------
        scan_embedded(raw, report)
        scan_shellcode_markers(raw, report)
        scan_cobalt_strike(raw, report)

    # ---- Behavioural heuristics --------------------------------------------
    apply_heuristics(report)

    # ---- ATT&CK technique tagging (last so it covers every finding) -------
    tag_findings(report)


def _run_archive(
    raw: bytes,
    report: AnalyzerReport,
    *,
    depth: int,
    budget: list[int] | None,
) -> None:
    """Wire ``analyze_archive`` to ``analyze_bytes`` for member recursion,
    threading the shared depth + uncompressed-byte budget."""
    if budget is None:
        budget = [_ARCHIVE_BUDGET]

    def recurse(data: bytes, label: str) -> AnalyzerReport:
        return analyze_bytes(data, label=label, want_strings=False, depth=depth + 1, budget=budget)

    analyze_archive(raw, report=report, recurse=recurse, depth=depth, budget=budget)

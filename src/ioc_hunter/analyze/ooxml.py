"""OOXML (ZIP-based Office) walker.

OOXML is what Microsoft Office 2007+ writes: a ZIP archive whose top-
level layout is described by ``[Content_Types].xml``. The macro
container ``vbaProject.bin`` is itself a CFB blob — we extract it,
hand it to ``ole.parse_cfb``, then to ``vba.analyze_vba_project``.

The interesting attack surface around OOXML, by family:

- **Macro-enabled subtype** (.docm / .xlsm / .pptm): any payload reachable
  from VBA. Inspect via ``vbaProject.bin``.
- **External relationships** (``word/_rels/document.xml.rels``,
  ``word/_rels/settings.xml.rels``, …): a ``<Relationship
  Target="http://attacker/template.dotm" TargetMode="External"
  Type="…/officeDocument/.../attachedTemplate"/>`` is the classic
  template-injection IOC. Same shape used by CVE-2022-30190 (Follina,
  ``ms-msdt:`` URI) and "ole-object" remote references.
- **Embedded payloads**: ``word/embeddings/*.bin`` (CFB), ``oleObject*``,
  raw PE / ELF / Mach-O drops in any folder. The dispatcher's
  ``scan_embedded`` runs after us and catches those — we just make
  sure the bytes flow through.
- **DDE in shared strings**: ``xl/sharedStrings.xml`` containing
  ``=cmd|'/c …'!A0`` is a classic 2017-era DDE attack.

Reference:
  https://learn.microsoft.com/en-us/openspecs/office_standards/ms-docx/
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from io import BytesIO

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

#: Max entries we read out of a ZIP. Real OOXML docs are <200 entries.
MAX_ZIP_ENTRIES = 4096

#: Max bytes we extract from any single ZIP member — zip bombs are real.
MAX_MEMBER_BYTES = 64 * 1024 * 1024

#: Max external relationships we surface as findings.
MAX_EXTERNAL_RELS = 64

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Subtype detection from [Content_Types].xml. The default values cover
# every Office 2007+ format we care about.
_SUBTYPE_MARKERS: tuple[tuple[str, str], ...] = (
    ("vnd.ms-word.document.macroEnabled", "docm"),
    ("vnd.ms-excel.sheet.macroEnabled", "xlsm"),
    ("vnd.ms-powerpoint.presentation.macroEnabled", "pptm"),
    ("vnd.ms-word.template.macroEnabled", "dotm"),
    ("vnd.ms-excel.template.macroEnabled", "xltm"),
    ("wordprocessingml.document", "docx"),
    ("spreadsheetml.sheet", "xlsx"),
    ("presentationml.presentation", "pptx"),
)

# Relationship types that, when External, are the Follina / template-
# injection / remote-OLE attack vectors.
_DANGEROUS_REL_TYPES: tuple[str, ...] = (
    "attachedTemplate",
    "frame",
    "oleObject",
    "subDocument",
    "image",  # remote image is the SMB-NTLM-leak vector
    "footer",  # template-injection variant
    "header",  # template-injection variant
)

# Follina / ms-msdt and other URL-scheme markers worth surfacing on sight.
_MSDT_RE = re.compile(rb"ms-(?:msdt|search-ms|excel|word|powerpoint):", re.IGNORECASE)

# Outbound URLs inside relationship targets (used to flag Follina-style
# template injection). Loose intentionally — any http/https + External
# wins; the IOC sweep does the deduping.
_REL_HTTP_RE = re.compile(
    rb'Target="(https?://[^"<>\s]{4,1024})"[^>]*TargetMode="External"',
    re.IGNORECASE,
)


@dataclass(slots=True)
class _Entry:
    name: str
    size: int
    crc: int


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def is_ooxml(raw: bytes) -> bool:
    """Cheap PK header check; the full subtype peek happens in analyze_ooxml."""
    return raw[:2] == b"PK" and raw[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08")


def analyze_ooxml(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    report.format = FileFormat.OOXML

    try:
        zf = zipfile.ZipFile(BytesIO(raw))
    except (zipfile.BadZipFile, OSError) as e:
        report.add(
            Finding(
                rule="ooxml.bad_zip",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"OOXML walker could not open the ZIP container: {e}",
            )
        )
        return report

    entries = _list_entries(zf)
    report.metadata["ooxml_entries"] = [e.name for e in entries[:MAX_ZIP_ENTRIES]]
    report.metadata["ooxml_entry_count"] = len(entries)

    content_types = _read_member(zf, "[Content_Types].xml")
    subtype = _detect_subtype(content_types) if content_types else ""
    report.metadata["ooxml_subtype"] = subtype

    # Macro-enabled subtype + presence of vbaProject.bin = obvious VBA target.
    vba_path = _find_vba_project(entries)
    has_vba = vba_path is not None or "macroEnabled" in (content_types or b"").decode(
        "latin-1", "replace"
    )
    if has_vba:
        report.add(
            Finding(
                rule="ooxml.macro_enabled",
                severity=Severity.MEDIUM,
                category="document",
                message=f"OOXML container declares macros ({subtype or 'unknown subtype'}).",
                evidence=(vba_path or "Content_Types.xml",),
            )
        )

    # External relationships — Follina / template-injection territory.
    external_rels = _scan_external_relationships(zf, entries)
    if external_rels:
        report.metadata["ooxml_external_rels"] = external_rels[:MAX_EXTERNAL_RELS]
        report.add(
            Finding(
                rule="ooxml.external_relationship",
                severity=Severity.HIGH,
                category="document",
                message=f"{len(external_rels)} external relationship(s) — "
                "template injection or remote-template fetch vector "
                "(CVE-2022-30190 family).",
                evidence=tuple(external_rels[:8]),
            )
        )

    # ms-msdt: / ms-search-ms: schemes — Follina-style direct invocation.
    msdt_hits = _scan_msdt_schemes(zf, entries)
    if msdt_hits:
        report.add(
            Finding(
                rule="ooxml.msdt_scheme",
                severity=Severity.CRITICAL,
                category="document",
                message="ms-msdt: or ms-search-ms: URI scheme present — Follina "
                "/ CVE-2022-30190 direct invocation pattern.",
                evidence=tuple(msdt_hits[:6]),
            )
        )

    # DDE in shared strings.
    if _has_dde_in_shared_strings(zf, entries):
        report.add(
            Finding(
                rule="ooxml.dde_field",
                severity=Severity.HIGH,
                category="document",
                message="Excel sharedStrings.xml contains DDE formula prefix "
                "(=cmd|'/c …'!) — classic 2017-era DDE drop.",
            )
        )

    # If vbaProject.bin is present, parse it as a CFB and run the VBA analyzer.
    if vba_path:
        body = _read_member(zf, vba_path)
        if body:
            report.metadata["ooxml_vba_path"] = vba_path
            report.metadata["ooxml_vba_size"] = len(body)
            # Local import to avoid a circular dep at module load time.
            from ioc_hunter.analyze.ole import parse_cfb
            from ioc_hunter.analyze.vba import analyze_vba_project

            container = parse_cfb(body)
            if container.parse_error:
                report.add(
                    Finding(
                        rule="ooxml.vba_parse_error",
                        severity=Severity.MEDIUM,
                        category="anomaly",
                        message=f"vbaProject.bin failed to parse: {container.parse_error}",
                    )
                )
            else:
                analyze_vba_project(container, report=report)

    # Embedded payloads bubble up through the dispatcher's scan_embedded;
    # we just make sure the bytes are reachable by appending them to the
    # `pdf_decoded_blob`-style scratch buffer (so the dispatcher's sweep
    # sees decoded VBA text and any embedded artefact bodies).
    embedded_bodies = _collect_embedded_bodies(zf, entries)
    if embedded_bodies:
        joined = b"\n".join(embedded_bodies)
        existing = report.metadata.get("pdf_decoded_blob", b"")
        report.metadata["pdf_decoded_blob"] = existing + joined
        report.metadata["ooxml_embedded_member_count"] = len(embedded_bodies)

    vba_blob = report.metadata.get("vba_decoded_blob")
    if vba_blob:
        existing = report.metadata.get("pdf_decoded_blob", b"")
        report.metadata["pdf_decoded_blob"] = existing + b"\n" + vba_blob

    return report


# ---------------------------------------------------------------------------
# ZIP helpers
# ---------------------------------------------------------------------------


def _list_entries(zf: zipfile.ZipFile) -> list[_Entry]:
    out: list[_Entry] = []
    for info in zf.infolist()[:MAX_ZIP_ENTRIES]:
        out.append(_Entry(name=info.filename, size=info.file_size, crc=info.CRC))
    return out


def _read_member(zf: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_MEMBER_BYTES:
        return None
    try:
        with zf.open(info) as fp:
            return fp.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES]
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return None


def _detect_subtype(content_types: bytes) -> str:
    text = content_types.decode("latin-1", "replace")
    for marker, name in _SUBTYPE_MARKERS:
        if marker in text:
            return name
    return ""


def _find_vba_project(entries: list[_Entry]) -> str | None:
    # The macro container always lives at one of these well-known paths.
    candidates = (
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
        "visio/vbaProject.bin",
    )
    names = {e.name for e in entries}
    for path in candidates:
        if path in names:
            return path
    # Fallback: any path ending in vbaProject.bin.
    for e in entries:
        if e.name.endswith("/vbaProject.bin"):
            return e.name
    return None


def _scan_external_relationships(zf: zipfile.ZipFile, entries: list[_Entry]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for e in entries:
        if not e.name.endswith(".rels"):
            continue
        body = _read_member(zf, e.name)
        if not body:
            continue
        # Quick check: External must be present + a dangerous type.
        if b"External" not in body:
            continue
        if not any(rel.encode() in body for rel in _DANGEROUS_REL_TYPES):
            continue
        for m in _REL_HTTP_RE.finditer(body):
            url = m.group(1).decode("latin-1", "replace")
            if url not in seen:
                seen.add(url)
                out.append(url)
                if len(out) >= MAX_EXTERNAL_RELS:
                    return out
    return out


def _scan_msdt_schemes(zf: zipfile.ZipFile, entries: list[_Entry]) -> list[str]:
    out: list[str] = []
    for e in entries:
        body = _read_member(zf, e.name)
        if not body:
            continue
        for m in _MSDT_RE.finditer(body):
            out.append(m.group(0).decode("ascii", "replace"))
    return list(dict.fromkeys(out))  # dedupe, preserve order


def _has_dde_in_shared_strings(zf: zipfile.ZipFile, entries: list[_Entry]) -> bool:
    # sharedStrings.xml lives at xl/sharedStrings.xml in xlsx/xlsm.
    body = _read_member(zf, "xl/sharedStrings.xml")
    if not body:
        return False
    lowered = body.lower()
    if b"=cmd|" in lowered:
        return True
    return b"=dde(" in lowered or b"=ddeauto(" in lowered


def _collect_embedded_bodies(zf: zipfile.ZipFile, entries: list[_Entry]) -> list[bytes]:
    """Pull bytes from /embeddings/ / oleObject*.bin so they flow into the
    cross-cutting scan_embedded + IOC sweep.
    """
    out: list[bytes] = []
    for e in entries:
        n = e.name.lower()
        if "embeddings/" in n or "oleobject" in n or "/media/" in n:
            body = _read_member(zf, e.name)
            if body:
                out.append(body)
    return out

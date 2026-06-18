"""PDF analyzer.

Pure-Python (no pdfminer / no PyPDF) parser focused on the artefacts
that matter for malware triage: auto-fire actions, JavaScript bodies,
embedded files, suspicious filters.

Architecture
------------

We do two passes over the bytes:

1. **Structured walk** — locate the trailing ``startxref`` offset, parse
   the classic xref table, build ``{obj_num: file_offset}``, then read
   each indirect object as ``N M obj ... endobj``. This gives us object
   identity, which we use to dedupe and attribute findings.

2. **Regex fallback** — scan the raw bytes for action keys
   (``/JavaScript``, ``/Launch``, ``/OpenAction``, ``/AA``, ``/URI``,
   ``/EmbeddedFile``, ``/SubmitForm``, ``/RichMedia``, ``/GoToR``,
   ``/Movie``, ``/JBIG2Decode``) and JS markers. Real malicious PDFs
   routinely break the xref on purpose to defeat strict parsers; the
   regex pass refuses to be defeated by that.

Streams flagged as ``/FlateDecode`` are zlib-decompressed (best-effort)
so their content joins the cross-cutting IOC sweep — JS bodies often
contain URLs that we want enriched.

Every finding is mapped to MITRE ATT&CK by ``attack_map.tag_findings``
later in the pipeline. Keep rule names stable: ``pdf.<concept>``.
"""

from __future__ import annotations

import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from ioc_hunter.analyze.common import (
    MAX_FILE_BYTES,
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Caps. PDFs in the wild can carry millions of indirect objects (often a
# malformed-xref tell). We bound everything we walk.
# ---------------------------------------------------------------------------

#: Max indirect objects we walk via the xref. Real benign PDFs are <10k.
MAX_OBJECTS = 50_000

#: Max bytes we attempt to FlateDecode per stream — JS bodies are tiny;
#: an attacker-controlled gigantic stream would just waste CPU.
MAX_STREAM_BYTES = 2 * 1024 * 1024

#: Cap on URIs we extract directly from /URI dictionaries (the rest still
#: get caught by the global strings sweep).
MAX_URIS = 256


# ---------------------------------------------------------------------------
# Regexes — compiled once
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(rb"^%PDF-(\d\.\d)", re.MULTILINE)
_STARTXREF_RE = re.compile(rb"startxref\s*\n?\s*(\d+)\s*\n?\s*%%EOF", re.DOTALL)
_XREF_HEADER_RE = re.compile(rb"^xref\s*\n", re.MULTILINE)
_XREF_SUBSEC_RE = re.compile(rb"^(\d+)\s+(\d+)\s*$", re.MULTILINE)
_XREF_ENTRY_RE = re.compile(rb"^(\d{10})\s+(\d{5})\s+([fn])\s*\r?\n?", re.MULTILINE)
_OBJ_HDR_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
_ENDOBJ_RE = re.compile(rb"\bendobj\b")
_STREAM_RE = re.compile(rb"\bstream(?:\r\n|\r|\n)")
_ENDSTREAM_RE = re.compile(rb"endstream")

# Risky keys for the regex fallback pass.
_RISKY_KEYS_RE = re.compile(
    rb"/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|EmbeddedFiles"
    rb"|RichMedia|GoToR|SubmitForm|URI|Movie|JBIG2Decode|Filespec)\b"
)

# A loose URI extractor for /URI(...) literal strings. Doesn't try to be
# a full PDF lexer — the IOC sweep on raw strings catches the rest.
_URI_LITERAL_RE = re.compile(rb"/URI\s*\(([^)\\]{4,2048})\)")

# JS-obfuscation markers — high false-positive rate as a standalone signal,
# but very meaningful when combined with /JavaScript in the same PDF.
_JS_OBFUSCATION_TOKENS = (
    b"eval(",
    b"unescape(",
    b"String.fromCharCode",
    b"app.alert",
    b"util.printf",
    b"Collab.collectEmailInfo",
    b"getAnnots",
    b"this.exportDataObject",
)

# Stream filter detection — chained filters are an obfuscation tell.
# Two shapes: ``/Filter /Name`` (single) or ``/Filter [ /A /B ]`` (chain).
_FILTER_RE = re.compile(
    rb"/Filter\s*(?:"
    rb"\[\s*((?:/[A-Za-z0-9]+\s*)+)\]"  # bracketed list
    rb"|"
    rb"(/[A-Za-z0-9]+)"  # single filter
    rb")"
)


@dataclass(frozen=True, slots=True)
class _RiskyKey:
    rule: str
    severity: Severity
    message: str


# Map raw key name → (rule_id, severity, default_message). Severity is the
# *baseline*; some rules escalate when combined (e.g. JavaScript +
# OpenAction in the same PDF → MALICIOUS).
_KEYS: dict[bytes, _RiskyKey] = {
    b"JavaScript": _RiskyKey(
        "pdf.javascript",
        Severity.HIGH,
        "PDF contains JavaScript — phishing PDFs use this for payload fetch or exploit triggers.",
    ),
    b"JS": _RiskyKey(
        "pdf.js_shortform",
        Severity.HIGH,
        "/JS short-form JavaScript reference present.",
    ),
    b"OpenAction": _RiskyKey(
        "pdf.open_action",
        Severity.MEDIUM,
        "/OpenAction fires automatically when the document is opened.",
    ),
    b"AA": _RiskyKey(
        "pdf.additional_actions",
        Severity.MEDIUM,
        "/AA additional actions fire on focus / page-open / form-trigger — frequent phishing path.",
    ),
    b"Launch": _RiskyKey(
        "pdf.launch_action",
        Severity.HIGH,
        "/Launch action runs an arbitrary file. Modern readers warn but still execute.",
    ),
    b"EmbeddedFile": _RiskyKey(
        "pdf.embedded_file",
        Severity.MEDIUM,
        "PDF carries an embedded file — common dropper pattern.",
    ),
    b"EmbeddedFiles": _RiskyKey(
        "pdf.embedded_file",
        Severity.MEDIUM,
        "PDF carries an embedded-files dictionary — common dropper pattern.",
    ),
    b"RichMedia": _RiskyKey(
        "pdf.rich_media",
        Severity.HIGH,
        "/RichMedia (Flash / SWF) — historically an exploit vector; deprecated by every modern reader.",
    ),
    b"GoToR": _RiskyKey(
        "pdf.gotor_remote",
        Severity.MEDIUM,
        "/GoToR — remote go-to action. Pointed at \\\\attacker\\share, leaks NTLM creds via SMB.",
    ),
    b"SubmitForm": _RiskyKey(
        "pdf.submit_form",
        Severity.MEDIUM,
        "/SubmitForm posts form data — credential exfiltration vector when target is external.",
    ),
    b"URI": _RiskyKey(
        "pdf.uri",
        Severity.LOW,
        "/URI action — extracted as IOC.",
    ),
    b"Movie": _RiskyKey(
        "pdf.movie",
        Severity.LOW,
        "/Movie action — historic exploit vector.",
    ),
    b"JBIG2Decode": _RiskyKey(
        "pdf.jbig2_filter",
        Severity.HIGH,
        "/JBIG2Decode filter — classic exploit primitive (CVE-2009-3459 family).",
    ),
    b"Filespec": _RiskyKey(
        "pdf.filespec",
        Severity.LOW,
        "/Filespec dictionary present — usually accompanies an embedded file.",
    ),
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_pdf(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    """Populate ``report`` with PDF-specific findings.

    Never raises. A malformed PDF degrades to a string-only sweep with an
    ``analyzer.pdf_malformed`` info finding.
    """
    report.format = FileFormat.PDF

    version = _parse_header(raw)
    if version is not None:
        report.metadata["pdf_version"] = version
    else:
        report.add(
            Finding(
                rule="pdf.no_header",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="PDF lacks a %PDF-x.y header at file start.",
            )
        )

    # ---- Structured walk -------------------------------------------------
    obj_table = _parse_xref(raw)
    objects = _walk_objects(raw, obj_table)
    report.metadata["pdf_objects_parsed"] = len(objects)
    report.metadata["pdf_xref_entries"] = len(obj_table)

    if obj_table and not objects:
        report.add(
            Finding(
                rule="pdf.xref_inconsistent",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="xref pointed to objects that don't parse — likely tampered to defeat strict tools.",
            )
        )

    # ---- Action-key detection (regex pass over the whole file) ----------
    counts = _count_risky_keys(raw)
    report.metadata["pdf_risky_key_counts"] = counts
    seen_keys: set[bytes] = set()
    for key, count in counts.items():
        if count <= 0:
            continue
        seen_keys.add(key)
        rk = _KEYS[key]
        msg = rk.message
        if count > 1:
            msg = f"{msg} ({count} occurrences)"
        report.add(
            Finding(
                rule=rk.rule,
                severity=rk.severity,
                category="document",
                message=msg,
                evidence=(f"/{key.decode('ascii', 'replace')}",),
            )
        )

    # ---- Combination escalations ----------------------------------------
    has_js = bool({b"JavaScript", b"JS"} & seen_keys)
    has_open = bool({b"OpenAction", b"AA"} & seen_keys)
    if has_js and has_open:
        report.add(
            Finding(
                rule="pdf.auto_javascript",
                severity=Severity.CRITICAL,
                category="document",
                message="JavaScript is wired to fire automatically on open "
                "(/OpenAction or /AA + /JavaScript). Strongest single signal "
                "of a malicious PDF.",
                evidence=("/JavaScript", "/OpenAction or /AA"),
            )
        )

    # ---- URI extraction (also flows into the global IOC sweep) ----------
    uris = _extract_uris(raw)
    if uris:
        report.metadata["pdf_uris"] = uris[:MAX_URIS]

    # ---- Filter analysis: chained filters are obfuscation ---------------
    filter_chains = _extract_filter_chains(raw)
    report.metadata["pdf_filter_chains"] = filter_chains
    long_chains = [chain for chain in filter_chains if len(chain) >= 2]
    if long_chains:
        report.add(
            Finding(
                rule="pdf.filter_chain",
                severity=Severity.MEDIUM,
                category="document",
                message=f"{len(long_chains)} stream(s) use chained filters — "
                "obfuscation pattern frequently combined with JavaScript payloads.",
                evidence=tuple(" → ".join(chain) for chain in long_chains[:8]),
            )
        )

    # ---- Stream decode + JS-obfuscation tokens --------------------------
    decoded_bodies = _decode_streams(raw, objects)
    js_obfuscation_hits = _scan_js_obfuscation(decoded_bodies)
    if js_obfuscation_hits:
        report.add(
            Finding(
                rule="pdf.js_obfuscation",
                severity=Severity.HIGH,
                category="document",
                message="JavaScript bodies contain obfuscation primitives "
                "commonly used in PDF exploits.",
                evidence=tuple(sorted(js_obfuscation_hits)),
            )
        )

    # Append decoded stream bodies to the strings list so the IOC sweep in
    # the dispatcher picks up URLs hidden inside FlateDecode'd JavaScript.
    if decoded_bodies:
        report.metadata["pdf_decoded_stream_count"] = len(decoded_bodies)
        # Cap the synthesised "string" so we don't blow MAX_STRINGS.
        joined = b"\n".join(decoded_bodies)[:MAX_FILE_BYTES]
        # Stash for the dispatcher's strings pass to fold in.
        existing = report.metadata.get("pdf_decoded_blob", b"")
        report.metadata["pdf_decoded_blob"] = existing + joined

    return report


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def _parse_header(raw: bytes) -> str | None:
    # Look at the first 1 KiB — some PDFs prepend a tiny shebang or BOM
    # before %PDF-.
    head = raw[:1024]
    m = _HEADER_RE.search(head)
    if not m:
        return None
    return m.group(1).decode("ascii")


# ---------------------------------------------------------------------------
# xref table
# ---------------------------------------------------------------------------


def _parse_xref(raw: bytes) -> dict[int, int]:
    """Best-effort parser for the classic ``xref ... trailer`` table.

    Returns ``{obj_num: file_offset}``. Cross-reference streams (PDF 1.5+)
    are not handled — the walker falls back to scanning for ``N M obj``
    markers across the whole file in that case.
    """
    # Find startxref near the end.
    tail = raw[-2048:] if len(raw) > 2048 else raw
    m = _STARTXREF_RE.search(tail)
    if not m:
        return {}

    xref_offset = int(m.group(1))
    if xref_offset < 0 or xref_offset >= len(raw):
        return {}

    # Locate the xref table — must start with `xref`.
    region = raw[xref_offset : xref_offset + 256 * 1024]
    if not region.startswith(b"xref"):
        # Probably a cross-reference stream. Fallback to whole-file scan
        # for object headers — handled by ``_walk_objects(..., {})``.
        return {}

    table: dict[int, int] = {}
    cursor = 4  # past "xref"
    # PDF spec: subsections of the form "first count\n" followed by
    # ``count`` 20-byte entries each like "offset gen flag\n".
    while True:
        # Skip whitespace and newlines.
        while cursor < len(region) and region[cursor : cursor + 1] in (b"\r", b"\n", b" "):
            cursor += 1
        # Stop on trailer.
        if region[cursor : cursor + 7] == b"trailer":
            break
        # Parse "first count"
        line_end = region.find(b"\n", cursor)
        if line_end == -1 or line_end > cursor + 64:
            break
        header_line = region[cursor:line_end].strip()
        parts = header_line.split()
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            break
        first, count = int(parts[0]), int(parts[1])
        if count < 0 or count > MAX_OBJECTS:
            break
        cursor = line_end + 1
        for i in range(count):
            entry = region[cursor : cursor + 20]
            cursor += 20
            if len(entry) < 18:
                return table
            ent_parts = entry.split()
            if len(ent_parts) < 3:
                continue
            try:
                offset = int(ent_parts[0])
                flag = ent_parts[2]
            except ValueError:
                continue
            if flag == b"n" and 0 < offset < len(raw):
                table[first + i] = offset
        if len(table) >= MAX_OBJECTS:
            break

    return table


# ---------------------------------------------------------------------------
# Object walker
# ---------------------------------------------------------------------------


def _walk_objects(raw: bytes, xref: dict[int, int]) -> dict[tuple[int, int], bytes]:
    """Return ``{(obj_num, gen): raw_obj_bytes}``.

    If ``xref`` is empty (cross-reference stream PDF or malformed table),
    fall back to scanning the whole file for ``N M obj`` markers.
    """
    out: dict[tuple[int, int], bytes] = {}

    if xref:
        for obj_num, offset in xref.items():
            m = _OBJ_HDR_RE.match(raw, offset)
            if not m:
                # Try a small jitter — some xrefs are off by a byte.
                m = _OBJ_HDR_RE.search(raw, offset, offset + 32)
            if not m:
                continue
            gen = int(m.group(2))
            end = _ENDOBJ_RE.search(raw, m.end(), m.end() + MAX_FILE_BYTES)
            if not end:
                continue
            out[(obj_num, gen)] = raw[m.end() : end.start()]
            if len(out) >= MAX_OBJECTS:
                break
        return out

    # Fallback: scan whole file.
    for m in _OBJ_HDR_RE.finditer(raw):
        obj_num = int(m.group(1))
        gen = int(m.group(2))
        end = _ENDOBJ_RE.search(raw, m.end(), m.end() + MAX_FILE_BYTES)
        if not end:
            continue
        out[(obj_num, gen)] = raw[m.end() : end.start()]
        if len(out) >= MAX_OBJECTS:
            break
    return out


# ---------------------------------------------------------------------------
# Risky key counter
# ---------------------------------------------------------------------------


def _count_risky_keys(raw: bytes) -> dict[bytes, int]:
    counts: dict[bytes, int] = dict.fromkeys(_KEYS, 0)
    for m in _RISKY_KEYS_RE.finditer(raw):
        key = m.group(1)
        counts[key] = counts.get(key, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# URI extraction
# ---------------------------------------------------------------------------


def _extract_uris(raw: bytes) -> list[str]:
    out: list[str] = []
    seen: set[bytes] = set()
    for m in _URI_LITERAL_RE.finditer(raw):
        uri = m.group(1).strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)
        try:
            out.append(uri.decode("ascii"))
        except UnicodeDecodeError:
            out.append(uri.decode("latin-1", "replace"))
        if len(out) >= MAX_URIS:
            break
    return out


# ---------------------------------------------------------------------------
# Filter chain extraction
# ---------------------------------------------------------------------------


def _extract_filter_chains(raw: bytes) -> list[list[str]]:
    chains: list[list[str]] = []
    for m in _FILTER_RE.finditer(raw):
        if m.group(1) is not None:
            tokens = m.group(1).split()
            names = [tok.decode("ascii", "replace").lstrip("/") for tok in tokens]
        else:
            names = [m.group(2).decode("ascii", "replace").lstrip("/")]
        names = [n for n in names if n]
        if names:
            chains.append(names)
    return chains


# ---------------------------------------------------------------------------
# Stream decode (FlateDecode only — covers ~99% of real samples)
# ---------------------------------------------------------------------------


def _decode_streams(raw: bytes, objects: dict[tuple[int, int], bytes]) -> list[bytes]:
    out: list[bytes] = []
    for body in objects.values():
        # We only attempt single-FlateDecode streams. Chained filters get
        # flagged elsewhere; decoding them right requires implementing
        # ASCII85 / ASCIIHex / LZW which we punt on for now.
        if b"/Filter" not in body or b"/FlateDecode" not in body:
            continue
        if b"/Filter" in body and b"[" in body[: body.find(b"/Filter") + 256]:
            # Likely a chain — skip to avoid wrong-decode noise.
            continue
        s = _STREAM_RE.search(body)
        if not s:
            continue
        e = _ENDSTREAM_RE.search(body, s.end())
        if not e:
            continue
        payload = body[s.end() : e.start()]
        # Trim trailing whitespace per spec.
        payload = payload.rstrip(b"\r\n ")
        if not payload or len(payload) > MAX_STREAM_BYTES:
            continue
        try:
            decoded = zlib.decompress(payload)
        except zlib.error:
            continue
        out.append(decoded[:MAX_STREAM_BYTES])
    return out


def _scan_js_obfuscation(streams: list[bytes]) -> set[str]:
    hits: set[str] = set()
    for body in streams:
        for token in _JS_OBFUSCATION_TOKENS:
            if token in body:
                hits.add(token.decode("ascii"))
    return hits


# ---------------------------------------------------------------------------
# Convenience iterator (used by tests)
# ---------------------------------------------------------------------------


def iter_objects(raw: bytes) -> Iterator[tuple[tuple[int, int], bytes]]:
    """Yield every indirect object in document order. Public for tests."""
    return iter(_walk_objects(raw, _parse_xref(raw)).items())

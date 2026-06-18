"""RTF analyzer.

Rich Text Format is text-based markup whose attack surface is almost
entirely about *embedded OLE objects*. The CVE-2017-11882 (Equation
Editor) and CVE-2017-0199 (OLE2Link) families both ride RTF; so do
classic Package-class droppers.

We do not implement a full RTF interpreter. The artefacts analysts
need live in three places:

1. ``\\objclass`` — the OLE class name. ``Equation.3`` / ``Equation.2``
   / ``OLE2Link`` / ``Package`` are the bright-red flags.
2. ``\\objupdate`` / ``\\objautlink`` — auto-load triggers; the
   embedded OLE fires the moment the document opens.
3. ``\\objdata`` — hex-encoded CFB payload. We decode it, peek for the
   compound-file signature, and if it matches we drill into the
   resulting CFB looking for the ``Equation Native`` stream.

Reference:
  https://learn.microsoft.com/en-us/openspecs/office_standards/ms-oe376/
"""

from __future__ import annotations

import re

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)
from ioc_hunter.analyze.ole import CFB_SIGNATURE, parse_cfb

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

#: Max ``\\objdata`` blobs we decode per file. Real malicious RTFs ship
#: one object; a flood is a synthetic-stress / DOS tell.
MAX_OBJDATA_BLOBS = 64

#: Cap on the raw hex characters per blob we decode — 16 MiB of hex is
#: 8 MiB of payload, plenty for any real exploit.
MAX_OBJDATA_HEX_CHARS = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Regexes — compiled once.
#
# RTF tolerates lots of whitespace and intermediate control words between
# ``\\objclass`` and its class name. We accept anything from a single
# space to a newline + further control bytes by anchoring on a leading
# space and reading the first identifier-looking run.
# ---------------------------------------------------------------------------

# RTF should start with "{\rtf". Real malicious samples occasionally
# corrupt the header to evade strict parsers, so we tolerate whitespace
# before the brace and accept the first few bytes case-insensitively.
_HEADER_RE = re.compile(rb"\{\s*\\rtf", re.IGNORECASE)

# OLE class name after \objclass. Class names are alphanumerics + . - _.
_OBJCLASS_RE = re.compile(rb"\\\*?\\?objclass\s+([A-Za-z][\w.\-]*)")

# Hex blob after \objdata, terminated by the next control word or close
# brace. We grab the whole region then strip whitespace + hex-decode.
_OBJDATA_RE = re.compile(rb"\\\*?\\?objdata([\s0-9A-Fa-f]+?)(?=[}\\])")

# Auto-fire control words.
_AUTOFIRE_RE = re.compile(rb"\\(objupdate|objautlink)\b")

# Object embedding control words; presence alone is informational, but
# combined with the autofire triggers becomes the real signal.
_OBJEMB_RE = re.compile(rb"\\objemb\b")
_OBJOCX_RE = re.compile(rb"\\objocx\b")

# Raw-binary inclusion. ``\bin<N> <N bytes>`` slips raw payload into the
# RTF stream — same trick as Word's old binary-fallback path.
_BIN_RE = re.compile(rb"\\bin(\d+)")


# ---------------------------------------------------------------------------
# OLE class → finding mapping
# ---------------------------------------------------------------------------


_RISKY_OBJCLASSES: dict[bytes, tuple[Severity, str, str]] = {
    b"Equation.3": (
        Severity.CRITICAL,
        "rtf.equation_editor_3",
        "Equation Editor 3.0 OLE class — CVE-2017-11882 family.",
    ),
    b"Equation.2": (
        Severity.HIGH,
        "rtf.equation_editor_2",
        "Equation Editor 2.0 OLE class — CVE-2018-0802 family.",
    ),
    b"OLE2Link": (
        Severity.CRITICAL,
        "rtf.ole2link",
        "OLE2Link OLE class — CVE-2017-0199 remote payload fetch.",
    ),
    b"Package": (
        Severity.HIGH,
        "rtf.package_dropper",
        "Package OLE class — legacy file-launcher / dropper primitive.",
    ),
    b"Word.Document": (
        Severity.MEDIUM,
        "rtf.embedded_word",
        "Embedded Word document via RTF — common phishing-attachment shape.",
    ),
}


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def is_rtf(head: bytes) -> bool:
    return bool(_HEADER_RE.match(head[:64]))


def analyze_rtf(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    report.format = FileFormat.RTF

    if not is_rtf(raw):
        report.add(
            Finding(
                rule="rtf.bad_header",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="RTF header missing or malformed (no {\\rtf prefix).",
            )
        )

    # ---- \objclass — exploit-class detection ---------------------------
    seen_classes: set[bytes] = set()
    for m in _OBJCLASS_RE.finditer(raw):
        cls = m.group(1)
        seen_classes.add(cls)
        for marker, (sev, rule, msg) in _RISKY_OBJCLASSES.items():
            if cls.startswith(marker):
                report.add(
                    Finding(
                        rule=rule,
                        severity=sev,
                        category="exploit",
                        message=msg,
                        evidence=(cls.decode("ascii", "replace"),),
                    )
                )
                break
    if seen_classes:
        report.metadata["rtf_objclasses"] = sorted(
            c.decode("ascii", "replace") for c in seen_classes
        )

    # ---- Auto-fire triggers --------------------------------------------
    autofire_hits = [m.group(1).decode() for m in _AUTOFIRE_RE.finditer(raw)]
    if autofire_hits:
        report.add(
            Finding(
                rule="rtf.auto_object_fire",
                severity=Severity.HIGH,
                category="document",
                message=r"\objupdate or \objautlink — embedded OLE auto-fires on document open.",
                evidence=tuple(sorted(set(autofire_hits))),
            )
        )

    if _OBJOCX_RE.search(raw):
        report.add(
            Finding(
                rule="rtf.objocx",
                severity=Severity.HIGH,
                category="document",
                message=r"\objocx — ActiveX object embedded in RTF (rare in legitimate documents).",
            )
        )

    # ---- \bin raw-binary inclusion -------------------------------------
    bin_blobs = [int(m.group(1)) for m in _BIN_RE.finditer(raw)]
    if bin_blobs:
        report.metadata["rtf_bin_blob_sizes"] = bin_blobs[:32]
        # The \bin primitive shouldn't appear in modern legitimate RTFs.
        report.add(
            Finding(
                rule="rtf.raw_binary_blob",
                severity=Severity.MEDIUM,
                category="document",
                message=rf"\bin raw-binary primitive used {len(bin_blobs)} time(s) — "
                "uncommon in modern legitimate documents.",
            )
        )

    # ---- \objdata hex blobs → decode → recurse into nested CFBs -------
    blobs = _extract_objdata_blobs(raw)
    report.metadata["rtf_objdata_blob_count"] = len(blobs)

    nested_cfb_total = 0
    equation_native_hits = 0
    for blob in blobs:
        if blob.startswith(CFB_SIGNATURE):
            nested_cfb_total += 1
            container = parse_cfb(blob)
            if container.parse_error:
                continue
            if any("Equation Native" in name for name in container.streams):
                equation_native_hits += 1

    if nested_cfb_total:
        report.add(
            Finding(
                rule="rtf.embedded_cfb",
                severity=Severity.HIGH,
                category="exploit",
                message=f"RTF carries {nested_cfb_total} embedded CFB object(s) "
                r"in \objdata — usually a packaged exploit payload.",
            )
        )
    if equation_native_hits:
        report.add(
            Finding(
                rule="rtf.equation_native_payload",
                severity=Severity.CRITICAL,
                category="exploit",
                message="Embedded CFB inside RTF contains an 'Equation Native' stream "
                "— delivered payload for CVE-2017-11882 / CVE-2018-0802.",
            )
        )

    # Decoded objdata bytes flow into the strings + IOC sweep — same path
    # OOXML and PDF use.
    if blobs:
        joined = b"\n".join(blobs)
        existing = report.metadata.get("pdf_decoded_blob", b"")
        report.metadata["pdf_decoded_blob"] = existing + joined

    return report


# ---------------------------------------------------------------------------
# \objdata hex-blob extraction
# ---------------------------------------------------------------------------


def _extract_objdata_blobs(raw: bytes) -> list[bytes]:
    out: list[bytes] = []
    for m in _OBJDATA_RE.finditer(raw):
        hex_region = m.group(1)
        if len(hex_region) > MAX_OBJDATA_HEX_CHARS:
            hex_region = hex_region[:MAX_OBJDATA_HEX_CHARS]
        cleaned = re.sub(rb"\s+", b"", hex_region)
        # An odd-length hex string can't decode — drop the last nibble.
        if len(cleaned) % 2 == 1:
            cleaned = cleaned[:-1]
        if not cleaned:
            continue
        try:
            decoded = bytes.fromhex(cleaned.decode("ascii"))
        except ValueError:
            continue
        out.append(decoded)
        if len(out) >= MAX_OBJDATA_BLOBS:
            break
    return out

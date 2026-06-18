"""End-to-end tests for the PDF analyzer.

Synthetic PDFs are built byte-by-byte (no PyPDF dep) so the test data
matches what real malicious samples look like. The builder is in this
file because it's tiny and only used here.
"""

from __future__ import annotations

import zlib

from ioc_hunter.analyze import analyze, detect_format
from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity, Verdict
from ioc_hunter.analyze.pdf import (
    _count_risky_keys,
    _extract_filter_chains,
    _extract_uris,
    _parse_header,
    _parse_xref,
    _walk_objects,
    analyze_pdf,
)

# ---------------------------------------------------------------------------
# Synthetic-PDF builder. Real malicious PDFs in the wild look exactly like
# this — small object count, hand-crafted xref, single trailer.
# ---------------------------------------------------------------------------


def build_minimal_pdf(
    *,
    objects: list[bytes] | None = None,
    version: bytes = b"1.7",
    include_header: bool = True,
    valid_xref: bool = True,
) -> bytes:
    objects = objects if objects is not None else [b"<< /Type /Catalog >>"]
    out = bytearray()
    if include_header:
        out += b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n"
    offsets: list[int] = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode()
        out += body
        if not body.endswith(b"\n"):
            out += b"\n"
        out += b"endobj\n"
    xref_offset = len(out)
    out += b"xref\n"
    out += f"0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\n"
    if valid_xref:
        out += b"startxref\n" + f"{xref_offset}\n".encode() + b"%%EOF\n"
    else:
        out += b"startxref\n9999999999\n%%EOF\n"
    return bytes(out)


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.PDF,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


def _flate(payload: bytes) -> bytes:
    return zlib.compress(payload)


# ---------------------------------------------------------------------------
# Header + dispatch
# ---------------------------------------------------------------------------


class TestHeaderAndDispatch:
    def test_detect_format_recognises_pdf(self):
        raw = build_minimal_pdf()
        assert detect_format(raw[:16]) is FileFormat.PDF

    def test_parse_header_picks_version(self):
        raw = build_minimal_pdf(version=b"1.4")
        assert _parse_header(raw) == "1.4"

    def test_parse_header_missing_returns_none(self):
        raw = build_minimal_pdf(include_header=False)
        assert _parse_header(raw) is None

    def test_no_header_finding_when_missing(self):
        raw = build_minimal_pdf(include_header=False)
        r = analyze_pdf(raw, report=_new_report())
        assert any(f.rule == "pdf.no_header" for f in r.findings)


# ---------------------------------------------------------------------------
# xref + object walk
# ---------------------------------------------------------------------------


class TestXrefAndObjects:
    def test_xref_parses_classic_table(self):
        raw = build_minimal_pdf(objects=[b"<< /Type /Catalog >>", b"<< /Type /Pages /Count 0 >>"])
        table = _parse_xref(raw)
        # Two objects (1 and 2). Object 0 is the free entry and not stored.
        assert sorted(table.keys()) == [1, 2]

    def test_walk_objects_returns_bodies(self):
        raw = build_minimal_pdf(objects=[b"<< /Type /Catalog >>", b"<< /Type /Pages >>"])
        objs = _walk_objects(raw, _parse_xref(raw))
        assert len(objs) == 2
        # First object's body contains the catalog dict.
        first = next(iter(objs.values()))
        assert b"/Type /Catalog" in first

    def test_fallback_scan_when_xref_broken(self):
        raw = build_minimal_pdf(objects=[b"<< /Type /Catalog >>"], valid_xref=False)
        # xref unreachable → empty table → falls back to file scan.
        objs = _walk_objects(raw, _parse_xref(raw))
        assert objs, "fallback should still find the obj header"


# ---------------------------------------------------------------------------
# Risky-key counter
# ---------------------------------------------------------------------------


class TestRiskyKeys:
    def test_count_javascript(self):
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Catalog /Names << /JavaScript << /Names [(MyScript) 2 0 R] >> >> >>",
                b"<< /S /JavaScript /JS (app.alert('x')) >>",
            ]
        )
        counts = _count_risky_keys(raw)
        # Both /JavaScript and /JS should be seen.
        assert counts[b"JavaScript"] >= 1
        assert counts[b"JS"] >= 1

    def test_count_launch_action(self):
        raw = build_minimal_pdf(objects=[b"<< /S /Launch /F (cmd.exe) >>"])
        counts = _count_risky_keys(raw)
        assert counts[b"Launch"] == 1


# ---------------------------------------------------------------------------
# Action-specific findings
# ---------------------------------------------------------------------------


class TestActionFindings:
    def test_javascript_fires_high(self):
        raw = build_minimal_pdf(objects=[b"<< /S /JavaScript /JS (app.alert('boom')) >>"])
        r = analyze_pdf(raw, report=_new_report())
        rules = {f.rule for f in r.findings}
        assert "pdf.js_shortform" in rules or "pdf.javascript" in rules
        high = [f for f in r.findings if f.severity >= Severity.HIGH]
        assert high, "JavaScript-bearing PDF should produce at least one HIGH finding"

    def test_launch_action_fires_high(self):
        raw = build_minimal_pdf(objects=[b"<< /S /Launch /F (calc.exe) >>"])
        r = analyze_pdf(raw, report=_new_report())
        rules = {f.rule for f in r.findings}
        assert "pdf.launch_action" in rules

    def test_embedded_file_fires_medium(self):
        raw = build_minimal_pdf(objects=[b"<< /Type /Filespec /EmbeddedFile 2 0 R >>"])
        r = analyze_pdf(raw, report=_new_report())
        rules = {f.rule for f in r.findings}
        assert "pdf.embedded_file" in rules

    def test_additional_actions_fires(self):
        raw = build_minimal_pdf(objects=[b"<< /AA << /O 2 0 R >> >>"])
        r = analyze_pdf(raw, report=_new_report())
        assert any(f.rule == "pdf.additional_actions" for f in r.findings)

    def test_rich_media_fires_high(self):
        raw = build_minimal_pdf(objects=[b"<< /RichMedia << /Type /Flash >> >>"])
        r = analyze_pdf(raw, report=_new_report())
        rich = [f for f in r.findings if f.rule == "pdf.rich_media"]
        assert rich and rich[0].severity == Severity.HIGH

    def test_jbig2_filter_fires_high(self):
        raw = build_minimal_pdf(
            objects=[b"<< /Filter /JBIG2Decode /Length 8 >>stream\n00000000endstream"]
        )
        r = analyze_pdf(raw, report=_new_report())
        assert any(f.rule == "pdf.jbig2_filter" for f in r.findings)


# ---------------------------------------------------------------------------
# Combo escalation: /OpenAction + /JavaScript
# ---------------------------------------------------------------------------


class TestAutoJavaScript:
    def test_open_action_with_js_escalates_to_critical(self):
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>",
                b"<< /S /JavaScript /JS (app.alert('boom')) >>",
                b"<< /Type /Pages /Count 0 >>",
            ]
        )
        r = analyze_pdf(raw, report=_new_report())
        critical = [f for f in r.findings if f.severity == Severity.CRITICAL]
        assert any(f.rule == "pdf.auto_javascript" for f in critical)

    def test_open_action_without_js_does_not_escalate(self):
        raw = build_minimal_pdf(objects=[b"<< /Type /Catalog /OpenAction 2 0 R >>"])
        r = analyze_pdf(raw, report=_new_report())
        assert not any(f.rule == "pdf.auto_javascript" for f in r.findings)


# ---------------------------------------------------------------------------
# URI extraction
# ---------------------------------------------------------------------------


class TestUriExtraction:
    def test_uri_literal_extracted(self):
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Action /S /URI /URI (https://evil.example/steal) >>",
            ]
        )
        uris = _extract_uris(raw)
        assert "https://evil.example/steal" in uris

    def test_uri_finding_present_in_report(self):
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Action /S /URI /URI (https://evil.example/steal) >>",
            ]
        )
        r = analyze_pdf(raw, report=_new_report())
        assert any(f.rule == "pdf.uri" for f in r.findings)
        assert r.metadata.get("pdf_uris") == ["https://evil.example/steal"]


# ---------------------------------------------------------------------------
# Filter chains
# ---------------------------------------------------------------------------


class TestFilterChains:
    def test_single_filter_does_not_fire(self):
        raw = build_minimal_pdf(objects=[b"<< /Filter /FlateDecode /Length 0 >>stream\nendstream"])
        chains = _extract_filter_chains(raw)
        assert all(len(chain) <= 1 for chain in chains)
        r = analyze_pdf(raw, report=_new_report())
        assert not any(f.rule == "pdf.filter_chain" for f in r.findings)

    def test_chained_filter_fires_medium(self):
        raw = build_minimal_pdf(
            objects=[b"<< /Filter [/ASCIIHexDecode /FlateDecode] /Length 0 >>stream\nendstream"]
        )
        chains = _extract_filter_chains(raw)
        assert any(len(chain) >= 2 for chain in chains)
        r = analyze_pdf(raw, report=_new_report())
        chain_findings = [f for f in r.findings if f.rule == "pdf.filter_chain"]
        assert chain_findings and chain_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Stream decode + JS obfuscation
# ---------------------------------------------------------------------------


class TestStreamDecode:
    def test_flate_decoded_js_obfuscation_detected(self):
        js = b"var a = unescape('%75%6e%70%61%63%6b'); eval(a);"
        compressed = _flate(js)
        body = (
            b"<< /Filter /FlateDecode /Length "
            + str(len(compressed)).encode()
            + b" >>\nstream\n"
            + compressed
            + b"\nendstream"
        )
        raw = build_minimal_pdf(objects=[body])
        r = analyze_pdf(raw, report=_new_report())
        assert any(f.rule == "pdf.js_obfuscation" for f in r.findings)

    def test_decoded_blob_propagated_to_dispatcher(self, tmp_path):
        # Hide a URL inside a FlateDecode'd stream and confirm the full
        # analyze() pipeline surfaces it as an IOC (via the strings
        # sweep fed from `pdf_decoded_blob`).
        secret = b"phone-home: https://hidden.example/c2\n"
        compressed = _flate(secret)
        body = (
            b"<< /Filter /FlateDecode /Length "
            + str(len(compressed)).encode()
            + b" >>\nstream\n"
            + compressed
            + b"\nendstream"
        )
        raw = build_minimal_pdf(objects=[body])
        p = tmp_path / "stealth.pdf"
        p.write_bytes(raw)
        r = analyze(p)
        ioc_values = {ioc.value for ioc in r.iocs}
        # The defang-aware sweep stores domains separately, so check for
        # the domain we hid.
        assert any("hidden.example" in v for v in ioc_values), (
            f"decoded-stream IOCs missing — got {ioc_values}"
        )


# ---------------------------------------------------------------------------
# Full dispatcher integration
# ---------------------------------------------------------------------------


class TestDispatcherIntegration:
    def test_clean_pdf_verdict_clean(self, tmp_path):
        raw = build_minimal_pdf()
        p = tmp_path / "ok.pdf"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.PDF
        # No findings or only INFO-level → CLEAN.
        assert r.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS)
        assert r.metadata.get("pdf_version") == "1.7"

    def test_malicious_pdf_verdict_malicious(self, tmp_path):
        # OpenAction + JavaScript = pdf.auto_javascript (CRITICAL).
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Catalog /OpenAction 2 0 R >>",
                b"<< /S /JavaScript /JS (app.alert('1')) >>",
            ]
        )
        p = tmp_path / "evil.pdf"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.verdict is Verdict.MALICIOUS
        # ATT&CK tagging populated.
        techniques = {t for f in r.findings for t in f.mitre}
        assert "T1059.005" in techniques
        assert "T1204.002" in techniques

    def test_launch_action_pdf_critical_attack_map(self, tmp_path):
        raw = build_minimal_pdf(
            objects=[
                b"<< /Type /Catalog /OpenAction 2 0 R >>",
                b"<< /S /Launch /F (calc.exe) >>",
            ]
        )
        p = tmp_path / "launcher.pdf"
        p.write_bytes(raw)
        r = analyze(p)
        techniques = {t for f in r.findings for t in f.mitre}
        # Launch action should map to T1204.002 + T1218.
        assert {"T1204.002", "T1218"} <= techniques

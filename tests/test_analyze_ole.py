"""Tests for the OLE/CFB container parser."""

from __future__ import annotations

from ioc_hunter.analyze import analyze, detect_format
from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Verdict
from ioc_hunter.analyze.ole import (
    OBJ_ROOT,
    OBJ_STORAGE,
    OBJ_STREAM,
    analyze_ole,
    is_cfb,
    parse_cfb,
)
from tests._doc_fixtures import build_minimal_cfb


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.OLE,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


class TestCFBHeader:
    def test_signature_detect(self):
        cfb = build_minimal_cfb({"Doc": b"hello world" * 500})
        assert is_cfb(cfb)
        assert detect_format(cfb[:16]) is FileFormat.OLE

    def test_parse_header_versions(self):
        cfb = build_minimal_cfb({"Doc": b"x" * 5000})
        c = parse_cfb(cfb)
        assert c.parse_error == ""
        assert c.sector_size == 512
        assert c.mini_sector_size == 64
        assert c.major_version == 3

    def test_short_input_no_crash(self):
        c = parse_cfb(b"D0CF11E0")
        assert c.parse_error == "not a CFB file"


class TestStreams:
    def test_single_stream_extracted(self):
        body = b"the quick brown fox" * 300
        cfb = build_minimal_cfb({"OneStream": body})
        c = parse_cfb(cfb)
        assert c.parse_error == ""
        assert "OneStream" in c.streams
        assert c.streams["OneStream"].startswith(body)

    def test_nested_storage(self):
        cfb = build_minimal_cfb(
            {
                "VBA/Module1": b"abc" * 2000,
                "VBA/dir": b"def" * 2000,
            }
        )
        c = parse_cfb(cfb)
        assert c.parse_error == ""
        names = set(c.streams)
        assert "VBA/Module1" in names
        assert "VBA/dir" in names

    def test_directory_types(self):
        cfb = build_minimal_cfb({"VBA/Module1": b"x" * 5000})
        c = parse_cfb(cfb)
        # Root entry, VBA storage, Module1 stream — type values match spec.
        types = [e.obj_type for e in c.directory if e.name]
        assert OBJ_ROOT in types
        assert OBJ_STORAGE in types
        assert OBJ_STREAM in types


class TestAnalyzeOle:
    def test_vba_project_finding(self):
        cfb = build_minimal_cfb(
            {
                "VBA/dir": b"placeholder",
                "VBA/Module1": b"x" * 5000,
            }
        )
        r = analyze_ole(cfb, report=_new_report())
        # vba_project finding emitted because VBA/dir is present.
        assert any(f.rule == "ole.vba_project" for f in r.findings)

    def test_equation_editor_stream(self):
        cfb = build_minimal_cfb(
            {
                "Equation Native": b"placeholder equation data" * 200,
            }
        )
        r = analyze_ole(cfb, report=_new_report())
        assert any(f.rule == "ole.equation_editor" for f in r.findings)

    def test_dispatcher_routes_to_ole(self, tmp_path):
        cfb = build_minimal_cfb({"VBA/dir": b"x" * 5000, "VBA/Module1": b"y" * 5000})
        p = tmp_path / "doc.bin"
        p.write_bytes(cfb)
        r = analyze(p)
        assert r.format is FileFormat.OLE
        # We don't claim a verdict here (depends on VBA content); just
        # make sure the analyzer fired without crashing.
        assert r.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.MALICIOUS)

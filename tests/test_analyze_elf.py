"""End-to-end tests for the ELF analyzer."""

from __future__ import annotations

from ioc_hunter.analyze.common import AnalyzerReport, FileFormat
from ioc_hunter.analyze.elf import analyze_elf
from tests._binary_fixtures import build_minimal_elf64


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.ELF,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


class TestElfHeader:
    def test_parses_64_lsb(self):
        raw = build_minimal_elf64()
        r = analyze_elf(raw, report=_new_report())
        assert r.bitness == 64
        assert r.architecture == "x86_64"
        assert r.metadata["endian"] == "little"
        assert r.metadata["e_type"] == "EXEC"

    def test_load_segment_appears_in_sections(self):
        raw = build_minimal_elf64()
        r = analyze_elf(raw, report=_new_report())
        assert any(s.name.startswith("LOAD") for s in r.sections)


class TestNxStack:
    def test_nx_stack_detected(self):
        raw = build_minimal_elf64(nx_stack=True)
        r = analyze_elf(raw, report=_new_report())
        assert r.metadata["nx_stack"] is True
        assert all(f.rule != "elf.exec_stack" for f in r.findings)

    def test_exec_stack_flagged(self):
        raw = build_minimal_elf64(nx_stack=False)
        r = analyze_elf(raw, report=_new_report())
        assert r.metadata["nx_stack"] is False
        assert any(f.rule == "elf.exec_stack" for f in r.findings)


class TestMalformedRobustness:
    def test_bad_magic(self):
        raw = b"NOT_ELF" + b"\x00" * 100
        r = analyze_elf(raw, report=_new_report())
        assert any(f.rule == "elf.bad_magic" for f in r.findings)


class TestDispatcherRoutes:
    def test_dispatcher_routes_elf(self, tmp_path):
        from ioc_hunter.analyze import FileFormat, analyze

        raw = build_minimal_elf64()
        p = tmp_path / "tinyelf"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format == FileFormat.ELF

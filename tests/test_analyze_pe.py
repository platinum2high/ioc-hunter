"""End-to-end tests for the PE analyzer against hand-built binaries."""

from __future__ import annotations

import os

from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity
from ioc_hunter.analyze.pe import analyze_pe
from tests._binary_fixtures import build_minimal_pe


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.PE,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


class TestMinimalPE:
    def test_parses_without_imports(self):
        raw = build_minimal_pe()
        r = analyze_pe(raw, report=_new_report())
        assert r.bitness == 64
        assert r.architecture == "x86_64"
        # At least one section (.text) parsed.
        assert any(s.name == ".text" for s in r.sections)
        # No imports → no_imports finding is raised at heuristics layer,
        # not here, but the imports list should be empty.
        assert r.imports == []
        # Standard mitigations are flagged on in the optional header.
        assert r.metadata["mitigations"]["ASLR"] is True
        assert r.metadata["mitigations"]["DEP/NX"] is True


class TestImportsWalk:
    def test_kernel32_three_injection_imports(self):
        raw = build_minimal_pe(
            imports=[
                (
                    "kernel32.dll",
                    ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                )
            ]
        )
        r = analyze_pe(raw, report=_new_report())
        assert len(r.imports) == 1
        assert r.imports[0].library == "kernel32.dll"
        assert "VirtualAllocEx" in r.imports[0].symbols
        assert "WriteProcessMemory" in r.imports[0].symbols
        assert "CreateRemoteThread" in r.imports[0].symbols


class TestHighEntropySection:
    def test_high_entropy_section_finding(self):
        # A 0x200-byte section of random bytes will exceed entropy 7.5.
        payload = os.urandom(0x200)
        raw = build_minimal_pe(
            extra_section_name=b".upx1\x00\x00\x00",
            extra_section_data=payload,
            extra_section_chars=0xE0000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE
        )
        r = analyze_pe(raw, report=_new_report())
        rules = {f.rule for f in r.findings}
        assert "pe.high_entropy_section" in rules
        # And W+X section triggers its own finding.
        assert "pe.wx_section" in rules


class TestPackerSignature:
    def test_upx_section_name_match(self):
        raw = build_minimal_pe(
            extra_section_name=b"UPX0\x00\x00\x00\x00",
            extra_section_data=b"\x00" * 0x200,
        )
        r = analyze_pe(raw, report=_new_report())
        assert r.is_packed
        assert r.detected_packer == "UPX"


class TestMalformedRobustness:
    def test_not_a_pe_does_not_crash(self):
        # Hand the analyser something with no MZ at all.
        raw = os.urandom(1024)
        r = analyze_pe(raw, report=_new_report())
        # Either bad_dos, bad_e_lfanew, or bad_pe_sig should fire — never a stack trace.
        assert any(f.severity == Severity.HIGH for f in r.findings)

    def test_truncated_after_dos(self):
        # MZ + e_lfanew pointing way past the file.
        raw = b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\xff"
        r = analyze_pe(raw, report=_new_report())
        assert any(f.rule == "pe.bad_e_lfanew" for f in r.findings)


class TestEndToEnd:
    def test_dispatcher_routes_pe(self, tmp_path):
        from ioc_hunter.analyze import FileFormat, analyze

        raw = build_minimal_pe(
            imports=[
                ("kernel32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])
            ]
        )
        p = tmp_path / "sample.exe"
        p.write_bytes(raw)
        r = analyze(p)
        assert r.format == FileFormat.PE
        # Heuristics should now have run too — combo.process_injection fires.
        rules = {f.rule for f in r.findings}
        assert "combo.process_injection" in rules

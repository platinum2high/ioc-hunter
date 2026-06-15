"""Behavioural-rule tests over hand-constructed reports.

We bypass the format parsers entirely and feed ``apply_heuristics`` a
report whose ``imports`` / ``metadata`` were populated by hand. That
lets us assert each rule's contract in isolation.
"""

from __future__ import annotations

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Import,
    Section,
    Severity,
)
from ioc_hunter.analyze.heuristics import apply_heuristics


def _empty(fmt: FileFormat = FileFormat.PE) -> AnalyzerReport:
    return AnalyzerReport(
        path="test",
        format=fmt,
        file_size=4096,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


def _findings_by_rule(report: AnalyzerReport) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in report.findings:
        out.setdefault(f.rule, []).append(f)
    return out


class TestInjectionRule:
    def test_three_injection_apis_is_critical(self):
        r = _empty()
        r.imports = [
            Import(
                "kernel32.dll",
                ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
            )
        ]
        apply_heuristics(r)
        f = _findings_by_rule(r)["combo.process_injection"]
        assert len(f) == 1
        assert f[0].severity == Severity.CRITICAL
        assert "CreateRemoteThread" in f[0].evidence

    def test_two_injection_apis_is_medium(self):
        r = _empty()
        r.imports = [Import("kernel32.dll", ("VirtualAllocEx", "WriteProcessMemory"))]
        apply_heuristics(r)
        f = _findings_by_rule(r)
        assert "combo.process_injection_partial" in f
        assert f["combo.process_injection_partial"][0].severity == Severity.MEDIUM


class TestKeylogger:
    def test_keylogger_pattern(self):
        r = _empty()
        r.imports = [Import("user32.dll", ("GetAsyncKeyState", "GetForegroundWindow"))]
        apply_heuristics(r)
        assert "combo.keylogger" in _findings_by_rule(r)


class TestPersistence:
    def test_service_install_high(self):
        r = _empty()
        r.imports = [
            Import(
                "advapi32.dll",
                ("OpenSCManagerA", "CreateServiceA"),
            )
        ]
        apply_heuristics(r)
        assert "combo.service_install" in _findings_by_rule(r)

    def test_registry_persistence_medium(self):
        r = _empty()
        r.imports = [
            Import(
                "advapi32.dll",
                ("RegCreateKeyExA", "RegSetValueExA"),
            )
        ]
        apply_heuristics(r)
        assert "combo.registry_persistence" in _findings_by_rule(r)


class TestDPAPI:
    def test_crypt_unprotect_data(self):
        r = _empty()
        r.imports = [Import("crypt32.dll", ("CryptUnprotectData",))]
        apply_heuristics(r)
        assert "combo.dpapi_dump" in _findings_by_rule(r)


class TestDynamicResolution:
    def test_low_without_aggravator(self):
        r = _empty()
        r.imports = [Import("kernel32.dll", ("GetProcAddress", "LoadLibraryA"))]
        apply_heuristics(r)
        f = _findings_by_rule(r)["combo.dynamic_resolution"]
        assert f[0].severity == Severity.LOW

    def test_medium_when_packed(self):
        r = _empty()
        r.is_packed = True
        r.imports = [Import("kernel32.dll", ("GetProcAddress", "LoadLibraryA"))]
        apply_heuristics(r)
        f = _findings_by_rule(r)["combo.dynamic_resolution"]
        assert f[0].severity == Severity.MEDIUM

    def test_medium_when_high_entropy_section(self):
        r = _empty()
        r.sections.append(
            Section(
                name=".text",
                virtual_size=2048,
                raw_size=2048,
                file_offset=0x400,
                entropy=7.6,
                flags="RX",
            )
        )
        r.imports = [Import("kernel32.dll", ("GetProcAddress", "LoadLibraryA"))]
        apply_heuristics(r)
        f = _findings_by_rule(r)["combo.dynamic_resolution"]
        assert f[0].severity == Severity.MEDIUM


class TestNoImports:
    def test_pe_no_imports_high(self):
        r = _empty()
        apply_heuristics(r)
        assert "pe.no_imports" in _findings_by_rule(r)

    def test_dotnet_pe_excluded(self):
        r = _empty()
        r.metadata["dotnet"] = True
        apply_heuristics(r)
        assert "pe.no_imports" not in _findings_by_rule(r)

    def test_elf_does_not_fire(self):
        r = _empty(FileFormat.ELF)
        apply_heuristics(r)
        assert "pe.no_imports" not in _findings_by_rule(r)


class TestPosixReverseShell:
    def test_elf_reverse_shell(self):
        r = _empty(FileFormat.ELF)
        r.metadata["dyn_symbols"] = [
            "socket",
            "connect",
            "dup2",
            "execve",
            "__libc_start_main",
        ]
        apply_heuristics(r)
        assert "combo.posix_reverse_shell" in _findings_by_rule(r)

    def test_pe_does_not_match_posix_rules(self):
        r = _empty(FileFormat.PE)
        r.metadata["dyn_symbols"] = [
            "socket",
            "connect",
            "dup2",
            "execve",
        ]
        apply_heuristics(r)
        assert "combo.posix_reverse_shell" not in _findings_by_rule(r)


class TestPosixLoader:
    def test_elf_in_memory_loader(self):
        r = _empty(FileFormat.ELF)
        r.metadata["dyn_symbols"] = ["dlopen", "dlsym", "mprotect", "free"]
        apply_heuristics(r)
        assert "combo.posix_in_memory_loader" in _findings_by_rule(r)


class TestPackedThinImports:
    def test_packed_with_thin_imports(self):
        r = _empty()
        r.is_packed = True
        r.imports = [
            Import(
                "kernel32.dll",
                ("LoadLibraryA", "GetProcAddress", "ExitProcess"),
            )
        ]
        apply_heuristics(r)
        assert "combo.packed_thin_imports" in _findings_by_rule(r)

    def test_packed_with_fat_imports_no_finding(self):
        r = _empty()
        r.is_packed = True
        r.imports = [Import("kernel32.dll", tuple(f"func{i}" for i in range(20)))]
        apply_heuristics(r)
        assert "combo.packed_thin_imports" not in _findings_by_rule(r)

"""End-to-end tests for the Mach-O analyzer (including fat binaries)."""

from __future__ import annotations

from ioc_hunter.analyze.common import AnalyzerReport, FileFormat
from ioc_hunter.analyze.macho import analyze_macho, parse_fat_header
from tests._binary_fixtures import build_fat_macho, build_minimal_macho64


def _new_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="<mem>",
        format=FileFormat.MACHO,
        file_size=0,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


class TestMachoHeader:
    def test_parses_minimal(self):
        raw = build_minimal_macho64()
        r = analyze_macho(raw, report=_new_report())
        assert r.bitness == 64
        assert r.architecture == "x86_64"
        assert r.metadata["filetype"] == "EXECUTE"
        assert r.metadata["pie"] is True


class TestLoadCommands:
    def test_dylibs_collected(self):
        raw = build_minimal_macho64(
            dylibs=["/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"]
        )
        r = analyze_macho(raw, report=_new_report())
        assert "/usr/lib/libSystem.B.dylib" in r.linked_libraries
        assert "/usr/lib/libobjc.A.dylib" in r.linked_libraries

    def test_code_signature_present(self):
        raw = build_minimal_macho64(code_signature=True)
        r = analyze_macho(raw, report=_new_report())
        assert r.is_signed is True

    def test_code_signature_absent(self):
        raw = build_minimal_macho64(code_signature=False)
        r = analyze_macho(raw, report=_new_report())
        assert r.is_signed is False

    def test_encryption_flagged(self):
        raw = build_minimal_macho64(encrypted=True)
        r = analyze_macho(raw, report=_new_report())
        assert any(f.rule == "macho.encrypted" for f in r.findings)

    def test_rpath_flagged(self):
        raw = build_minimal_macho64(rpaths=["@executable_path/../Frameworks"])
        r = analyze_macho(raw, report=_new_report())
        assert any(f.rule == "macho.rpath" for f in r.findings)
        assert "@executable_path/../Frameworks" in r.metadata["rpaths"]


class TestFatBinary:
    def test_parse_fat_header(self):
        slice0 = build_minimal_macho64()
        slice1 = build_minimal_macho64(dylibs=["/usr/lib/libfoo.dylib"])
        fat = build_fat_macho([slice0, slice1])
        slices = parse_fat_header(fat)
        assert slices is not None
        assert len(slices) == 2

    def test_dispatcher_handles_fat(self, tmp_path):
        from ioc_hunter.analyze import FileFormat, analyze

        slice0 = build_minimal_macho64()
        slice1 = build_minimal_macho64()
        fat = build_fat_macho([slice0, slice1])
        p = tmp_path / "fat.bin"
        p.write_bytes(fat)
        r = analyze(p)
        assert r.format == FileFormat.MACHO_FAT
        assert len(r.metadata["fat_slices"]) == 2


class TestMalformedRobustness:
    def test_bad_magic(self):
        raw = b"NOT_A_MACHO" + b"\x00" * 100
        r = analyze_macho(raw, report=_new_report())
        assert any(f.rule == "macho.bad_magic" for f in r.findings)

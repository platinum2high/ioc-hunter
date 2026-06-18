"""Tests for the MS-OVBA decompressor and VBA heuristics."""

from __future__ import annotations

from ioc_hunter.analyze.common import AnalyzerReport, FileFormat, Severity
from ioc_hunter.analyze.ole import parse_cfb
from ioc_hunter.analyze.vba import (
    analyze_vba_project,
    decompress_compressed_atom,
    decompress_module_stream,
    extract_vba_modules,
)
from tests._doc_fixtures import build_compressed_atom, build_minimal_cfb


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


class TestDecompressor:
    def test_empty_input_returns_error(self):
        out, err = decompress_compressed_atom(b"")
        assert out == b""
        assert err

    def test_missing_signature_byte(self):
        _out, err = decompress_compressed_atom(b"\x00\x0f\xb0abcdefghijklmnop")
        assert err

    def test_literal_only_chunk_round_trip(self):
        payload = b"hello world " * 5
        atom = build_compressed_atom(payload)
        out, err = decompress_compressed_atom(atom)
        assert err == ""
        assert out == payload

    def test_large_round_trip_split_chunks(self):
        # > 4 KiB forces multiple chunks.
        payload = (b"abcdefghij" * 600).strip()  # ~6000 bytes
        atom = build_compressed_atom(payload)
        out, err = decompress_compressed_atom(atom)
        assert err == ""
        assert out == payload

    def test_truncated_chunk_returns_partial(self):
        payload = b"x" * 100
        atom = build_compressed_atom(payload)
        # Cut off the body mid-chunk.
        truncated = atom[: len(atom) - 5]
        out, _err = decompress_compressed_atom(truncated)
        # We expect SOME output, even if not the full thing.
        assert isinstance(out, bytes)


class TestModuleStreamScan:
    def test_finds_atom_past_performance_cache(self):
        payload = b"Sub Test()\n    Debug.Print 1\nEnd Sub\n"
        module = b"\x00" * 0x123 + build_compressed_atom(payload)
        decoded, err = decompress_module_stream(module)
        assert decoded is not None
        assert err == ""
        assert b"Sub Test()" in decoded

    def test_no_atom_returns_none(self):
        decoded, _err = decompress_module_stream(b"\x00" * 200)
        assert decoded is None


class TestExtractFromCFB:
    def test_module_round_trip(self):
        src = b'Sub AutoOpen()\n    CreateObject("WScript.Shell").Run "cmd /c calc.exe"\nEnd Sub\n'
        module_body = b"\x00" * 0x100 + build_compressed_atom(src)
        cfb = build_minimal_cfb({"VBA/dir": b"x" * 5000, "VBA/Module1": module_body})
        container = parse_cfb(cfb)
        assert container.parse_error == ""
        modules = extract_vba_modules(container)
        assert any(m.name == "Module1" for m in modules)
        m = next(mod for mod in modules if mod.name == "Module1")
        assert b"AutoOpen" in m.decompressed
        assert "AutoOpen" in m.auto_exec_subs


class TestHeuristics:
    def _run(self, vba_src: bytes) -> AnalyzerReport:
        module_body = b"\x00" * 0x100 + build_compressed_atom(vba_src)
        cfb = build_minimal_cfb({"VBA/dir": b"x" * 5000, "VBA/Module1": module_body})
        container = parse_cfb(cfb)
        assert container.parse_error == ""
        r = _new_report()
        analyze_vba_project(container, report=r)
        return r

    def test_auto_exec_emits_high(self):
        r = self._run(b"Sub AutoOpen()\n  Debug.Print 1\nEnd Sub\n")
        autos = [f for f in r.findings if f.rule == "vba.auto_exec"]
        assert autos and autos[0].severity == Severity.HIGH

    def test_workbook_open_auto_exec(self):
        r = self._run(b"Private Sub Workbook_Open()\n  Debug.Print 1\nEnd Sub\n")
        assert any(f.rule == "vba.auto_exec" for f in r.findings)

    def test_suspicious_api_detected(self):
        src = b'Sub Foo()\n  Dim sh As Object\n  Set sh = CreateObject("WScript.Shell")\nEnd Sub\n'
        r = self._run(src)
        assert any(f.rule == "vba.suspicious_api" for f in r.findings)

    def test_lolbin_spawn_detected(self):
        src = b'Sub Foo()\n  Shell "powershell -EncodedCommand AAAA"\nEnd Sub\n'
        r = self._run(src)
        # Both lolbin_spawn AND encoded_powershell should fire.
        rules = {f.rule for f in r.findings}
        assert "vba.lolbin_spawn" in rules
        assert "vba.encoded_powershell" in rules

    def test_encoded_powershell_is_critical(self):
        src = b'Sub Foo()\n  Shell "powershell -enc QQBBAA=="\nEnd Sub\n'
        r = self._run(src)
        crits = [f for f in r.findings if f.rule == "vba.encoded_powershell"]
        assert crits and crits[0].severity == Severity.CRITICAL

    def test_obfuscation_density_threshold(self):
        # 25 Chr() calls — over the dense threshold of 20.
        chr_calls = b" + ".join(f"Chr({i})".encode() for i in range(25))
        src = b"Sub Foo()\n  Debug.Print " + chr_calls + b"\nEnd Sub\n"
        r = self._run(src)
        assert any(f.rule == "vba.obfuscation_density" for f in r.findings)

"""Tests for the phase-14.1+ extensions.

Covers: imphash, Authenticode CN extraction, PE resources, ELF NOTE
parsing, embedded payload scan, shellcode markers, ATT&CK tagging,
markdown export.
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.attack_map import all_techniques, tag_findings
from ioc_hunter.analyze.authenticode import extract_signer_names
from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Import,
    Severity,
)
from ioc_hunter.analyze.embedded import (
    scan_cobalt_strike,
    scan_embedded,
    scan_shellcode_markers,
)
from ioc_hunter.analyze.imphash import compute_imphash
from ioc_hunter.analyze.markdown import to_markdown
from tests._binary_fixtures import build_minimal_pe

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _empty_pe_report() -> AnalyzerReport:
    return AnalyzerReport(
        path="test.exe",
        format=FileFormat.PE,
        file_size=4096,
        truncated=False,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )


# ---------------------------------------------------------------------------
# Imphash
# ---------------------------------------------------------------------------


class TestImphash:
    def test_empty_yields_empty(self):
        assert compute_imphash([]) == ""

    def test_deterministic(self):
        imps = [Import("kernel32.dll", ("LoadLibraryA", "GetProcAddress"))]
        assert compute_imphash(imps) == compute_imphash(imps)

    def test_strips_dll_suffix(self):
        # Same set of (DLL, fn) pairs should hash identically whether
        # the DLL is given with or without the .dll suffix.
        a = compute_imphash([Import("kernel32.dll", ("LoadLibraryA",))])
        b = compute_imphash([Import("kernel32", ("LoadLibraryA",))])
        assert a == b

    def test_case_insensitive(self):
        a = compute_imphash([Import("KERNEL32.DLL", ("LOADLIBRARYA",))])
        b = compute_imphash([Import("kernel32.dll", ("loadlibrarya",))])
        assert a == b

    def test_ordinal_normalization(self):
        # Ordinal symbols emitted by our parser as "#42" must canonicalise
        # to "ord42" for cross-tool imphash compatibility.
        h_ours = compute_imphash([Import("ws2_32.dll", ("#42",))])
        h_ref = compute_imphash([Import("ws2_32.dll", ("ord42",))])
        assert h_ours == h_ref

    def test_delayed_suffix_stripped(self):
        # The "(delayed)" tag we append for delayed imports must not bleed
        # into the imphash.
        a = compute_imphash([Import("kernel32.dll (delayed)", ("LoadLibraryA",))])
        b = compute_imphash([Import("kernel32.dll", ("LoadLibraryA",))])
        assert a == b

    def test_pe_dispatcher_populates_imphash(self, tmp_path):
        from ioc_hunter.analyze import analyze

        raw = build_minimal_pe(
            imports=[("kernel32.dll", ["LoadLibraryA", "GetProcAddress", "ExitProcess"])]
        )
        p = tmp_path / "x.exe"
        p.write_bytes(raw)
        r = analyze(p)
        # Non-empty, lowercase hex, 32 chars.
        assert len(r.imphash) == 32
        assert all(c in "0123456789abcdef" for c in r.imphash)


# ---------------------------------------------------------------------------
# Authenticode (DER walker)
# ---------------------------------------------------------------------------


class TestAuthenticode:
    def _wrap_cn(self, name: str, tag: int = 0x0C) -> bytes:
        """Encode 06 03 55 04 03 <tag> <len> <name> — a single CN TLV."""
        name_b = name.encode("utf-8")
        return b"\x06\x03\x55\x04\x03" + bytes([tag, len(name_b)]) + name_b

    def test_empty_input(self):
        assert extract_signer_names(b"") == ("", "")

    def test_single_cn_treated_as_subject(self):
        blob = self._wrap_cn("Microsoft Corporation")
        signer, issuer = extract_signer_names(blob)
        assert signer == "Microsoft Corporation"
        assert issuer == ""

    def test_two_cns_returns_subject_then_issuer(self):
        # Issuer first (per X.509 TBSCertificate order), then subject.
        blob = self._wrap_cn("DigiCert SHA2 Code Signing CA") + self._wrap_cn(
            "Microsoft Corporation"
        )
        signer, issuer = extract_signer_names(blob)
        assert signer == "Microsoft Corporation"
        assert issuer == "DigiCert SHA2 Code Signing CA"

    def test_long_form_length(self):
        # DER long-form length: 81 LL for one length byte.
        name = "A" * 200
        cn = b"\x06\x03\x55\x04\x03\x0c\x81" + bytes([len(name)]) + name.encode()
        signer, _issuer = extract_signer_names(cn)
        assert signer == name

    def test_bmpstring_utf16be(self):
        # BMPString CN encoded big-endian UCS-2.
        text = "Acme Corp"
        encoded = text.encode("utf-16-be")
        cn = b"\x06\x03\x55\x04\x03\x1e" + bytes([len(encoded)]) + encoded
        signer, _issuer = extract_signer_names(cn)
        assert signer == text

    def test_malformed_length_skipped(self):
        # Length byte 0xFF (5 length-bytes claimed) should be skipped, not crash.
        blob = b"\x06\x03\x55\x04\x03\x0c\xff" + b"X" * 5
        # No good CN found.
        assert extract_signer_names(blob) == ("", "")


# ---------------------------------------------------------------------------
# Embedded scanner
# ---------------------------------------------------------------------------


class TestEmbeddedScanner:
    def test_finds_embedded_pe(self):
        r = _empty_pe_report()
        # Build a tiny fake "outer" prefix, then a valid mini-PE we craft
        # by hand with MZ at offset N and "PE\0\0" at MZ + e_lfanew.
        outer = b"\x00" * 1024
        e_lfanew = 0x40
        # 64-byte DOS stub.
        stub = b"MZ" + b"\x00" * (e_lfanew - 2 - 4) + struct.pack("<I", e_lfanew)
        # Then PE signature where e_lfanew points.
        pe = stub + b"PE\x00\x00" + b"\x00" * 32
        raw = outer + pe
        scan_embedded(raw, r)
        rules = {f.rule for f in r.findings}
        assert "embedded.pe" in rules

    def test_finds_embedded_elf(self):
        r = _empty_pe_report()
        raw = b"X" * 1000 + b"\x7fELF" + b"\x00" * 60
        scan_embedded(raw, r)
        assert "embedded.elf" in {f.rule for f in r.findings}

    def test_archive_detection(self):
        r = _empty_pe_report()
        raw = b"\x00" * 100 + b"PK\x03\x04" + b"\x00" * 100
        scan_embedded(raw, r)
        rules = {f.rule for f in r.findings}
        assert "embedded.archive" in rules

    def test_skips_fat_slices(self):
        """A Mach-O fat carrier should not flag its own slices as 'embedded'."""
        r = _empty_pe_report()
        # Two FEEDFACF magics at known offsets, recorded as fat slices.
        raw = (
            b"\x00" * 0x4000
            + b"\xcf\xfa\xed\xfe"
            + b"\x00" * 0x4000
            + b"\xcf\xfa\xed\xfe"
            + b"\x00" * 4
        )
        r.metadata["fat_slices"] = [
            {"cputype": 0, "cpusubtype": 0, "offset": 0x4000, "size": 0x4004},
            {"cputype": 0, "cpusubtype": 0, "offset": 0x8004, "size": 4},
        ]
        scan_embedded(raw, r)
        # No embedded.macho finding because both slices were excluded.
        assert "embedded.macho" not in {f.rule for f in r.findings}


# ---------------------------------------------------------------------------
# Shellcode patterns
# ---------------------------------------------------------------------------


class TestShellcodeMarkers:
    def test_msfvenom_x64_prologue(self):
        r = _empty_pe_report()
        raw = b"\x00" * 100 + b"\xfc\x48\x83\xe4\xf0\xe8" + b"\x00" * 100
        scan_shellcode_markers(raw, r)
        assert "shellcode.msfvenom_x64" in {f.rule for f in r.findings}

    def test_msfvenom_x86_hash_prologue(self):
        r = _empty_pe_report()
        raw = b"\x00" * 16 + b"\xfc\xe8\x82\x00\x00\x00" + b"\x00" * 16
        scan_shellcode_markers(raw, r)
        assert "shellcode.msfvenom_x86_hash" in {f.rule for f in r.findings}

    def test_clean_traffic_no_finding(self):
        r = _empty_pe_report()
        raw = b"hello world " * 100
        scan_shellcode_markers(raw, r)
        assert all(not f.rule.startswith("shellcode.") for f in r.findings)


class TestCobaltStrike:
    def test_plain_marker(self):
        r = _empty_pe_report()
        raw = b"\x00" * 256 + b"\x00\x01\x00\x01\x00\x02\x00\x04" + b"\x00" * 256
        scan_cobalt_strike(raw, r)
        assert "c2.cobalt_strike_beacon_marker" in {f.rule for f in r.findings}

    def test_xor_marker(self):
        r = _empty_pe_report()
        marker = bytes(b ^ 0x69 for b in b"\x00\x01\x00\x01\x00\x02\x00\x04")
        raw = b"\x00" * 64 + marker + b"\x00" * 64
        scan_cobalt_strike(raw, r)
        assert "c2.cobalt_strike_xor_marker" in {f.rule for f in r.findings}

    def test_no_false_positive(self):
        r = _empty_pe_report()
        scan_cobalt_strike(b"safe content" * 100, r)
        assert not any(f.rule.startswith("c2.cobalt") for f in r.findings)


# ---------------------------------------------------------------------------
# ATT&CK tagging
# ---------------------------------------------------------------------------


class TestAttackMap:
    def test_known_rule_tagged(self):
        r = _empty_pe_report()
        r.findings.append(
            Finding(
                rule="combo.process_injection",
                severity=Severity.CRITICAL,
                category="injection",
                message="x",
            )
        )
        tag_findings(r)
        assert r.findings[0].mitre == ("T1055",)

    def test_unknown_rule_keeps_empty(self):
        r = _empty_pe_report()
        r.findings.append(
            Finding(rule="some.unknown.rule", severity=Severity.LOW, category="x", message="y")
        )
        tag_findings(r)
        assert r.findings[0].mitre == ()

    def test_all_techniques_unique_sorted(self):
        r = _empty_pe_report()
        r.findings.extend(
            [
                Finding(
                    rule="combo.process_injection",
                    severity=Severity.CRITICAL,
                    category="injection",
                    message="",
                    mitre=("T1055",),
                ),
                Finding(
                    rule="combo.dpapi_dump",
                    severity=Severity.HIGH,
                    category="infostealer",
                    message="",
                    mitre=("T1555.003",),
                ),
                # Duplicate technique — should appear once.
                Finding(
                    rule="combo.process_injection",
                    severity=Severity.HIGH,
                    category="injection",
                    message="",
                    mitre=("T1055",),
                ),
            ]
        )
        techs = all_techniques(r)
        assert techs == ["T1055", "T1555.003"]


# ---------------------------------------------------------------------------
# Markdown exporter
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_renders_minimal(self):
        r = _empty_pe_report()
        text = to_markdown(r)
        assert "# Binary Analysis Report" in text
        assert "Verdict" in text
        # Hashes always present.
        assert "MD5" in text

    def test_includes_findings_and_iocs(self):
        r = _empty_pe_report()
        r.findings.append(
            Finding(
                rule="combo.process_injection",
                severity=Severity.CRITICAL,
                category="injection",
                message="Test inject",
                mitre=("T1055",),
            )
        )
        text = to_markdown(r)
        assert "combo.process_injection" in text
        assert "T1055" in text
        assert "CRITICAL" in text

    def test_escapes_pipe(self):
        r = _empty_pe_report()
        r.path = "C:\\Some|Path\\sample.exe"
        text = to_markdown(r)
        # Pipe in the path must be backslash-escaped or the row would split.
        assert r"Some\|Path" in text


# ---------------------------------------------------------------------------
# Real-world end-to-end: synthesise a PE with imports, run the full pipeline,
# assert that the new sections come together.
# ---------------------------------------------------------------------------


class TestEndToEndIntegration:
    def test_pipeline_populates_new_fields(self, tmp_path):
        from ioc_hunter.analyze import analyze

        raw = build_minimal_pe(
            imports=[
                (
                    "kernel32.dll",
                    ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                )
            ]
        )
        p = tmp_path / "inject.exe"
        p.write_bytes(raw)
        r = analyze(p)

        assert r.imphash, "imphash should populate when imports present"
        # ATT&CK tagging fires on the heuristic combo.
        assert any(f.mitre for f in r.findings)
        # all_techniques surfaces the unique IDs.
        techs = all_techniques(r)
        assert "T1055" in techs

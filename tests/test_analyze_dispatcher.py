"""Dispatcher tests — magic-byte routing and hashing."""

from __future__ import annotations

import hashlib
import os
import struct

from ioc_hunter.analyze.common import FileFormat
from ioc_hunter.analyze.dispatcher import analyze, detect_format


class TestDetectFormat:
    def test_pe(self):
        assert detect_format(b"MZ\x90\x00") == FileFormat.PE

    def test_elf(self):
        assert detect_format(b"\x7fELF\x02\x01\x01") == FileFormat.ELF

    def test_macho_64_le(self):
        assert detect_format(struct.pack("<I", 0xFEEDFACF) + b"\x00" * 12) == FileFormat.MACHO

    def test_macho_32_be(self):
        assert detect_format(struct.pack("<I", 0xCEFAEDFE) + b"\x00" * 12) == FileFormat.MACHO

    def test_fat(self):
        assert detect_format(struct.pack("<I", 0xCAFEBABE) + b"\x00" * 12) == FileFormat.MACHO_FAT

    def test_unknown(self):
        assert detect_format(b"hello world!") == FileFormat.UNKNOWN
        assert detect_format(b"\x00\x00\x00\x00") == FileFormat.UNKNOWN

    def test_short_input(self):
        assert detect_format(b"\x7f") == FileFormat.UNKNOWN
        assert detect_format(b"") == FileFormat.UNKNOWN


class TestAnalyzeUnknown:
    def test_unknown_file_still_returns_report(self, tmp_path):
        # Random bytes; should not crash and should still IOC-sweep.
        path = tmp_path / "junk.bin"
        content = b"http://abuse.example/path\n" + os.urandom(2048)
        path.write_bytes(content)
        report = analyze(path)
        assert report.format == FileFormat.UNKNOWN
        assert report.sha256 == hashlib.sha256(content).hexdigest()
        # The URL embedded in the bytes is picked up.
        assert any(i.value.startswith("http://abuse.example") for i in report.iocs)


class TestHashes:
    def test_hashes_match_full_file(self, tmp_path):
        path = tmp_path / "x.bin"
        content = os.urandom(64 * 1024)
        path.write_bytes(content)
        report = analyze(path)
        assert report.md5 == hashlib.md5(content).hexdigest()
        assert report.sha1 == hashlib.sha1(content).hexdigest()
        assert report.sha256 == hashlib.sha256(content).hexdigest()
        assert report.truncated is False


class TestTruncationCap:
    def test_truncation_flag_set_when_over_cap(self, tmp_path, monkeypatch):
        # Lower the cap so we don't have to write 257 MiB.
        from ioc_hunter.analyze import dispatcher

        monkeypatch.setattr(dispatcher, "MAX_FILE_BYTES", 1024)
        path = tmp_path / "big.bin"
        content = os.urandom(4 * 1024)
        path.write_bytes(content)
        report = dispatcher.analyze(path)
        assert report.truncated is True
        # Hashes still reflect the full content.
        assert report.sha256 == hashlib.sha256(content).hexdigest()
        # ``analyzer.truncated`` info finding is appended.
        assert any(f.rule == "analyzer.truncated" for f in report.findings)

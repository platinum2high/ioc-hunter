"""Tests for the shared building blocks of the binary analyser."""

from __future__ import annotations

import pytest

from ioc_hunter.analyze.common import (
    Reader,
    extract_all_strings,
    extract_ascii_strings,
    extract_utf16le_strings,
    humanize_size,
    packer_match,
    shannon_entropy,
    sweep_iocs,
)
from ioc_hunter.core.types import IOCType

# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


class TestReader:
    def test_in_bounds(self):
        r = Reader(b"\x01\x02\x03\x04\x05")
        assert r.u8(0) == 1
        assert r.u8(4) == 5
        assert r.u16(0) == 0x0201
        assert r.u32(0) == 0x04030201

    def test_oob_returns_none(self):
        r = Reader(b"\x01\x02\x03")
        assert r.u32(0) is None  # need 4, have 3
        assert r.u8(5) is None
        assert r.u16(2) is None
        assert r.slice(10, 1) is None
        assert r.slice(0, 10) is None

    def test_negative_offset_safe(self):
        r = Reader(b"\x01\x02\x03")
        assert r.slice(-1, 1) is None
        assert r.slice(0, -1) is None
        assert r.cstr(-1) is None

    def test_cstr_terminates_on_nul(self):
        r = Reader(b"hello\x00world\x00")
        assert r.cstr(0) == "hello"
        assert r.cstr(6) == "world"

    def test_cstr_capped_when_no_nul(self):
        r = Reader(b"A" * 1000)
        assert r.cstr(0, max_len=16) == "A" * 16

    def test_endianness(self):
        r = Reader(b"\x12\x34")
        assert r.u16(0, little=True) == 0x3412
        assert r.u16(0, little=False) == 0x1234


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_is_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_uniform_byte_is_zero(self):
        assert shannon_entropy(b"A" * 1000) == pytest.approx(0.0)

    def test_balanced_two_byte_is_one(self):
        data = b"AB" * 500
        assert shannon_entropy(data) == pytest.approx(1.0)

    def test_uniform_distribution_approaches_eight(self):
        # All 256 byte values, each once → 8.0 bits exactly.
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_text_lower_than_random(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        random_like = bytes(range(256)) * 4
        assert shannon_entropy(text) < shannon_entropy(random_like)


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------


class TestStringExtraction:
    def test_ascii_finds_long_runs(self):
        data = b"\x00\x01" + b"HELLO_WORLD" + b"\x00\x02"
        out = extract_ascii_strings(data)
        assert "HELLO_WORLD" in out

    def test_ascii_ignores_short_runs(self):
        # Below MIN_STRING_LEN (6).
        data = b"\x00abc\x00"
        assert extract_ascii_strings(data) == []

    def test_utf16le(self):
        # "MALWARE" in UTF-16LE
        data = b"\x00\x00" + "MALWARE".encode("utf-16-le") + b"\x00\x00"
        out = extract_utf16le_strings(data)
        assert "MALWARE" in out

    def test_extract_all_dedups(self):
        s = "EXACTLY_THIS_STRING"
        data = s.encode() + b"\x00" + s.encode()
        out = extract_all_strings(data)
        # Even though it appears twice, it shows once.
        assert out.count(s) == 1


# ---------------------------------------------------------------------------
# IOC sweep
# ---------------------------------------------------------------------------


class TestSweepIocs:
    def test_extracts_url_and_ip(self):
        strs = [
            "https://malicious.net/loader.bin",
            "C2 IP is 198.51.100.42",
            "garbage with no IOC here",
        ]
        iocs = sweep_iocs(strs)
        values = {(i.type, i.value) for i in iocs}
        assert (IOCType.URL, "https://malicious.net/loader.bin") in values
        assert (IOCType.IPV4, "198.51.100.42") in values
        # Host of the URL is surfaced too.
        assert (IOCType.DOMAIN, "malicious.net") in values

    def test_empty_input(self):
        assert sweep_iocs([]) == []


# ---------------------------------------------------------------------------
# Packer signature match
# ---------------------------------------------------------------------------


class TestPackerMatch:
    def test_matches_upx_by_section_name(self):
        assert packer_match(["UPX0", ".text"], b"\x00" * 1024) == "UPX"

    def test_matches_upx_signature_anywhere(self):
        raw = b"\x00" * 100 + b"UPX!" + b"\x00" * 100
        assert packer_match([".text"], raw) == "UPX"

    def test_no_match(self):
        assert packer_match([".text", ".data"], b"benign bytes") is None

    def test_themida_section_name(self):
        assert packer_match([".themida"], b"") == "Themida"


# ---------------------------------------------------------------------------
# humanize_size
# ---------------------------------------------------------------------------


class TestHumanize:
    def test_bytes(self):
        assert humanize_size(500) == "500 B"

    def test_kib(self):
        assert humanize_size(2048) == "2.0 KiB"

    def test_mib(self):
        assert humanize_size(5 * 1024 * 1024) == "5.0 MiB"

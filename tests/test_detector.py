"""Tests for single-string IOC type detection."""

import pytest

from ioc_hunter.core.detector import _btc_legacy_checksum_valid, detect_type
from ioc_hunter.core.types import IOCType


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8", IOCType.IPV4),
        ("192.168.1.1", IOCType.IPV4),
        ("255.255.255.255", IOCType.IPV4),
        ("2001:db8::1", IOCType.IPV6),
        ("::1", IOCType.IPV6),
        ("evil.com", IOCType.DOMAIN),
        ("sub.evil.co.uk", IOCType.DOMAIN),
        ("https://evil.com/login", IOCType.URL),
        ("http://1.2.3.4", IOCType.URL),
        ("ftp://files.example.com", IOCType.URL),
        ("bad@evil.com", IOCType.EMAIL),
        ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
        (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            IOCType.SHA256,
        ),
        ("CVE-2021-44228", IOCType.CVE),
        ("cve-2024-1234", IOCType.CVE),
        ("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", IOCType.BTC_ADDRESS),
        (
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            IOCType.BTC_ADDRESS,
        ),
    ],
)
def test_detect_positive(value: str, expected: IOCType) -> None:
    assert detect_type(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not an ioc",
        "256.256.256.256",  # invalid octet
        "1.2.3",  # incomplete IP
        "abc",  # bare word, no TLD
        "evil.x",  # 1-char TLD
        "1234567890abcdef",  # 16 hex — not a hash
        "CVE-99-1",  # malformed CVE year
    ],
)
def test_detect_negative(value: str) -> None:
    assert detect_type(value) is None


@pytest.mark.parametrize(
    "address",
    [
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",  # well-known P2PKH
        "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",  # P2PKH, block-170 coinbase hash
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",  # P2SH
    ],
)
def test_btc_legacy_checksum_valid_accepts_real_addresses(address: str) -> None:
    assert _btc_legacy_checksum_valid(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "1JS95cPZqKKmDKapZuxbaSuh7HKw7Y",    # regex-match, wrong checksum
        "1aupYQ21YKaNUP2CPmKit1hqswspQ7",   # regex-match, wrong checksum
        "1RuyioeufVSEJzwZMGWdKwU483xJ8M",   # regex-match, wrong checksum
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyX",  # last char mutated → bad checksum
    ],
)
def test_btc_legacy_checksum_valid_rejects_invalid(address: str) -> None:
    assert _btc_legacy_checksum_valid(address) is False


@pytest.mark.parametrize(
    "address",
    [
        "1JS95cPZqKKmDKapZuxbaSuh7HKw7Y",
        "1aupYQ21YKaNUP2CPmKit1hqswspQ7",
        "1RuyioeufVSEJzwZMGWdKwU483xJ8M",
    ],
)
def test_detect_rejects_btc_with_bad_checksum(address: str) -> None:
    """Strings matching the Base58 regex but failing checksum must not be BTC_ADDRESS."""
    assert detect_type(address) is None

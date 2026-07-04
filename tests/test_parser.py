"""Tests for the raw-text IOC extractor."""

from ioc_hunter.core.parser import extract_iocs
from ioc_hunter.core.types import IOCType


def _by_type(text: str) -> dict[IOCType, list[str]]:
    out: dict[IOCType, list[str]] = {}
    for ioc in extract_iocs(text):
        out.setdefault(ioc.type, []).append(ioc.value)
    return out


def test_extracts_valid_ipv4_only() -> None:
    text = "Hits from 8.8.8.8 and 192.168.1.1 but ignore 999.0.0.1 and 256.1.1.1"
    ips = _by_type(text).get(IOCType.IPV4, [])
    assert "8.8.8.8" in ips
    assert "192.168.1.1" in ips
    assert "999.0.0.1" not in ips
    assert "256.1.1.1" not in ips


def test_refangs_defanged_ip() -> None:
    iocs = extract_iocs("Block 1[.]2[.]3[.]4 now")
    assert any(i.type == IOCType.IPV4 and i.value == "1.2.3.4" for i in iocs)


def test_refangs_defanged_url() -> None:
    iocs = extract_iocs("Visit hxxps://evil[.]com/login")
    urls = [i.value for i in iocs if i.type == IOCType.URL]
    assert urls == ["https://evil.com/login"]


def test_url_surfaces_host_as_domain() -> None:
    by_type = _by_type("Phishing kit hosted at https://evil.com/login.php")
    assert by_type[IOCType.URL] == ["https://evil.com/login.php"]
    assert by_type[IOCType.DOMAIN] == ["evil.com"]


def test_email_surfaces_domain() -> None:
    by_type = _by_type("Sender: bad@evil.com")
    assert by_type[IOCType.EMAIL] == ["bad@evil.com"]
    assert by_type[IOCType.DOMAIN] == ["evil.com"]


def test_url_host_can_be_disabled() -> None:
    iocs = extract_iocs("https://evil.com/login.php", include_url_hosts=False)
    assert {i.type for i in iocs} == {IOCType.URL}


def test_hash_types_separated_by_length() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    by_type = _by_type(f"Sample hashes: {md5} | {sha1} | {sha256}")
    assert by_type[IOCType.MD5] == [md5]
    assert by_type[IOCType.SHA1] == [sha1]
    assert by_type[IOCType.SHA256] == [sha256]


def test_cves_uppercased_and_deduped() -> None:
    by_type = _by_type("Affected by cve-2021-44228 and CVE-2021-44228 again")
    assert by_type[IOCType.CVE] == ["CVE-2021-44228"]


def test_dedups_case_insensitive_domain() -> None:
    by_type = _by_type("evil.com, EVIL.com, Evil.Com")
    assert by_type[IOCType.DOMAIN] == ["evil.com"]


def test_full_incident_text() -> None:
    sample = """
    SOC report 2026-06-13:

    Phishing campaign delivered via hxxps://evil[.]com/login.php
    from sender bad[at]evil[.]com.

    Beaconing to 185[.]220[.]101[.]42 over TCP/443.
    Dropper SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Exploit chain leverages CVE-2024-21762.
    Ransom note demands payment to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT.
    """
    by_type = _by_type(sample)
    assert "https://evil.com/login.php" in by_type[IOCType.URL]
    assert "bad@evil.com" in by_type[IOCType.EMAIL]
    assert "evil.com" in by_type[IOCType.DOMAIN]
    assert "185.220.101.42" in by_type[IOCType.IPV4]
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in by_type[IOCType.SHA256]
    )
    assert "CVE-2024-21762" in by_type[IOCType.CVE]
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in by_type[IOCType.BTC_ADDRESS]


def test_iocs_are_hashable_for_dedup() -> None:
    iocs = extract_iocs("evil.com evil.com")
    assert len(set(iocs)) == len(iocs)


def test_btc_invalid_checksum_not_extracted() -> None:
    """Base58-looking tokens that fail checksum must be silently dropped."""
    text = (
        "Incident artifacts: 1JS95cPZqKKmDKapZuxbaSuh7HKw7Y "
        "1aupYQ21YKaNUP2CPmKit1hqswspQ7 and real addr 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    )
    iocs = extract_iocs(text)
    values = {ioc.value for ioc in iocs}
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" in values
    assert "1JS95cPZqKKmDKapZuxbaSuh7HKw7Y" not in values
    assert "1aupYQ21YKaNUP2CPmKit1hqswspQ7" not in values

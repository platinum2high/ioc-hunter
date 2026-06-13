"""Tests for the Sigma and Suricata rule generators."""

from __future__ import annotations

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.rules import to_sigma, to_suricata
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict


def _v(
    value: str,
    t: IOCType,
    verdict: Verdict = Verdict.MALICIOUS,
    tags: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
) -> IOCVerdict:
    return IOCVerdict(
        ioc=IOC(value=value, type=t),
        verdict=verdict,
        confidence=0.9,
        results=(),
        tags=tags,
        references=references,
    )


# --- Sigma -------------------------------------------------------------------


def test_sigma_groups_by_type() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4),
        _v("5.6.7.8", IOCType.IPV4),
        _v("evil.com", IOCType.DOMAIN),
    ]
    yaml = to_sigma(verdicts)
    # Two documents — one per type.
    documents = yaml.split("\n---\n")
    assert len(documents) == 2
    ipv4_doc = next(d for d in documents if "DestinationIp" in d)
    assert "- '1.2.3.4'" in ipv4_doc
    assert "- '5.6.7.8'" in ipv4_doc
    domain_doc = next(d for d in documents if "QueryName" in d)
    assert "- 'evil.com'" in domain_doc


def test_sigma_hash_uses_prefix() -> None:
    verdicts = [_v("a" * 64, IOCType.SHA256), _v("b" * 32, IOCType.MD5)]
    yaml = to_sigma(verdicts)
    assert f"'SHA256={'a' * 64}'" in yaml
    assert f"'MD5={'b' * 32}'" in yaml
    assert "Hashes|contains" in yaml


def test_sigma_filters_below_threshold() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4, Verdict.SUSPICIOUS),
        _v("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
    ]
    yaml = to_sigma(verdicts, min_verdict=Verdict.MALICIOUS)
    assert "1.2.3.4" not in yaml
    assert "evil.com" in yaml


def test_sigma_lower_threshold_includes_suspicious() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4, Verdict.SUSPICIOUS),
    ]
    yaml = to_sigma(verdicts, min_verdict=Verdict.SUSPICIOUS)
    assert "1.2.3.4" in yaml


def test_sigma_empty_when_no_qualifying_verdicts() -> None:
    verdicts = [_v("1.2.3.4", IOCType.IPV4, Verdict.BENIGN)]
    assert to_sigma(verdicts) == ""


def test_sigma_tags_normalized_and_deduped() -> None:
    verdicts = [
        _v("evil.com", IOCType.DOMAIN, tags=("RedLine Stealer", "phishing")),
        _v("evil2.com", IOCType.DOMAIN, tags=("redline_stealer", "phishing")),
    ]
    yaml = to_sigma(verdicts)
    assert "redline_stealer" in yaml
    assert yaml.count("phishing") == 1


def test_sigma_includes_references() -> None:
    verdicts = [
        _v(
            "1.2.3.4",
            IOCType.IPV4,
            references=("https://urlhaus.abuse.ch/host/1.2.3.4/",),
        )
    ]
    yaml = to_sigma(verdicts)
    assert "https://urlhaus.abuse.ch/host/1.2.3.4/" in yaml


# --- Suricata ----------------------------------------------------------------


def test_suricata_unique_sids() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4),
        _v("evil.com", IOCType.DOMAIN),
        _v("https://evil.com/x", IOCType.URL),
    ]
    rules = to_suricata(verdicts, sid_start=2_000_000)
    sids = [line for line in rules.splitlines() if "sid:" in line]
    assert len(sids) == 3
    extracted = sorted(int(line.split("sid:")[1].split(";")[0]) for line in sids)
    assert extracted == [2_000_000, 2_000_001, 2_000_002]


def test_suricata_ip_rule_shape() -> None:
    rules = to_suricata([_v("1.2.3.4", IOCType.IPV4)])
    assert "alert ip any any -> 1.2.3.4 any" in rules
    assert "classtype:trojan-activity" in rules


def test_suricata_domain_rule_shape() -> None:
    rules = to_suricata([_v("evil.com", IOCType.DOMAIN)])
    assert "alert dns any any -> any any" in rules
    assert 'dns.query; content:"evil.com"' in rules


def test_suricata_url_rule_shape() -> None:
    rules = to_suricata([_v("https://evil.com/login.php", IOCType.URL)])
    assert "alert http any any -> any any" in rules
    assert 'http.host; content:"evil.com"' in rules
    assert 'http.uri; content:"/login.php"' in rules


def test_suricata_skips_hashes() -> None:
    rules = to_suricata([_v("a" * 64, IOCType.SHA256)])
    # Hashes can't be matched by Suricata without filemd5 plumbing — skip.
    assert "Generated" in rules
    assert "alert " not in rules


def test_suricata_escapes_special_chars_in_content() -> None:
    # A URL with a semicolon would close the rule prematurely if unescaped.
    rules = to_suricata([_v("https://evil.com/a;b", IOCType.URL)])
    assert "alert http" in rules
    # Semicolon must be escaped inside content.
    assert r"/a\;b" in rules


def test_suricata_filters_below_threshold() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4, Verdict.SUSPICIOUS),
        _v("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS),
    ]
    rules = to_suricata(verdicts)
    assert "1.2.3.4" not in rules
    assert "evil.com" in rules


def test_suricata_empty_when_no_qualifying_verdicts() -> None:
    assert to_suricata([_v("ok.com", IOCType.DOMAIN, Verdict.BENIGN)]) == ""

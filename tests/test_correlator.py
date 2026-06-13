"""Tests for the IOC correlator."""

from __future__ import annotations

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.correlator import correlate
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict


def _v(value: str, t: IOCType, tags: tuple[str, ...] = ()) -> IOCVerdict:
    return IOCVerdict(
        ioc=IOC(value=value, type=t),
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        results=(),
        tags=tags,
    )


def test_url_to_host_edge() -> None:
    verdicts = [
        _v("https://evil.com/login", IOCType.URL),
        _v("evil.com", IOCType.DOMAIN),
    ]
    edges = correlate(verdicts)
    assert any(
        e.kind == "url_to_host"
        and e.source.value == "https://evil.com/login"
        and e.target.value == "evil.com"
        for e in edges
    )


def test_email_to_domain_edge() -> None:
    verdicts = [
        _v("bad@evil.com", IOCType.EMAIL),
        _v("evil.com", IOCType.DOMAIN),
    ]
    edges = correlate(verdicts)
    assert any(e.kind == "email_to_domain" and e.target.value == "evil.com" for e in edges)


def test_shared_subnet_edges() -> None:
    verdicts = [
        _v("185.220.101.42", IOCType.IPV4),
        _v("185.220.101.99", IOCType.IPV4),
        _v("185.220.101.105", IOCType.IPV4),
        _v("8.8.8.8", IOCType.IPV4),
    ]
    edges = correlate(verdicts)
    subnet_edges = [e for e in edges if e.kind == "shared_subnet"]
    # 3-clique in the .101 subnet → 3 unordered pairs.
    assert len(subnet_edges) == 3
    assert all("185.220.101.0/24" in e.evidence for e in subnet_edges)


def test_shared_tag_edges() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4, tags=("redline",)),
        _v("evil.com", IOCType.DOMAIN, tags=("redline", "phishing")),
        _v("a" * 64, IOCType.SHA256, tags=("redline",)),
    ]
    edges = [e for e in correlate(verdicts) if e.kind == "shared_tag"]
    # 3 IOCs share "redline" → 3 unordered pairs.
    assert len(edges) == 3
    assert all("redline" in e.evidence for e in edges)


def test_noise_tags_do_not_correlate() -> None:
    verdicts = [
        _v("1.2.3.4", IOCType.IPV4, tags=("country:US", "usage:hosting")),
        _v("5.6.7.8", IOCType.IPV4, tags=("country:US",)),
    ]
    edges = [e for e in correlate(verdicts) if e.kind == "shared_tag"]
    assert edges == []


def test_empty_input() -> None:
    assert correlate([]) == []


def test_no_correlations_for_unrelated_iocs() -> None:
    verdicts = [
        _v("https://safe.example/x", IOCType.URL),
        _v("other.example", IOCType.DOMAIN),
    ]
    edges = correlate(verdicts)
    assert edges == []

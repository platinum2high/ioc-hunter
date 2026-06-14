"""Offline IP classifier — keyless, no network calls, stdlib only.

Returns context that no online TI feed gives you for free:

- **Bogon / unallocated** — RFC 6890 reserved blocks (TEST-NET, documentation,
  benchmarking, future-use 240/4, etc.). Seeing one of these in production
  logs is almost always either misconfiguration or spoofed traffic.
- **Private / loopback / link-local / multicast** — useful negative context
  when triaging "is this IP from outside?" questions.
- **Carrier-grade NAT** (100.64.0.0/10) — distinguishes a CGNAT customer
  from a true public IP.

The verdict is always informational: BENIGN for clean private/loopback,
SUSPICIOUS for bogon-in-prod (because it shouldn't be routable), and
UNKNOWN for normal public IPs that need other sources to classify.

This source is intentionally tiny — its job is enriching context, not
verdict-driving. Weight is low (0.2) so it nudges the score without
overriding signal from real TI feeds.
"""

from __future__ import annotations

import ipaddress

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

# Reserved/bogon ranges from RFC 6890 + RFC 5737 + RFC 6598. ipaddress's
# built-in classifications cover most of these, but we name them explicitly
# so we can tag the result with which category triggered.
_BOGON_NAMED: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "this-network"),
    ("192.0.0.0/24", "ietf-protocol"),
    ("192.0.2.0/24", "test-net-1"),
    ("198.51.100.0/24", "test-net-2"),
    ("203.0.113.0/24", "test-net-3"),
    ("198.18.0.0/15", "benchmarking"),
    ("240.0.0.0/4", "reserved-future"),
    ("255.255.255.255/32", "broadcast"),
)
_BOGON_NETS = tuple((ipaddress.ip_network(c), name) for c, name in _BOGON_NAMED)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _classify_v4(addr: ipaddress.IPv4Address) -> tuple[Verdict, tuple[str, ...]] | None:
    """Return (verdict, tags) for a private/reserved IPv4, or None if public-routable."""
    for net, name in _BOGON_NETS:
        if isinstance(net, ipaddress.IPv4Network) and addr in net:
            return Verdict.SUSPICIOUS, ("bogon", name, "non-routable")
    if addr in _CGNAT:
        return Verdict.BENIGN, ("cgnat", "rfc6598")
    if addr.is_loopback:
        return Verdict.BENIGN, ("loopback",)
    if addr.is_link_local:
        return Verdict.BENIGN, ("link-local",)
    if addr.is_private:
        return Verdict.BENIGN, ("private", "rfc1918")
    if addr.is_multicast:
        return Verdict.BENIGN, ("multicast",)
    if addr.is_unspecified:
        return Verdict.SUSPICIOUS, ("unspecified",)
    return None


def _classify_v6(addr: ipaddress.IPv6Address) -> tuple[Verdict, tuple[str, ...]] | None:
    if addr.is_loopback:
        return Verdict.BENIGN, ("loopback",)
    if addr.is_link_local:
        return Verdict.BENIGN, ("link-local",)
    if addr.is_site_local:
        return Verdict.BENIGN, ("site-local",)
    if addr.is_private:
        return Verdict.BENIGN, ("private", "ula")
    if addr.is_multicast:
        return Verdict.BENIGN, ("multicast",)
    if addr.is_unspecified:
        return Verdict.SUSPICIOUS, ("unspecified",)
    if addr.is_reserved:
        return Verdict.SUSPICIOUS, ("reserved",)
    return None


class NetMetaSource(Source):
    """Offline IP context — bogon, private, CGNAT, loopback classification."""

    name = "netmeta"
    weight = 0.2
    supported_types = frozenset({IOCType.IPV4, IOCType.IPV6})
    requires_key = False

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        api_key: str | None = None,
    ) -> None:
        super().__init__(client, api_key=api_key)

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        try:
            addr = ipaddress.ip_address(ioc_value)
        except ValueError as exc:
            return self._error(ioc_type, ioc_value, f"invalid IP: {exc}")

        classified: tuple[Verdict, tuple[str, ...]] | None
        if isinstance(addr, ipaddress.IPv4Address):
            classified = _classify_v4(addr)
        else:
            classified = _classify_v6(addr)

        if classified is None:
            # Public-routable address — we have nothing useful to add.
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=Verdict.UNKNOWN,
                tags=("public",),
            )

        verdict, tags = classified
        # Bogons in production logs are SUSPICIOUS at full confidence; clean
        # private/loopback IPs are BENIGN but at modest confidence — we don't
        # want this source to drown out a real malicious verdict from another
        # feed just because an attacker came from a known cloud range.
        score = 0.8 if verdict is Verdict.SUSPICIOUS else 0.3
        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tags,
        )

"""Find non-obvious relationships across a batch of enriched IOCs.

The correlator looks for the pivots an analyst would chase by hand:

- A URL's host showing up as its own IOC (URL → host).
- An email's domain showing up as its own IOC (email → domain).
- Multiple IPv4s landing in the same /24 — strong shared-infrastructure
  signal.
- Multiple IOCs carrying the same discriminating tag (malware family,
  campaign, threat actor) — same operator across types.

Geo / ISP / usage-class tags are filtered as noise — they correlate every
IP from any major cloud provider and would drown out real findings.
"""

from __future__ import annotations

import contextlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.scorer import IOCVerdict


@dataclass(frozen=True, slots=True)
class Correlation:
    """An edge in the correlation graph."""

    source: IOC
    target: IOC
    kind: str
    evidence: str


_NOISE_TAG_PREFIXES = ("country:", "usage:", "isp:")


def _is_noise_tag(tag: str) -> bool:
    return any(tag.lower().startswith(prefix) for prefix in _NOISE_TAG_PREFIXES)


def correlate(verdicts: list[IOCVerdict]) -> list[Correlation]:
    """Return every detected relationship across the verdict batch."""
    by_value: dict[str, IOC] = {v.ioc.value: v.ioc for v in verdicts}
    edges: list[Correlation] = []

    # URL → its host
    for v in verdicts:
        if v.ioc.type is not IOCType.URL:
            continue
        with contextlib.suppress(ValueError):
            host = urlparse(v.ioc.value).hostname
            if host and host in by_value:
                edges.append(
                    Correlation(
                        source=v.ioc,
                        target=by_value[host],
                        kind="url_to_host",
                        evidence=f"URL is hosted on {host}",
                    )
                )

    # Email → its domain
    for v in verdicts:
        if v.ioc.type is not IOCType.EMAIL or "@" not in v.ioc.value:
            continue
        domain = v.ioc.value.split("@", 1)[1].lower()
        if domain in by_value:
            edges.append(
                Correlation(
                    source=v.ioc,
                    target=by_value[domain],
                    kind="email_to_domain",
                    evidence=f"Email at {domain}",
                )
            )

    # Shared /24 (IPv4)
    by_subnet: dict[str, list[IOC]] = {}
    for v in verdicts:
        if v.ioc.type is not IOCType.IPV4:
            continue
        try:
            net = str(ipaddress.IPv4Network(f"{v.ioc.value}/24", strict=False))
        except (ipaddress.AddressValueError, ValueError):
            continue
        by_subnet.setdefault(net, []).append(v.ioc)
    for net, group in by_subnet.items():
        if len(group) < 2:
            continue
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                edges.append(
                    Correlation(
                        source=a,
                        target=b,
                        kind="shared_subnet",
                        evidence=f"both in {net}",
                    )
                )

    # Shared discriminating tag
    by_tag: dict[str, list[IOC]] = {}
    for v in verdicts:
        for tag in v.tags:
            if _is_noise_tag(tag):
                continue
            by_tag.setdefault(tag, []).append(v.ioc)
    for tag, group in by_tag.items():
        if len(group) < 2:
            continue
        # Dedup IOCs in case the same one carries the tag from two sources.
        unique = list({ioc.value: ioc for ioc in group}.values())
        if len(unique) < 2:
            continue
        for i, a in enumerate(unique):
            for b in unique[i + 1 :]:
                edges.append(
                    Correlation(
                        source=a,
                        target=b,
                        kind="shared_tag",
                        evidence=f"both tagged {tag!r}",
                    )
                )

    return edges

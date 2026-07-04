"""Extract IOCs from arbitrary text.

Strategy:

1. Refang the whole text so defanged IOCs match plain regexes.
2. Scan for each IOC type in order of *containment* — URLs and emails first,
   then hashes, then IPs, finally bare domains. Matched character spans are
   masked so a domain inside a URL is not also extracted as a domain.
3. For URLs and emails we additionally surface the host/domain as a separate
   IOC — TI sources query hosts independently of full URLs, and the
   correlator needs the host to find pivots.
4. Deduplicate on `(type, value)` with case normalization on hostnames,
   emails, and hashes.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from urllib.parse import urlparse

from ioc_hunter.core._tlds import IANA_TLDS
from ioc_hunter.core.defang import refang
from ioc_hunter.core.detector import _btc_legacy_checksum_valid, detect_type
from ioc_hunter.core.types import IOC, IOCType

_URL_SCAN = re.compile(r"\b(?:https?|ftps?)://[^\s<>\"'\[\]{}|\\^`]+", re.IGNORECASE)
_EMAIL_SCAN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,63}\b")
_SHA256_SCAN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_SCAN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_SCAN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_CVE_SCAN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_BTC_BECH32_SCAN = re.compile(r"\bbc1[a-z0-9]{39,59}\b")
_BTC_LEGACY_SCAN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_IPV4_SCAN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_IPV6_SCAN = re.compile(
    r"(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}|::(?:[A-F0-9]{1,4}:){0,6}[A-F0-9]{1,4}",
    re.IGNORECASE,
)
_DOMAIN_SCAN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)

_LOWERCASE_TYPES = frozenset(
    {
        IOCType.DOMAIN,
        IOCType.EMAIL,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
)


def extract_iocs(
    text: str,
    *,
    do_refang: bool = True,
    include_url_hosts: bool = True,
) -> list[IOC]:
    """Return every distinct IOC found in `text`, in extraction order."""
    if do_refang:
        text = refang(text)

    found: list[IOC] = []
    seen: set[tuple[IOCType, str]] = set()
    masked = bytearray(len(text))

    def is_free(start: int, end: int) -> bool:
        return not any(masked[start:end])

    def mark(start: int, end: int) -> None:
        for i in range(start, end):
            masked[i] = 1

    def add(value: str, ioc_type: IOCType, raw: str | None = None) -> None:
        canonical = value.lower() if ioc_type in _LOWERCASE_TYPES else value
        key = (ioc_type, canonical)
        if key in seen:
            return
        seen.add(key)
        found.append(IOC(value=canonical, type=ioc_type, raw=raw))

    def add_host_of(host: str | None) -> None:
        if not host:
            return
        host_type = detect_type(host)
        if host_type in {IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6}:
            add(host, host_type)

    # 1. URLs — consume their full span so we don't re-extract host/path.
    for m in _URL_SCAN.finditer(text):
        if not is_free(*m.span()):
            continue
        url = m.group().rstrip(".,;:)")
        mark(m.start(), m.start() + len(url))
        add(url, IOCType.URL)
        if include_url_hosts:
            with contextlib.suppress(ValueError):
                add_host_of(urlparse(url).hostname)

    # 2. Emails — consume span, surface the domain part.
    for m in _EMAIL_SCAN.finditer(text):
        if not is_free(*m.span()):
            continue
        email = m.group()
        mark(*m.span())
        add(email, IOCType.EMAIL)
        if include_url_hosts:
            add_host_of(email.split("@", 1)[1])

    # 3. Hashes, longest first.
    for scan, ioc_type in (
        (_SHA256_SCAN, IOCType.SHA256),
        (_SHA1_SCAN, IOCType.SHA1),
        (_MD5_SCAN, IOCType.MD5),
    ):
        for m in scan.finditer(text):
            if is_free(*m.span()):
                mark(*m.span())
                add(m.group(), ioc_type)

    # 4. CVEs.
    for m in _CVE_SCAN.finditer(text):
        if is_free(*m.span()):
            mark(*m.span())
            add(m.group().upper(), IOCType.CVE)

    # 5. BTC (bech32 first, then legacy — legacy is more permissive).
    for m in _BTC_BECH32_SCAN.finditer(text):
        if is_free(*m.span()):
            mark(*m.span())
            add(m.group(), IOCType.BTC_ADDRESS)
    for m in _BTC_LEGACY_SCAN.finditer(text):
        if is_free(*m.span()) and _btc_legacy_checksum_valid(m.group()):
            mark(*m.span())
            add(m.group(), IOCType.BTC_ADDRESS)

    # 6. IPv6 (validate via stdlib, regex is loose).
    for m in _IPV6_SCAN.finditer(text):
        candidate = m.group()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if is_free(*m.span()):
            mark(*m.span())
            add(candidate, IOCType.IPV6)

    # 7. IPv4.
    for m in _IPV4_SCAN.finditer(text):
        if is_free(*m.span()):
            mark(*m.span())
            add(m.group(), IOCType.IPV4)

    # 8. Bare domains — reject if the final label is not a real IANA TLD.
    for m in _DOMAIN_SCAN.finditer(text):
        val = m.group()
        if val.rsplit(".", 1)[-1].lower() not in IANA_TLDS:
            continue
        if is_free(*m.span()):
            mark(*m.span())
            add(val, IOCType.DOMAIN, raw=val)

    return found

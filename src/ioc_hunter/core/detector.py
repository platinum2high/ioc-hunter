"""Detect the type of a single (already-refanged) IOC string."""

from __future__ import annotations

import hashlib
import ipaddress
import re

from ioc_hunter.core._tlds import IANA_TLDS
from ioc_hunter.core.types import IOCType

_BASE58_MAP: dict[int, int] = {
    c: i
    for i, c in enumerate(b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
}


def _btc_legacy_checksum_valid(s: str) -> bool:
    """Return True iff s is a structurally valid Base58Check legacy BTC address.

    Decodes to exactly 25 bytes and verifies that the final 4 bytes equal
    the first 4 bytes of SHA256(SHA256(payload)).
    """
    try:
        n = 0
        for byte in s.encode():
            n = n * 58 + _BASE58_MAP[byte]
        raw = n.to_bytes(25, "big")
    except (KeyError, OverflowError):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_BTC_LEGACY_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
_BTC_BECH32_RE = re.compile(r"^bc1[a-z0-9]{39,59}$")
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,63}$")
_URL_RE = re.compile(r"^(?:https?|ftps?)://\S+$", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def detect_type(value: str) -> IOCType | None:
    """Return the IOC type for a single string, or `None` if no match.

    Ordering is by specificity: hashes and CVEs are unambiguous and tested
    first; IP detection falls through to `ipaddress` so we get full IPv4/IPv6
    semantics; domain is the most permissive and goes last.
    """
    if not value:
        return None
    s = value.strip()
    if not s:
        return None

    if _SHA256_RE.match(s):
        return IOCType.SHA256
    if _SHA1_RE.match(s):
        return IOCType.SHA1
    if _MD5_RE.match(s):
        return IOCType.MD5

    if _CVE_RE.match(s):
        return IOCType.CVE

    if _BTC_BECH32_RE.match(s.lower()) and s.lower().startswith("bc1"):
        return IOCType.BTC_ADDRESS
    if _BTC_LEGACY_RE.match(s) and _btc_legacy_checksum_valid(s):
        return IOCType.BTC_ADDRESS

    if _URL_RE.match(s):
        return IOCType.URL

    if _EMAIL_RE.match(s):
        return IOCType.EMAIL

    try:
        ip = ipaddress.ip_address(s)
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    if _DOMAIN_RE.match(s) and s.rsplit(".", 1)[-1].lower() in IANA_TLDS:
        return IOCType.DOMAIN

    return None

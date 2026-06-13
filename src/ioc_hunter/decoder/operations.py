"""Individual decoding operations — each one is a `str -> str` function.

All decoders share the same contract: input is the (possibly stripped) text,
output is the decoded text. On failure they raise `DecodeError` so the magic
runner can skip them cleanly.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import html
import json
import re
import urllib.parse
import zlib
from collections.abc import Callable


class DecodeError(ValueError):
    """Raised when a decoder cannot handle its input."""


def _bytes_to_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def base64_decode(text: str) -> str:
    """Decode standard or urlsafe base64. Padding is fixed up automatically."""
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned:
        raise DecodeError("empty input")
    # Normalize urlsafe alphabet so we can use strict validation.
    normalized = cleaned.replace("-", "+").replace("_", "/")
    padding = (-len(normalized)) % 4
    normalized += "=" * padding
    try:
        return _bytes_to_text(base64.b64decode(normalized, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"not valid base64: {exc}") from exc


def base32_decode(text: str) -> str:
    cleaned = re.sub(r"\s+", "", text).upper()
    padding = (-len(cleaned)) % 8
    cleaned += "=" * padding
    try:
        return _bytes_to_text(base64.b32decode(cleaned))
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"not valid base32: {exc}") from exc


def hex_decode(text: str) -> str:
    cleaned = re.sub(r"[\s:-]+", "", text)
    if not cleaned or len(cleaned) % 2 != 0:
        raise DecodeError("hex input must have an even number of characters")
    try:
        return _bytes_to_text(bytes.fromhex(cleaned))
    except ValueError as exc:
        raise DecodeError(f"not valid hex: {exc}") from exc


def url_decode(text: str) -> str:
    if "%" not in text and "+" not in text:
        raise DecodeError("no percent-encoded characters")
    return urllib.parse.unquote_plus(text)


def html_decode(text: str) -> str:
    if "&" not in text:
        raise DecodeError("no HTML entities")
    decoded = html.unescape(text)
    if decoded == text:
        raise DecodeError("input contains no decodable HTML entities")
    return decoded


def rot13(text: str) -> str:
    if not any(c.isalpha() for c in text):
        raise DecodeError("no letters to rotate")
    return codecs.encode(text, "rot_13")


def gzip_decode(text: str) -> str:
    raw = _coerce_bytes(text)
    try:
        return _bytes_to_text(gzip.decompress(raw))
    except (OSError, EOFError) as exc:
        raise DecodeError(f"not valid gzip: {exc}") from exc


def zlib_decode(text: str) -> str:
    raw = _coerce_bytes(text)
    try:
        return _bytes_to_text(zlib.decompress(raw))
    except zlib.error as exc:
        raise DecodeError(f"not valid zlib: {exc}") from exc


def jwt_decode(text: str) -> str:
    """Decode a JWT into a `{header, payload}` JSON document.

    Signature verification is intentionally out of scope — this is a triage
    helper, not an auth library.
    """
    parts = text.strip().split(".")
    if len(parts) != 3:
        raise DecodeError("JWT must have three parts separated by '.'")
    try:
        header = json.loads(base64_decode(parts[0]))
        payload = json.loads(base64_decode(parts[1]))
    except (DecodeError, json.JSONDecodeError) as exc:
        raise DecodeError(f"not a valid JWT: {exc}") from exc
    return json.dumps({"header": header, "payload": payload}, indent=2)


def _coerce_bytes(text: str) -> bytes:
    """Best-effort: accept hex, base64, or raw latin-1 bytes wrapped in str."""
    candidate = text.strip()
    # Try base64 first (most common for gz/zlib blobs in logs).
    try:
        padding = (-len(candidate)) % 4
        return base64.urlsafe_b64decode(candidate + "=" * padding)
    except (binascii.Error, ValueError):
        pass
    try:
        return bytes.fromhex(re.sub(r"\s+", "", candidate))
    except ValueError:
        pass
    return candidate.encode("latin-1", errors="replace")


OPERATIONS: dict[str, Callable[[str], str]] = {
    "base64": base64_decode,
    "base32": base32_decode,
    "hex": hex_decode,
    "url": url_decode,
    "html": html_decode,
    "rot13": rot13,
    "gzip": gzip_decode,
    "zlib": zlib_decode,
    "jwt": jwt_decode,
}


def decode(operation: str, text: str) -> str:
    """Run a single named operation."""
    op = OPERATIONS.get(operation)
    if op is None:
        valid = ", ".join(sorted(OPERATIONS))
        raise DecodeError(f"unknown operation {operation!r}; valid: {valid}")
    return op(text)

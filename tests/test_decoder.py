"""Tests for the decoding operations and magic runner."""

from __future__ import annotations

import base64
import gzip
import json

import pytest

from ioc_hunter.decoder import (
    DecodeError,
    base64_decode,
    decode,
    gzip_decode,
    hex_decode,
    html_decode,
    jwt_decode,
    magic,
    rot13,
    url_decode,
    zlib_decode,
)

# --- single ops --------------------------------------------------------------


def test_base64_roundtrip() -> None:
    encoded = base64.b64encode(b"https://evil.com").decode()
    assert base64_decode(encoded) == "https://evil.com"


def test_base64_urlsafe_variant() -> None:
    encoded = base64.urlsafe_b64encode(b"https://evil.com/x?y=1").decode()
    assert "https://evil.com" in base64_decode(encoded)


def test_base64_handles_missing_padding() -> None:
    encoded = base64.b64encode(b"hi").decode().rstrip("=")
    assert base64_decode(encoded) == "hi"


def test_base64_rejects_garbage() -> None:
    with pytest.raises(DecodeError):
        base64_decode("@@@@@@")


def test_hex_decode() -> None:
    encoded = "68747470733a2f2f6576696c2e636f6d"
    assert hex_decode(encoded) == "https://evil.com"


def test_hex_tolerates_separators() -> None:
    assert hex_decode("68:74:74:70:73") == "https"


def test_hex_rejects_odd_length() -> None:
    with pytest.raises(DecodeError):
        hex_decode("abc")


def test_url_decode() -> None:
    assert url_decode("https%3A%2F%2Fevil.com") == "https://evil.com"


def test_url_no_op_raises() -> None:
    with pytest.raises(DecodeError):
        url_decode("plain text")


def test_html_decode() -> None:
    assert html_decode("&lt;script&gt;") == "<script>"


def test_html_no_op_raises() -> None:
    with pytest.raises(DecodeError):
        html_decode("plain text")


def test_rot13() -> None:
    assert rot13("Uryyb") == "Hello"
    assert rot13(rot13("hello world")) == "hello world"


def test_gzip_decode() -> None:
    compressed = gzip.compress(b"https://evil.com")
    encoded = base64.b64encode(compressed).decode()
    assert "https://evil.com" in gzip_decode(encoded)


def test_zlib_decode() -> None:
    import zlib

    compressed = zlib.compress(b"https://evil.com")
    encoded = base64.b64encode(compressed).decode()
    assert "https://evil.com" in zlib_decode(encoded)


def test_jwt_decode() -> None:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user@evil.com", "exp": 1700000000}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    token = f"{h}.{p}.fake-signature"
    decoded = json.loads(jwt_decode(token))
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "user@evil.com"


def test_jwt_rejects_bad_input() -> None:
    with pytest.raises(DecodeError):
        jwt_decode("not.a.jwt")


def test_decode_dispatcher() -> None:
    encoded = base64.b64encode(b"hi").decode()
    assert decode("base64", encoded) == "hi"


def test_decode_unknown_op() -> None:
    with pytest.raises(DecodeError, match="unknown operation"):
        decode("rot47", "x")


# --- magic -------------------------------------------------------------------


def test_magic_picks_base64_for_b64_input() -> None:
    encoded = base64.b64encode(b"https://evil.com/login.php").decode()
    candidates = magic(encoded)
    assert candidates
    assert candidates[0].operation == "base64"
    assert "evil.com" in candidates[0].decoded


def test_magic_picks_hex_for_hex_input() -> None:
    encoded = "68747470733a2f2f6576696c2e636f6d"
    candidates = magic(encoded)
    assert candidates
    top = candidates[0]
    assert top.operation == "hex"


def test_magic_url_decoded_extracts_ioc() -> None:
    encoded = "https%3A%2F%2Fevil.com%2Flogin"
    candidates = magic(encoded)
    # url should win because it's the only one producing IOC-rich output.
    top_ops = [c.operation for c in candidates]
    assert "url" in top_ops


def test_magic_does_not_crash_on_natural_language() -> None:
    # Natural prose contains chars valid in many alphabets — make sure we
    # don't crash and don't return obviously broken records.
    candidates = magic("the quick brown fox jumps over the lazy dog")
    for c in candidates:
        assert 0.0 <= c.score <= 1.0
        assert c.operation in {
            "base64",
            "base32",
            "hex",
            "rot13",
            "html",
            "url",
            "gzip",
            "zlib",
            "jwt",
        }


def test_magic_ioc_bonus_in_score() -> None:
    encoded_with_ioc = base64.b64encode(b"contact bad@evil.com").decode()
    encoded_plain = base64.b64encode(b"hello world here").decode()
    ioc_results = magic(encoded_with_ioc)
    plain_results = magic(encoded_plain)
    # Ioc-bearing decoded text should score higher.
    assert ioc_results[0].score > plain_results[0].score

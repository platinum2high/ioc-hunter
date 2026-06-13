"""CyberChef-style decoders for SOC triage.

`decode()` runs a single named operation. `magic()` tries every operation
and returns the candidates ranked by printability, so an analyst pasting
in a chunk of base64/hex/etc gets the answer immediately.
"""

from ioc_hunter.decoder.magic import MagicResult, magic
from ioc_hunter.decoder.operations import (
    OPERATIONS,
    DecodeError,
    base32_decode,
    base64_decode,
    decode,
    gzip_decode,
    hex_decode,
    html_decode,
    jwt_decode,
    rot13,
    url_decode,
    zlib_decode,
)

__all__ = [
    "OPERATIONS",
    "DecodeError",
    "MagicResult",
    "base32_decode",
    "base64_decode",
    "decode",
    "gzip_decode",
    "hex_decode",
    "html_decode",
    "jwt_decode",
    "magic",
    "rot13",
    "url_decode",
    "zlib_decode",
]

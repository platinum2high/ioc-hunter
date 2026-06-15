"""Authenticode signer / issuer extraction.

The PE SECURITY data directory points at a ``WIN_CERTIFICATE`` whose
``bCertificate`` payload is a PKCS#7 ``SignedData`` ASN.1 structure
containing one or more X.509 certificates. SOC triage wants two
strings:

- ``signer_cn``  — Common Name of the leaf signer certificate
- ``issuer_cn``  — Common Name of the CA that issued the signer cert

We deliberately do **not** validate the signature — that requires the
full CA chain and timestamp verification, which is out of scope for a
static-only stdlib tool. We just want to surface "signed by Microsoft
Corporation" vs "signed by O=Foo Bar Cyber LLC", which is what
analysts actually look at first.

Implementation: a minimal DER walker (no external deps). We scan for
the ``commonName`` OID (``2.5.4.3``) encoded as ``\\x06\\x03\\x55\\x04\\x03``
and the immediately-following string TLV. The first occurrence inside
each X.509 certificate's ``subject`` and ``issuer`` ``Name`` sequences
is what we want.

Pure pattern-scanning works because:

- ``Name`` is the only place AttributeTypeAndValue(commonName, ...) is
  used in standard X.509;
- the OID encoding ``06 03 55 04 03`` is unambiguous in DER;
- after that, DER demands a STRING TLV (``UTF8String``=0x0C,
  ``PrintableString``=0x13, ``IA5String``=0x16, or ``BMPString``=0x1E),
  each of which we know how to extract.

To distinguish signer vs issuer we walk certificates in document order:
the first cert is typically the signer (Microsoft cert convention), and
within that cert the issuer ``Name`` appears before the subject ``Name``
per X.509 ``TBSCertificate`` ordering. So inside cert #0 the first CN is
the issuer and the second CN is the signer. We extract both.
"""

from __future__ import annotations

# OID 2.5.4.3 commonName in DER: 06 03 55 04 03
_OID_CN = b"\x06\x03\x55\x04\x03"
# String tag bytes we accept after the OID.
_STR_UTF8 = 0x0C
_STR_PRINTABLE = 0x13
_STR_IA5 = 0x16
_STR_BMP = 0x1E
_STR_TELETEX = 0x14


def _decode_string(tag: int, payload: bytes) -> str:
    if tag == _STR_BMP:
        # BMPString is big-endian UCS-2.
        try:
            return payload.decode("utf-16-be", errors="replace")
        except Exception:
            return ""
    try:
        return payload.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _scan_cn_pairs(blob: bytes, *, max_results: int = 32) -> list[str]:
    """Return CN strings in DER document order.

    The walk uses ``bytes.find`` for the OID sentinel which makes the
    scan effectively O(n). Each match consumes its TLV and we resume
    from the next byte after the value.
    """
    out: list[str] = []
    pos = 0
    n = len(blob)
    while pos < n and len(out) < max_results:
        found = blob.find(_OID_CN, pos)
        if found == -1:
            break
        # After the OID, DER demands a TLV for the value.
        i = found + len(_OID_CN)
        if i >= n:
            break
        tag = blob[i]
        if tag not in (_STR_UTF8, _STR_PRINTABLE, _STR_IA5, _STR_BMP, _STR_TELETEX):
            pos = found + 1
            continue
        if i + 1 >= n:
            break
        first_len = blob[i + 1]
        # DER length: short form (0..127) or long form (high bit set ⇒
        # the low 7 bits give the number of subsequent length bytes).
        if first_len < 0x80:
            length = first_len
            val_off = i + 2
        else:
            n_len = first_len & 0x7F
            if n_len == 0 or n_len > 4 or i + 2 + n_len > n:
                pos = found + 1
                continue
            length = 0
            for k in range(n_len):
                length = (length << 8) | blob[i + 2 + k]
            val_off = i + 2 + n_len
        if length > 256 or val_off + length > n:
            pos = found + 1
            continue
        payload = blob[val_off : val_off + length]
        decoded = _decode_string(tag, payload).strip()
        if decoded:
            out.append(decoded)
        pos = val_off + length
    return out


def extract_signer_names(pkcs7_blob: bytes) -> tuple[str, str]:
    """Best-effort ``(signer_cn, issuer_cn)`` extraction.

    The PKCS#7 ``SignedData`` carries a SEQUENCE of certificates. For
    Authenticode-signed PEs Microsoft's convention is that the first
    certificate is the signer leaf, with ``issuer`` preceding
    ``subject`` per X.509. So the first two CN matches in document
    order are ``(issuer, signer)``.

    Returns ``("", "")`` when nothing parseable was found.
    """
    if not pkcs7_blob:
        return "", ""
    cns = _scan_cn_pairs(pkcs7_blob, max_results=8)
    if not cns:
        return "", ""
    if len(cns) == 1:
        # One CN typically means the only field present is the subject.
        return cns[0], ""
    # X.509 TBSCertificate order: issuer, then subject. We want
    # (signer_cn, issuer_cn) → (subject, issuer) = (cns[1], cns[0]).
    return cns[1], cns[0]

"""Pure-Python synthesizers for libpcap classic and PCAPNG fixtures.

We construct captures from scratch byte-by-byte so the tests pin the
parser against the documented spec rather than against whatever a
helper library happens to emit. Every fixture is self-contained:
build one, hand the bytes to ``analyze``, assert what comes out.

Coverage notes:

- ``build_pcap`` and ``build_pcapng`` are the two container builders.
- Helpers below build properly framed Ethernet + IPv4/IPv6 + TCP/UDP/ICMP.
  Higher protocols (DNS / HTTP / TLS) are appended as the L4 payload.
- ``synth_tls_clienthello`` deliberately matches the JA3 spec byte-for-
  byte so the JA3 test can pin the resulting MD5 against a known value.
"""

from __future__ import annotations

import socket
import struct

# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 12
LINKTYPE_LINUX_SLL = 113

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_BOM = 0x1A2B3C4D


def build_pcap(
    frames: list[tuple[float, bytes]],
    *,
    link_type: int = LINKTYPE_ETHERNET,
    nanosecond: bool = False,
) -> bytes:
    """Wrap ``(ts_seconds, frame_bytes)`` records in a libpcap classic file."""
    magic = PCAP_MAGIC_NS if nanosecond else PCAP_MAGIC_US
    out = bytearray()
    out.extend(struct.pack("<I", magic))
    out.extend(struct.pack("<H", 2))  # ver major
    out.extend(struct.pack("<H", 4))  # ver minor
    out.extend(struct.pack("<i", 0))  # thiszone
    out.extend(struct.pack("<I", 0))  # sigfigs
    out.extend(struct.pack("<I", 65535))  # snaplen
    out.extend(struct.pack("<I", link_type))
    for ts, data in frames:
        sec = int(ts)
        frac = round((ts - sec) * (1_000_000_000 if nanosecond else 1_000_000))
        out.extend(struct.pack("<IIII", sec, frac, len(data), len(data)))
        out.extend(data)
    return bytes(out)


def build_pcapng(
    frames: list[tuple[float, bytes]],
    *,
    link_type: int = LINKTYPE_ETHERNET,
) -> bytes:
    """Wrap frames in a minimal-but-valid PCAPNG: SHB → IDB → EPBs."""
    out = bytearray()
    # SHB: type(4) total_len(4) BOM(4) major(2) minor(2) section_len(8)
    #      options(0) total_len(4)
    shb_body = struct.pack("<IHHQ", PCAPNG_BOM, 1, 0, 0xFFFFFFFFFFFFFFFF)
    shb_total = 8 + len(shb_body) + 4
    out.extend(struct.pack("<II", PCAPNG_SHB, shb_total))
    out.extend(shb_body)
    out.extend(struct.pack("<I", shb_total))
    # IDB: link_type(2) reserved(2) snaplen(4) options(0) total_len(4)
    idb_body = struct.pack("<HHI", link_type, 0, 65535)
    idb_total = 8 + len(idb_body) + 4
    out.extend(struct.pack("<II", PCAPNG_IDB, idb_total))
    out.extend(idb_body)
    out.extend(struct.pack("<I", idb_total))
    # EPBs
    for ts, data in frames:
        ts_us = int(ts * 1_000_000)
        ts_hi = (ts_us >> 32) & 0xFFFFFFFF
        ts_lo = ts_us & 0xFFFFFFFF
        # iface_id(4) ts_hi(4) ts_lo(4) cap_len(4) orig_len(4) data... pad opts total_len(4)
        body = struct.pack("<IIIII", 0, ts_hi, ts_lo, len(data), len(data)) + data
        pad = (-len(body)) % 4
        body += b"\x00" * pad
        total = 8 + len(body) + 4
        out.extend(struct.pack("<II", PCAPNG_EPB, total))
        out.extend(body)
        out.extend(struct.pack("<I", total))
    return bytes(out)


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------


def eth(src_mac: bytes, dst_mac: bytes, etype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, ttl: int = 64) -> bytes:
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total_len = 20 + len(payload)
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0,  # DSCP/ECN
        total_len,
        0,  # ident
        0,  # flags+frag
        ttl,
        proto,
        0,  # checksum — readers we built never validate it
        src_b,
        dst_b,
    )
    return hdr + payload


def ipv6(src: str, dst: str, next_hdr: int, payload: bytes) -> bytes:
    src_b = socket.inet_pton(socket.AF_INET6, src)
    dst_b = socket.inet_pton(socket.AF_INET6, dst)
    return struct.pack(">IHBB", 0x60000000, len(payload), next_hdr, 64) + src_b + dst_b + payload


def tcp(
    sport: int,
    dport: int,
    seq: int = 0,
    ack: int = 0,
    flags: int = 0x18,  # PSH+ACK
    payload: bytes = b"",
) -> bytes:
    """TCP segment with no options."""
    off_flags = (5 << 12) | (flags & 0x1FF)
    return (
        struct.pack(">HHIIH", sport, dport, seq, ack, off_flags)
        + struct.pack(">HHH", 65535, 0, 0)
        + payload
    )


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def icmp_echo(payload: bytes) -> bytes:
    return struct.pack(">BBHHH", 8, 0, 0, 0, 0) + payload


def eth_ipv4_tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    *,
    flags: int = 0x18,
    payload: bytes = b"",
    seq: int = 0,
    ack: int = 0,
    src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
    dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02",
) -> bytes:
    return eth(
        src_mac,
        dst_mac,
        0x0800,
        ipv4(src_ip, dst_ip, 6, tcp(sport, dport, seq, ack, flags, payload)),
    )


def eth_ipv4_udp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
    *,
    src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
    dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02",
) -> bytes:
    return eth(src_mac, dst_mac, 0x0800, ipv4(src_ip, dst_ip, 17, udp(sport, dport, payload)))


def eth_ipv4_icmp(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    return eth(
        b"\x02\x00\x00\x00\x00\x01",
        b"\x02\x00\x00\x00\x00\x02",
        0x0800,
        ipv4(src_ip, dst_ip, 1, icmp_echo(payload)),
    )


def eth_ipv6_tcp(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    *,
    flags: int = 0x18,
    payload: bytes = b"",
) -> bytes:
    return eth(
        b"\x02\x00\x00\x00\x00\x01",
        b"\x02\x00\x00\x00\x00\x02",
        0x86DD,
        ipv6(src_ip, dst_ip, 6, tcp(sport, dport, 0, 0, flags, payload)),
    )


# ---------------------------------------------------------------------------
# DNS / HTTP / TLS payload synth
# ---------------------------------------------------------------------------


def dns_query(name: str, qtype: int = 1, *, tx_id: int = 0x1234) -> bytes:
    qname = (
        b"".join(struct.pack(">B", len(label)) + label.encode("ascii") for label in name.split("."))
        + b"\x00"
    )
    header = struct.pack(">HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", qtype, 1)


def dns_response(
    name: str,
    qtype: int = 1,
    rcode: int = 0,
    *,
    tx_id: int = 0x1234,
    answer_count: int = 1,
    txt_value: bytes | None = None,
) -> bytes:
    qname = (
        b"".join(struct.pack(">B", len(label)) + label.encode("ascii") for label in name.split("."))
        + b"\x00"
    )
    flags = 0x8180 | (rcode & 0xF)
    header = struct.pack(">HHHHHH", tx_id, flags, 1, answer_count, 0, 0)
    body = qname + struct.pack(">HH", qtype, 1)
    if answer_count and txt_value is not None and qtype == 16:
        # TXT answer with pointer to question name
        rdata = struct.pack(">B", len(txt_value)) + txt_value
        body += struct.pack(">HHHIH", 0xC00C, 16, 1, 60, len(rdata)) + rdata
    elif answer_count:
        # A record with 1.2.3.4
        body += struct.pack(">HHHIH4s", 0xC00C, qtype, 1, 60, 4, b"\x01\x02\x03\x04")
    return header + body


def http_request(
    method: str,
    host: str,
    uri: str,
    *,
    user_agent: str = "Mozilla/5.0",
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> bytes:
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}", f"User-Agent: {user_agent}"]
    for k, v in extra_headers:
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")
    return ("\r\n".join(lines)).encode("ascii")


def http_response(status: int = 200, body: bytes = b"") -> bytes:
    head = (
        f"HTTP/1.1 {status} OK\r\nServer: test/0\r\n"
        f"Content-Length: {len(body)}\r\nContent-Type: text/plain\r\n\r\n"
    ).encode("ascii")
    return head + body


def synth_tls_clienthello(
    sni: str = "",
    *,
    version: int = 0x0303,
    ciphers: tuple[int, ...] = (0xC02B, 0xC02F, 0x009E),
    extensions_order: tuple[int, ...] = (0x0000, 0x000A, 0x000B, 0x0010),
    curves: tuple[int, ...] = (0x001D, 0x0017),
    ec_pt_fmts: tuple[int, ...] = (0,),
    alpn: tuple[bytes, ...] = (b"h2", b"http/1.1"),
) -> bytes:
    """Build a TLS record carrying one ClientHello with the given parameters.

    The default tuple yields a small, deterministic JA3 string we can
    pin in tests.
    """
    cipher_blob = b"".join(struct.pack(">H", c) for c in ciphers)
    comp_methods = b"\x01\x00"  # length 1, "null"

    extensions: bytearray = bytearray()
    for et in extensions_order:
        if et == 0x0000 and sni:
            name = sni.encode("ascii")
            entry = struct.pack(">BH", 0, len(name)) + name
            ext_data = struct.pack(">H", len(entry)) + entry
        elif et == 0x000A:
            curves_blob = b"".join(struct.pack(">H", c) for c in curves)
            ext_data = struct.pack(">H", len(curves_blob)) + curves_blob
        elif et == 0x000B:
            pts_blob = bytes(ec_pt_fmts)
            ext_data = struct.pack(">B", len(pts_blob)) + pts_blob
        elif et == 0x0010:
            alpn_blob = b"".join(struct.pack(">B", len(p)) + p for p in alpn)
            ext_data = struct.pack(">H", len(alpn_blob)) + alpn_blob
        else:
            ext_data = b""
        extensions.extend(struct.pack(">HH", et, len(ext_data)) + ext_data)
    ext_total = struct.pack(">H", len(extensions)) + bytes(extensions)

    body = (
        struct.pack(">H", version)
        + b"\x00" * 32  # client_random
        + b"\x00"  # session_id len
        + struct.pack(">H", len(cipher_blob))
        + cipher_blob
        + comp_methods
        + ext_total
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body  # handshake type 0x01 + 3-byte length
    record = b"\x16" + struct.pack(">H", 0x0301) + struct.pack(">H", len(hs)) + hs
    return record


def synth_tls_serverhello(
    *,
    version: int = 0x0303,
    cipher: int = 0xC02F,
    extensions_order: tuple[int, ...] = (0x0000, 0x000B, 0xFF01),
) -> bytes:
    """Build a TLS record carrying one ServerHello with the given parameters.

    The server selects a single cipher (unlike the client's list), so JA3S
    keys on (version, cipher, extension-list). Extension bodies are empty —
    JA3S only fingerprints the extension *types*, in order.
    """
    extensions = bytearray()
    for et in extensions_order:
        extensions.extend(struct.pack(">HH", et, 0))  # type + zero-length body
    ext_total = struct.pack(">H", len(extensions)) + bytes(extensions)
    body = (
        struct.pack(">H", version)
        + b"\x11" * 32  # server_random
        + b"\x00"  # session_id len
        + struct.pack(">H", cipher)
        + b"\x00"  # compression method (single byte)
        + ext_total
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body  # handshake type 0x02 ServerHello
    return b"\x16" + struct.pack(">H", 0x0303) + struct.pack(">H", len(hs)) + hs


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------


def smb2_header(command: int, *, flags: int = 0, message_id: int = 0) -> bytes:
    """A 64-byte SMB2 sync header (MS-SMB2 §2.2.1.2)."""
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)  # structure size
        + struct.pack("<H", 0)  # credit charge
        + struct.pack("<I", 0)  # status / channel sequence
        + struct.pack("<H", command)
        + struct.pack("<H", 1)  # credits
        + struct.pack("<I", flags)
        + struct.pack("<I", 0)  # next command
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0)  # reserved
        + struct.pack("<I", 0)  # tree id
        + struct.pack("<Q", 0)  # session id
        + b"\x00" * 16  # signature
    )


def smb2_tree_connect(path: str) -> bytes:
    """SMB2 TREE_CONNECT request with a UNC ``path`` (e.g. ``\\\\host\\ADMIN$``)."""
    hdr = smb2_header(3)
    path_b = path.encode("utf-16-le")
    # struct_size(2)=9 flags(2) path_offset(2)=72 path_length(2) buffer
    body = struct.pack("<HHHH", 9, 0, 72, len(path_b)) + path_b
    return hdr + body


def smb2_session_setup(blob: bytes) -> bytes:
    """SMB2 SESSION_SETUP carrying a security ``blob`` (e.g. an NTLM message)."""
    hdr = smb2_header(1)
    body = struct.pack("<HBBIIHHQ", 25, 0, 0, 0, 0, 88, len(blob), 0) + blob
    return hdr + body


def smb1_negotiate() -> bytes:
    """A bare SMB1 packet (``\\xffSMB`` + command byte)."""
    return b"\xffSMB" + bytes([0x72]) + b"\x00" * 27  # 0x72 = SMB_COM_NEGOTIATE


def nbss_wrap(smb: bytes) -> bytes:
    """Prepend a NetBIOS Session Service header (used on TCP/139)."""
    length = len(smb)
    return bytes([0x00, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]) + smb


# ---------------------------------------------------------------------------
# NTLMSSP
# ---------------------------------------------------------------------------

_NTLM_UNICODE = 0x00000001


def ntlm_challenge(server_challenge: bytes = b"\x11" * 8, target: str = "CORP") -> bytes:
    """A type-2 NTLMSSP CHALLENGE message carrying ``server_challenge``."""
    target_b = target.encode("utf-16-le")
    payload_off = 56
    fixed = (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)  # type
        + struct.pack("<HHI", len(target_b), len(target_b), payload_off)  # TargetName fields
        + struct.pack("<I", _NTLM_UNICODE)  # flags
        + server_challenge  # 8 bytes
        + b"\x00" * 8  # reserved
        + b"\x00" * 8  # TargetInfo fields (empty)
        + b"\x00" * 8  # version
    )
    assert len(fixed) == payload_off
    return fixed + target_b


def ntlm_authenticate(
    domain: str = "CORP",
    user: str = "jdoe",
    workstation: str = "WS01",
    nt_response: bytes = b"\xaa" * 16 + b"\xbb" * 20,
) -> bytes:
    """A type-3 NTLMSSP AUTHENTICATE message (NTLMv2 NT response)."""
    dom_b = domain.encode("utf-16-le")
    usr_b = user.encode("utf-16-le")
    ws_b = workstation.encode("utf-16-le")
    payload_off = 72
    dom_off = payload_off
    usr_off = dom_off + len(dom_b)
    ws_off = usr_off + len(usr_b)
    nt_off = ws_off + len(ws_b)

    def field(length: int, offset: int) -> bytes:
        return struct.pack("<HHI", length, length, offset)

    fixed = (
        b"NTLMSSP\x00"
        + struct.pack("<I", 3)  # type
        + field(0, payload_off)  # LM response (empty)
        + field(len(nt_response), nt_off)  # NT response
        + field(len(dom_b), dom_off)  # domain
        + field(len(usr_b), usr_off)  # user
        + field(len(ws_b), ws_off)  # workstation
        + field(0, payload_off)  # session key (empty)
        + struct.pack("<I", _NTLM_UNICODE)  # flags
        + b"\x00" * 8  # version
    )
    assert len(fixed) == payload_off
    return fixed + dom_b + usr_b + ws_b + nt_response


# ---------------------------------------------------------------------------
# Kerberos — a tiny DER encoder, just enough to exercise the walker.
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def der_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def der_int(value: int) -> bytes:
    if value == 0:
        return der_tlv(0x02, b"\x00")
    out = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return der_tlv(0x02, out)


def der_genstr(s: str) -> bytes:
    return der_tlv(0x1B, s.encode("ascii"))


def der_octet(b: bytes) -> bytes:
    return der_tlv(0x04, b)


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_ctx(num: int, content: bytes) -> bytes:
    return der_tlv(0xA0 | num, content)  # context, constructed


def der_app(num: int, content: bytes) -> bytes:
    return der_tlv(0x60 | num, content)  # application, constructed


def krb_principal(name_type: int, parts: tuple[str, ...]) -> bytes:
    name_strings = der_seq(*[der_genstr(p) for p in parts])
    return der_seq(der_ctx(0, der_int(name_type)), der_ctx(1, name_strings))


def krb_as_req(
    realm: str = "CORP.LOCAL",
    cname: tuple[str, ...] = ("jdoe",),
    sname: tuple[str, ...] = ("krbtgt", "CORP.LOCAL"),
    etypes: tuple[int, ...] = (18, 17, 23),
    with_preauth: bool = False,
) -> bytes:
    body = der_seq(
        der_ctx(0, der_tlv(0x03, b"\x00\x00\x00\x00\x00")),  # kdc-options BIT STRING
        der_ctx(1, krb_principal(1, cname)),
        der_ctx(2, der_genstr(realm)),
        der_ctx(3, krb_principal(2, sname)),
        der_ctx(8, der_seq(*[der_int(e) for e in etypes])),
    )
    seq_items = [der_ctx(1, der_int(5)), der_ctx(2, der_int(10))]
    if with_preauth:
        padata = der_seq(der_seq(der_ctx(1, der_int(2)), der_ctx(2, der_octet(b"x"))))
        seq_items.append(der_ctx(3, padata))
    seq_items.append(der_ctx(4, body))
    return der_app(10, der_seq(*seq_items))


def krb_tgs_rep(
    realm: str = "CORP.LOCAL",
    cname: tuple[str, ...] = ("jdoe",),
    sname: tuple[str, ...] = ("MSSQLSvc", "db01.corp.local"),
    ticket_etype: int = 23,
) -> bytes:
    ticket_enc = der_seq(der_ctx(0, der_int(ticket_etype)), der_ctx(2, der_octet(b"\x00" * 16)))
    ticket_seq = der_seq(
        der_ctx(0, der_int(5)),
        der_ctx(1, der_genstr(realm)),
        der_ctx(2, krb_principal(2, sname)),
        der_ctx(3, ticket_enc),
    )
    rep_enc = der_seq(der_ctx(0, der_int(18)), der_ctx(2, der_octet(b"\x00")))
    seq = der_seq(
        der_ctx(0, der_int(5)),
        der_ctx(1, der_int(13)),
        der_ctx(3, der_genstr(realm)),
        der_ctx(4, krb_principal(1, cname)),
        der_ctx(5, der_app(1, ticket_seq)),
        der_ctx(6, rep_enc),
    )
    return der_app(13, seq)


def krb_tcp(msg: bytes) -> bytes:
    """Prepend the 4-byte big-endian length prefix Kerberos-over-TCP uses."""
    return struct.pack(">I", len(msg)) + msg

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

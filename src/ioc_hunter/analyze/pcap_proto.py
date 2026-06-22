"""Application-layer protocol dissectors for the PCAP analyzer.

Three protocols matter for SOC triage above L4 and they're handled here:

- **DNS** — UDP/53 and TCP/53 (length-prefixed). Queries, response code,
  and record types. We keep a per-name aggregation so DNS heuristics
  (NXDOMAIN ratio, TXT volume, DGA shape) can run against it without a
  second pass.

- **HTTP** — TCP/80 (and any other port where the payload looks like an
  HTTP/1.x request or response). Request line + headers only — no body
  reassembly — which is what an analyst needs: Host / User-Agent / URL /
  Method / Status. We also flag plaintext HTTP Basic-auth headers because
  they're a free credential leak that SOC analysts grade hard.

- **TLS** — ClientHello extraction (SNI, version, cipher list, ext list,
  EC curves, EC point formats) and the **JA3** fingerprint, plus the
  **ServerHello** → **JA3S** server fingerprint. JA3/JA3S are the
  industry-standard fingerprints and are what separate a "screenshot
  pcap parser" from a tool a tier-3 analyst will actually use; pairing a
  flow's JA3 with its JA3S fingerprints the server implementation.

Everything in this module operates on the ``Packet`` records yielded by
``pcap_parse.iter_packets``. We don't do full TCP stream reassembly —
that's a 100-line project on its own and rarely necessary for the parts
of these protocols that fit in the first segment. Instead we look at
each packet's payload and, for HTTP/TLS, opportunistically stitch the
**first** TCP segment per direction per flow when the parse needs more
bytes than one segment carries. That covers the vast majority of real
captures while keeping memory bounded.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import struct
from dataclasses import dataclass, field

from ioc_hunter.analyze.pcap_parse import (
    TCP_SYN,
    IPProto,
    Packet,
)

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

#: Cap on stitched-payload bytes per flow per direction. Real ClientHellos
#: live in <2 KB; HTTP request/response head fits well under 8 KB. We give
#: a generous 16 KB before truncating.
_STITCH_CAP = 16 * 1024

#: Cap on the number of distinct DNS names tracked. Above this we stop
#: aggregating (still parse messages so per-message heuristics keep
#: working).
MAX_DNS_NAMES = 10_000

#: Cap on stored HTTP requests / responses.
MAX_HTTP_TXNS = 5_000

#: Cap on stored TLS ClientHellos.
MAX_TLS_CLIENTHELLOS = 5_000


# ---------------------------------------------------------------------------
# Dataclasses surfacing dissected protocol records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DNSMessage:
    ts: float
    frame_no: int
    src_ip: str
    dst_ip: str
    qname: str  # lowercased, dot-joined
    qtype: int  # IANA RR type (1=A, 28=AAAA, 16=TXT, 5=CNAME, 15=MX, ...)
    is_response: bool
    rcode: int  # 0=NOERROR, 3=NXDOMAIN, 5=REFUSED, ...
    answer_count: int


@dataclass(slots=True)
class DNSStats:
    """Aggregate view across all DNS messages in the capture."""

    queries: int = 0
    responses: int = 0
    nxdomain: int = 0
    txt_query_bytes: int = 0  # total payload bytes in TXT-record responses
    qtype_counts: dict[int, int] = field(default_factory=dict)
    per_name: dict[str, dict[str, int]] = field(default_factory=dict)
    # ``per_name[qname] = {"q": queries, "nx": nx_count, "txt": txt_bytes}``


@dataclass(frozen=True, slots=True)
class HTTPRequest:
    ts: float
    frame_no: int
    src_ip: str
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    host: str
    user_agent: str
    headers: tuple[tuple[str, str], ...]
    has_basic_auth: bool


@dataclass(frozen=True, slots=True)
class HTTPResponse:
    ts: float
    frame_no: int
    src_ip: str
    dst_ip: str
    src_port: int
    status: int
    reason: str
    server: str
    content_type: str
    content_length: int


@dataclass(frozen=True, slots=True)
class TLSClientHello:
    ts: float
    frame_no: int
    src_ip: str
    dst_ip: str
    dst_port: int
    tls_version: int  # advertised legacy_version on the record (e.g. 0x0303)
    sni: str  # "" if no SNI extension
    alpn: tuple[str, ...]  # ("h2", "http/1.1", ...) or ()
    ja3_string: str
    ja3_md5: str


@dataclass(frozen=True, slots=True)
class TLSServerHello:
    ts: float
    frame_no: int
    src_ip: str  # the server (this record flows server → client)
    dst_ip: str
    src_port: int
    tls_version: int
    cipher: int  # the single cipher the server selected
    ja3s_string: str
    ja3s_md5: str


# ---------------------------------------------------------------------------
# Stream stitcher — tiny, per-flow, per-direction
# ---------------------------------------------------------------------------


class _Stitcher:
    """Accumulate first-segment-or-so TCP payloads per flow direction.

    Real captures: ClientHellos cross a single segment maybe 1% of the
    time; HTTP request headers basically never. Rather than do full TCP
    reassembly with seq tracking, we just concatenate payloads in
    capture order per (5-tuple + direction) until the upper-layer parser
    returns "done" or we hit the cap. That's enough for headers + first
    few hundred bytes of body — the parts SOC analysts read.
    """

    __slots__ = ("buffers",)

    def __init__(self) -> None:
        # key = (src_ip, src_port, dst_ip, dst_port)
        self.buffers: dict[tuple[str, int, str, int], bytearray] = {}

    def feed(self, pkt: Packet) -> bytes:
        key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        if pkt.tcp_flags & TCP_SYN and not pkt.payload:
            self.buffers.pop(key, None)
            return b""
        buf = self.buffers.get(key)
        if buf is None:
            buf = bytearray()
            self.buffers[key] = buf
        if len(buf) < _STITCH_CAP:
            buf.extend(pkt.payload[: _STITCH_CAP - len(buf)])
        return bytes(buf)

    def drop(self, pkt: Packet) -> None:
        self.buffers.pop((pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port), None)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


# DNS header: id(2) flags(2) qd(2) an(2) ns(2) ar(2) = 12 bytes.
# Flags bit layout (big-endian network order):
#   QR(1) Opcode(4) AA(1) TC(1) RD(1) | RA(1) Z(3) RCODE(4)


def parse_dns_message(payload: bytes) -> DNSMessage | None:
    """Parse one DNS message body into a ``DNSMessage`` or return ``None``.

    Only the first question is decoded — virtually every real query has
    exactly one. We don't materialise the answer records; the counts and
    rcode are enough for the heuristics we run.

    Defensive: compressed-name loops, malformed labels, and truncated
    questions all return ``None`` rather than crash.
    """
    if len(payload) < 12:
        return None
    try:
        _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", payload[:12])
    except struct.error:
        return None
    if qd < 1:
        return None
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    qname, after = _decode_qname(payload, 12)
    if qname is None or after + 4 > len(payload):
        return None
    try:
        qtype, _qclass = struct.unpack(">HH", payload[after : after + 4])
    except struct.error:
        return None
    return DNSMessage(
        ts=0.0,  # filled in by the caller
        frame_no=0,
        src_ip="",
        dst_ip="",
        qname=qname,
        qtype=qtype,
        is_response=is_response,
        rcode=rcode,
        answer_count=an,
    )


def _decode_qname(payload: bytes, off: int) -> tuple[str | None, int]:
    """Decode a DNS QNAME starting at ``off``. Returns (name, offset-after).

    Handles label compression pointers but caps total label hops + total
    decoded-length so a malformed name can't spin or balloon RAM.
    """
    labels: list[str] = []
    cur = off
    jumped = False
    after_off = off
    hops = 0
    while True:
        if cur >= len(payload):
            return (None, off)
        ln = payload[cur]
        if ln == 0:
            cur += 1
            if not jumped:
                after_off = cur
            break
        if (ln & 0xC0) == 0xC0:
            if cur + 1 >= len(payload):
                return (None, off)
            ptr = ((ln & 0x3F) << 8) | payload[cur + 1]
            if not jumped:
                after_off = cur + 2
                jumped = True
            cur = ptr
            hops += 1
            if hops > 16:
                return (None, off)
            continue
        if (ln & 0xC0) != 0:
            return (None, off)  # reserved
        if cur + 1 + ln > len(payload):
            return (None, off)
        try:
            labels.append(payload[cur + 1 : cur + 1 + ln].decode("ascii"))
        except UnicodeDecodeError:
            return (None, off)
        cur += 1 + ln
        if sum(len(label) + 1 for label in labels) > 255:
            return (None, off)
    name = ".".join(labels).lower()
    return (name, after_off)


def is_dns_packet(pkt: Packet) -> bool:
    """Heuristic: UDP/53 either direction, or first TCP/53 segment."""
    return pkt.proto in (IPProto.UDP, IPProto.TCP) and (pkt.src_port == 53 or pkt.dst_port == 53)


def dissect_dns(pkt: Packet, stats: DNSStats) -> DNSMessage | None:
    """If ``pkt`` is a DNS message, parse it and update aggregate stats."""
    if not is_dns_packet(pkt) or not pkt.payload:
        return None
    # TCP/53 prefixes the message with a 2-byte length. Strip it.
    body = pkt.payload
    if pkt.proto == IPProto.TCP and len(body) >= 2:
        msg_len = (body[0] << 8) | body[1]
        if 12 <= msg_len <= len(body) - 2:
            body = body[2 : 2 + msg_len]
    msg = parse_dns_message(body)
    if msg is None:
        return None
    msg = DNSMessage(
        ts=pkt.ts,
        frame_no=pkt.frame_no,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        qname=msg.qname,
        qtype=msg.qtype,
        is_response=msg.is_response,
        rcode=msg.rcode,
        answer_count=msg.answer_count,
    )
    if msg.is_response:
        stats.responses += 1
        if msg.rcode == 3:
            stats.nxdomain += 1
        if msg.qtype == 16:  # TXT
            stats.txt_query_bytes += len(body)
    else:
        stats.queries += 1
    stats.qtype_counts[msg.qtype] = stats.qtype_counts.get(msg.qtype, 0) + 1
    if msg.qname and len(stats.per_name) < MAX_DNS_NAMES:
        slot = stats.per_name.setdefault(msg.qname, {"q": 0, "nx": 0, "txt": 0})
        if not msg.is_response:
            slot["q"] += 1
        elif msg.rcode == 3:
            slot["nx"] += 1
        if msg.qtype == 16:
            slot["txt"] += len(body)
    return msg


# ---------------------------------------------------------------------------
# HTTP plaintext
# ---------------------------------------------------------------------------


_HTTP_METHODS = (
    b"GET",
    b"POST",
    b"PUT",
    b"DELETE",
    b"HEAD",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
    b"PROPFIND",
    b"MKCOL",
    b"COPY",
    b"MOVE",
)

#: User-agent strings that real malware families have been observed
#: hard-coding. Each pattern is a substring match — we keep them tight
#: (literal byte strings or short regex anchors) to avoid false positives.
_BAD_UA_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Emotet (custom Mozilla string)", re.compile(r"^Mozilla/4\.0$")),
    ("Sliver default", re.compile(r"^Sliver/|grpc-go/")),
    ("PowerShell client", re.compile(r"Mozilla/5\.0 \(Windows NT.*WindowsPowerShell")),
    ("BITSAdmin (LOLBin download)", re.compile(r"^Microsoft BITS/")),
    ("WinHTTP raw", re.compile(r"^Mozilla/4\.0 \(compatible; MSIE.*Windows NT")),
    ("curl (uncommon in user traffic)", re.compile(r"^curl/")),
    ("Python urllib", re.compile(r"^Python-urllib/")),
    ("Empty UA", re.compile(r"^$")),
)


def _looks_like_http_request(head: bytes) -> bool:
    sp = head.find(b" ")
    if sp <= 0 or sp > 16:
        return False
    return head[:sp] in _HTTP_METHODS


def _looks_like_http_response(head: bytes) -> bool:
    return head.startswith(b"HTTP/1.")


def _parse_http_head(buf: bytes) -> tuple[list[str], int] | None:
    """Split ``buf`` at CRLF CRLF (or LF LF) and return (lines, body_off)."""
    end = buf.find(b"\r\n\r\n")
    sep = 4
    if end < 0:
        end = buf.find(b"\n\n")
        sep = 2
    if end < 0:
        return None
    head = buf[:end].decode("latin-1", errors="replace")
    return (head.splitlines(), end + sep)


def dissect_http_request(buf: bytes, pkt: Packet) -> HTTPRequest | None:
    if not _looks_like_http_request(buf[:32]):
        return None
    parsed = _parse_http_head(buf)
    if parsed is None:
        return None
    lines, _ = parsed
    if not lines:
        return None
    first = lines[0].split(" ", 2)
    if len(first) < 2:
        return None
    method = first[0]
    uri = first[1]
    host = ""
    user_agent = ""
    has_basic = False
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        kl = k.strip().lower()
        vv = v.strip()
        headers.append((kl, vv))
        if kl == "host":
            host = vv
        elif kl == "user-agent":
            user_agent = vv
        elif kl == "authorization" and vv.lower().startswith("basic "):
            has_basic = True
    return HTTPRequest(
        ts=pkt.ts,
        frame_no=pkt.frame_no,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        dst_port=pkt.dst_port,
        method=method,
        uri=uri,
        host=host,
        user_agent=user_agent,
        headers=tuple(headers[:64]),
        has_basic_auth=has_basic,
    )


def dissect_http_response(buf: bytes, pkt: Packet) -> HTTPResponse | None:
    if not _looks_like_http_response(buf[:8]):
        return None
    parsed = _parse_http_head(buf)
    if parsed is None:
        return None
    lines, _ = parsed
    if not lines:
        return None
    first = lines[0].split(" ", 2)
    if len(first) < 2 or not first[1].isdigit():
        return None
    status = int(first[1])
    reason = first[2] if len(first) > 2 else ""
    server = ""
    content_type = ""
    content_length = -1
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        kl = k.strip().lower()
        vv = v.strip()
        if kl == "server":
            server = vv
        elif kl == "content-type":
            content_type = vv
        elif kl == "content-length":
            with contextlib.suppress(ValueError):
                content_length = int(vv)
    return HTTPResponse(
        ts=pkt.ts,
        frame_no=pkt.frame_no,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        src_port=pkt.src_port,
        status=status,
        reason=reason,
        server=server,
        content_type=content_type,
        content_length=content_length,
    )


def flag_bad_user_agent(ua: str) -> str | None:
    """Return a human label if ``ua`` matches a known-malicious pattern."""
    for label, pat in _BAD_UA_PATTERNS:
        if pat.search(ua):
            return label
    return None


# ---------------------------------------------------------------------------
# TLS ClientHello + JA3
# ---------------------------------------------------------------------------


# JA3 GREASE values per draft-davidben-tls-grease — the spec mandates that
# these be skipped when computing JA3 so two Chromes with different GREASE
# selections still produce the same fingerprint.
_GREASE = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)


def _read_u8(buf: bytes, off: int) -> tuple[int, int] | None:
    if off + 1 > len(buf):
        return None
    return (buf[off], off + 1)


def _read_u16(buf: bytes, off: int) -> tuple[int, int] | None:
    if off + 2 > len(buf):
        return None
    return (struct.unpack(">H", buf[off : off + 2])[0], off + 2)


def _read_bytes(buf: bytes, off: int, n: int) -> tuple[bytes, int] | None:
    if off + n > len(buf):
        return None
    return (buf[off : off + n], off + n)


def dissect_tls_clienthello(buf: bytes, pkt: Packet) -> TLSClientHello | None:
    """Parse a stitched TCP payload for the *first* ClientHello.

    Returns ``None`` on anything that's not a complete record carrying a
    ClientHello, or on malformed input. Computes JA3 per the published
    spec:

        SSLVersion,Cipher,Extension,EllipticCurve,EllipticCurvePointFormat

    Each list is dash-separated; sections are comma-separated; GREASE
    values are stripped from the cipher / extension / curve lists.
    Result is hex(md5(string)).
    """
    if len(buf) < 11:
        return None
    # TLS record: type(1) version(2) length(2) handshake(...)
    if buf[0] != 0x16:  # 0x16 = Handshake
        return None
    rec_ver = struct.unpack(">H", buf[1:3])[0]
    if rec_ver < 0x0300 or rec_ver > 0x0304:
        return None
    rec_len = struct.unpack(">H", buf[3:5])[0]
    end_record = 5 + rec_len
    if end_record > len(buf):
        end_record = len(buf)  # truncated capture — try anyway
    # Handshake: type(1)=01 length(3) body
    if buf[5] != 0x01:  # 0x01 = ClientHello
        return None
    hs_len = (buf[6] << 16) | (buf[7] << 8) | buf[8]
    hs_end = 9 + hs_len
    if hs_end > end_record:
        hs_end = end_record  # again, allow truncated capture
    off = 9
    cur = _read_u16(buf, off)
    if cur is None:
        return None
    legacy_version, off = cur

    cur = _read_bytes(buf, off, 32)  # client_random
    if cur is None:
        return None
    _, off = cur

    cur = _read_u8(buf, off)  # session_id len
    if cur is None:
        return None
    sid_len, off = cur
    cur = _read_bytes(buf, off, sid_len)
    if cur is None:
        return None
    _, off = cur

    cur = _read_u16(buf, off)
    if cur is None:
        return None
    cipher_bytes_len, off = cur
    cur = _read_bytes(buf, off, cipher_bytes_len)
    if cur is None:
        return None
    cipher_blob, off = cur
    if cipher_bytes_len % 2:
        return None
    ciphers = [
        struct.unpack(">H", cipher_blob[i : i + 2])[0] for i in range(0, cipher_bytes_len, 2)
    ]

    cur = _read_u8(buf, off)  # compression methods len
    if cur is None:
        return None
    comp_len, off = cur
    cur = _read_bytes(buf, off, comp_len)
    if cur is None:
        return None
    _, off = cur

    # Extensions (optional in TLS 1.0 but always present in modern hellos).
    extensions_list: list[int] = []
    curves_list: list[int] = []
    ec_pt_fmt_list: list[int] = []
    sni = ""
    alpn: list[str] = []
    if off + 2 <= hs_end:
        ext_total_len = struct.unpack(">H", buf[off : off + 2])[0]
        off += 2
        ext_end = off + ext_total_len
        if ext_end > hs_end:
            ext_end = hs_end
        while off + 4 <= ext_end:
            ext_type = struct.unpack(">H", buf[off : off + 2])[0]
            ext_len = struct.unpack(">H", buf[off + 2 : off + 4])[0]
            ext_data_off = off + 4
            ext_data_end = ext_data_off + ext_len
            if ext_data_end > ext_end:
                break
            extensions_list.append(ext_type)
            if ext_type == 0x0000:  # SNI
                sni = _parse_sni(buf, ext_data_off, ext_data_end)
            elif ext_type == 0x000A:  # supported_groups (a.k.a. curves)
                curves_list = _parse_u16_list(buf, ext_data_off, ext_data_end)
            elif ext_type == 0x000B:  # ec_point_formats
                ec_pt_fmt_list = _parse_u8_list(buf, ext_data_off, ext_data_end)
            elif ext_type == 0x0010:  # ALPN
                alpn = _parse_alpn(buf, ext_data_off, ext_data_end)
            off = ext_data_end

    ciphers_clean = [c for c in ciphers if c not in _GREASE]
    extensions_clean = [e for e in extensions_list if e not in _GREASE]
    curves_clean = [c for c in curves_list if c not in _GREASE]
    pt_clean = list(ec_pt_fmt_list)
    ja3 = "{ver},{ciphers},{exts},{curves},{pts}".format(
        ver=legacy_version,
        ciphers="-".join(str(c) for c in ciphers_clean),
        exts="-".join(str(e) for e in extensions_clean),
        curves="-".join(str(c) for c in curves_clean),
        pts="-".join(str(p) for p in pt_clean),
    )
    ja3_md5 = hashlib.md5(ja3.encode("ascii")).hexdigest()
    return TLSClientHello(
        ts=pkt.ts,
        frame_no=pkt.frame_no,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        dst_port=pkt.dst_port,
        tls_version=legacy_version,
        sni=sni,
        alpn=tuple(alpn),
        ja3_string=ja3,
        ja3_md5=ja3_md5,
    )


def dissect_tls_serverhello(buf: bytes, pkt: Packet) -> TLSServerHello | None:
    """Parse a stitched server→client TCP payload for the *first* ServerHello.

    Computes **JA3S** per the published spec:

        SSLVersion,Cipher,Extension

    Unlike JA3 (client), the server selects a *single* cipher, so the
    cipher field is one value, not a dash-joined list. The extension list
    is dash-joined in wire order with GREASE stripped, exactly like JA3.
    Result is hex(md5(string)).

    Pairing a flow's JA3 (client) with its JA3S (server) is what lets an
    analyst fingerprint a *server implementation* — the single strongest
    tell for "this benign-looking 443 flow is actually a Cobalt Strike
    teamserver", because the malleable C2 profile fixes both.
    """
    if len(buf) < 11:
        return None
    if buf[0] != 0x16:  # Handshake record
        return None
    rec_ver = struct.unpack(">H", buf[1:3])[0]
    if rec_ver < 0x0300 or rec_ver > 0x0304:
        return None
    rec_len = struct.unpack(">H", buf[3:5])[0]
    end_record = min(5 + rec_len, len(buf))
    if buf[5] != 0x02:  # 0x02 = ServerHello
        return None
    hs_len = (buf[6] << 16) | (buf[7] << 8) | buf[8]
    hs_end = min(9 + hs_len, end_record)
    off = 9

    cur = _read_u16(buf, off)
    if cur is None:
        return None
    legacy_version, off = cur

    cur = _read_bytes(buf, off, 32)  # server_random
    if cur is None:
        return None
    _, off = cur

    cur = _read_u8(buf, off)  # session_id len
    if cur is None:
        return None
    sid_len, off = cur
    cur = _read_bytes(buf, off, sid_len)
    if cur is None:
        return None
    _, off = cur

    cur = _read_u16(buf, off)  # the single selected cipher suite
    if cur is None:
        return None
    cipher, off = cur

    cur = _read_u8(buf, off)  # compression_method (single byte for server)
    if cur is None:
        return None
    _, off = cur

    extensions_list: list[int] = []
    if off + 2 <= hs_end:
        ext_total_len = struct.unpack(">H", buf[off : off + 2])[0]
        off += 2
        ext_end = min(off + ext_total_len, hs_end)
        while off + 4 <= ext_end:
            ext_type = struct.unpack(">H", buf[off : off + 2])[0]
            ext_len = struct.unpack(">H", buf[off + 2 : off + 4])[0]
            ext_data_end = off + 4 + ext_len
            if ext_data_end > ext_end:
                break
            extensions_list.append(ext_type)
            off = ext_data_end

    extensions_clean = [e for e in extensions_list if e not in _GREASE]
    ja3s = "{ver},{cipher},{exts}".format(
        ver=legacy_version,
        cipher=cipher,
        exts="-".join(str(e) for e in extensions_clean),
    )
    ja3s_md5 = hashlib.md5(ja3s.encode("ascii")).hexdigest()
    return TLSServerHello(
        ts=pkt.ts,
        frame_no=pkt.frame_no,
        src_ip=pkt.src_ip,
        dst_ip=pkt.dst_ip,
        src_port=pkt.src_port,
        tls_version=legacy_version,
        cipher=cipher,
        ja3s_string=ja3s,
        ja3s_md5=ja3s_md5,
    )


def _parse_sni(buf: bytes, off: int, end: int) -> str:
    """SNI extension: ServerNameList layout is len(2) [type(1) name_len(2) name]*"""
    if off + 2 > end:
        return ""
    list_len = struct.unpack(">H", buf[off : off + 2])[0]
    cur = off + 2
    list_end = min(cur + list_len, end)
    while cur + 3 <= list_end:
        name_type = buf[cur]
        name_len = struct.unpack(">H", buf[cur + 1 : cur + 3])[0]
        name_off = cur + 3
        if name_off + name_len > list_end:
            return ""
        if name_type == 0:  # host_name
            try:
                return buf[name_off : name_off + name_len].decode("ascii").lower()
            except UnicodeDecodeError:
                return ""
        cur = name_off + name_len
    return ""


def _parse_u16_list(buf: bytes, off: int, end: int) -> list[int]:
    if off + 2 > end:
        return []
    list_len = struct.unpack(">H", buf[off : off + 2])[0]
    cur = off + 2
    list_end = min(cur + list_len, end)
    if (list_end - cur) % 2:
        return []
    return [struct.unpack(">H", buf[i : i + 2])[0] for i in range(cur, list_end, 2)]


def _parse_u8_list(buf: bytes, off: int, end: int) -> list[int]:
    if off + 1 > end:
        return []
    list_len = buf[off]
    cur = off + 1
    list_end = min(cur + list_len, end)
    return list(buf[cur:list_end])


def _parse_alpn(buf: bytes, off: int, end: int) -> list[str]:
    if off + 2 > end:
        return []
    list_len = struct.unpack(">H", buf[off : off + 2])[0]
    cur = off + 2
    list_end = min(cur + list_len, end)
    out: list[str] = []
    while cur < list_end:
        ln = buf[cur]
        cur += 1
        if cur + ln > list_end:
            break
        with contextlib.suppress(UnicodeDecodeError):
            out.append(buf[cur : cur + ln].decode("ascii"))
        cur += ln
    return out

"""PCAP / PCAPNG parser, L2-L4 dissector, and flow aggregator.

Pure-stdlib. No scapy / no dpkt / no pyshark. The codebase ships
hand-rolled PE / ELF / Mach-O parsers; PCAP follows the same template — a
defensive walker that returns ``None`` on bounds violation rather than
blowing up on a hostile capture. Malware traffic captures in the wild are
routinely truncated, sliced, or written by tools that bend the spec, so
totality is non-negotiable.

Layers handled
--------------
- **Containers**: libpcap classic (microsecond *and* nanosecond magics),
  and PCAPNG (Section Header Block + Interface Description Block +
  Enhanced Packet Block + Simple Packet Block). Other PCAPNG block types
  are skipped via ``block_total_length`` so we keep walking.
- **Link**: Ethernet II, 802.1Q VLAN tag (one nesting), Linux SLL (cooked
  v1), Linux SLL2, BSD NULL/LOOP, RAW (no link header).
- **Network**: IPv4 (with IHL-correct options skip) and IPv6 (with
  extension header chain walked through to the transport).
- **Transport**: TCP, UDP, ICMP, ICMPv6.

Higher protocols (DNS / HTTP / TLS) live in ``pcap_proto`` and consume
the ``Packet`` records this module yields. The flow aggregator stores at
most ``MAX_FLOWS`` bidirectional 5-tuple flows; once that cap is hit we
keep updating existing flows but stop creating new ones.

Design rule (mirrors ``common.Reader``): every routine that touches
capture bytes is total. Bad input degrades the report, never raises.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import IntEnum

# ---------------------------------------------------------------------------
# Hard caps. A 256 MiB capture can carry millions of packets; we bound the
# parser so a hostile or malformed file can't OOM the analyser.
# ---------------------------------------------------------------------------

#: Largest number of frames we will dissect. Beyond this the analyser
#: returns what it has and emits a ``pcap.truncated`` finding upstream.
MAX_FRAMES = 200_000

#: Largest number of distinct bidirectional flows we track. Real captures
#: that exceed this are typically scans (one src to many dst) — we still
#: detect the scan because flow creation is monotonic in observation order.
MAX_FLOWS = 50_000

#: Cap on captured-bytes per frame we walk. Anything past the cap is
#: ignored at dissect time; the capture file itself can be larger.
MAX_FRAME_BYTES = 65_535


# ---------------------------------------------------------------------------
# Magic numbers
# ---------------------------------------------------------------------------

#: libpcap classic, microsecond timestamps, native byte order.
PCAP_MAGIC_US_NATIVE = 0xA1B2C3D4
#: libpcap classic, microsecond timestamps, swapped byte order.
PCAP_MAGIC_US_SWAPPED = 0xD4C3B2A1
#: libpcap, nanosecond timestamps, native byte order.
PCAP_MAGIC_NS_NATIVE = 0xA1B23C4D
#: libpcap, nanosecond timestamps, swapped byte order.
PCAP_MAGIC_NS_SWAPPED = 0x4D3CB2A1

#: PCAPNG: every file starts with a Section Header Block.
PCAPNG_BLOCK_TYPE_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_TYPE_IDB = 0x00000001  # Interface Description
PCAPNG_BLOCK_TYPE_SPB = 0x00000003  # Simple Packet
PCAPNG_BLOCK_TYPE_EPB = 0x00000006  # Enhanced Packet
#: Byte-order magic that lives at offset +8 inside the SHB.
PCAPNG_BOM_NATIVE = 0x1A2B3C4D
PCAPNG_BOM_SWAPPED = 0x4D3C2B1A


# ---------------------------------------------------------------------------
# LINKTYPE_ values from the libpcap registry. We only enumerate the ones we
# actually dissect; everything else falls through and is skipped.
# ---------------------------------------------------------------------------


class LinkType(IntEnum):
    NULL = 0  # BSD loopback: 4-byte AF_* prefix, then IP
    ETHERNET = 1  # Ethernet II
    RAW = 12  # Raw IP (Linux raw socket capture)
    LINUX_SLL = 113  # Linux cooked v1 (16-byte header)
    LOOP = 108  # OpenBSD loopback (4-byte BE AF prefix)
    IPV4 = 228  # Raw IPv4
    IPV6 = 229  # Raw IPv6
    LINUX_SLL2 = 276  # Linux cooked v2 (20-byte header)


# ---------------------------------------------------------------------------
# IANA protocol numbers we care about.
# ---------------------------------------------------------------------------


class IPProto(IntEnum):
    HOPOPT = 0  # IPv6 Hop-by-Hop options
    ICMP = 1
    TCP = 6
    UDP = 17
    IPV6_ROUTE = 43
    IPV6_FRAG = 44
    ESP = 50
    AH = 51
    ICMPV6 = 58
    IPV6_NONE = 59
    IPV6_DSTOPT = 60


#: Extension headers that carry their own length and chain to a next header.
_IPV6_EXT_HEADERS = frozenset(
    {
        IPProto.HOPOPT,
        IPProto.IPV6_ROUTE,
        IPProto.IPV6_DSTOPT,
        IPProto.AH,
    }
)


# ---------------------------------------------------------------------------
# Ethertypes
# ---------------------------------------------------------------------------

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8


# ---------------------------------------------------------------------------
# TCP flag bits
# ---------------------------------------------------------------------------

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Frame:
    """One raw captured frame at the link layer."""

    ts: float  # seconds since epoch; sub-second precision preserved
    link_type: int  # LINKTYPE_ value
    data: bytes  # captured bytes (already trimmed to MAX_FRAME_BYTES)
    orig_len: int  # original on-wire length (>= len(data) if sliced)


@dataclass(frozen=True, slots=True)
class Packet:
    """One dissected L3+L4 packet.

    ``payload`` is the L4 payload bytes (TCP/UDP/ICMP body). Higher
    protocol parsers consume this directly; no re-slicing of the frame
    required. ``raw_frame`` is the original link-layer bytes — kept for
    the rare case a higher layer wants to look at Ethernet metadata.
    """

    ts: float
    frame_no: int  # 1-based frame number in the capture
    src_ip: str  # presentation form (dotted quad or canonical IPv6)
    dst_ip: str
    src_port: int  # 0 if proto is not TCP/UDP
    dst_port: int
    proto: int  # IANA protocol number (IPProto)
    is_ipv6: bool
    payload: bytes
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    ip_ttl: int = 0  # Hop Limit on v6


@dataclass(slots=True)
class Flow:
    """A bidirectional 5-tuple flow.

    The "a" side is the endpoint that initiated (whichever direction we
    saw first). ``bytes_a2b`` / ``bytes_b2a`` track payload bytes per
    direction so one-sided heavy uploads stand out from balanced
    request/response chatter.
    """

    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    proto: int
    first_ts: float
    last_ts: float
    packets_a2b: int = 0
    packets_b2a: int = 0
    bytes_a2b: int = 0
    bytes_b2a: int = 0
    saw_syn: bool = False
    saw_synack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    # Timestamps for inter-arrival analysis on the *initiating* side. Capped
    # so beacon heuristics have something to crunch but we never balloon RAM.
    a2b_ts: list[float] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def total_bytes(self) -> int:
        return self.bytes_a2b + self.bytes_b2a

    @property
    def total_packets(self) -> int:
        return self.packets_a2b + self.packets_b2a


# ---------------------------------------------------------------------------
# Container parsers
# ---------------------------------------------------------------------------


def detect_pcap_format(head: bytes) -> str:
    """Return ``'pcap'``, ``'pcapng'``, or ``''`` for the given file head.

    Cheap magic check — caller invokes the right ``iter_*`` after.
    """
    if len(head) < 4:
        return ""
    magic_le = struct.unpack("<I", head[:4])[0]
    magic_be = struct.unpack(">I", head[:4])[0]
    if magic_le in (
        PCAP_MAGIC_US_NATIVE,
        PCAP_MAGIC_US_SWAPPED,
        PCAP_MAGIC_NS_NATIVE,
        PCAP_MAGIC_NS_SWAPPED,
    ):
        return "pcap"
    if magic_be in (
        PCAP_MAGIC_US_NATIVE,
        PCAP_MAGIC_US_SWAPPED,
        PCAP_MAGIC_NS_NATIVE,
        PCAP_MAGIC_NS_SWAPPED,
    ):
        return "pcap"
    if magic_le == PCAPNG_BLOCK_TYPE_SHB or magic_be == PCAPNG_BLOCK_TYPE_SHB:
        return "pcapng"
    return ""


def iter_pcap_classic(raw: bytes, *, max_frames: int = MAX_FRAMES) -> Iterator[Frame]:
    """Yield ``Frame``s from a libpcap classic capture.

    Supports both microsecond and nanosecond timestamp magics, and both
    endiannesses. Stops at ``max_frames`` or first malformed record.
    """
    if len(raw) < 24:
        return
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (PCAP_MAGIC_US_NATIVE, PCAP_MAGIC_NS_NATIVE):
        endian = "<"
    elif magic in (PCAP_MAGIC_US_SWAPPED, PCAP_MAGIC_NS_SWAPPED):
        endian = ">"
    else:
        return
    nanosecond = magic in (PCAP_MAGIC_NS_NATIVE, PCAP_MAGIC_NS_SWAPPED)

    # Global header layout: magic(4) ver_major(2) ver_minor(2) thiszone(4)
    # sigfigs(4) snaplen(4) network(4). We only need link type.
    try:
        link_type = struct.unpack(endian + "I", raw[20:24])[0]
    except struct.error:
        return

    off = 24
    n = len(raw)
    yielded = 0
    while off + 16 <= n and yielded < max_frames:
        try:
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                endian + "IIII", raw[off : off + 16]
            )
        except struct.error:
            return
        off += 16
        if incl_len > MAX_FRAME_BYTES or incl_len == 0:
            # Sanity: snaplen lies happen. Bail rather than soldier through
            # whatever follows — if the length is wrong we cannot trust the
            # next record either.
            return
        if off + incl_len > n:
            return
        data = bytes(raw[off : off + incl_len])
        off += incl_len
        denom = 1_000_000_000.0 if nanosecond else 1_000_000.0
        ts = ts_sec + (ts_frac / denom)
        yield Frame(ts=ts, link_type=link_type, data=data, orig_len=orig_len)
        yielded += 1


def iter_pcapng(raw: bytes, *, max_frames: int = MAX_FRAMES) -> Iterator[Frame]:
    """Yield ``Frame``s from a PCAPNG capture.

    PCAPNG ties packets to interfaces via interface IDs declared in
    Interface Description Blocks. We accumulate ``(link_type, ts_resol)``
    per IDB in a small list keyed by index. ``ts_resol`` is the negative
    base-10 power for non-default timestamp resolution (default == 1e-6).

    Unknown / unrecognised block types are skipped via the
    ``block_total_length`` field. Section Header Blocks reset the
    interface table because a new section can redefine everything.
    """
    n = len(raw)
    if n < 12:
        return
    # Pick endianness from the SHB BOM. The SHB layout is:
    #   block_type(4) block_total_length(4) byte_order_magic(4) major(2)
    #   minor(2) section_length(8) options... block_total_length(4)
    bt = struct.unpack("<I", raw[:4])[0]
    if bt != PCAPNG_BLOCK_TYPE_SHB:
        return
    bom = raw[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        return

    interfaces: list[tuple[int, float]] = []  # (link_type, ts_resolution_seconds)
    off = 0
    yielded = 0
    # Walk block-by-block. Each block: type(4) total_len(4) body total_len(4).
    while off + 12 <= n and yielded < max_frames:
        try:
            block_type = struct.unpack(endian + "I", raw[off : off + 4])[0]
            block_len = struct.unpack(endian + "I", raw[off + 4 : off + 8])[0]
        except struct.error:
            return
        if block_len < 12 or block_len % 4 != 0 or off + block_len > n:
            return
        body_end = off + block_len - 4
        body_off = off + 8

        if block_type == PCAPNG_BLOCK_TYPE_SHB:
            # New section — re-read endianness, reset interface table.
            if body_off + 4 <= body_end:
                bom = raw[body_off : body_off + 4]
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    return
            interfaces = []
        elif block_type == PCAPNG_BLOCK_TYPE_IDB:
            # IDB: link_type(2) reserved(2) snaplen(4) options...
            if body_off + 8 > body_end:
                interfaces.append((0, 1e-6))
            else:
                link_type = struct.unpack(endian + "H", raw[body_off : body_off + 2])[0]
                ts_resol = _pcapng_ts_resolution(raw, body_off + 8, body_end, endian, default=1e-6)
                interfaces.append((link_type, ts_resol))
        elif block_type == PCAPNG_BLOCK_TYPE_EPB:
            # EPB: iface_id(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data ...
            if body_off + 20 > body_end:
                off += block_len
                continue
            iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(
                endian + "IIIII", raw[body_off : body_off + 20]
            )
            data_off = body_off + 20
            if cap_len > MAX_FRAME_BYTES or data_off + cap_len > body_end:
                off += block_len
                continue
            link_type, ts_resol = interfaces[iface_id] if iface_id < len(interfaces) else (0, 1e-6)
            ts_combined = (ts_hi << 32) | ts_lo
            ts = ts_combined * ts_resol
            yield Frame(
                ts=ts,
                link_type=link_type,
                data=bytes(raw[data_off : data_off + cap_len]),
                orig_len=orig_len,
            )
            yielded += 1
        elif block_type == PCAPNG_BLOCK_TYPE_SPB:
            # SPB: orig_len(4) data ... — no timestamp, no iface id.
            if body_off + 4 > body_end:
                off += block_len
                continue
            orig_len = struct.unpack(endian + "I", raw[body_off : body_off + 4])[0]
            cap_len = body_end - (body_off + 4)
            if cap_len > MAX_FRAME_BYTES or cap_len < 0:
                off += block_len
                continue
            link_type, ts_resol = interfaces[0] if interfaces else (0, 1e-6)
            yield Frame(
                ts=0.0,
                link_type=link_type,
                data=bytes(raw[body_off + 4 : body_off + 4 + cap_len]),
                orig_len=orig_len,
            )
            yielded += 1
        # Any other block type (NRB, ISB, ...) — skip silently via block_len.
        off += block_len


def _pcapng_ts_resolution(
    raw: bytes, opt_off: int, end: int, endian: str, *, default: float
) -> float:
    """Walk IDB options to find ``if_tsresol`` (option code 9). Default 1e-6.

    Option layout: code(2) length(2) value(length, padded to 32-bit).
    ``if_tsresol`` is a single byte: if the high bit is set the resolution
    is ``2**-(low7 bits)`` seconds, else ``10**-(low7 bits)`` seconds.
    """
    while opt_off + 4 <= end:
        try:
            code, length = struct.unpack(endian + "HH", raw[opt_off : opt_off + 4])
        except struct.error:
            return default
        val_off = opt_off + 4
        val_end = val_off + length
        if val_end > end:
            return default
        if code == 0:  # opt_endofopt
            return default
        if code == 9 and length >= 1:
            byte = raw[val_off]
            base = 2 if (byte & 0x80) else 10
            exp = byte & 0x7F
            return base ** (-exp)
        # advance, padded to 32-bit
        opt_off = val_off + ((length + 3) & ~3)
    return default


# ---------------------------------------------------------------------------
# L2 → L3 → L4 dissection
# ---------------------------------------------------------------------------


def dissect_frame(frame: Frame, frame_no: int) -> Packet | None:
    """Walk a single frame to a ``Packet``, or return ``None`` if undissectable.

    Defensive: every read is bounds-checked. If any layer can't be parsed
    we return ``None`` and let the caller move on.
    """
    data = frame.data
    if not data:
        return None
    lt = frame.link_type
    if lt == LinkType.ETHERNET:
        ip_off, is_ipv6 = _strip_ethernet(data)
    elif lt == LinkType.LINUX_SLL:
        ip_off, is_ipv6 = _strip_linux_sll(data)
    elif lt == LinkType.LINUX_SLL2:
        ip_off, is_ipv6 = _strip_linux_sll2(data)
    elif lt == LinkType.NULL or lt == LinkType.LOOP:
        ip_off, is_ipv6 = _strip_bsd_loopback(data, big_endian=(lt == LinkType.LOOP))
    elif lt == LinkType.RAW or lt == LinkType.IPV4:
        ip_off, is_ipv6 = (0, False) if (data[0] >> 4) == 4 else (0, True)
    elif lt == LinkType.IPV6:
        ip_off, is_ipv6 = (0, True)
    else:
        return None
    if ip_off < 0 or ip_off >= len(data):
        return None
    if is_ipv6:
        return _dissect_ipv6(data, ip_off, frame.ts, frame_no)
    return _dissect_ipv4(data, ip_off, frame.ts, frame_no)


def _strip_ethernet(data: bytes) -> tuple[int, bool]:
    """Return (offset-of-IP-header, is_ipv6) or (-1, False) on failure.

    Handles one level of 802.1Q VLAN tag and one level of QinQ (S+C tag).
    Anything we don't recognise yields (-1, False).
    """
    if len(data) < 14:
        return (-1, False)
    etype = struct.unpack(">H", data[12:14])[0]
    off = 14
    # Up to two stacked VLAN/QinQ tags.
    for _ in range(2):
        if etype in (ETH_VLAN, ETH_QINQ):
            if off + 4 > len(data):
                return (-1, False)
            etype = struct.unpack(">H", data[off + 2 : off + 4])[0]
            off += 4
        else:
            break
    if etype == ETH_IPV4:
        return (off, False)
    if etype == ETH_IPV6:
        return (off, True)
    return (-1, False)


def _strip_linux_sll(data: bytes) -> tuple[int, bool]:
    if len(data) < 16:
        return (-1, False)
    proto = struct.unpack(">H", data[14:16])[0]
    if proto == ETH_IPV4:
        return (16, False)
    if proto == ETH_IPV6:
        return (16, True)
    return (-1, False)


def _strip_linux_sll2(data: bytes) -> tuple[int, bool]:
    if len(data) < 20:
        return (-1, False)
    proto = struct.unpack(">H", data[0:2])[0]
    if proto == ETH_IPV4:
        return (20, False)
    if proto == ETH_IPV6:
        return (20, True)
    return (-1, False)


def _strip_bsd_loopback(data: bytes, *, big_endian: bool) -> tuple[int, bool]:
    if len(data) < 4:
        return (-1, False)
    af = struct.unpack(">I" if big_endian else "<I", data[:4])[0]
    # BSD AF_INET == 2 everywhere; AF_INET6 varies (24/28/30) — accept all.
    if af == 2:
        return (4, False)
    if af in (24, 28, 30):
        return (4, True)
    return (-1, False)


def _dissect_ipv4(data: bytes, off: int, ts: float, frame_no: int) -> Packet | None:
    if off + 20 > len(data):
        return None
    vh = data[off]
    version = vh >> 4
    if version != 4:
        return None
    ihl = (vh & 0x0F) * 4
    if ihl < 20 or off + ihl > len(data):
        return None
    total_len = struct.unpack(">H", data[off + 2 : off + 4])[0]
    ttl = data[off + 8]
    proto = data[off + 9]
    src = socket.inet_ntop(socket.AF_INET, data[off + 12 : off + 16])
    dst = socket.inet_ntop(socket.AF_INET, data[off + 16 : off + 20])
    # IP total_length may be 0 in TCP segmentation offload captures; fall back
    # to "everything left after the IP header".
    payload_end = off + total_len if 0 < total_len <= len(data) - off else len(data)
    l4_off = off + ihl
    if l4_off > payload_end:
        return None
    return _dissect_l4(
        data,
        l4_off,
        payload_end,
        proto,
        src,
        dst,
        ts,
        frame_no,
        is_ipv6=False,
        ttl=ttl,
    )


def _dissect_ipv6(data: bytes, off: int, ts: float, frame_no: int) -> Packet | None:
    if off + 40 > len(data):
        return None
    vh = data[off]
    if (vh >> 4) != 6:
        return None
    payload_len = struct.unpack(">H", data[off + 4 : off + 6])[0]
    next_hdr = data[off + 6]
    hop_limit = data[off + 7]
    src = socket.inet_ntop(socket.AF_INET6, data[off + 8 : off + 24])
    dst = socket.inet_ntop(socket.AF_INET6, data[off + 24 : off + 40])
    payload_end = off + 40 + payload_len
    if payload_end > len(data) or payload_len == 0:
        payload_end = len(data)
    cur = off + 40
    # Walk extension header chain to the transport. Cap iterations so a
    # malformed loop can't spin forever.
    for _ in range(8):
        if next_hdr in _IPV6_EXT_HEADERS:
            if cur + 2 > payload_end:
                return None
            new_next = data[cur]
            # HOPOPT/DSTOPT/ROUTE length is in 8-byte units, +1 (RFC 8200).
            # AH length is in 4-byte units, +2 (RFC 4302).
            ext_len = (data[cur + 1] + 2) * 4 if next_hdr == IPProto.AH else (data[cur + 1] + 1) * 8
            cur += ext_len
            next_hdr = new_next
            if cur > payload_end:
                return None
            continue
        if next_hdr == IPProto.IPV6_FRAG:
            # Fixed 8-byte fragment header. We dissect first-fragment payloads
            # only; later fragments lack the L4 header anyway.
            if cur + 8 > payload_end:
                return None
            new_next = data[cur]
            cur += 8
            next_hdr = new_next
            continue
        break
    return _dissect_l4(
        data,
        cur,
        payload_end,
        next_hdr,
        src,
        dst,
        ts,
        frame_no,
        is_ipv6=True,
        ttl=hop_limit,
    )


def _dissect_l4(
    data: bytes,
    off: int,
    end: int,
    proto: int,
    src_ip: str,
    dst_ip: str,
    ts: float,
    frame_no: int,
    *,
    is_ipv6: bool,
    ttl: int,
) -> Packet | None:
    """Dissect TCP / UDP / ICMP into a ``Packet``.

    ICMP packets are reported with both ports = 0; that lets the flow
    aggregator put them on a per-protocol channel without colliding with
    TCP/UDP flows that share endpoints.
    """
    if off >= end or off >= len(data):
        return None
    if proto == IPProto.TCP:
        if off + 20 > end:
            return None
        src_port, dst_port, seq, ack, off_flags = struct.unpack(">HHIIH", data[off : off + 14])
        data_off_words = (off_flags >> 12) & 0xF
        flags = off_flags & 0x1FF  # 9 bits: NS+CWR+ECE+URG+ACK+PSH+RST+SYN+FIN
        hdr_len = data_off_words * 4
        if hdr_len < 20 or off + hdr_len > end:
            return None
        payload = bytes(data[off + hdr_len : end])
        return Packet(
            ts=ts,
            frame_no=frame_no,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=IPProto.TCP,
            is_ipv6=is_ipv6,
            payload=payload,
            tcp_flags=flags & 0xFF,
            tcp_seq=seq,
            tcp_ack=ack,
            ip_ttl=ttl,
        )
    if proto == IPProto.UDP:
        if off + 8 > end:
            return None
        src_port, dst_port, length = struct.unpack(">HHH", data[off : off + 6])
        payload_end = off + length if 8 <= length <= end - off else end
        payload = bytes(data[off + 8 : payload_end])
        return Packet(
            ts=ts,
            frame_no=frame_no,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=IPProto.UDP,
            is_ipv6=is_ipv6,
            payload=payload,
            ip_ttl=ttl,
        )
    if proto in (IPProto.ICMP, IPProto.ICMPV6):
        payload = bytes(data[off:end])
        return Packet(
            ts=ts,
            frame_no=frame_no,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=0,
            dst_port=0,
            proto=proto,
            is_ipv6=is_ipv6,
            payload=payload,
            ip_ttl=ttl,
        )
    return None


# ---------------------------------------------------------------------------
# Top-level iteration helpers
# ---------------------------------------------------------------------------


def iter_frames(raw: bytes, *, max_frames: int = MAX_FRAMES) -> Iterator[Frame]:
    """Auto-detect the container and yield frames."""
    fmt = detect_pcap_format(raw[:12])
    if fmt == "pcap":
        yield from iter_pcap_classic(raw, max_frames=max_frames)
    elif fmt == "pcapng":
        yield from iter_pcapng(raw, max_frames=max_frames)


def iter_packets(raw: bytes, *, max_frames: int = MAX_FRAMES) -> Iterator[Packet]:
    """Auto-detect + dissect, yielding ``Packet``s in capture order.

    Skips frames we can't dissect — non-IP traffic (ARP, LLDP, ...) is
    legitimate and shouldn't break the loop.
    """
    for idx, frame in enumerate(iter_frames(raw, max_frames=max_frames), 1):
        pkt = dissect_frame(frame, idx)
        if pkt is not None:
            yield pkt


# ---------------------------------------------------------------------------
# Flow aggregation
# ---------------------------------------------------------------------------


class FlowTable:
    """Bidirectional 5-tuple flow aggregator.

    Flows are keyed by the *canonical* tuple ``(ip_a, port_a, ip_b, port_b,
    proto)`` where ``(ip_a, port_a) <= (ip_b, port_b)``. We pick canonical
    ordering at insert time, but track packet direction relative to the
    *initiating* side (whichever endpoint we first saw send a SYN, or the
    first packet's source if no SYN exists).

    Capped at ``MAX_FLOWS`` entries. Once full, subsequent packets that
    don't match an existing flow are dropped from flow accounting but
    still seen by higher-layer dissectors (DNS/HTTP/TLS).
    """

    __slots__ = ("_init_side", "flows")

    def __init__(self) -> None:
        self.flows: dict[tuple[str, int, str, int, int], Flow] = {}
        # For each flow, remember which endpoint we called the "a" side
        # (the initiator). Keys are canonical 5-tuples.
        self._init_side: dict[tuple[str, int, str, int, int], tuple[str, int]] = {}

    def update(self, pkt: Packet) -> None:
        key = self._canonical_key(pkt)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                return
            # First packet decides the initiator: SYN-without-ACK is the
            # gold standard; otherwise just the source of the first packet.
            init_ip, init_port = pkt.src_ip, pkt.src_port
            if (
                pkt.proto == IPProto.TCP
                and pkt.tcp_flags & TCP_SYN
                and not (pkt.tcp_flags & TCP_ACK)
            ):
                init_ip, init_port = pkt.src_ip, pkt.src_port
            self._init_side[key] = (init_ip, init_port)
            # Lay out the flow with `a` = initiator, `b` = peer.
            other = (
                (key[2], key[3]) if (init_ip, init_port) == (key[0], key[1]) else (key[0], key[1])
            )
            flow = Flow(
                a_ip=init_ip,
                a_port=init_port,
                b_ip=other[0],
                b_port=other[1],
                proto=pkt.proto,
                first_ts=pkt.ts,
                last_ts=pkt.ts,
            )
            self.flows[key] = flow

        flow.last_ts = max(flow.last_ts, pkt.ts)
        from_a = (pkt.src_ip, pkt.src_port) == (flow.a_ip, flow.a_port)
        payload_len = len(pkt.payload)
        if from_a:
            flow.packets_a2b += 1
            flow.bytes_a2b += payload_len
            if len(flow.a2b_ts) < 4096:
                flow.a2b_ts.append(pkt.ts)
        else:
            flow.packets_b2a += 1
            flow.bytes_b2a += payload_len

        if pkt.proto == IPProto.TCP:
            f = pkt.tcp_flags
            if f & TCP_SYN and not (f & TCP_ACK):
                flow.saw_syn = True
            if (f & TCP_SYN) and (f & TCP_ACK):
                flow.saw_synack = True
            if f & TCP_FIN:
                flow.saw_fin = True
            if f & TCP_RST:
                flow.saw_rst = True

    @staticmethod
    def _canonical_key(pkt: Packet) -> tuple[str, int, str, int, int]:
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        if a <= b:
            return (a[0], a[1], b[0], b[1], pkt.proto)
        return (b[0], b[1], a[0], a[1], pkt.proto)

    def top_talkers(self, n: int = 10) -> list[tuple[str, int, int]]:
        """Return [(ip, packets, bytes), ...] sorted by bytes desc."""
        agg: dict[str, list[int]] = {}
        for flow in self.flows.values():
            for ip, pkts, byts in (
                (flow.a_ip, flow.packets_a2b, flow.bytes_a2b),
                (flow.b_ip, flow.packets_b2a, flow.bytes_b2a),
            ):
                slot = agg.setdefault(ip, [0, 0])
                slot[0] += pkts
                slot[1] += byts
        ranked = sorted(
            ((ip, p, b) for ip, (p, b) in agg.items()),
            key=lambda x: x[2],
            reverse=True,
        )
        return ranked[:n]

    def top_dst_ports(self, n: int = 10) -> list[tuple[int, int, int]]:
        """Return [(port, flows, packets), ...] sorted by flow count desc.

        Port is taken from the *non-initiator* side (the server / service)
        which is what an analyst expects to see in a top-ports view.
        """
        agg: dict[int, list[int]] = {}
        for flow in self.flows.values():
            if flow.b_port == 0:
                continue
            slot = agg.setdefault(flow.b_port, [0, 0])
            slot[0] += 1
            slot[1] += flow.total_packets
        ranked = sorted(
            ((p, f, pk) for p, (f, pk) in agg.items()),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[:n]

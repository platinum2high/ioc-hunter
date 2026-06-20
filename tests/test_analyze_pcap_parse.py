"""Unit tests for the PCAP container + dissectors."""

from __future__ import annotations

import struct

import pytest

from ioc_hunter.analyze.pcap_parse import (
    FlowTable,
    Frame,
    IPProto,
    detect_pcap_format,
    dissect_frame,
    iter_frames,
    iter_packets,
    iter_pcap_classic,
    iter_pcapng,
)
from tests._pcap_fixtures import (
    build_pcap,
    build_pcapng,
    dns_query,
    eth_ipv4_icmp,
    eth_ipv4_tcp,
    eth_ipv4_udp,
    eth_ipv6_tcp,
)

# ---------------------------------------------------------------------------
# detect_pcap_format
# ---------------------------------------------------------------------------


def test_detect_pcap_classic_microsecond():
    head = build_pcap([])[:16]
    assert detect_pcap_format(head) == "pcap"


def test_detect_pcap_classic_nanosecond():
    head = build_pcap([], nanosecond=True)[:16]
    assert detect_pcap_format(head) == "pcap"


def test_detect_pcapng():
    head = build_pcapng([])[:16]
    assert detect_pcap_format(head) == "pcapng"


def test_detect_random_bytes():
    assert detect_pcap_format(b"") == ""
    assert detect_pcap_format(b"\x00" * 12) == ""
    assert detect_pcap_format(b"MZ\x90\x00") == ""


# ---------------------------------------------------------------------------
# Container walkers
# ---------------------------------------------------------------------------


def test_classic_yields_frames_in_order():
    raw = build_pcap(
        [
            (1.0, eth_ipv4_udp("10.0.0.1", "10.0.0.2", 1000, 53, dns_query("a.com"))),
            (2.5, eth_ipv4_udp("10.0.0.2", "10.0.0.1", 53, 1000, dns_query("a.com"))),
        ]
    )
    frames = list(iter_pcap_classic(raw))
    assert len(frames) == 2
    assert frames[0].ts == pytest.approx(1.0)
    assert frames[1].ts == pytest.approx(2.5)


def test_classic_nanosecond_timestamps_round_correctly():
    raw = build_pcap(
        [(1.000000003, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1, 2, b""))], nanosecond=True
    )
    frames = list(iter_pcap_classic(raw))
    assert frames[0].ts == pytest.approx(1.000000003, abs=1e-9)


def test_classic_swapped_endianness_magic_detected():
    # Stamp the BE magic on a 16-byte header and confirm detect routes it
    # to "pcap". Full BE-walk parsing is exercised indirectly through real
    # captures (which are routinely little-endian on the platforms we run on);
    # what matters here is the magic dispatch.
    head = bytearray(b"\x00" * 16)
    head[0:4] = struct.pack(">I", 0xA1B2C3D4)
    assert detect_pcap_format(bytes(head)) == "pcap"


def test_pcapng_yields_frames_with_correct_link_type():
    raw = build_pcapng(
        [
            (
                5.0,
                eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1000, 80, payload=b"GET / HTTP/1.1\r\n\r\n"),
            ),
        ]
    )
    frames = list(iter_pcapng(raw))
    assert len(frames) == 1
    assert frames[0].link_type == 1  # Ethernet


def test_pcapng_block_skipping_unknown_block_type():
    # Build a SHB + an unknown block + an IDB + an EPB. The unknown block has
    # a valid block_total_length so the walker must skip past it.
    base = build_pcapng([(0.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1, 2, b""))])
    # The fixture above already builds SHB+IDB+EPB. Insert a 16-byte unknown
    # block after the SHB (which is the first 28 bytes).
    shb_end = 28
    unknown_total = 16
    unknown = (
        struct.pack("<II", 0xDEADBEEF, unknown_total)
        + b"\x00" * (unknown_total - 12)
        + struct.pack("<I", unknown_total)
    )
    raw = base[:shb_end] + unknown + base[shb_end:]
    frames = list(iter_pcapng(raw))
    assert len(frames) == 1


def test_classic_truncated_record_stops_cleanly():
    raw = build_pcap([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1, 2, b"AAAA"))])
    # Lop off the last 5 bytes — last record's data is now short.
    truncated = raw[:-5]
    frames = list(iter_pcap_classic(truncated))
    assert frames == []  # Should bail rather than crash.


def test_max_frames_cap_obeyed():
    raw = build_pcap(
        [(float(i), eth_ipv4_udp("1.1.1.1", "2.2.2.2", i, 53, b"")) for i in range(50)]
    )
    frames = list(iter_pcap_classic(raw, max_frames=10))
    assert len(frames) == 10


# ---------------------------------------------------------------------------
# L2/L3/L4 dissection
# ---------------------------------------------------------------------------


def test_dissect_ipv4_tcp():
    frame = Frame(
        ts=1.0,
        link_type=1,
        data=eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, payload=b"hi"),
        orig_len=0,
    )
    pkt = dissect_frame(frame, 1)
    assert pkt is not None
    assert pkt.src_ip == "10.0.0.1"
    assert pkt.dst_ip == "10.0.0.2"
    assert pkt.src_port == 12345
    assert pkt.dst_port == 80
    assert pkt.proto == IPProto.TCP
    assert pkt.payload == b"hi"
    assert pkt.is_ipv6 is False


def test_dissect_ipv6_tcp():
    frame = Frame(
        ts=1.0,
        link_type=1,
        data=eth_ipv6_tcp("2001:db8::1", "2001:db8::2", 1234, 443, payload=b"x"),
        orig_len=0,
    )
    pkt = dissect_frame(frame, 1)
    assert pkt is not None
    assert pkt.is_ipv6
    assert pkt.src_ip == "2001:db8::1"
    assert pkt.dst_port == 443


def test_dissect_ipv4_icmp():
    frame = Frame(
        ts=1.0, link_type=1, data=eth_ipv4_icmp("10.0.0.1", "10.0.0.2", b"PING_PAYLOAD"), orig_len=0
    )
    pkt = dissect_frame(frame, 1)
    assert pkt is not None
    assert pkt.proto == IPProto.ICMP
    assert pkt.src_port == 0 and pkt.dst_port == 0
    assert b"PING_PAYLOAD" in pkt.payload


def test_dissect_truncated_ip_returns_none():
    frame = Frame(ts=1.0, link_type=1, data=b"\x00" * 14 + b"\x45\x00\x00", orig_len=0)
    assert dissect_frame(frame, 1) is None


def test_dissect_unknown_etype_returns_none():
    payload = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + b"\x88\xcc" + b"AAAA"  # LLDP
    frame = Frame(ts=1.0, link_type=1, data=payload, orig_len=0)
    assert dissect_frame(frame, 1) is None


def test_dissect_vlan_tagged_frame():
    # Eth header: dst+src+ethertype(VLAN)+vlan_tag+inner_ethertype(IPv4)+ip...
    eth = (
        b"\x02" * 6
        + b"\x03" * 6
        + struct.pack(">H", 0x8100)
        + struct.pack(">H", 100)
        + struct.pack(">H", 0x0800)
    )
    from tests._pcap_fixtures import ipv4, tcp

    payload = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1000, 80, payload=b"x"))
    frame = Frame(ts=1.0, link_type=1, data=eth + payload, orig_len=0)
    pkt = dissect_frame(frame, 1)
    assert pkt is not None
    assert pkt.dst_port == 80


# ---------------------------------------------------------------------------
# Flow table
# ---------------------------------------------------------------------------


def test_flow_table_aggregates_bidirectional():
    raw = build_pcap(
        [
            (1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 12345, 80, flags=0x02)),  # SYN
            (1.1, eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 80, 12345, flags=0x12)),  # SYN-ACK
            (
                1.2,
                eth_ipv4_tcp(
                    "10.0.0.1", "10.0.0.2", 12345, 80, flags=0x18, payload=b"GET / HTTP/1.0\r\n\r\n"
                ),
            ),
            (
                1.3,
                eth_ipv4_tcp(
                    "10.0.0.2",
                    "10.0.0.1",
                    80,
                    12345,
                    flags=0x18,
                    payload=b"HTTP/1.0 200 OK\r\n\r\n",
                ),
            ),
        ]
    )
    ft = FlowTable()
    for pkt in iter_packets(raw):
        ft.update(pkt)
    assert len(ft.flows) == 1
    flow = next(iter(ft.flows.values()))
    assert flow.a_ip == "10.0.0.1"  # initiator (SYN sender)
    assert flow.b_ip == "10.0.0.2"
    assert flow.b_port == 80
    assert flow.saw_syn and flow.saw_synack
    assert flow.bytes_a2b > 0 and flow.bytes_b2a > 0


def test_flow_table_top_talkers_orders_by_bytes():
    raw = build_pcap(
        [
            (1.0, eth_ipv4_tcp("1.1.1.1", "2.2.2.2", 1, 80, payload=b"A" * 100)),
            (1.1, eth_ipv4_tcp("3.3.3.3", "2.2.2.2", 2, 80, payload=b"B" * 200)),
        ]
    )
    ft = FlowTable()
    for pkt in iter_packets(raw):
        ft.update(pkt)
    talkers = ft.top_talkers(3)
    # 2.2.2.2 is the destination of both flows (zero bytes back); top two senders
    # are 3.3.3.3 (200 B) then 1.1.1.1 (100 B).
    ips = [t[0] for t in talkers]
    assert ips[0] == "3.3.3.3"
    assert "1.1.1.1" in ips


# ---------------------------------------------------------------------------
# End-to-end iter_packets path
# ---------------------------------------------------------------------------


def test_iter_packets_skips_non_ip_frames_gracefully():
    # Mix a valid IPv4 packet with an LLDP frame; ensure we yield only the IPv4.
    lldp = b"\x02" * 6 + b"\x03" * 6 + struct.pack(">H", 0x88CC) + b"LLDP_BYTES"
    raw = build_pcap(
        [
            (1.0, lldp),
            (1.1, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 53000, 53, dns_query("x.io"))),
        ]
    )
    pkts = list(iter_packets(raw))
    assert len(pkts) == 1
    assert pkts[0].dst_port == 53


def test_iter_frames_routes_classic_and_pcapng_through_same_api():
    one = build_pcap([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1, 2, b""))])
    two = build_pcapng([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1, 2, b""))])
    assert len(list(iter_frames(one))) == 1
    assert len(list(iter_frames(two))) == 1

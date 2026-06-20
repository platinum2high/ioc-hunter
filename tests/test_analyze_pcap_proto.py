"""Tests for the application-layer protocol dissectors."""

from __future__ import annotations

import hashlib
import struct

from ioc_hunter.analyze.pcap_parse import iter_packets
from ioc_hunter.analyze.pcap_proto import (
    DNSStats,
    _Stitcher,
    dissect_dns,
    dissect_http_request,
    dissect_http_response,
    dissect_tls_clienthello,
    flag_bad_user_agent,
    parse_dns_message,
)
from tests._pcap_fixtures import (
    build_pcap,
    dns_query,
    dns_response,
    eth_ipv4_tcp,
    eth_ipv4_udp,
    http_request,
    http_response,
    synth_tls_clienthello,
)

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def test_dns_query_parses_basic_a_record():
    msg = parse_dns_message(dns_query("malicious.example.com", 1))
    assert msg is not None
    assert msg.qname == "malicious.example.com"
    assert msg.qtype == 1
    assert msg.is_response is False


def test_dns_response_nxdomain_flagged():
    msg = parse_dns_message(dns_response("does.not.exist", rcode=3, answer_count=0))
    assert msg is not None
    assert msg.is_response and msg.rcode == 3


def test_dns_compressed_name_pointer_loop_does_not_hang():
    # Build a header + first byte 0xC0 0x0C pointing to itself's offset (12).
    # The decoder caps hops at 16; this must return None, not hang.
    payload = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    msg = parse_dns_message(payload)
    assert msg is None


def test_dissect_dns_updates_stats():
    raw = build_pcap(
        [
            (1.0, eth_ipv4_udp("10.0.0.5", "8.8.8.8", 50000, 53, dns_query("evil.example", 16))),
            (
                1.1,
                eth_ipv4_udp(
                    "8.8.8.8",
                    "10.0.0.5",
                    53,
                    50000,
                    dns_response("evil.example", qtype=16, txt_value=b"X" * 200),
                ),
            ),
            (1.2, eth_ipv4_udp("10.0.0.5", "8.8.8.8", 50001, 53, dns_query("nothere.example"))),
            (
                1.3,
                eth_ipv4_udp(
                    "8.8.8.8",
                    "10.0.0.5",
                    53,
                    50001,
                    dns_response("nothere.example", rcode=3, answer_count=0),
                ),
            ),
        ]
    )
    stats = DNSStats()
    for pkt in iter_packets(raw):
        dissect_dns(pkt, stats)
    assert stats.queries == 2
    assert stats.responses == 2
    assert stats.nxdomain == 1
    assert stats.txt_query_bytes > 0
    assert "evil.example" in stats.per_name
    assert stats.per_name["nothere.example"]["nx"] == 1


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def test_dissect_http_request_extracts_host_and_ua():
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    "10.0.0.1",
                    "10.0.0.2",
                    1000,
                    80,
                    payload=http_request("GET", "evil.host", "/path?a=1", user_agent="Mozilla/4.0"),
                ),
            ),
        ]
    )
    stitcher = _Stitcher()
    req = None
    for pkt in iter_packets(raw):
        buf = stitcher.feed(pkt)
        req = dissect_http_request(buf, pkt)
        if req:
            break
    assert req is not None
    assert req.method == "GET"
    assert req.host == "evil.host"
    assert req.uri == "/path?a=1"
    assert req.user_agent == "Mozilla/4.0"
    assert req.has_basic_auth is False


def test_dissect_http_request_flags_basic_auth():
    payload = http_request(
        "POST",
        "internal.app",
        "/login",
        extra_headers=(("Authorization", "Basic YWRtaW46aHVudGVyMg=="),),
    )
    raw = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 80, payload=payload))])
    stitcher = _Stitcher()
    req = None
    for pkt in iter_packets(raw):
        req = dissect_http_request(stitcher.feed(pkt), pkt)
    assert req is not None and req.has_basic_auth


def test_dissect_http_response_parses_status():
    raw = build_pcap(
        [(1.0, eth_ipv4_tcp("10.0.0.2", "10.0.0.1", 80, 1, payload=http_response(404, b"")))]
    )
    stitcher = _Stitcher()
    resp = None
    for pkt in iter_packets(raw):
        resp = dissect_http_response(stitcher.feed(pkt), pkt)
    assert resp is not None
    assert resp.status == 404
    assert resp.server == "test/0"


def test_flag_bad_user_agent_emotet_mozilla_4():
    assert flag_bad_user_agent("Mozilla/4.0") is not None


def test_flag_bad_user_agent_curl():
    assert flag_bad_user_agent("curl/8.4.0") is not None


def test_flag_bad_user_agent_empty():
    assert flag_bad_user_agent("") is not None


def test_flag_bad_user_agent_chrome_clean():
    assert (
        flag_bad_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36")
        is None
    )


# ---------------------------------------------------------------------------
# TLS / JA3
# ---------------------------------------------------------------------------


def test_tls_clienthello_extracts_sni_and_alpn():
    ch_bytes = synth_tls_clienthello(sni="login.microsoft.com")
    raw = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=ch_bytes))])
    stitcher = _Stitcher()
    ch = None
    for pkt in iter_packets(raw):
        buf = stitcher.feed(pkt)
        ch = dissect_tls_clienthello(buf, pkt)
    assert ch is not None
    assert ch.sni == "login.microsoft.com"
    assert "h2" in ch.alpn


def test_tls_ja3_is_deterministic_and_matches_spec():
    ch_bytes = synth_tls_clienthello(
        sni="api.test",
        version=0x0303,
        ciphers=(0xC02B, 0xC02F),
        extensions_order=(0x0000, 0x000A, 0x000B),
        curves=(0x001D,),
        ec_pt_fmts=(0,),
    )
    raw = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=ch_bytes))])
    stitcher = _Stitcher()
    ch = None
    for pkt in iter_packets(raw):
        ch = dissect_tls_clienthello(stitcher.feed(pkt), pkt)
    assert ch is not None
    expected_string = "771,49195-49199,0-10-11,29,0"
    expected_md5 = hashlib.md5(expected_string.encode()).hexdigest()
    assert ch.ja3_string == expected_string
    assert ch.ja3_md5 == expected_md5


def test_tls_ja3_strips_grease():
    # Inject GREASE values 0x0A0A and 0x1A1A into the cipher list; JA3 must
    # drop them so the fingerprint matches the GREASE-less version.
    plain = synth_tls_clienthello(sni="x", ciphers=(0xC02B,), extensions_order=(0x0000,))
    grea = synth_tls_clienthello(
        sni="x", ciphers=(0x0A0A, 0xC02B, 0x1A1A), extensions_order=(0x0000,)
    )
    raw_a = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=plain))])
    raw_b = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=grea))])
    stitcher = _Stitcher()
    a = next(
        filter(None, (dissect_tls_clienthello(stitcher.feed(p), p) for p in iter_packets(raw_a)))
    )
    stitcher = _Stitcher()
    b = next(
        filter(None, (dissect_tls_clienthello(stitcher.feed(p), p) for p in iter_packets(raw_b)))
    )
    assert a.ja3_md5 == b.ja3_md5


def test_tls_clienthello_rejects_non_handshake_record():
    # Record type 0x17 = application_data
    bad = b"\x17\x03\x03\x00\x05" + b"\x00" * 5
    raw = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=bad))])
    stitcher = _Stitcher()
    for pkt in iter_packets(raw):
        ch = dissect_tls_clienthello(stitcher.feed(pkt), pkt)
        assert ch is None


def test_tls_clienthello_handles_no_extensions():
    # Older TLS hellos can omit the extensions block entirely.
    ch_bytes = synth_tls_clienthello(extensions_order=())
    raw = build_pcap([(1.0, eth_ipv4_tcp("10.0.0.1", "10.0.0.2", 1, 443, payload=ch_bytes))])
    stitcher = _Stitcher()
    ch = None
    for pkt in iter_packets(raw):
        ch = dissect_tls_clienthello(stitcher.feed(pkt), pkt)
    assert ch is not None
    assert ch.sni == ""  # no SNI extension supplied

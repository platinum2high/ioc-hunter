"""End-to-end tests: bytes → ``analyze()`` → ``AnalyzerReport``.

We assemble synthetic captures that combine multiple signals (beacon
plus DGA plus FTP creds plus exfil) and confirm every expected
finding rule fires, formats are routed through the dispatcher, and
the markdown renderer produces something sensible.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ioc_hunter.analyze import FileFormat, analyze, to_markdown
from tests._pcap_fixtures import (
    build_pcap,
    build_pcapng,
    dns_query,
    dns_response,
    eth_ipv4_icmp,
    eth_ipv4_tcp,
    eth_ipv4_udp,
    http_request,
    synth_tls_clienthello,
)


def _write_pcap(raw: bytes) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(raw)
        return Path(f.name)


# ---------------------------------------------------------------------------
# Dispatcher routing
# ---------------------------------------------------------------------------


def test_dispatcher_routes_classic_pcap():
    raw = build_pcap([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1000, 53, dns_query("x.io")))])
    path = _write_pcap(raw)
    report = analyze(path)
    assert report.format == FileFormat.PCAP
    summary = report.metadata.get("pcap_summary")
    assert summary is not None
    assert summary["packets_dissected"] == 1


def test_dispatcher_routes_pcapng():
    raw = build_pcapng([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1000, 53, dns_query("x.io")))])
    path = _write_pcap(raw)
    report = analyze(path)
    assert report.format == FileFormat.PCAP


# ---------------------------------------------------------------------------
# Composite signals
# ---------------------------------------------------------------------------


def test_beaconing_signal_fires_end_to_end():
    frames = []
    for i in range(12):
        frames.append(
            (
                100.0 + 60.0 * i + 0.03 * (i % 4),
                eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 51000, 443, payload=b"X" * 16),
            )
        )
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.beaconing" in rules


def test_dga_dns_signal_fires_end_to_end():
    frames = []
    for i, name in enumerate(
        [
            "vqxznmkpfhg.com",
            "rzxvbnmwerty.net",
            "kjhwbcxpvnzm.org",
            "btxkcnxrtgmd.io",
            "qzwxrtbnmhgf.cc",
        ]
    ):
        frames.append(
            (1.0 + i, eth_ipv4_udp("10.0.0.5", "8.8.8.8", 50000 + i, 53, dns_query(name)))
        )
        frames.append(
            (1.0 + i + 0.05, eth_ipv4_udp("8.8.8.8", "10.0.0.5", 53, 50000 + i, dns_response(name)))
        )
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.dga_dns" in rules


def test_ftp_plaintext_creds_signal_fires_end_to_end():
    frames = [
        (1.0, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 21, payload=b"USER admin\r\n")),
        (1.1, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 21, payload=b"PASS hunter2\r\n")),
    ]
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.plaintext_ftp_creds" in rules


def test_exfil_signal_fires_end_to_end():
    frames = [
        (
            float(i) * 0.05,
            eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 443, payload=b"X" * 1400),
        )
        for i in range(250)
    ]
    frames.append((20.0, eth_ipv4_tcp("203.0.113.10", "10.0.0.5", 443, 60000, payload=b"ok")))
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.unidirectional_exfil" in rules


def test_tls_clienthello_summary_includes_ja3_and_sni():
    ch = synth_tls_clienthello(sni="suspicious.example.com")
    frames = [(1.0, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 50000, 443, payload=ch))]
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    summary = report.metadata["pcap_summary"]
    assert "suspicious.example.com" in summary["tls"]["snis"]
    assert summary["tls"]["distinct_ja3"] == 1


def test_http_basic_auth_signal_fires_end_to_end():
    payload = http_request(
        "POST",
        "internal.app",
        "/api/login",
        extra_headers=(("Authorization", "Basic YWRtaW46aHVudGVyMg=="),),
    )
    frames = [(1.0, eth_ipv4_tcp("10.0.0.5", "10.0.0.10", 50000, 80, payload=payload))]
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.plaintext_http_basic" in rules


def test_icmp_tunnel_signal_fires_end_to_end():
    frames = [
        (float(i) * 0.1, eth_ipv4_icmp("10.0.0.5", "203.0.113.10", b"X" * 300)) for i in range(25)
    ]
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    rules = {f.rule for f in report.findings}
    assert "pcap.icmp_tunnel" in rules


def test_iocs_include_dns_and_tls_extracted_names():
    ch = synth_tls_clienthello(sni="exfil.attacker.tld")
    frames = [
        (1.0, eth_ipv4_udp("10.0.0.5", "8.8.8.8", 50000, 53, dns_query("c2.attacker.tld"))),
        (1.1, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 50000, 443, payload=ch)),
    ]
    raw = build_pcap(frames)
    report = analyze(_write_pcap(raw))
    ioc_values = {ioc.value for ioc in report.iocs}
    assert "c2.attacker.tld" in ioc_values
    assert "exfil.attacker.tld" in ioc_values


def test_markdown_renderer_handles_pcap_report():
    raw = build_pcap([(1.0, eth_ipv4_udp("1.1.1.1", "2.2.2.2", 1000, 53, dns_query("x.io")))])
    report = analyze(_write_pcap(raw))
    md = to_markdown(report)
    assert "Binary Analysis Report" in md
    assert "PCAP" in md  # format header

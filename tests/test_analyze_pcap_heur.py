"""Tests for behavioural heuristics over PCAP captures."""

from __future__ import annotations

import pytest

from ioc_hunter.analyze.pcap_heur import (
    consonant_run,
    detect_beacons,
    detect_exfil,
    detect_icmp_tunnel,
    detect_scans,
    find_dga_names,
    find_ftp_credentials,
    looks_dga,
    second_level_label,
    shannon_entropy_str,
)
from ioc_hunter.analyze.pcap_parse import FlowTable, iter_packets
from ioc_hunter.analyze.pcap_proto import DNSStats
from tests._pcap_fixtures import (
    build_pcap,
    eth_ipv4_icmp,
    eth_ipv4_tcp,
)

# ---------------------------------------------------------------------------
# Utility heuristics
# ---------------------------------------------------------------------------


def test_shannon_entropy_str_known_values():
    assert shannon_entropy_str("") == 0
    assert shannon_entropy_str("aaaa") == pytest.approx(0.0)
    assert shannon_entropy_str("ab") == pytest.approx(1.0)


def test_consonant_run_picks_longest():
    assert consonant_run("strength") == 4  # 'str' + 'ngth' → longest 'ngth' (4)
    assert consonant_run("aeiou") == 0
    assert consonant_run("xxxxxx") == 6


def test_second_level_label_basic():
    assert second_level_label("www.example.com") == "example"
    assert second_level_label("example.com") == "example"


def test_second_level_label_compound_tld():
    assert second_level_label("ministry.gov.uk") == "ministry"
    assert second_level_label("foo.bar.example.co.uk") == "example"


def test_looks_dga_rejects_real_brand_names():
    assert not looks_dga("microsoft")
    assert not looks_dga("google")
    assert not looks_dga("github")
    assert not looks_dga("cloudflare")


def test_looks_dga_flags_high_entropy_strings():
    assert looks_dga("zxqvbngrt")
    assert looks_dga("k3hd9zqs7v")


def test_looks_dga_ignores_short_labels():
    assert not looks_dga("zxqvb")  # too short to trust


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------


def _flow_with_packets_at(ts_list, *, src="10.0.0.5", dst="93.184.216.34", dport=443):
    """Build a flow table from synthetic packets at the given timestamps."""
    frames = []
    for ts in ts_list:
        frames.append((ts, eth_ipv4_tcp(src, dst, 50000, dport, flags=0x18, payload=b"x" * 16)))
    raw = build_pcap(frames)
    ft = FlowTable()
    for pkt in iter_packets(raw):
        ft.update(pkt)
    return list(ft.flows.values())


def test_detect_beacons_finds_periodic_flow():
    # 60-second beacon with sub-second jitter (positive timestamps only).
    timestamps = [100.0 + 60.0 * i + (0.05 * (i % 3)) for i in range(10)]
    flows = _flow_with_packets_at(timestamps)
    beacons = detect_beacons(flows)
    assert len(beacons) == 1
    b = beacons[0]
    assert b.dst_ip == "93.184.216.34"
    assert b.mean_interval == pytest.approx(60.0, rel=0.05)


def test_detect_beacons_rejects_random_intervals():
    import random

    random.seed(42)
    timestamps = sorted(random.uniform(0, 600) for _ in range(20))
    flows = _flow_with_packets_at(timestamps)
    beacons = detect_beacons(flows)
    assert beacons == []  # noisy chatter, not a beacon


def test_detect_beacons_rejects_too_few_packets():
    flows = _flow_with_packets_at([0.0, 60.0, 120.0])  # only 3 packets
    assert detect_beacons(flows) == []


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def test_detect_vertical_port_scan():
    frames = [
        (float(i) * 0.01, eth_ipv4_tcp("10.0.0.99", "10.0.0.10", 50000 + i, 80 + i, flags=0x02))
        for i in range(30)
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    scans = detect_scans(pkts)
    assert any(s.kind == "vertical" and s.src_ip == "10.0.0.99" for s in scans)


def test_detect_horizontal_sweep():
    frames = [
        (float(i) * 0.01, eth_ipv4_tcp("10.0.0.99", f"10.0.0.{i + 1}", 50000, 445, flags=0x02))
        for i in range(40)
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    scans = detect_scans(pkts)
    assert any(s.kind == "horizontal" and s.target == "port=445" for s in scans)


def test_detect_scans_ignores_syn_ack_responses():
    # Server side returning SYN+ACK to many sources must not count as a scan.
    frames = [
        (float(i) * 0.01, eth_ipv4_tcp("10.0.0.10", f"10.0.0.{i + 1}", 80, 50000, flags=0x12))
        for i in range(40)
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    assert detect_scans(pkts) == []


# ---------------------------------------------------------------------------
# Exfil
# ---------------------------------------------------------------------------


def test_detect_exfil_one_sided_upload():
    # 300 KiB upload, ~1 KiB back
    frames = [
        (
            float(i) * 0.1,
            eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 443, payload=b"X" * 1400),
        )
        for i in range(300)
    ]
    # Send back a few packets worth of acks
    frames.append((50.0, eth_ipv4_tcp("203.0.113.10", "10.0.0.5", 443, 60000, payload=b"ok")))
    raw = build_pcap(frames)
    ft = FlowTable()
    for pkt in iter_packets(raw):
        ft.update(pkt)
    exfil = detect_exfil(list(ft.flows.values()))
    assert len(exfil) == 1
    assert exfil[0].bytes_out > exfil[0].bytes_in * 100


def test_detect_exfil_ignores_balanced_flow():
    frames = []
    for i in range(50):
        frames.append(
            (float(i) * 0.1, eth_ipv4_tcp("10.0.0.5", "10.0.0.10", 60000, 80, payload=b"X" * 6000))
        )
        frames.append(
            (
                float(i) * 0.1 + 0.05,
                eth_ipv4_tcp("10.0.0.10", "10.0.0.5", 80, 60000, payload=b"Y" * 6000),
            )
        )
    raw = build_pcap(frames)
    ft = FlowTable()
    for pkt in iter_packets(raw):
        ft.update(pkt)
    assert detect_exfil(list(ft.flows.values())) == []


# ---------------------------------------------------------------------------
# DGA on DNS stats
# ---------------------------------------------------------------------------


def test_find_dga_names_picks_only_algorithm_shapes():
    stats = DNSStats()
    for name in (
        "microsoft.com",
        "google.com",
        "vqxznmkpfhg.com",
        "rzxvbnmwerty.net",
        "asdqwerty.io",
        "github.com",
    ):
        stats.per_name[name] = {"q": 1, "nx": 0, "txt": 0}
    hits = sorted(find_dga_names(stats))
    assert "microsoft.com" not in hits
    assert "google.com" not in hits
    assert "vqxznmkpfhg.com" in hits


# ---------------------------------------------------------------------------
# ICMP tunnel
# ---------------------------------------------------------------------------


def test_detect_icmp_tunnel_flags_large_payload_floods():
    frames = [
        (float(i) * 0.1, eth_ipv4_icmp("10.0.0.5", "203.0.113.10", b"X" * 300)) for i in range(25)
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    tunnels = detect_icmp_tunnel(pkts)
    assert len(tunnels) == 1
    assert tunnels[0].big_packets >= 20


def test_detect_icmp_tunnel_ignores_normal_ping():
    frames = [
        (float(i) * 0.1, eth_ipv4_icmp("10.0.0.5", "10.0.0.10", b"X" * 32)) for i in range(25)
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    assert detect_icmp_tunnel(pkts) == []


# ---------------------------------------------------------------------------
# FTP plaintext creds
# ---------------------------------------------------------------------------


def test_find_ftp_credentials_extracts_user_pass():
    frames = [
        (1.0, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 21, payload=b"USER admin\r\n")),
        (1.1, eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 60000, 21, payload=b"PASS hunter2\r\n")),
    ]
    raw = build_pcap(frames)
    pkts = list(iter_packets(raw))
    creds = find_ftp_credentials(pkts)
    verbs = [c[2].split(":")[0] for c in creds]
    assert "USER" in verbs and "PASS" in verbs

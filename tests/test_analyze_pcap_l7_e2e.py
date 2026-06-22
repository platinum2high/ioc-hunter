"""End-to-end tests for the phase-14.3b L7 layer.

Assemble real captures, push them through ``analyze()``, and assert the
right findings fire, the ATT&CK tags attach, and ``pcap_summary`` carries
the JA3S / SMB / Kerberos sections the CLI renders.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ioc_hunter.analyze import FileFormat, analyze
from ioc_hunter.analyze import pcap_heur as heur
from ioc_hunter.analyze.pcap_parse import IPProto, Packet
from ioc_hunter.analyze.pcap_proto import dissect_tls_clienthello
from tests._pcap_fixtures import (
    build_pcap,
    eth_ipv4_tcp,
    krb_as_req,
    krb_tcp,
    krb_tgs_rep,
    ntlm_authenticate,
    ntlm_challenge,
    smb1_negotiate,
    smb2_session_setup,
    smb2_tree_connect,
    synth_tls_clienthello,
    synth_tls_serverhello,
)

CLIENT = "10.0.0.5"
SERVER = "10.0.0.9"


def _write(raw: bytes) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(raw)
        return Path(f.name)


def _rules(report) -> set[str]:
    return {f.rule for f in report.findings}


# ---------------------------------------------------------------------------
# JA3S
# ---------------------------------------------------------------------------


def test_serverhello_surfaces_ja3s_in_summary():
    ch = synth_tls_clienthello("example.com")
    sh = synth_tls_serverhello()
    raw = build_pcap(
        [
            (1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, flags=0x02)),  # SYN
            (1.1, eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, payload=ch)),
            (1.2, eth_ipv4_tcp(SERVER, CLIENT, 443, 50000, payload=sh)),
        ]
    )
    report = analyze(_write(raw))
    tls = report.metadata["pcap_summary"]["tls"]
    assert tls["client_hellos"] == 1
    assert tls["server_hellos"] == 1
    assert tls["distinct_ja3s"] == 1
    assert len(tls["ja3s_sample"]) == 1


def test_known_bad_ja3_fires_finding(monkeypatch):
    ch = synth_tls_clienthello("evil.example")
    pkt = Packet(
        ts=1.0,
        frame_no=1,
        src_ip=CLIENT,
        dst_ip=SERVER,
        src_port=50000,
        dst_port=443,
        proto=IPProto.TCP,
        is_ipv6=False,
        payload=ch,
    )
    ja3 = dissect_tls_clienthello(ch, pkt).ja3_md5
    monkeypatch.setitem(heur.KNOWN_BAD_JA3, ja3, "Test C2 profile")
    raw = build_pcap([(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, payload=ch))])
    report = analyze(_write(raw))
    rules = _rules(report)
    assert "pcap.ja3_known_bad" in rules
    finding = next(f for f in report.findings if f.rule == "pcap.ja3_known_bad")
    assert "T1071.001" in finding.mitre


def test_tls_non_standard_port_flagged():
    ch = synth_tls_clienthello("c2.example")
    raw = build_pcap([(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 4444, payload=ch))])
    report = analyze(_write(raw))
    assert "pcap.tls_non_standard_port" in _rules(report)


def test_tls_no_sni_on_443_flagged():
    ch = synth_tls_clienthello("")  # no SNI
    raw = build_pcap([(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 443, payload=ch))])
    report = analyze(_write(raw))
    assert "pcap.tls_no_sni" in _rules(report)


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------


def test_smb_admin_share_fires_lateral_movement_finding():
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    CLIENT, SERVER, 50000, 445, payload=smb2_tree_connect(r"\\DC01\ADMIN$")
                ),
            )
        ]
    )
    report = analyze(_write(raw))
    rules = _rules(report)
    assert "pcap.smb_admin_share" in rules
    finding = next(f for f in report.findings if f.rule == "pcap.smb_admin_share")
    assert "T1021.002" in finding.mitre
    assert report.metadata["pcap_summary"]["smb"]["admin_shares"] == [r"\\DC01\ADMIN$"]


def test_smb_ipc_share_does_not_fire():
    raw = build_pcap(
        [(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 445, payload=smb2_tree_connect(r"\\DC01\IPC$")))]
    )
    report = analyze(_write(raw))
    assert "pcap.smb_admin_share" not in _rules(report)


def test_smb1_legacy_dialect_flagged():
    raw = build_pcap([(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 445, payload=smb1_negotiate()))])
    report = analyze(_write(raw))
    assert "pcap.smb1_in_use" in _rules(report)
    assert "SMB1" in report.metadata["pcap_summary"]["smb"]["dialects"]


# ---------------------------------------------------------------------------
# NTLM credential capture
# ---------------------------------------------------------------------------


def test_netntlmv2_capture_assembles_crackable_hash():
    sc = b"\x11" * 8
    nt = b"\xaa" * 16 + b"\xbb" * 20
    challenge = smb2_session_setup(ntlm_challenge(sc, "CORP"))
    authenticate = smb2_session_setup(ntlm_authenticate("CORP", "jdoe", "WS01", nt))
    raw = build_pcap(
        [
            (1.0, eth_ipv4_tcp(SERVER, CLIENT, 445, 50000, payload=challenge)),  # type 2
            (1.1, eth_ipv4_tcp(CLIENT, SERVER, 50000, 445, payload=authenticate)),  # type 3
        ]
    )
    report = analyze(_write(raw))
    rules = _rules(report)
    assert "pcap.netntlmv2_capture" in rules
    finding = next(f for f in report.findings if f.rule == "pcap.netntlmv2_capture")
    expected = "jdoe::CORP:" + sc.hex() + ":" + ("aa" * 16) + ":" + ("bb" * 20)
    assert finding.evidence[0] == expected
    assert "T1557.001" in finding.mitre
    assert report.metadata["pcap_summary"]["ntlm_observed"] is True


def test_netntlm_without_challenge_does_not_assemble():
    # Authenticate with no preceding challenge → nothing to pair against.
    authenticate = smb2_session_setup(ntlm_authenticate())
    raw = build_pcap([(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 445, payload=authenticate))])
    report = analyze(_write(raw))
    assert "pcap.netntlmv2_capture" not in _rules(report)


# ---------------------------------------------------------------------------
# Kerberos
# ---------------------------------------------------------------------------


def test_kerberoasting_fires_on_rc4_service_ticket():
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    SERVER, CLIENT, 88, 50000, payload=krb_tcp(krb_tgs_rep(ticket_etype=23))
                ),
            )
        ]
    )
    report = analyze(_write(raw))
    rules = _rules(report)
    assert "pcap.kerberoasting" in rules
    finding = next(f for f in report.findings if f.rule == "pcap.kerberoasting")
    assert "T1558.003" in finding.mitre
    krb = report.metadata["pcap_summary"]["kerberos"]
    assert "TGS-REP" in krb["msg_types"]
    assert "MSSQLSvc/db01.corp.local" in krb["service_principals"]


def test_asrep_roasting_fires_on_no_preauth():
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    CLIENT, SERVER, 50000, 88, payload=krb_tcp(krb_as_req(with_preauth=False))
                ),
            )
        ]
    )
    report = analyze(_write(raw))
    rules = _rules(report)
    assert "pcap.asrep_roasting" in rules
    finding = next(f for f in report.findings if f.rule == "pcap.asrep_roasting")
    assert "T1558.004" in finding.mitre


def test_kerberos_preauth_does_not_fire_asrep():
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    CLIENT, SERVER, 50000, 88, payload=krb_tcp(krb_as_req(with_preauth=True))
                ),
            )
        ]
    )
    report = analyze(_write(raw))
    assert "pcap.asrep_roasting" not in _rules(report)


def test_kerberos_rc4_downgrade_flagged():
    raw = build_pcap(
        [(1.0, eth_ipv4_tcp(CLIENT, SERVER, 50000, 88, payload=krb_tcp(krb_as_req(etypes=(23,)))))]
    )
    report = analyze(_write(raw))
    assert "pcap.kerberos_rc4_downgrade" in _rules(report)


# ---------------------------------------------------------------------------
# Composite — a mini intrusion in one capture
# ---------------------------------------------------------------------------


def test_composite_intrusion_capture():
    """One capture: lateral movement (admin share) + NTLM capture +
    Kerberoasting. All three should surface and the verdict be malicious."""
    sc = b"\x22" * 8
    nt = b"\xcc" * 16 + b"\xdd" * 24
    raw = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(CLIENT, SERVER, 50000, 445, payload=smb2_tree_connect(r"\\DC01\C$")),
            ),
            (
                1.1,
                eth_ipv4_tcp(
                    SERVER, CLIENT, 445, 50001, payload=smb2_session_setup(ntlm_challenge(sc))
                ),
            ),
            (
                1.2,
                eth_ipv4_tcp(
                    CLIENT,
                    SERVER,
                    50001,
                    445,
                    payload=smb2_session_setup(ntlm_authenticate("CORP", "svc_sql", "WS9", nt)),
                ),
            ),
            (
                1.3,
                eth_ipv4_tcp(
                    SERVER, CLIENT, 88, 50002, payload=krb_tcp(krb_tgs_rep(ticket_etype=23))
                ),
            ),
        ]
    )
    report = analyze(_write(raw))
    rules = _rules(report)
    assert {"pcap.smb_admin_share", "pcap.netntlmv2_capture", "pcap.kerberoasting"} <= rules
    assert report.format == FileFormat.PCAP
    assert report.verdict.value == "malicious"

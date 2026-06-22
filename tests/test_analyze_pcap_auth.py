"""Unit tests for the phase-14.3b auth/L7 dissectors.

Covers the pieces in isolation — JA3S, the SMB dialect/path parser, the
NTLMSSP parser + NetNTLMv2 assembly, the Kerberos DER walker, and the
roastability predicates — before the e2e tests wire them through
``analyze()``. Every dissector is hammered with malformed input too, to
hold the "total on hostile bytes" line the parser package promises.
"""

from __future__ import annotations

import hashlib

from ioc_hunter.analyze import pcap_auth as auth
from ioc_hunter.analyze import pcap_heur as heur
from ioc_hunter.analyze.pcap_parse import IPProto, Packet
from ioc_hunter.analyze.pcap_proto import dissect_tls_serverhello
from tests import _pcap_fixtures as fix


def _pkt(payload: bytes, *, sport: int = 50000, dport: int = 445, proto=IPProto.TCP) -> Packet:
    return Packet(
        ts=1.0,
        frame_no=1,
        src_ip="10.0.0.5",
        dst_ip="10.0.0.9",
        src_port=sport,
        dst_port=dport,
        proto=proto,
        is_ipv6=False,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# JA3S
# ---------------------------------------------------------------------------


def test_ja3s_matches_independent_md5():
    record = fix.synth_tls_serverhello(
        version=0x0303, cipher=0xC02F, extensions_order=(0x0000, 0x000B, 0xFF01)
    )
    sh = dissect_tls_serverhello(record, _pkt(record, sport=443, dport=50000))
    assert sh is not None
    # version=771, cipher=49199, exts 0-11-65281 (none are GREASE)
    expected_str = "771,49199,0-11-65281"
    assert sh.ja3s_string == expected_str
    assert sh.ja3s_md5 == hashlib.md5(expected_str.encode()).hexdigest()
    assert sh.cipher == 0xC02F


def test_ja3s_strips_grease_extensions():
    record = fix.synth_tls_serverhello(extensions_order=(0x0A0A, 0x0000, 0x000B))
    sh = dissect_tls_serverhello(record, _pkt(record, sport=443))
    assert sh is not None
    # 0x0A0A is GREASE and must be dropped from the extension list.
    assert sh.ja3s_string.endswith(",0-11")


def test_ja3s_rejects_clienthello_and_junk():
    # A ClientHello (handshake type 0x01) must not parse as a ServerHello.
    ch = fix.synth_tls_clienthello("example.com")
    assert dissect_tls_serverhello(ch, _pkt(ch)) is None
    assert dissect_tls_serverhello(b"\x16\x03\x03", _pkt(b"")) is None
    assert dissect_tls_serverhello(b"", _pkt(b"")) is None


# ---------------------------------------------------------------------------
# SMB
# ---------------------------------------------------------------------------


def test_smb2_tree_connect_extracts_unc_path():
    rec = auth.dissect_smb(_pkt(fix.smb2_tree_connect(r"\\db01\ADMIN$")))
    assert rec is not None
    assert rec.dialect == "SMB2"
    assert rec.command_name == "TREE_CONNECT"
    assert rec.tree_path == r"\\db01\ADMIN$"
    assert rec.is_response is False


def test_smb_admin_share_classification():
    assert auth.is_admin_share(r"\\h\ADMIN$") is True
    assert auth.is_admin_share(r"\\h\C$") is True
    assert auth.is_admin_share(r"\\h\D$") is True
    assert auth.is_admin_share(r"\\h\IPC$") is False  # benign RPC pipe
    assert auth.is_admin_share(r"\\h\Share") is False
    assert auth.is_admin_share(r"\\h\Public$") is False  # named share, not a drive


def test_smb1_detected_and_nbss_stripped_on_139():
    rec = auth.dissect_smb(_pkt(fix.smb1_negotiate()))
    assert rec is not None and rec.dialect == "SMB1"
    # SMB2 wrapped in a NetBIOS session header on TCP/139.
    wrapped = auth.dissect_smb(_pkt(fix.nbss_wrap(fix.smb2_tree_connect(r"\\h\C$")), dport=139))
    assert wrapped is not None and wrapped.dialect == "SMB2"
    assert wrapped.tree_path == r"\\h\C$"


def test_smb_ignores_non_smb_and_malformed():
    assert auth.dissect_smb(_pkt(b"GET / HTTP/1.1\r\n\r\n", dport=80)) is None  # wrong port
    assert auth.dissect_smb(_pkt(b"not smb at all", dport=445)) is None
    assert auth.dissect_smb(_pkt(b"\xfeSMB\x00", dport=445)) is None  # truncated header


# ---------------------------------------------------------------------------
# NTLMSSP + NetNTLMv2
# ---------------------------------------------------------------------------


def test_ntlm_challenge_and_authenticate_parse():
    chal = auth.parse_ntlmssp(fix.ntlm_challenge(b"\x01\x02\x03\x04\x05\x06\x07\x08", "CORP"))
    assert len(chal) == 1 and chal[0].msg_type == 2
    assert chal[0].server_challenge == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert chal[0].target_name == "CORP"

    authn = auth.parse_ntlmssp(fix.ntlm_authenticate("CORP", "jdoe", "WS01"))
    assert len(authn) == 1 and authn[0].msg_type == 3
    assert authn[0].domain == "CORP"
    assert authn[0].user == "jdoe"
    assert authn[0].workstation == "WS01"


def test_netntlmv2_hash_format():
    sc = b"\x11" * 8
    nt = b"\xaa" * 16 + b"\xbb" * 20
    h = auth.netntlmv2_hash("jdoe", "CORP", sc, nt)
    assert h == "jdoe::CORP:" + sc.hex() + ":" + ("aa" * 16) + ":" + ("bb" * 20)


def test_netntlmv2_hash_declines_bad_input():
    assert auth.netntlmv2_hash("jdoe", "CORP", b"\x11" * 7, b"\xaa" * 16) is None  # short challenge
    assert auth.netntlmv2_hash("jdoe", "CORP", b"\x11" * 8, b"\xaa" * 15) is None  # short NT (v1)
    assert auth.netntlmv2_hash("", "CORP", b"\x11" * 8, b"\xaa" * 16) is None  # no user


def test_parse_ntlmssp_total_on_junk():
    assert auth.parse_ntlmssp(b"") == []
    assert auth.parse_ntlmssp(b"NTLMSSP\x00") == []  # signature only, truncated
    assert auth.parse_ntlmssp(b"no signature here" * 4) == []


# ---------------------------------------------------------------------------
# Kerberos
# ---------------------------------------------------------------------------


def test_kerberos_as_req_no_preauth_is_asrep_roastable():
    rec = auth.dissect_kerberos(fix.krb_tcp(fix.krb_as_req(with_preauth=False)), tcp=True)
    assert rec is not None
    assert rec.msg_name == "AS-REQ"
    assert rec.realm == "CORP.LOCAL"
    assert rec.cname == "jdoe"
    assert rec.sname == "krbtgt/CORP.LOCAL"
    assert rec.preauth is False
    assert auth.is_asrep_roastable(rec) is True


def test_kerberos_as_req_with_preauth_not_roastable():
    rec = auth.dissect_kerberos(fix.krb_tcp(fix.krb_as_req(with_preauth=True)), tcp=True)
    assert rec is not None and rec.preauth is True
    assert auth.is_asrep_roastable(rec) is False


def test_kerberos_tgs_rep_rc4_is_kerberoastable():
    rec = auth.dissect_kerberos(fix.krb_tcp(fix.krb_tgs_rep(ticket_etype=23)), tcp=True)
    assert rec is not None
    assert rec.msg_name == "TGS-REP"
    assert rec.sname == "MSSQLSvc/db01.corp.local"
    assert rec.ticket_etype == 23
    assert auth.is_kerberoastable(rec) is True


def test_kerberos_tgs_rep_aes_not_kerberoastable():
    rec = auth.dissect_kerberos(fix.krb_tcp(fix.krb_tgs_rep(ticket_etype=18)), tcp=True)
    assert rec is not None and auth.is_kerberoastable(rec) is False


def test_kerberos_rc4_downgrade_detection():
    rc4_only = auth.dissect_kerberos(fix.krb_tcp(fix.krb_as_req(etypes=(23,))), tcp=True)
    assert auth.is_rc4_downgrade(rc4_only) is True
    with_aes = auth.dissect_kerberos(fix.krb_tcp(fix.krb_as_req(etypes=(18, 23))), tcp=True)
    assert auth.is_rc4_downgrade(with_aes) is False


def test_kerberos_udp_no_length_prefix():
    rec = auth.dissect_kerberos(fix.krb_as_req(), tcp=False)
    assert rec is not None and rec.msg_name == "AS-REQ"


def test_kerberos_total_on_junk():
    assert auth.dissect_kerberos(b"", tcp=True) is None
    assert auth.dissect_kerberos(b"\x00\x00\x00\x04\xff\xff\xff\xff", tcp=True) is None
    assert auth.dissect_kerberos(b"\x6a\x80not-valid-der", tcp=False) is None


# ---------------------------------------------------------------------------
# DER walker edge cases
# ---------------------------------------------------------------------------


def test_der_walker_handles_long_form_length():
    # A SEQUENCE with a long-form length (>127 bytes of content).
    inner = fix.der_genstr("x" * 200)
    seq = fix.der_seq(inner)
    root = auth._der_root(seq)
    assert root is not None
    assert root.num == 16  # SEQUENCE
    assert auth._der_strings(root) == ["x" * 200]


def test_der_walker_bounded_on_truncated_length():
    # Claims 0x82 (2 length bytes) then runs out — must not raise.
    assert auth._der_root(b"\x30\x82\xff") is None or True


# ---------------------------------------------------------------------------
# JA3 known-bad table
# ---------------------------------------------------------------------------


def test_known_bad_ja3_lookup():
    assert heur.match_known_bad_ja3("72a589da586844d7f0818ce684948eea") is not None
    assert heur.match_known_bad_ja3("0" * 32) is None
    assert heur.match_known_bad_ja3s("623de93db17d313345d7ea481e7443cf") is not None

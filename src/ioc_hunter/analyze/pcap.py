"""PCAP / PCAPNG analyzer — top-level entry point.

This is the orchestrator. The heavy lifting lives in three sister
modules — ``pcap_parse`` (container + L2/L3/L4), ``pcap_proto`` (DNS /
HTTP / TLS+JA3), ``pcap_heur`` (behavioural shapes) — keeping each file
short enough to read and review on its own.

Pipeline
--------

1. Detect PCAP or PCAPNG and stream out frames → packets.
2. Maintain a ``FlowTable`` (bidirectional 5-tuple) as packets arrive.
3. For each TCP segment, also feed an opportunistic per-direction
   stitcher and run the HTTP / TLS parsers against the head of the
   stitched bytes. UDP/53 packets feed straight into the DNS parser.
4. After the stream is drained, run heuristics (beacons, scans, exfil,
   DGA, DNS tunneling, ICMP tunnel, plaintext creds, bad UAs) and emit
   findings into the report.
5. Surface a metadata snapshot the renderer reads to populate the
   PCAP-specific section of the report (top talkers, flow counts,
   notable JA3s, etc).

The IOC sweep and ATT&CK tagging are run upstream by the dispatcher,
same as every other format. We populate ``report.metadata`` with a
``pcap_summary`` dict carrying the structured findings; the markdown
renderer in ``pcap_markdown.render_pcap_section`` consumes it.
"""

from __future__ import annotations

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)
from ioc_hunter.analyze.pcap_auth import (
    KERBEROS_PORTS,
    KerberosRecord,
    SMBRecord,
    dissect_kerberos,
    dissect_smb,
    etype_name,
    is_admin_share,
    is_asrep_roastable,
    is_kerberoastable,
    is_rc4_downgrade,
    is_smb_packet,
    netntlmv2_hash,
    parse_ntlmssp,
)
from ioc_hunter.analyze.pcap_heur import (
    detect_beacons,
    detect_dns_tunneling,
    detect_exfil,
    detect_icmp_tunnel,
    detect_scans,
    detect_tls_anomalies,
    emit_findings,
    emit_l7_findings,
    find_dga_names,
    find_ftp_credentials,
    match_known_bad_ja3,
    match_known_bad_ja3s,
)
from ioc_hunter.analyze.pcap_parse import (
    MAX_FRAMES,
    FlowTable,
    IPProto,
    iter_packets,
)
from ioc_hunter.analyze.pcap_proto import (
    DNSStats,
    HTTPRequest,
    HTTPResponse,
    TLSClientHello,
    TLSServerHello,
    _Stitcher,
    dissect_dns,
    dissect_http_request,
    dissect_http_response,
    dissect_tls_clienthello,
    dissect_tls_serverhello,
    flag_bad_user_agent,
)


def _flow_key(pkt) -> tuple:
    """Direction-agnostic flow key: canonicalise the two endpoints so the
    NTLM CHALLENGE (server→client) and AUTHENTICATE (client→server) of one
    exchange hash to the same bucket."""
    return tuple(sorted(((pkt.src_ip, pkt.src_port), (pkt.dst_ip, pkt.dst_port))))


def _harvest_ntlm(
    pkt,
    challenges: dict[tuple, bytes],
    creds: list[tuple[str, str, str, str, str]],
    *,
    ntlm_seen: bool,
) -> bool:
    """Pull NTLMSSP messages from one SMB segment, pairing CHALLENGE→AUTH.

    Stores the 8-byte server challenge per flow on a type-2 message, then
    on the matching type-3 (AUTHENTICATE) assembles a crackable NetNTLMv2
    hash. Returns the updated ``ntlm_seen`` flag.
    """
    msgs = parse_ntlmssp(pkt.payload)
    if not msgs:
        return ntlm_seen
    key = _flow_key(pkt)
    for m in msgs:
        ntlm_seen = True
        if m.msg_type == 2 and len(m.server_challenge) == 8:
            challenges[key] = m.server_challenge
        elif m.msg_type == 3:
            chal = challenges.get(key)
            if chal and len(creds) < 5000:
                h = netntlmv2_hash(m.user, m.domain, chal, m.nt_response)
                if h is not None:
                    creds.append((m.user, m.domain, h, pkt.src_ip, pkt.dst_ip))
    return ntlm_seen


def analyze_pcap(raw: bytes, *, report: AnalyzerReport) -> None:
    """Entry point: analyse a PCAP/PCAPNG capture in ``raw``.

    Mutates ``report`` in place. Stops at ``MAX_FRAMES`` frames and
    records that fact so an analyst knows they're looking at a partial
    view.
    """
    packets: list = []
    dns_stats = DNSStats()
    dns_messages: list = []
    http_requests: list[HTTPRequest] = []
    http_responses: list[HTTPResponse] = []
    tls_chs: list[TLSClientHello] = []
    tls_shs: list[TLSServerHello] = []
    suspicious_uas: list[tuple[HTTPRequest, str]] = []

    # ---- L7 auth / lateral-movement collection (phase 14.3b) --------------
    smb_records: list[SMBRecord] = []
    smb_admin_shares: list[tuple[str, str, str]] = []
    smb1_pairs: set[tuple[str, str]] = set()
    kerberos_records: list[KerberosRecord] = []
    # NTLM challenge→response pairing, keyed by canonical flow endpoints.
    ntlm_challenges: dict[tuple, bytes] = {}
    netntlm_creds: list[tuple[str, str, str, str, str]] = []
    ntlm_seen = False

    flow_table = FlowTable()
    stitcher = _Stitcher()

    # Per-flow direction state: once we've successfully parsed an HTTP head
    # or a TLS ClientHello in a direction, stop re-parsing on every segment.
    parsed_http_dir: set[tuple[str, int, str, int]] = set()
    parsed_tls_dir: set[tuple[str, int, str, int]] = set()
    parsed_tls_server_dir: set[tuple[str, int, str, int]] = set()

    seen_ja3: set[str] = set()
    seen_ja3s: set[str] = set()
    frame_count = 0
    ts_first = 0.0
    ts_last = 0.0

    for pkt in iter_packets(raw, max_frames=MAX_FRAMES):
        frame_count += 1
        if frame_count == 1:
            ts_first = pkt.ts
        ts_last = pkt.ts
        packets.append(pkt)
        flow_table.update(pkt)

        # ---- DNS ----------------------------------------------------------
        if pkt.proto in (IPProto.UDP, IPProto.TCP) and (pkt.src_port == 53 or pkt.dst_port == 53):
            msg = dissect_dns(pkt, dns_stats)
            if msg is not None and len(dns_messages) < 2000:
                dns_messages.append(msg)

        # ---- HTTP / TLS (TCP only) ---------------------------------------
        if pkt.proto == IPProto.TCP and pkt.payload:
            dir_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            stitched = stitcher.feed(pkt)

            if dir_key not in parsed_http_dir:
                req = dissect_http_request(stitched, pkt)
                if req is not None:
                    parsed_http_dir.add(dir_key)
                    stitcher.drop(pkt)  # free the buffer once parsed
                    if len(http_requests) < 5000:
                        http_requests.append(req)
                    if req.user_agent:
                        label = flag_bad_user_agent(req.user_agent)
                        if label:
                            suspicious_uas.append((req, label))
                else:
                    resp = dissect_http_response(stitched, pkt)
                    if resp is not None:
                        parsed_http_dir.add(dir_key)
                        stitcher.drop(pkt)
                        if len(http_responses) < 5000:
                            http_responses.append(resp)

            if (
                dir_key not in parsed_tls_dir
                and dir_key not in parsed_tls_server_dir
                and dir_key not in parsed_http_dir
                and stitched
                and stitched[0] == 0x16
            ):
                ch = dissect_tls_clienthello(stitched, pkt)
                if ch is not None:
                    parsed_tls_dir.add(dir_key)
                    stitcher.drop(pkt)
                    if len(tls_chs) < 5000:
                        tls_chs.append(ch)
                    seen_ja3.add(ch.ja3_md5)
                else:
                    sh = dissect_tls_serverhello(stitched, pkt)
                    if sh is not None:
                        parsed_tls_server_dir.add(dir_key)
                        stitcher.drop(pkt)
                        if len(tls_shs) < 5000:
                            tls_shs.append(sh)
                        seen_ja3s.add(sh.ja3s_md5)

            # ---- SMB (445 / 139) -----------------------------------------
            if is_smb_packet(pkt) and len(smb_records) < 20000:
                smb = dissect_smb(pkt)
                if smb is not None:
                    smb_records.append(smb)
                    if smb.dialect == "SMB1":
                        smb1_pairs.add((pkt.src_ip, pkt.dst_ip))
                    if smb.tree_path and is_admin_share(smb.tree_path):
                        smb_admin_shares.append((pkt.src_ip, pkt.dst_ip, smb.tree_path))
                ntlm_seen = _harvest_ntlm(pkt, ntlm_challenges, netntlm_creds, ntlm_seen=ntlm_seen)

        # ---- Kerberos (88, TCP length-prefixed or UDP) -------------------
        if (
            pkt.proto in (IPProto.TCP, IPProto.UDP)
            and (pkt.src_port in KERBEROS_PORTS or pkt.dst_port in KERBEROS_PORTS)
            and pkt.payload
            and len(kerberos_records) < 20000
        ):
            krb = dissect_kerberos(pkt.payload, tcp=(pkt.proto == IPProto.TCP))
            if krb is not None:
                kerberos_records.append(krb)

    if frame_count >= MAX_FRAMES:
        report.add(
            Finding(
                rule="pcap.frames_truncated",
                severity=Severity.INFO,
                category="anomaly",
                message=(f"Stopped at {MAX_FRAMES:,} frames — capture may carry more."),
            )
        )

    capture_duration = max(0.0, ts_last - ts_first)
    flows = list(flow_table.flows.values())
    beacons = detect_beacons(flows)
    scans = detect_scans(packets)
    exfil = detect_exfil(flows)
    dga = find_dga_names(dns_stats)
    tunnels = detect_dns_tunneling(dns_stats, capture_duration)
    ftp_creds = find_ftp_credentials(packets)
    http_basic = [r for r in http_requests if r.has_basic_auth]
    icmp_tun = detect_icmp_tunnel(packets)

    emit_findings(
        report=report,
        beacons=beacons,
        scans=scans,
        exfil=exfil,
        dga_names=dga,
        tunneling_hits=tunnels,
        ftp_creds=ftp_creds,
        http_basic=http_basic,
        icmp_tunnels=icmp_tun,
        suspicious_uas=suspicious_uas,
        dns_messages_sample=dns_messages,
    )

    # ---- L7 auth / fingerprint findings (phase 14.3b) ---------------------
    ja3_bad = [
        (label, ch.ja3_md5, ch.src_ip, ch.dst_ip, ch.dst_port)
        for ch in tls_chs
        if (label := match_known_bad_ja3(ch.ja3_md5)) is not None
    ]
    ja3s_bad = [
        (label, sh.ja3s_md5, sh.src_ip, sh.dst_ip, sh.src_port)
        for sh in tls_shs
        if (label := match_known_bad_ja3s(sh.ja3s_md5)) is not None
    ]
    tls_anomalies = detect_tls_anomalies(tls_chs)
    kerberoast = [(k.cname, k.sname, k.realm) for k in kerberos_records if is_kerberoastable(k)]
    asrep_roast = [(k.cname, k.realm) for k in kerberos_records if is_asrep_roastable(k)]
    krb_downgrade = [
        (k.cname, k.realm, "/".join(etype_name(e) for e in k.etypes))
        for k in kerberos_records
        if is_rc4_downgrade(k)
    ]
    # De-dup admin-share + SMB1 lists so a chatty session doesn't repeat them.
    smb_admin_uniq = list(dict.fromkeys(smb_admin_shares))
    emit_l7_findings(
        report=report,
        ja3_bad=ja3_bad,
        ja3s_bad=ja3s_bad,
        tls_anomalies=tls_anomalies,
        smb_admin_shares=smb_admin_uniq,
        smb1_pairs=sorted(smb1_pairs),
        netntlm_creds=netntlm_creds,
        kerberoast=kerberoast,
        asrep_roast=asrep_roast,
        krb_downgrade=krb_downgrade,
    )

    # ---- High-volume NXDOMAIN — combined signal ---------------------------
    if dns_stats.responses >= 50:
        nx_ratio = dns_stats.nxdomain / dns_stats.responses
        if nx_ratio >= 0.5:
            report.add(
                Finding(
                    rule="pcap.high_nxdomain_ratio",
                    severity=Severity.MEDIUM,
                    category="c2",
                    message=(
                        f"{dns_stats.nxdomain} of {dns_stats.responses} DNS responses "
                        f"were NXDOMAIN ({nx_ratio:.0%}) — classic DGA churn"
                    ),
                )
            )

    # Stash a snapshot the renderer can read. We deliberately keep this
    # report-side rather than introducing new fields to AnalyzerReport so
    # the binary-side schema stays untouched.
    report.metadata["pcap_summary"] = {
        "frames": frame_count,
        "packets_dissected": len(packets),
        "capture_duration_s": capture_duration,
        "flows": len(flows),
        "top_talkers": flow_table.top_talkers(10),
        "top_dst_ports": flow_table.top_dst_ports(10),
        "dns": {
            "queries": dns_stats.queries,
            "responses": dns_stats.responses,
            "nxdomain": dns_stats.nxdomain,
            "qtype_counts": dict(dns_stats.qtype_counts),
            "distinct_names": len(dns_stats.per_name),
            "txt_response_bytes": dns_stats.txt_query_bytes,
        },
        "http": {
            "requests": len(http_requests),
            "responses": len(http_responses),
            "hosts": sorted({r.host for r in http_requests if r.host})[:20],
            "user_agents": sorted({r.user_agent for r in http_requests if r.user_agent})[:20],
        },
        "tls": {
            "client_hellos": len(tls_chs),
            "server_hellos": len(tls_shs),
            "distinct_ja3": len(seen_ja3),
            "distinct_ja3s": len(seen_ja3s),
            "snis": sorted({ch.sni for ch in tls_chs if ch.sni})[:30],
            "ja3_sample": sorted(seen_ja3)[:10],
            "ja3s_sample": sorted(seen_ja3s)[:10],
        },
        "smb": {
            "messages": len(smb_records),
            "dialects": sorted({r.dialect for r in smb_records}),
            "commands": sorted({r.command_name for r in smb_records})[:20],
            "admin_shares": [unc for _, _, unc in smb_admin_uniq][:20],
        },
        "kerberos": {
            "messages": len(kerberos_records),
            "msg_types": sorted({k.msg_name for k in kerberos_records}),
            "realms": sorted({k.realm for k in kerberos_records if k.realm})[:10],
            "service_principals": sorted({k.sname for k in kerberos_records if k.sname})[:20],
        },
        "ntlm_observed": ntlm_seen,
    }

    # Carry IPs / domains / URLs the heuristics layer surfaced into the
    # ``iocs`` list via the standard string-sweep path — the dispatcher
    # runs that automatically over the raw bytes, but DNS/HTTP/TLS
    # extractions might surface things the byte sweep misses (e.g. a
    # ClientHello SNI that lives only in length-prefixed bytes). We append
    # those as a synthetic strings blob the dispatcher will sweep next.
    extra: list[str] = []
    for ch in tls_chs:
        if ch.sni:
            extra.append(ch.sni)
    for req in http_requests:
        if req.host:
            extra.append(req.host)
        if req.uri.startswith(("http://", "https://")):
            extra.append(req.uri)
        elif req.host and req.uri.startswith("/"):
            extra.append(f"http://{req.host}{req.uri}")
    for name in dns_stats.per_name:
        extra.append(name)
    if extra:
        # Stash for the dispatcher's IOC sweep. ``analyze.dispatcher`` already
        # mixes a ``pdf_decoded_blob`` into its strings; we use the same hook
        # so behaviour stays consistent across analysers.
        existing = report.metadata.get("pdf_decoded_blob", b"")
        synthetic = "\n".join(extra).encode("utf-8", errors="replace")
        report.metadata["pdf_decoded_blob"] = (
            existing + b"\n" + synthetic if existing else synthetic
        )

    report.format = FileFormat.PCAP

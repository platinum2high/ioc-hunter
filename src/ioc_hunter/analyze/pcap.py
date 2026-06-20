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
from ioc_hunter.analyze.pcap_heur import (
    detect_beacons,
    detect_dns_tunneling,
    detect_exfil,
    detect_icmp_tunnel,
    detect_scans,
    emit_findings,
    find_dga_names,
    find_ftp_credentials,
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
    _Stitcher,
    dissect_dns,
    dissect_http_request,
    dissect_http_response,
    dissect_tls_clienthello,
    flag_bad_user_agent,
)


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
    suspicious_uas: list[tuple[HTTPRequest, str]] = []

    flow_table = FlowTable()
    stitcher = _Stitcher()

    # Per-flow direction state: once we've successfully parsed an HTTP head
    # or a TLS ClientHello in a direction, stop re-parsing on every segment.
    parsed_http_dir: set[tuple[str, int, str, int]] = set()
    parsed_tls_dir: set[tuple[str, int, str, int]] = set()

    seen_ja3: set[str] = set()
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
            "distinct_ja3": len(seen_ja3),
            "snis": sorted({ch.sni for ch in tls_chs if ch.sni})[:30],
            "ja3_sample": sorted(seen_ja3)[:10],
        },
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

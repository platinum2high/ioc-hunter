"""ioc-hunter CLI entrypoint.

Commands:
    ioc-hunter check <ioc>            single-IOC lookup
    ioc-hunter scan-file <path>       extract + enrich every IOC in a file
    ioc-hunter parse-eml <path>       parse phishing .eml — headers, body, attachments
    ioc-hunter analyze <path>         static analysis of PE / ELF / Mach-O binaries
    ioc-hunter watch <path>           tail a log file and alert on suspicious IOCs
    ioc-hunter correlate <path>       find pivots across a batch of IOCs
    ioc-hunter report <path>          render JSON / Markdown / STIX / MISP / Sigma / Suricata
    ioc-hunter decode <text>          base64 / hex / URL / JWT / gzip / ... (magic by default)
    ioc-hunter sources                show which TI sources are active
    ioc-hunter configure              interactive .env wizard
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import typer
from rich.box import SIMPLE
from rich.console import Console
from rich.markup import escape as _escape_markup
from rich.panel import Panel
from rich.table import Table

from ioc_hunter import __version__
from ioc_hunter.analyze import (
    AnalyzerReport,
    Severity,
    analyze,
)
from ioc_hunter.analyze import Verdict as AnalyzerVerdict
from ioc_hunter.cache import TICache
from ioc_hunter.config import Settings
from ioc_hunter.core import IOC, defang, detect_type, extract_iocs, parse_eml, refang
from ioc_hunter.core.eml import EmailReport
from ioc_hunter.core.types import IOCType
from ioc_hunter.correlator import correlate as _correlate
from ioc_hunter.decoder import OPERATIONS as _DECODE_OPS
from ioc_hunter.decoder import DecodeError
from ioc_hunter.decoder import decode as _decode_op
from ioc_hunter.decoder import magic as _magic
from ioc_hunter.engine import Engine
from ioc_hunter.exporters import to_json, to_markdown, to_misp, to_stix
from ioc_hunter.rules import to_sigma, to_suricata
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources import (
    AbuseIPDBSource,
    NetMetaSource,
    OTXSource,
    Source,
    ThreatFoxSource,
    TorExitSource,
    URLhausSource,
    Verdict,
    VirusTotalSource,
)
from ioc_hunter.watcher import WatchAlert, resolve_threshold
from ioc_hunter.watcher import watch as _watch

app = typer.Typer(
    name="ioc-hunter",
    help="Async threat intelligence correlation engine for SOC analysts.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _safe(value: str) -> str:
    """Defang + escape Rich markup so `[.]`, `[@]` etc render literally."""
    return _escape_markup(defang(value))


_VERDICT_STYLES: dict[Verdict, tuple[str, str]] = {
    Verdict.MALICIOUS: ("MALICIOUS", "bold red"),
    Verdict.SUSPICIOUS: ("SUSPICIOUS", "bold yellow"),
    Verdict.BENIGN: ("BENIGN", "bold green"),
    Verdict.UNKNOWN: ("UNKNOWN", "dim"),
}


def _build_sources(client: httpx.AsyncClient, settings: Settings) -> list[Source]:
    """Instantiate every source. Sources without a key stay registered but
    will short-circuit to UNKNOWN with an error explaining why."""
    return [
        NetMetaSource(client),
        TorExitSource(client),
        URLhausSource(client, api_key=settings.abuse_ch_auth_key),
        ThreatFoxSource(client, api_key=settings.abuse_ch_auth_key),
        AbuseIPDBSource(client, api_key=settings.abuseipdb_api_key),
        OTXSource(client, api_key=settings.otx_api_key),
        VirusTotalSource(client, api_key=settings.virustotal_api_key),
    ]


def _build_engine(
    client: httpx.AsyncClient,
    settings: Settings,
    cache: TICache | None,
) -> Engine:
    return Engine(
        _build_sources(client, settings),
        cache=cache,
        max_concurrency=settings.max_concurrency,
    )


def _open_cache(settings: Settings, enabled: bool) -> TICache | None:
    if not enabled:
        return None
    return TICache(settings.cache_dir / "ioc_hunter.db", default_ttl=settings.cache_ttl)


def _parse_ioc(value: str, type_hint: str | None) -> IOC | None:
    # Refang first so defanged input like `1[.]2[.]3[.]4` or `hxxps://...`
    # works through `check` the same way it does through `scan-file`.
    value = refang(value.strip())
    if not value:
        return None
    if type_hint:
        try:
            return IOC(value=value, type=IOCType(type_hint.lower()))
        except ValueError as exc:
            valid = ", ".join(t.value for t in IOCType)
            raise typer.BadParameter(f"unknown type {type_hint!r}; valid: {valid}") from exc
    detected = detect_type(value)
    if detected is None:
        return None
    return IOC(value=value, type=detected)


def _render_verdict_panel(verdict: IOCVerdict) -> None:
    label, style = _VERDICT_STYLES[verdict.verdict]
    body = (
        f"[bold cyan]{_safe(verdict.ioc.value)}[/]\n"
        f"[dim]type:[/] {verdict.ioc.type.value}\n\n"
        f"[{style}]{label}[/]  "
        f"[dim]confidence[/] {verdict.confidence:.0%}"
    )
    console.print(Panel.fit(body, title="IOC Hunter", border_style=style))


def _render_per_source_table(verdict: IOCVerdict) -> None:
    table = Table(title="Per-source results", box=SIMPLE, show_lines=False)
    table.add_column("Source", style="cyan")
    table.add_column("Verdict")
    table.add_column("Score", justify="right")
    table.add_column("Notes", style="dim")

    for r in verdict.results:
        if r.error:
            notes = r.error if len(r.error) <= 60 else r.error[:57] + "..."
            table.add_row(r.source, "[dim]error[/]", "—", notes)
            continue
        v_label, v_style = _VERDICT_STYLES[r.verdict]
        notes = ", ".join(r.tags[:3]) if r.tags else ""
        table.add_row(
            r.source,
            f"[{v_style}]{v_label}[/]",
            f"{r.score:.2f}",
            notes,
        )
    console.print(table)


def _render_extras(verdict: IOCVerdict) -> None:
    if verdict.tags:
        console.print(f"[yellow]Tags:[/] {', '.join(verdict.tags[:15])}")
    if verdict.references:
        console.print("[blue]References:[/]")
        for ref in verdict.references[:6]:
            console.print(f"  • {ref}")


def _render_batch_table(verdicts: list[IOCVerdict]) -> None:
    table = Table(title=f"{len(verdicts)} IOC(s)", show_lines=False, box=SIMPLE)
    table.add_column("IOC", style="cyan", overflow="fold")
    table.add_column("Type", style="dim")
    table.add_column("Verdict")
    table.add_column("Conf", justify="right")
    table.add_column("Hits", justify="right")
    table.add_column("Tags", style="yellow", overflow="fold")

    for v in sorted(verdicts, key=lambda x: -x.confidence):
        label, style = _VERDICT_STYLES[v.verdict]
        non_err = sum(1 for r in v.results if r.error is None)
        total = len(v.results)
        table.add_row(
            _safe(v.ioc.value)[:60],
            v.ioc.type.value,
            f"[{style}]{label}[/]",
            f"{v.confidence:.0%}",
            f"{non_err}/{total}",
            ", ".join(v.tags[:4]),
        )
    console.print(table)


async def _run_check(value: str, type_hint: str | None, use_cache: bool) -> int:
    ioc = _parse_ioc(value, type_hint)
    if ioc is None:
        console.print(f"[red]Could not detect IOC type for:[/] {value}")
        console.print("[dim]Hint: pass --type to override (e.g. --type domain).[/]")
        return 1

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            active = engine.active_sources
            if not active:
                console.print("[red]No active sources — run `ioc-hunter configure`.[/]")
                return 2
            with console.status(f"Querying {len(active)} source(s) for {_safe(ioc.value)}..."):
                verdict = await engine.lookup_one(ioc)
    finally:
        if cache is not None:
            cache.close()

    _render_verdict_panel(verdict)
    _render_per_source_table(verdict)
    _render_extras(verdict)
    return 0


async def _run_scan_file(path: Path, use_cache: bool) -> int:
    text = path.read_text(errors="replace")
    iocs = extract_iocs(text)
    if not iocs:
        console.print(f"[yellow]No IOCs found in[/] {path}")
        return 0
    console.print(f"Extracted [bold]{len(iocs)}[/] IOC(s) from {path}")

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            active = engine.active_sources
            if not active:
                console.print("[red]No active sources — run `ioc-hunter configure`.[/]")
                return 2
            with console.status(f"Enriching {len(iocs)} IOC(s) across {len(active)} source(s)..."):
                verdicts = await engine.lookup_many(iocs)
    finally:
        if cache is not None:
            cache.close()

    _render_batch_table(verdicts)
    return 0


@app.command(help="Look up a single IOC across every configured source.")
def check(
    ioc: str = typer.Argument(..., help="The indicator to look up (auto-detected)."),
    type_hint: str | None = typer.Option(
        None, "--type", "-t", help="Override auto-detection (ipv4, domain, ...)."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(_run_check(ioc, type_hint, use_cache=not no_cache))
    raise typer.Exit(exit_code)


@app.command(name="scan-file", help="Extract IOCs from a file and enrich every one.")
def scan_file(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(_run_scan_file(path, use_cache=not no_cache))
    raise typer.Exit(exit_code)


def _render_eml_summary(report: EmailReport) -> None:
    """Header / envelope summary for a parsed .eml."""
    lines = []
    if report.subject:
        lines.append(f"[bold cyan]Subject:[/] {_safe(report.subject)}")
    if report.from_addr:
        lines.append(f"[dim]From:[/]    {_safe(report.from_addr)}")
    if report.reply_to and report.reply_to != report.from_addr:
        lines.append(f"[yellow]Reply-To:[/] {_safe(report.reply_to)}  [dim](differs from From!)[/]")
    if report.return_path and report.return_path != report.from_addr:
        lines.append(f"[yellow]Return-Path:[/] {_safe(report.return_path)}")
    if report.to_addrs:
        joined = ", ".join(_safe(a) for a in report.to_addrs[:5])
        if len(report.to_addrs) > 5:
            joined += f", [dim]... +{len(report.to_addrs) - 5} more[/]"
        lines.append(f"[dim]To:[/]      {joined}")
    if report.date:
        lines.append(f"[dim]Date:[/]    {_safe(report.date)}")
    if report.message_id:
        lines.append(f"[dim]Msg-ID:[/]  {_safe(report.message_id)}")
    if report.x_originating_ip:
        lines.append(f"[bold magenta]X-Originating-IP:[/] {_safe(report.x_originating_ip)}")
    console.print(Panel.fit("\n".join(lines), title="Envelope", border_style="cyan"))


def _render_eml_received_chain(report: EmailReport) -> None:
    if not report.received_chain:
        return
    table = Table(title="Received chain (oldest last)", box=SIMPLE, show_lines=False)
    table.add_column("#", style="dim", justify="right")
    table.add_column("Hop", overflow="fold")
    for idx, hop in enumerate(report.received_chain, start=1):
        preview = hop if len(hop) <= 120 else hop[:117] + "..."
        table.add_row(str(idx), _safe(preview))
    console.print(table)


def _render_eml_attachments(report: EmailReport) -> None:
    if not report.attachments:
        return
    table = Table(title=f"Attachments ({len(report.attachments)})", box=SIMPLE)
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("Type", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("SHA-256", style="dim", overflow="fold")
    for att in report.attachments:
        table.add_row(
            _safe(att.filename),
            att.content_type,
            f"{att.size:,}",
            att.sha256,
        )
    console.print(table)


async def _run_parse_eml(path: Path, enrich: bool, use_cache: bool) -> int:
    report = parse_eml(path)
    _render_eml_summary(report)
    _render_eml_received_chain(report)
    _render_eml_attachments(report)

    if not report.iocs:
        console.print("[yellow]No IOCs extracted from this message.[/]")
        return 0
    console.print(f"\nExtracted [bold]{len(report.iocs)}[/] IOC(s) from .eml")

    if not enrich:
        # Show IOCs in a compact table without TI enrichment.
        table = Table(title="IOCs", box=SIMPLE)
        table.add_column("IOC", style="cyan", overflow="fold")
        table.add_column("Type", style="dim")
        for ioc in report.iocs:
            table.add_row(_safe(ioc.value), ioc.type.value)
        console.print(table)
        return 0

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            active = engine.active_sources
            if not active:
                console.print("[yellow]No active TI sources — run `ioc-hunter configure`.[/]")
                console.print("[dim]Re-run with --no-enrich to see IOCs without TI lookups.[/]")
                return 2
            with console.status(
                f"Enriching {len(report.iocs)} IOC(s) across {len(active)} source(s)..."
            ):
                verdicts = await engine.lookup_many(list(report.iocs))
    finally:
        if cache is not None:
            cache.close()

    _render_batch_table(verdicts)
    return 0


@app.command(
    name="parse-eml",
    help="Parse a phishing .eml — headers, body, attachments — and enrich its IOCs.",
)
def parse_eml_cmd(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Show IOCs without TI lookups (offline mode)."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(_run_parse_eml(path, enrich=not no_enrich, use_cache=not no_cache))
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# `analyze` — binary forensics for PE / ELF / Mach-O
# ---------------------------------------------------------------------------


_SEVERITY_STYLES: dict[Severity, tuple[str, str]] = {
    Severity.INFO: ("INFO", "dim"),
    Severity.LOW: ("LOW", "blue"),
    Severity.MEDIUM: ("MEDIUM", "yellow"),
    Severity.HIGH: ("HIGH", "red"),
    Severity.CRITICAL: ("CRITICAL", "bold red"),
}


_VERDICT_TEXT: dict[AnalyzerVerdict, tuple[str, str]] = {
    AnalyzerVerdict.CLEAN: ("CLEAN", "bold green"),
    AnalyzerVerdict.SUSPICIOUS: ("SUSPICIOUS", "bold yellow"),
    AnalyzerVerdict.MALICIOUS: ("MALICIOUS", "bold red"),
}


def _entropy_bar(value: float, width: int = 10) -> str:
    """ASCII bar for entropy in 0..8. Colours by bucket."""
    pct = max(0.0, min(1.0, value / 8.0))
    filled = round(pct * width)
    if value >= 7.5:
        color = "red"
    elif value >= 6.5:
        color = "yellow"
    else:
        color = "green"
    bar = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar}[/]"


def _render_analyze_header(report: AnalyzerReport) -> None:
    label, style = _VERDICT_TEXT[report.verdict]
    lines = [
        f"[bold cyan]File:[/] {_escape_markup(report.path)}",
        f"[dim]Format:[/]  {report.format.value.upper()}  "
        f"[dim]Arch:[/] {report.architecture or '—'}  "
        f"[dim]Bits:[/] {report.bitness or '—'}",
        f"[dim]Size:[/]    {report.file_size:,} bytes  "
        f"[dim]Entropy:[/] {report.overall_entropy:.2f}  "
        f"[dim]Sections:[/] {len(report.sections)}",
        f"[dim]MD5:[/]     {report.md5}",
        f"[dim]SHA1:[/]    {report.sha1}",
        f"[dim]SHA256:[/]  {report.sha256}",
    ]
    if report.entry_point:
        lines.append(f"[dim]Entry:[/]   0x{report.entry_point:x}")
    if report.compiler:
        lines.append(f"[dim]Compiler:[/] {_escape_markup(report.compiler)}")
    if report.imphash:
        lines.append(f"[dim]ImpHash:[/] {report.imphash}")
    if report.build_id:
        lines.append(f"[dim]BuildID:[/] {report.build_id}")
    if report.signer_cn:
        lines.append(f"[dim]Signer:[/]  {_escape_markup(report.signer_cn)}")
    if report.issuer_cn:
        lines.append(f"[dim]Issuer:[/]  {_escape_markup(report.issuer_cn)}")
    flags = []
    if report.is_signed:
        flags.append("[green]signed[/]")
    if report.is_packed:
        packer = f" ({_escape_markup(report.detected_packer)})" if report.detected_packer else ""
        flags.append(f"[red]packed[/]{packer}")
    if report.is_stripped:
        flags.append("[yellow]stripped[/]")
    if report.has_overlay:
        flags.append(f"[yellow]overlay[/] ({report.overlay_size:,} bytes)")
    if flags:
        lines.append("[dim]Flags:[/]   " + ", ".join(flags))
    lines.append(
        f"\n[{style}]VERDICT: {label}[/]  "
        f"[dim]({len(report.findings)} finding(s), confidence {report.confidence():.0%})[/]"
    )
    console.print(Panel.fit("\n".join(lines), title="Binary Analyzer", border_style=style))


def _render_analyze_sections(report: AnalyzerReport) -> None:
    if not report.sections:
        return
    table = Table(title="Sections / Segments", box=SIMPLE, show_lines=False)
    table.add_column("Name", style="cyan", overflow="fold")
    table.add_column("VSize", justify="right", style="dim")
    table.add_column("RSize", justify="right", style="dim")
    table.add_column("Entropy", justify="right")
    table.add_column("Bar", no_wrap=True)
    table.add_column("Perms")
    for s in report.sections[:40]:
        table.add_row(
            _escape_markup(s.name) or "<unnamed>",
            f"{s.virtual_size:,}",
            f"{s.raw_size:,}",
            f"{s.entropy:.2f}",
            _entropy_bar(s.entropy),
            s.flags,
        )
    if len(report.sections) > 40:
        table.add_row("…", "", "", "", "", f"+{len(report.sections) - 40} more")
    console.print(table)


def _render_analyze_imports(report: AnalyzerReport) -> None:
    if not report.imports:
        return
    table = Table(title=f"Imports ({len(report.imports)} libs)", box=SIMPLE, show_lines=False)
    table.add_column("Library", style="cyan", overflow="fold")
    table.add_column("Count", justify="right")
    table.add_column("Sample symbols", overflow="fold", style="dim")
    for imp in report.imports[:30]:
        sample = ", ".join(imp.symbols[:6])
        if len(imp.symbols) > 6:
            sample += f", … +{len(imp.symbols) - 6}"
        table.add_row(_escape_markup(imp.library), str(len(imp.symbols)), _escape_markup(sample))
    if len(report.imports) > 30:
        rest = sum(len(i.symbols) for i in report.imports[30:])
        table.add_row("…", "", f"+{len(report.imports) - 30} libs / {rest} symbols")
    console.print(table)


def _render_analyze_findings(report: AnalyzerReport) -> None:
    if not report.findings:
        console.print("[green]No findings — clean by every rule we apply.[/]")
        return
    table = Table(title=f"Findings ({len(report.findings)})", box=SIMPLE, show_lines=False)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", style="dim")
    table.add_column("ATT&CK", style="magenta", no_wrap=True)
    table.add_column("Rule", style="cyan")
    table.add_column("Message", overflow="fold")
    # Sort by severity desc.
    for f in sorted(report.findings, key=lambda x: -int(x.severity)):
        label, style = _SEVERITY_STYLES[f.severity]
        techniques = ", ".join(f.mitre) if f.mitre else "—"
        table.add_row(
            f"[{style}]{label}[/]",
            f.category,
            techniques,
            f.rule,
            _escape_markup(f.message),
        )
    console.print(table)


def _render_analyze_extras(report: AnalyzerReport) -> None:
    """VERSIONINFO + Manifest + entitlements blocks."""
    if report.version_info:
        table = Table(title="VERSIONINFO", box=SIMPLE)
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        for k, v in report.version_info.items():
            table.add_row(k, _escape_markup(v))
        console.print(table)
    if report.manifest:
        table = Table(title="Manifest", box=SIMPLE)
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        for k, v in report.manifest.items():
            table.add_row(k, _escape_markup(v))
        console.print(table)
    if report.entitlements:
        console.print(
            Panel.fit(
                "\n".join(f"• {_escape_markup(e)}" for e in report.entitlements[:30]),
                title=f"Entitlements ({len(report.entitlements)})",
                border_style="magenta",
            )
        )


def _render_analyze_iocs(report: AnalyzerReport) -> None:
    if not report.iocs:
        return
    table = Table(title=f"IOCs extracted ({len(report.iocs)})", box=SIMPLE, show_lines=False)
    table.add_column("IOC", style="cyan", overflow="fold")
    table.add_column("Type", style="dim")
    for ioc in report.iocs[:40]:
        table.add_row(_safe(ioc.value), ioc.type.value)
    if len(report.iocs) > 40:
        table.add_row("…", f"+{len(report.iocs) - 40} more")
    console.print(table)


def _report_to_jsonable(report: AnalyzerReport) -> dict:
    """Project the dataclass into a JSON-safe dict.

    We do this by hand (rather than ``dataclasses.asdict``) because the
    findings/IOCs/sections nested dataclasses are exactly the fields we
    want, but enums need ``.value`` flattening.
    """
    return {
        "path": report.path,
        "format": report.format.value,
        "file_size": report.file_size,
        "truncated": report.truncated,
        "md5": report.md5,
        "sha1": report.sha1,
        "sha256": report.sha256,
        "architecture": report.architecture,
        "bitness": report.bitness,
        "entry_point": report.entry_point,
        "timestamp": report.timestamp,
        "compiler": report.compiler,
        "overall_entropy": report.overall_entropy,
        "has_overlay": report.has_overlay,
        "overlay_size": report.overlay_size,
        "overlay_entropy": report.overlay_entropy,
        "is_signed": report.is_signed,
        "is_stripped": report.is_stripped,
        "is_packed": report.is_packed,
        "detected_packer": report.detected_packer,
        "imphash": report.imphash,
        "signer_cn": report.signer_cn,
        "issuer_cn": report.issuer_cn,
        "build_id": report.build_id,
        "version_info": report.version_info,
        "manifest": report.manifest,
        "entitlements": list(report.entitlements),
        "verdict": report.verdict.value,
        "confidence": report.confidence(),
        "sections": [
            {
                "name": s.name,
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "file_offset": s.file_offset,
                "entropy": s.entropy,
                "flags": s.flags,
            }
            for s in report.sections
        ],
        "imports": [{"library": i.library, "symbols": list(i.symbols)} for i in report.imports],
        "exports": [{"name": e.name, "ordinal": e.ordinal} for e in report.exports],
        "linked_libraries": list(report.linked_libraries),
        "findings": [
            {
                "rule": f.rule,
                "severity": int(f.severity),
                "severity_label": _SEVERITY_STYLES[f.severity][0],
                "category": f.category,
                "message": f.message,
                "evidence": list(f.evidence),
                "mitre": list(f.mitre),
            }
            for f in report.findings
        ],
        "iocs": [{"value": ioc.value, "type": ioc.type.value} for ioc in report.iocs],
        "metadata": report.metadata,
    }


async def _run_analyze(
    path: Path,
    *,
    enrich: bool,
    use_cache: bool,
    as_json: bool,
    as_md: bool,
    show_strings: bool,
) -> int:
    try:
        report = analyze(path)
    except OSError as exc:
        console.print(f"[red]Cannot read file:[/] {exc}")
        return 2

    if as_md:
        from ioc_hunter.analyze import to_markdown as _to_md

        print(_to_md(report))
        return 0

    if as_json:
        import json as _json

        payload = _report_to_jsonable(report)
        if enrich and report.iocs:
            verdicts = await _enrich_for_json(report.iocs, use_cache=use_cache)
            payload["enriched"] = [
                {
                    "ioc": v.ioc.value,
                    "type": v.ioc.type.value,
                    "verdict": str(v.verdict),
                    "confidence": v.confidence,
                    "tags": list(v.tags),
                }
                for v in verdicts
            ]
        console.print_json(_json.dumps(payload))
        return 0

    _render_analyze_header(report)
    _render_analyze_extras(report)
    _render_analyze_sections(report)
    _render_analyze_imports(report)
    _render_analyze_findings(report)
    _render_analyze_iocs(report)

    if show_strings and report.strings:
        console.print(f"\n[bold]Strings:[/] {len(report.strings):,} extracted")
        for s in report.strings[:40]:
            console.print(f"  {_escape_markup(s)}")

    if not enrich or not report.iocs:
        return 0

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            if not engine.active_sources:
                console.print(
                    "\n[yellow]No active TI sources — skipping IOC enrichment.[/]  "
                    "[dim]Run `ioc-hunter configure` to add keys, or pass --no-enrich.[/]"
                )
                return 0
            with console.status(
                f"Enriching {len(report.iocs)} IOC(s) across {len(engine.active_sources)} source(s)..."
            ):
                verdicts = await engine.lookup_many(report.iocs)
    finally:
        if cache is not None:
            cache.close()

    console.print()
    _render_batch_table(verdicts)
    return 0


async def _enrich_for_json(iocs, *, use_cache: bool):
    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            if not engine.active_sources:
                return []
            return await engine.lookup_many(iocs)
    finally:
        if cache is not None:
            cache.close()


@app.command(
    name="analyze",
    help="Deep static analysis of a PE / ELF / Mach-O binary.",
)
def analyze_cmd(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    no_enrich: bool = typer.Option(
        False, "--no-enrich", help="Show IOCs without TI lookups (offline mode)."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
    as_json: bool = typer.Option(False, "--json", help="Emit the full report as JSON."),
    as_md: bool = typer.Option(False, "--md", help="Emit the report as Jira/Slack-ready Markdown."),
    show_strings: bool = typer.Option(
        False, "--strings", help="Also print a preview of extracted strings."
    ),
) -> None:
    exit_code = asyncio.run(
        _run_analyze(
            path,
            enrich=not no_enrich,
            use_cache=not no_cache,
            as_json=as_json,
            as_md=as_md,
            show_strings=show_strings,
        )
    )
    raise typer.Exit(exit_code)


def _render_alert(alert: WatchAlert) -> None:
    label, style = _VERDICT_STYLES[alert.verdict.verdict]
    ioc = alert.verdict.ioc
    body = (
        f"[bold]IOC:[/] [cyan]{_safe(ioc.value)}[/] [dim]({ioc.type.value})[/]\n"
        f"[{style}]{label}[/]  [dim]confidence[/] {alert.verdict.confidence:.0%}\n"
    )
    if alert.verdict.tags:
        body += f"[yellow]tags:[/] {', '.join(alert.verdict.tags[:6])}\n"
    line_preview = alert.source_line
    if len(line_preview) > 140:
        line_preview = line_preview[:137] + "..."
    body += f"[dim]line:[/] {_safe(line_preview)}"
    console.print(Panel.fit(body, title="ALERT", border_style=style))


async def _run_watch(
    path: Path,
    threshold_name: str,
    from_start: bool,
    debounce: float,
    use_cache: bool,
) -> int:
    try:
        threshold = resolve_threshold(threshold_name)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        return 2

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    console.print(
        Panel.fit(
            f"[bold]Watching[/] {path}\n"
            f"[dim]threshold:[/] {threshold.value}  "
            f"[dim]debounce:[/] {debounce}s  "
            f"[dim]from-start:[/] {from_start}\n"
            f"[dim]Press Ctrl-C to stop.[/]",
            border_style="cyan",
        )
    )
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            if not engine.active_sources:
                console.print("[red]No active sources — run `ioc-hunter configure`.[/]")
                return 2
            try:
                async for alert in _watch(
                    path,
                    engine,
                    threshold=threshold,
                    debounce_seconds=debounce,
                    from_start=from_start,
                ):
                    _render_alert(alert)
            except KeyboardInterrupt:
                console.print("\n[dim]Stopped.[/]")
    finally:
        if cache is not None:
            cache.close()
    return 0


@app.command(
    name="watch",
    help="Tail a log file and alert on IOCs whose verdict meets a threshold.",
)
def watch_cmd(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    threshold: str = typer.Option(
        "suspicious",
        "--threshold",
        "-t",
        help="Alert on this verdict or worse: malicious | suspicious | benign | unknown.",
    ),
    from_start: bool = typer.Option(
        False,
        "--from-start",
        help="Scan from the start of the file (default: tail only new lines).",
    ),
    debounce: float = typer.Option(
        2.0, "--debounce", help="Seconds of quiet before flushing a batch."
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(
        _run_watch(path, threshold, from_start, debounce, use_cache=not no_cache)
    )
    raise typer.Exit(exit_code)


_EXPORTERS = {
    "json": to_json,
    "markdown": to_markdown,
    "md": to_markdown,
    "stix": to_stix,
    "misp": to_misp,
    "sigma": to_sigma,
    "suricata": to_suricata,
}


async def _run_report(
    path: Path,
    fmt: str,
    out: Path | None,
    use_cache: bool,
) -> int:
    if fmt not in _EXPORTERS:
        choices = ", ".join(sorted(set(_EXPORTERS)))
        console.print(f"[red]Unknown format[/] {fmt!r}; valid: {choices}")
        return 2

    iocs = extract_iocs(path.read_text(errors="replace"))
    if not iocs:
        console.print(f"[yellow]No IOCs found in[/] {path}")
        return 0

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            if not engine.active_sources:
                console.print("[red]No active sources — run `ioc-hunter configure`.[/]")
                return 2
            with console.status(f"Enriching {len(iocs)} IOC(s) for {fmt} report..."):
                verdicts = await engine.lookup_many(iocs)
    finally:
        if cache is not None:
            cache.close()

    rendered = _EXPORTERS[fmt](verdicts)
    if out is None:
        print(rendered)
    else:
        out.write_text(rendered)
        console.print(f"[green]Wrote[/] {out} ({len(rendered)} bytes)")
    return 0


@app.command(help="Enrich a file of IOCs and render JSON / Markdown / STIX / MISP.")
def report(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="json | markdown | stix | misp | sigma | suricata",
    ),
    out: Path | None = typer.Option(None, "--out", "-o", help="Write to file instead of stdout."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(_run_report(path, fmt, out, use_cache=not no_cache))
    raise typer.Exit(exit_code)


async def _run_correlate(path: Path, use_cache: bool) -> int:
    iocs = extract_iocs(path.read_text(errors="replace"))
    if not iocs:
        console.print(f"[yellow]No IOCs found in[/] {path}")
        return 0
    console.print(f"Extracted [bold]{len(iocs)}[/] IOC(s) from {path}")

    settings = Settings.from_env()
    cache = _open_cache(settings, use_cache)
    try:
        async with httpx.AsyncClient() as client:
            engine = _build_engine(client, settings, cache)
            if not engine.active_sources:
                console.print("[red]No active sources — run `ioc-hunter configure`.[/]")
                return 2
            with console.status(f"Enriching {len(iocs)} IOC(s) for correlation..."):
                verdicts = await engine.lookup_many(iocs)
    finally:
        if cache is not None:
            cache.close()

    edges = _correlate(verdicts)
    if not edges:
        console.print("[dim]No correlations found between the supplied IOCs.[/]")
        return 0

    table = Table(title=f"Correlations ({len(edges)})", box=SIMPLE)
    table.add_column("Kind", style="cyan")
    table.add_column("Source", overflow="fold")
    table.add_column("→", style="dim")
    table.add_column("Target", overflow="fold")
    table.add_column("Evidence", style="dim", overflow="fold")
    for edge in edges:
        table.add_row(
            edge.kind,
            _safe(edge.source.value),
            "→",
            _safe(edge.target.value),
            edge.evidence,
        )
    console.print(table)
    return 0


@app.command(
    name="correlate",
    help="Find shared infrastructure / tag pivots across a batch of IOCs.",
)
def correlate(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, resolve_path=True),
    no_cache: bool = typer.Option(False, "--no-cache", help="Skip the SQLite cache."),
) -> None:
    exit_code = asyncio.run(_run_correlate(path, use_cache=not no_cache))
    raise typer.Exit(exit_code)


@app.command(help="Decode obfuscated input (base64, hex, URL, JWT, gzip, ...).")
def decode(
    text: str = typer.Argument(..., help="The encoded string."),
    op: str | None = typer.Option(
        None,
        "--op",
        "-o",
        help=f"Force one operation. One of: {', '.join(sorted(_DECODE_OPS))}.",
    ),
) -> None:
    if op:
        try:
            decoded = _decode_op(op, text)
        except DecodeError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(2) from None
        console.print(Panel.fit(decoded, title=f"{op}", border_style="cyan"))
        return

    results = _magic(text)
    if not results:
        console.print("[yellow]No operation produced a valid decode.[/]")
        raise typer.Exit(1)

    table = Table(title=f"Magic decode — {len(results)} candidate(s)", box=SIMPLE)
    table.add_column("Op", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("IOCs", justify="right")
    table.add_column("Decoded", overflow="fold")
    for r in results:
        preview = r.decoded if len(r.decoded) <= 80 else r.decoded[:77] + "..."
        table.add_row(r.operation, f"{r.score:.2f}", str(r.ioc_count), preview)
    console.print(table)


@app.command(help="List configured and unconfigured sources.")
def sources() -> None:
    settings = Settings.from_env()
    table = Table(title="TI sources", box=SIMPLE)
    table.add_column("Source", style="cyan")
    table.add_column("Status")
    table.add_column("Weight", justify="right")
    table.add_column("Supports", style="dim", overflow="fold")
    table.add_column("Key required", style="dim")

    # Build with a dummy client so we can ask is_configured / supports.
    client = httpx.AsyncClient()
    try:
        for src in _build_sources(client, settings):
            status = "[green]active[/]" if src.is_configured else "[yellow]missing key[/]"
            table.add_row(
                src.name,
                status,
                f"{src.weight:.2f}",
                ", ".join(sorted(t.value for t in src.supported_types)),
                "yes" if src.requires_key else "no",
            )
    finally:
        # Sync close — httpx.AsyncClient supports close() in sync ctx for cleanup.
        asyncio.run(client.aclose())
    console.print(table)


_CONFIGURABLE = (
    (
        "ABUSE_CH_AUTH_KEY",
        "abuse.ch Auth-Key (URLhaus + ThreatFox)",
        "https://auth.abuse.ch/",
    ),
    (
        "ABUSEIPDB_API_KEY",
        "AbuseIPDB",
        "https://www.abuseipdb.com/register",
    ),
    ("OTX_API_KEY", "AlienVault OTX", "https://otx.alienvault.com/"),
    (
        "VIRUSTOTAL_API_KEY",
        "VirusTotal",
        "https://www.virustotal.com/",
    ),
    ("SHODAN_API_KEY", "Shodan (optional)", "https://account.shodan.io/"),
)


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def _write_env_file(path: Path, values: dict[str, str]) -> None:
    lines = ["# Generated by `ioc-hunter configure`."]
    for k, v in values.items():
        lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n")


@app.command(help="Interactive setup — collects API keys and writes .env.")
def configure(
    env_path: Path = typer.Option(Path(".env"), "--env-path", help="Where to write."),
) -> None:
    console.print(
        Panel.fit(
            "[bold]ioc-hunter setup[/]\n\n"
            "I'll ask for each API key in turn. Press Enter to skip — the\n"
            "corresponding source will short-circuit to UNKNOWN with a hint.\n\n"
            "[dim]All keys live only in this .env file (gitignored).[/]",
            border_style="cyan",
        )
    )

    existing = _read_env_file(env_path)
    updated = dict(existing)

    for key, label, url in _CONFIGURABLE:
        current = existing.get(key, "")
        marker = "[green]set[/]" if current else "[dim]empty[/]"
        console.print(f"\n[bold]{label}[/]  ({marker})")
        console.print(f"  [dim]register:[/] {url}")
        prompt_text = f"  {key} (Enter to keep current)"
        value = typer.prompt(prompt_text, default="", show_default=False)
        if value.strip():
            updated[key] = value.strip()

    _write_env_file(env_path, updated)
    console.print(f"\n[green]Wrote[/] {env_path}")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]ioc-hunter[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Root callback — global flags only."""


if __name__ == "__main__":
    app()

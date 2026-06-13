"""ioc-hunter CLI entrypoint.

Commands:
    ioc-hunter check <ioc>            single-IOC lookup
    ioc-hunter scan-file <path>       extract + enrich every IOC in a file
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
from rich.panel import Panel
from rich.table import Table

from ioc_hunter import __version__
from ioc_hunter.cache import TICache
from ioc_hunter.config import Settings
from ioc_hunter.core import IOC, defang, detect_type, extract_iocs
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
    OTXSource,
    Source,
    ThreatFoxSource,
    TorExitSource,
    URLhausSource,
    Verdict,
    VirusTotalSource,
)

app = typer.Typer(
    name="ioc-hunter",
    help="Async threat intelligence correlation engine for SOC analysts.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

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
    value = value.strip()
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
        f"[bold cyan]{defang(verdict.ioc.value)}[/]\n"
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
            defang(v.ioc.value)[:60],
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
            with console.status(f"Querying {len(active)} source(s) for {defang(ioc.value)}..."):
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
    fmt: str = typer.Option("markdown", "--format", "-f", help="json | markdown | stix | misp"),
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
            defang(edge.source.value),
            "→",
            defang(edge.target.value),
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

"""Render an ``AnalyzerReport`` as Jira/Slack-ready Markdown.

The structure mirrors what an analyst writes by hand when triaging a
sample: file identity → hashes → verdict → findings table → IOC table.
ATT&CK technique IDs are rendered as inline tags after each finding's
message so the page is greppable.
"""

from __future__ import annotations

from ioc_hunter.analyze.attack_map import all_techniques
from ioc_hunter.analyze.common import AnalyzerReport, Severity

_SEVERITY_LABEL = {
    Severity.INFO: "INFO",
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


def _esc(text: str) -> str:
    """Escape Markdown pipe / backtick characters in table cells."""
    return text.replace("|", r"\|").replace("`", "'")


def to_markdown(report: AnalyzerReport) -> str:
    lines: list[str] = []
    lines.append(f"# Binary Analysis Report — `{_esc(report.path)}`")
    lines.append("")

    verdict_label = report.verdict.value.upper()
    lines.append(
        f"**Verdict:** **{verdict_label}**  ·  "
        f"confidence {report.confidence():.0%}  ·  "
        f"findings {len(report.findings)}"
    )
    lines.append("")

    # ---- File identity -----------------------------------------------------
    lines.append("## File")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Format | {report.format.value.upper()} |")
    lines.append(f"| Architecture | {report.architecture or '—'} |")
    lines.append(f"| Bits | {report.bitness or '—'} |")
    lines.append(f"| Size | {report.file_size:,} bytes |")
    lines.append(f"| Entropy (overall) | {report.overall_entropy:.2f} |")
    lines.append(f"| Sections | {len(report.sections)} |")
    if report.entry_point:
        lines.append(f"| Entry point | 0x{report.entry_point:x} |")
    if report.compiler:
        lines.append(f"| Compiler | {_esc(report.compiler)} |")
    lines.append(f"| MD5 | `{report.md5}` |")
    lines.append(f"| SHA-1 | `{report.sha1}` |")
    lines.append(f"| SHA-256 | `{report.sha256}` |")
    if report.imphash:
        lines.append(f"| ImpHash | `{report.imphash}` |")
    if report.build_id:
        lines.append(f"| Build-ID | `{report.build_id}` |")
    if report.signer_cn:
        lines.append(f"| Signer CN | {_esc(report.signer_cn)} |")
    if report.issuer_cn:
        lines.append(f"| Issuer CN | {_esc(report.issuer_cn)} |")
    flags: list[str] = []
    if report.is_signed:
        flags.append("signed")
    if report.is_packed:
        flags.append(f"packed ({report.detected_packer or 'unknown'})")
    if report.is_stripped:
        flags.append("stripped")
    if report.has_overlay:
        flags.append(f"overlay ({report.overlay_size:,} B)")
    if flags:
        lines.append(f"| Flags | {', '.join(flags)} |")
    lines.append("")

    # ---- VERSIONINFO -------------------------------------------------------
    if report.version_info:
        lines.append("## VERSIONINFO")
        lines.append("")
        lines.append("| Key | Value |")
        lines.append("|---|---|")
        for k, v in report.version_info.items():
            lines.append(f"| {_esc(k)} | {_esc(v)} |")
        lines.append("")

    # ---- Manifest ----------------------------------------------------------
    if report.manifest:
        lines.append("## Manifest")
        lines.append("")
        lines.append("| Key | Value |")
        lines.append("|---|---|")
        for k, v in report.manifest.items():
            lines.append(f"| {_esc(k)} | {_esc(v)} |")
        lines.append("")

    # ---- Entitlements ------------------------------------------------------
    if report.entitlements:
        lines.append("## Entitlements")
        lines.append("")
        for e in report.entitlements:
            lines.append(f"- `{_esc(e)}`")
        lines.append("")

    # ---- Sections ----------------------------------------------------------
    if report.sections:
        lines.append("## Sections / Segments")
        lines.append("")
        lines.append("| Name | VSize | RSize | Entropy | Perms |")
        lines.append("|---|---:|---:|---:|---|")
        for s in report.sections[:60]:
            lines.append(
                f"| `{_esc(s.name)}` | {s.virtual_size:,} | {s.raw_size:,} | "
                f"{s.entropy:.2f} | {s.flags} |"
            )
        if len(report.sections) > 60:
            lines.append(f"| … | | | | +{len(report.sections) - 60} more |")
        lines.append("")

    # ---- Imports -----------------------------------------------------------
    if report.imports:
        lines.append("## Imports")
        lines.append("")
        for imp in report.imports[:30]:
            preview = ", ".join(imp.symbols[:8])
            extra = f" (+{len(imp.symbols) - 8} more)" if len(imp.symbols) > 8 else ""
            lines.append(
                f"- `{_esc(imp.library)}` — {len(imp.symbols)} symbols: {_esc(preview)}{extra}"
            )
        lines.append("")

    # ---- Findings ----------------------------------------------------------
    if report.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Severity | Rule | Category | ATT&CK | Message |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(report.findings, key=lambda x: -int(x.severity)):
            mitre = ", ".join(f.mitre) if f.mitre else "—"
            lines.append(
                f"| {_SEVERITY_LABEL[f.severity]} | `{f.rule}` | {f.category} | "
                f"{mitre} | {_esc(f.message)} |"
            )
        techs = all_techniques(report)
        if techs:
            lines.append("")
            lines.append(f"**ATT&CK coverage:** {', '.join(techs)}")
        lines.append("")

    # ---- IOCs --------------------------------------------------------------
    if report.iocs:
        lines.append("## IOCs extracted")
        lines.append("")
        lines.append("| Value | Type |")
        lines.append("|---|---|")
        for ioc in report.iocs[:80]:
            lines.append(f"| `{_esc(ioc.value)}` | {ioc.type.value} |")
        if len(report.iocs) > 80:
            lines.append(f"| … | +{len(report.iocs) - 80} more |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"

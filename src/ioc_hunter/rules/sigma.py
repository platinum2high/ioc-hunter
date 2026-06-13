"""Sigma rule generator.

One YAML document per IOC type that has malicious indicators in the batch.
All IOCs of the same type are listed as alternatives under one `selection`,
which keeps rule volume manageable when ingesting a batch.

Output is hand-formatted YAML (no pyyaml dep) — Sigma is a simple
flow-style subset, so a small builder is enough and avoids an extra runtime
dependency.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ioc_hunter.core.types import IOCType
from ioc_hunter.rules._common import filter_by_severity
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

# Per-type configuration: (logsource category, selection field, optional value
# transform). `field_value` becomes a YAML list of all IOCs of that type.
_TYPE_CONFIG: dict[IOCType, tuple[str, str, str]] = {
    IOCType.IPV4: ("network_connection", "DestinationIp", "high"),
    IOCType.IPV6: ("network_connection", "DestinationIp", "high"),
    IOCType.DOMAIN: ("dns", "QueryName", "high"),
    IOCType.URL: ("proxy", "c-uri", "high"),
    IOCType.EMAIL: ("email", "sender", "medium"),
    IOCType.MD5: ("file_event", "Hashes|contains", "high"),
    IOCType.SHA1: ("file_event", "Hashes|contains", "high"),
    IOCType.SHA256: ("file_event", "Hashes|contains", "high"),
}


def _yaml_quote(value: str) -> str:
    """Quote a scalar so it parses as a YAML string with no special meaning."""
    escaped = value.replace("\\", "\\\\").replace("'", "''")
    return f"'{escaped}'"


def _hash_field_value(ioc_type: IOCType, value: str) -> str:
    prefix = {IOCType.MD5: "MD5=", IOCType.SHA1: "SHA1=", IOCType.SHA256: "SHA256="}[ioc_type]
    return f"{prefix}{value}"


def _selection_values(ioc_type: IOCType, verdicts: list[IOCVerdict]) -> list[str]:
    if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
        return [_hash_field_value(ioc_type, v.ioc.value) for v in verdicts]
    return [v.ioc.value for v in verdicts]


def _collect_tags(verdicts: list[IOCVerdict]) -> list[str]:
    seen: list[str] = []
    for v in verdicts:
        for tag in v.tags:
            normalized = tag.strip().lower().replace(" ", "_")
            if normalized and normalized not in seen:
                seen.append(normalized)
    return seen[:20]


def _collect_references(verdicts: list[IOCVerdict]) -> list[str]:
    seen: list[str] = []
    for v in verdicts:
        for ref in v.references:
            if ref and ref not in seen:
                seen.append(ref)
    return seen[:10]


def _render_rule(ioc_type: IOCType, verdicts: list[IOCVerdict], now: str) -> str:
    category, field, level = _TYPE_CONFIG[ioc_type]
    values = _selection_values(ioc_type, verdicts)
    tags = _collect_tags(verdicts)
    references = _collect_references(verdicts)

    lines: list[str] = []
    lines.append(f"title: IOC Hunter - {len(verdicts)} malicious {ioc_type.value} indicator(s)")
    lines.append(f"id: {uuid.uuid4()}")
    lines.append("status: experimental")
    lines.append(f"description: Auto-generated from threat-intel verdicts on {now}.")
    lines.append(f"date: {now}")
    if references:
        lines.append("references:")
        for ref in references:
            lines.append(f"  - {ref}")
    lines.append("author: ioc-hunter")
    lines.append("logsource:")
    lines.append(f"  category: {category}")
    lines.append("detection:")
    lines.append("  selection:")
    lines.append(f"    {field}:")
    for value in values:
        lines.append(f"      - {_yaml_quote(value)}")
    lines.append("  condition: selection")
    lines.append(f"level: {level}")
    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"  - {tag}")
    return "\n".join(lines)


def to_sigma(
    verdicts: list[IOCVerdict],
    *,
    min_verdict: Verdict = Verdict.MALICIOUS,
) -> str:
    """Render every malicious IOC into Sigma YAML, grouped by type."""
    bad = filter_by_severity(verdicts, min_verdict)
    if not bad:
        return ""

    grouped: dict[IOCType, list[IOCVerdict]] = {}
    for v in bad:
        if v.ioc.type in _TYPE_CONFIG:
            grouped.setdefault(v.ioc.type, []).append(v)

    now = datetime.now(UTC).strftime("%Y/%m/%d")
    documents = [_render_rule(ioc_type, group, now) for ioc_type, group in grouped.items()]
    return "\n---\n".join(documents)

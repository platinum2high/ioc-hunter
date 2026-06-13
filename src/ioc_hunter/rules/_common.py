"""Shared helpers for rule generators."""

from __future__ import annotations

from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_SEVERITY: dict[Verdict, int] = {
    Verdict.UNKNOWN: 0,
    Verdict.BENIGN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}


def filter_by_severity(
    verdicts: list[IOCVerdict],
    min_verdict: Verdict,
) -> list[IOCVerdict]:
    """Return only verdicts whose severity is `min_verdict` or worse."""
    floor = _SEVERITY[min_verdict]
    return [v for v in verdicts if _SEVERITY[v.verdict] >= floor]

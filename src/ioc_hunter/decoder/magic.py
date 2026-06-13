"""Magic-style auto-decoding.

Try every registered operation against the input, score the result by how
"plausible" it looks as a decoded string, and return the candidates ranked
from best to worst. The analyst pasting in a random chunk of base64/hex/JWT
sees the right answer at the top.
"""

from __future__ import annotations

from dataclasses import dataclass

from ioc_hunter.core.parser import extract_iocs
from ioc_hunter.decoder.operations import OPERATIONS, DecodeError


@dataclass(frozen=True, slots=True)
class MagicResult:
    operation: str
    decoded: str
    score: float
    ioc_count: int


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
    return printable / len(text)


def _score(decoded: str, ioc_count: int) -> float:
    """Score a candidate decoding. Higher is better, capped at 1.0.

    Printability gets at most 0.85 so the IOC bonus is observable in
    rankings — a result with extractable IOCs beats one without even when
    both are fully printable.
    """
    if not decoded:
        return 0.0
    printable = _printable_ratio(decoded)
    if printable < 0.6:
        return printable * 0.3
    base = printable * 0.85
    base += min(0.15, 0.05 * ioc_count)
    return min(1.0, base)


def magic(text: str, *, limit: int = 5) -> list[MagicResult]:
    """Try every operation, return the top `limit` results by score."""
    candidates: list[MagicResult] = []
    for name, op in OPERATIONS.items():
        try:
            decoded = op(text)
        except DecodeError:
            continue
        if not decoded:
            continue
        ioc_count = len(extract_iocs(decoded))
        candidates.append(
            MagicResult(
                operation=name,
                decoded=decoded,
                score=_score(decoded, ioc_count),
                ioc_count=ioc_count,
            )
        )
    candidates.sort(key=lambda r: (-r.score, -r.ioc_count, r.operation))
    return candidates[:limit]

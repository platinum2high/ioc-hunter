"""Live log-file watcher.

`ioc-hunter watch /var/log/auth.log` opens the file, seeks to the end,
and continuously polls for new bytes. Newly-appended lines are scanned
for IOCs and accumulated into a small debounce buffer; once the buffer
is quiet for `debounce_seconds`, it's flushed to the engine for batched
TI lookup and any verdict at or above `threshold` is rendered as an
alert.

Design notes:

- Stdlib only — no inotify/watchdog. macOS + Linux both work via polling.
- Debounce so a thousand-line burst becomes one batch request, not 1000.
- Handles log rotation: if the file's inode changes or size shrinks,
  re-open from the start.
- Already-seen IOCs in the window are deduplicated so a domain appearing
  100 times in one batch is enriched once.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

from ioc_hunter.core import IOC, extract_iocs
from ioc_hunter.engine import Engine
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_THRESHOLD_BY_NAME = {
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "benign": Verdict.BENIGN,
    "unknown": Verdict.UNKNOWN,
}
_VERDICT_RANK = {
    Verdict.MALICIOUS: 3,
    Verdict.SUSPICIOUS: 2,
    Verdict.BENIGN: 1,
    Verdict.UNKNOWN: 0,
}


def resolve_threshold(name: str) -> Verdict:
    try:
        return _THRESHOLD_BY_NAME[name.lower()]
    except KeyError as exc:
        valid = ", ".join(_THRESHOLD_BY_NAME)
        raise ValueError(f"unknown threshold {name!r}; valid: {valid}") from exc


def meets_threshold(verdict: Verdict, threshold: Verdict) -> bool:
    return _VERDICT_RANK[verdict] >= _VERDICT_RANK[threshold]


@dataclass(frozen=True, slots=True)
class WatchAlert:
    """One alert: a verdict that met or exceeded the configured threshold."""

    verdict: IOCVerdict
    source_line: str


_MAX_LINE_BYTES = 1 * 1024 * 1024  # 1 MiB cap on a single un-terminated line


async def tail_file(
    path: Path,
    *,
    poll_interval: float = 0.5,
    from_start: bool = False,
) -> AsyncIterator[str]:
    """Yield newly-appended lines from `path` forever.

    Handles log rotation (inode change or truncate) by re-opening the file.
    A pathological line that never terminates is force-flushed at
    `_MAX_LINE_BYTES` so a malicious / broken writer can't OOM us.
    """
    fh = path.open("rb")
    try:
        if not from_start:
            fh.seek(0, os.SEEK_END)
        last_inode = os.fstat(fh.fileno()).st_ino
        last_size = fh.tell()
        buffer = b""

        while True:
            chunk = fh.read(65536)
            if chunk:
                buffer += chunk
                last_size = fh.tell()
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    yield line.decode("utf-8", errors="replace")
                if len(buffer) >= _MAX_LINE_BYTES:
                    yield buffer.decode("utf-8", errors="replace")
                    buffer = b""
                continue

            await asyncio.sleep(poll_interval)

            try:
                st = path.stat()
            except FileNotFoundError:
                continue

            rotated = st.st_ino != last_inode or st.st_size < last_size
            if rotated:
                fh.close()
                fh = path.open("rb")
                last_inode = os.fstat(fh.fileno()).st_ino
                last_size = 0
                buffer = b""
    finally:
        fh.close()


async def _drain_batches(
    line_iter: AsyncIterator[str],
    debounce_seconds: float,
    batch_max: int,
) -> AsyncIterator[tuple[list[IOC], str]]:
    """Group `extract_iocs` output from `line_iter` into batches.

    A batch flushes when either:
    - `debounce_seconds` pass without a new line, OR
    - the batch reaches `batch_max` distinct IOCs.

    Each yielded value is `(distinct_iocs, last_line_for_context)`.
    """
    pending: dict[tuple[str, str], IOC] = {}
    last_line = ""

    async def next_line_or_timeout(timeout: float) -> str | None:
        try:
            return await asyncio.wait_for(line_iter.__anext__(), timeout=timeout)
        except TimeoutError:
            return None
        except StopAsyncIteration:
            return None

    while True:
        line = await next_line_or_timeout(debounce_seconds if pending else 3600)
        if line is None:
            if pending:
                yield list(pending.values()), last_line
                pending.clear()
            continue
        last_line = line
        for ioc in extract_iocs(line):
            key = (ioc.type.value, ioc.value)
            if key not in pending:
                pending[key] = ioc
        if len(pending) >= batch_max:
            yield list(pending.values()), last_line
            pending.clear()


async def watch(
    path: Path,
    engine: Engine,
    *,
    threshold: Verdict = Verdict.SUSPICIOUS,
    debounce_seconds: float = 2.0,
    batch_max: int = 50,
    from_start: bool = False,
) -> AsyncIterator[WatchAlert]:
    """Async iterator of alerts for IOCs appearing in a tailed file.

    Stops only when the consumer breaks out — designed for daemon use.
    """
    lines = tail_file(path, from_start=from_start)
    batches = _drain_batches(lines, debounce_seconds, batch_max)
    async for iocs, context_line in batches:
        if not iocs:
            continue
        verdicts = await engine.lookup_many(iocs)
        for v in verdicts:
            if meets_threshold(v.verdict, threshold):
                yield WatchAlert(verdict=v, source_line=context_line)

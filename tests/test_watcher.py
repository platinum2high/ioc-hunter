"""Tests for the live log watcher."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict
from ioc_hunter.watcher import (
    _drain_batches,
    meets_threshold,
    resolve_threshold,
    tail_file,
    watch,
)


def test_resolve_threshold_valid() -> None:
    assert resolve_threshold("malicious") is Verdict.MALICIOUS
    assert resolve_threshold("Suspicious") is Verdict.SUSPICIOUS
    assert resolve_threshold("BENIGN") is Verdict.BENIGN


def test_resolve_threshold_invalid_raises() -> None:
    with pytest.raises(ValueError):
        resolve_threshold("bogus")


def test_meets_threshold_ordering() -> None:
    assert meets_threshold(Verdict.MALICIOUS, Verdict.SUSPICIOUS)
    assert meets_threshold(Verdict.SUSPICIOUS, Verdict.SUSPICIOUS)
    assert not meets_threshold(Verdict.BENIGN, Verdict.SUSPICIOUS)
    assert not meets_threshold(Verdict.UNKNOWN, Verdict.MALICIOUS)


@pytest.mark.asyncio
async def test_tail_file_picks_up_appended_lines(tmp_path) -> None:
    log = tmp_path / "live.log"
    log.write_text("old line\n")

    async def writer() -> None:
        await asyncio.sleep(0.1)
        with log.open("a") as fh:
            fh.write("first new\n")
            fh.flush()
        await asyncio.sleep(0.1)
        with log.open("a") as fh:
            fh.write("second new\n")
            fh.flush()

    collected: list[str] = []

    async def reader() -> None:
        async for line in tail_file(log, poll_interval=0.05):
            collected.append(line)
            if len(collected) == 2:
                return

    await asyncio.wait_for(asyncio.gather(reader(), writer()), timeout=3.0)
    assert collected == ["first new", "second new"]


@pytest.mark.asyncio
async def test_tail_handles_rotation(tmp_path) -> None:
    log = tmp_path / "rotate.log"
    log.write_text("seed\n")

    async def churn() -> None:
        await asyncio.sleep(0.1)
        # Simulate rotation: replace the file with a smaller one — same path,
        # new inode, smaller size — triggers re-open from the start.
        log.unlink()
        log.write_text("after-rotate\n")

    collected: list[str] = []

    async def reader() -> None:
        async for line in tail_file(log, poll_interval=0.05):
            collected.append(line)
            if collected:
                return

    await asyncio.wait_for(asyncio.gather(reader(), churn()), timeout=3.0)
    assert collected == ["after-rotate"]


@pytest.mark.asyncio
async def test_drain_batches_debounces() -> None:
    """A burst of lines should land in a single batch after the debounce."""

    async def feed() -> AsyncIterator[str]:
        yield "evil.net sent traffic to 1.2.3.4"
        yield "and again from 5.6.7.8"
        # Long sleep simulates "quiet" — debounce should fire.
        await asyncio.sleep(0.0)

    batches: list[list[IOC]] = []

    async def collect() -> None:
        async for iocs, _ in _drain_batches(feed(), debounce_seconds=0.05, batch_max=100):
            batches.append(iocs)
            if batches:
                return

    await asyncio.wait_for(collect(), timeout=3.0)
    assert len(batches) == 1
    # Both IPs and the domain should have arrived together.
    values = {ioc.value for ioc in batches[0]}
    assert "1.2.3.4" in values
    assert "5.6.7.8" in values
    assert "evil.net" in values


@pytest.mark.asyncio
async def test_drain_batches_dedupes_within_window() -> None:
    async def feed() -> AsyncIterator[str]:
        yield "saw 1.2.3.4 doing bad things"
        yield "again 1.2.3.4 hit endpoint"
        yield "and 1.2.3.4 once more"

    batches: list[list[IOC]] = []

    async def collect() -> None:
        async for iocs, _ in _drain_batches(feed(), debounce_seconds=0.05, batch_max=100):
            batches.append(iocs)
            if batches:
                return

    await asyncio.wait_for(collect(), timeout=3.0)
    assert len(batches) == 1
    ip_iocs = [i for i in batches[0] if i.type is IOCType.IPV4]
    assert len(ip_iocs) == 1


class _FakeEngine:
    """Minimal stand-in for the real Engine used in watch() integration."""

    def __init__(self, verdict_for: dict[str, Verdict]) -> None:
        self._verdict_for = verdict_for

    async def lookup_many(self, iocs: list[IOC]) -> list[IOCVerdict]:
        out = []
        for ioc in iocs:
            v = self._verdict_for.get(ioc.value, Verdict.UNKNOWN)
            out.append(
                IOCVerdict(
                    ioc=ioc,
                    verdict=v,
                    confidence=0.9 if v is Verdict.MALICIOUS else 0.4,
                    results=(),
                )
            )
        return out


@pytest.mark.asyncio
async def test_watch_emits_alert_above_threshold(tmp_path) -> None:
    log = tmp_path / "live.log"
    log.write_text("")

    async def writer() -> None:
        await asyncio.sleep(0.1)
        log.write_text("attacker from 1.2.3.4 hit /admin\n")

    engine = _FakeEngine({"1.2.3.4": Verdict.MALICIOUS})
    alerts = []

    async def consumer() -> None:
        async for alert in watch(log, engine, threshold=Verdict.SUSPICIOUS, debounce_seconds=0.1):
            alerts.append(alert)
            return

    await asyncio.wait_for(asyncio.gather(consumer(), writer()), timeout=5.0)
    assert len(alerts) == 1
    assert alerts[0].verdict.verdict is Verdict.MALICIOUS
    assert "1.2.3.4" in alerts[0].source_line


@pytest.mark.asyncio
async def test_watch_skips_below_threshold(tmp_path) -> None:
    log = tmp_path / "live.log"
    log.write_text("")

    async def writer() -> None:
        # Three appends — only one should generate an alert.
        for line in (
            "request from 10.0.0.5 to api",
            "user from 8.8.8.8 hit /home",
            "ssh from 1.2.3.4 root login",
        ):
            await asyncio.sleep(0.05)
            with log.open("a") as fh:
                fh.write(line + "\n")
                fh.flush()

    engine = _FakeEngine({"1.2.3.4": Verdict.MALICIOUS})
    alerts = []

    async def consumer() -> None:
        async for alert in watch(log, engine, threshold=Verdict.MALICIOUS, debounce_seconds=0.1):
            alerts.append(alert)
            return

    await asyncio.wait_for(asyncio.gather(consumer(), writer()), timeout=5.0)
    assert len(alerts) == 1
    assert alerts[0].verdict.ioc.value == "1.2.3.4"

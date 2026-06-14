"""Tests for the optional FastAPI front."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from ioc_hunter.core.types import IOC
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict
from ioc_hunter.web.app import create_app
from ioc_hunter.web.rate_limit import RateLimiter


class _FakeEngine:
    """In-memory engine that returns a canned verdict per IOC value."""

    def __init__(self) -> None:
        self._sources = []
        self._fixture: dict[str, Verdict] = {
            "1.2.3.4": Verdict.MALICIOUS,
            "10.0.0.5": Verdict.BENIGN,
            "evil.example": Verdict.MALICIOUS,
        }

    async def lookup_one(self, ioc: IOC) -> IOCVerdict:
        v = self._fixture.get(ioc.value, Verdict.UNKNOWN)
        return IOCVerdict(
            ioc=ioc,
            verdict=v,
            confidence=0.9 if v is Verdict.MALICIOUS else 0.3,
            results=(
                SourceResult(
                    source="fake",
                    ioc_type=ioc.type,
                    ioc_value=ioc.value,
                    verdict=v,
                    score=0.9,
                    tags=("test",),
                ),
            ),
            tags=("test",) if v is Verdict.MALICIOUS else (),
            references=(),
        )

    async def lookup_many(self, iocs):  # type: ignore[no-untyped-def]
        return [await self.lookup_one(i) for i in iocs]


@pytest_asyncio.fixture
async def app_with_fake_engine() -> AsyncIterator[FastAPI]:
    """Build the app and inject test state directly (skipping lifespan)."""
    app = create_app()
    app.state.engine = _FakeEngine()
    app.state.limiter = RateLimiter(max_requests=10_000, window_seconds=60)
    yield app


@pytest_asyncio.fixture
async def client(app_with_fake_engine: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_healthz_ok(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_sources_lists_all_sources(client: httpx.AsyncClient) -> None:
    # _FakeEngine has no sources; the real app would have 7. Either way
    # the endpoint should respond 200 with a list.
    resp = await client.get("/api/sources")
    assert resp.status_code == 200
    data = resp.json()
    assert "sources" in data
    assert isinstance(data["sources"], list)


@pytest.mark.asyncio
async def test_check_single_ip_returns_verdict(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/check", json={"value": "1.2.3.4"})
    assert resp.status_code == 200
    v = resp.json()["verdict"]
    assert v["verdict"] == "malicious"
    assert v["ioc"]["type"] == "ipv4"
    assert v["ioc"]["raw_value"] == "1.2.3.4"
    # Defanged in response.
    assert "[.]" in v["ioc"]["value"]


@pytest.mark.asyncio
async def test_check_refangs_input(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/check", json={"value": "1[.]2[.]3[.]4"})
    assert resp.status_code == 200
    v = resp.json()["verdict"]
    assert v["ioc"]["raw_value"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_check_invalid_value(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/check", json={"value": "###"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_check_missing_value(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/check", json={})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_check_value_too_long(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/check", json={"value": "a" * 5000})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_scan_extracts_and_enriches(client: httpx.AsyncClient) -> None:
    resp = await client.post(
        "/api/scan",
        json={"text": "found 1.2.3.4 talking to evil.example, and 10.0.0.5 too"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["iocs_extracted"] >= 3
    values = {v["ioc"]["raw_value"] for v in data["verdicts"]}
    assert "1.2.3.4" in values
    assert "evil.example" in values


@pytest.mark.asyncio
async def test_scan_caps_at_25_iocs(client: httpx.AsyncClient) -> None:
    # 30 unique IPs in one paste.
    ips = "\n".join(f"10.0.{i // 256}.{i % 256}" for i in range(30))
    resp = await client.post("/api/scan", json={"text": ips})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["verdicts"]) == 25
    assert data["cap"] == 25


@pytest.mark.asyncio
async def test_scan_text_too_long(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/scan", json={"text": "x" * 40_000})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_scan_empty_returns_empty(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/scan", json={"text": "no indicators in this text"})
    assert resp.status_code == 200
    assert resp.json()["verdicts"] == []


@pytest.mark.asyncio
async def test_post_body_too_large_413(client: httpx.AsyncClient) -> None:
    # Send a content-length header beyond the cap.
    payload = b'{"text":"' + b"x" * 70_000 + b'"}'
    resp = await client.post(
        "/api/scan",
        content=payload,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_rate_limit_blocks_after_burst(app_with_fake_engine: FastAPI) -> None:
    # Tiny limiter so the test runs fast.
    app_with_fake_engine.state.limiter = RateLimiter(max_requests=3, window_seconds=60)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        for _ in range(3):
            resp = await c.post("/api/check", json={"value": "1.2.3.4"})
            assert resp.status_code == 200
        resp = await c.post("/api/check", json={"value": "1.2.3.4"})
        assert resp.status_code == 429


@pytest.mark.asyncio
async def test_static_index_served(client: httpx.AsyncClient) -> None:
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "IOC Hunter" in resp.text


@pytest.mark.asyncio
async def test_security_headers_present(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "no-referrer"


@pytest.mark.asyncio
async def test_x_forwarded_for_used_for_rate_limit(app_with_fake_engine: FastAPI) -> None:
    """A client sending a spoofed XFF header should be bucketed by the
    leftmost value, not by request.client.host."""
    app_with_fake_engine.state.limiter = RateLimiter(max_requests=2, window_seconds=60)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        # Two requests from "user-a" succeed, third hits the limit.
        for _ in range(2):
            resp = await c.post(
                "/api/check",
                json={"value": "1.2.3.4"},
                headers={"X-Forwarded-For": "user-a"},
            )
            assert resp.status_code == 200
        resp = await c.post(
            "/api/check",
            json={"value": "1.2.3.4"},
            headers={"X-Forwarded-For": "user-a"},
        )
        assert resp.status_code == 429
        # A different XFF gets its own bucket.
        resp = await c.post(
            "/api/check",
            json={"value": "1.2.3.4"},
            headers={"X-Forwarded-For": "user-b"},
        )
        assert resp.status_code == 200


def test_rate_limiter_basic() -> None:
    rl = RateLimiter(max_requests=2, window_seconds=60)
    assert rl.allow("a") is True
    assert rl.allow("a") is True
    assert rl.allow("a") is False
    assert rl.allow("b") is True


def test_rate_limiter_window_rollover() -> None:
    import time

    rl = RateLimiter(max_requests=1, window_seconds=0.05)
    assert rl.allow("a") is True
    assert rl.allow("a") is False
    time.sleep(0.06)
    assert rl.allow("a") is True


def test_rate_limiter_evicts_when_full() -> None:
    rl = RateLimiter(max_requests=1, window_seconds=60, max_entries=3)
    for i in range(5):
        rl.allow(f"id{i}")
    # We should still be at or below max_entries.
    assert len(rl._buckets) <= 3

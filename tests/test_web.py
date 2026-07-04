"""Tests for the optional FastAPI front."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from ioc_hunter.config import Settings
from ioc_hunter.core.types import IOC
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import SourceResult, Verdict
from ioc_hunter.web.app import create_app
from ioc_hunter.web.quota import DailyQuota
from ioc_hunter.web.rate_limit import RateLimiter


class _FakeEngine:
    """In-memory engine that returns a canned verdict per IOC value."""

    def __init__(self) -> None:
        self._sources = []
        self._fixture: dict[str, Verdict] = {
            "1.2.3.4": Verdict.MALICIOUS,
            "10.0.0.5": Verdict.BENIGN,
            "evil.net": Verdict.MALICIOUS,
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
    app.state.quota = DailyQuota(limit=10_000)
    app.state.settings = Settings(
        abuse_ch_auth_key=None,
        abuseipdb_api_key=None,
        otx_api_key=None,
        virustotal_api_key=None,
        shodan_api_key=None,
        cache_ttl=3600,
        cache_dir=Path("/tmp"),
        log_level="INFO",
        max_concurrency=4,
    )
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
        json={"text": "found 1.2.3.4 talking to evil.net, and 10.0.0.5 too"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["iocs_extracted"] >= 3
    values = {v["ioc"]["raw_value"] for v in data["verdicts"]}
    assert "1.2.3.4" in values
    assert "evil.net" in values


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
    """Rate-limit bucket is derived from the rightmost XFF entry (proxy-added)."""
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


@pytest.mark.asyncio
async def test_xff_spoofing_cannot_bypass_rate_limit(app_with_fake_engine: FastAPI) -> None:
    """A client rotating fake leftmost XFF entries must still be rate-limited
    by the rightmost (proxy-appended) entry."""
    app_with_fake_engine.state.limiter = RateLimiter(max_requests=2, window_seconds=60)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        # Attacker rotates the leftmost entry but real IP (rightmost) stays constant.
        for fake_prefix in ("10.0.0.1", "10.0.0.2"):
            resp = await c.post(
                "/api/check",
                json={"value": "1.2.3.4"},
                headers={"X-Forwarded-For": f"{fake_prefix}, real-client-ip"},
            )
            assert resp.status_code == 200
        # Third request from the same real IP must be blocked.
        resp = await c.post(
            "/api/check",
            json={"value": "1.2.3.4"},
            headers={"X-Forwarded-For": "10.0.0.3, real-client-ip"},
        )
        assert resp.status_code == 429


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


# -- DailyQuota -----------------------------------------------------------


def test_daily_quota_consume_and_status() -> None:
    q = DailyQuota(limit=3)
    s0 = q.status("a")
    assert s0.used == 0
    assert s0.remaining == 3
    assert not s0.exhausted

    q.consume("a")
    q.consume("a")
    s2 = q.status("a")
    assert s2.used == 2
    assert s2.remaining == 1

    q.consume("a")
    s3 = q.status("a")
    assert s3.used == 3
    assert s3.exhausted

    # Over-consume is a no-op — used stays at the limit.
    q.consume("a")
    s4 = q.status("a")
    assert s4.used == 3


def test_daily_quota_per_identifier() -> None:
    q = DailyQuota(limit=1)
    q.consume("a")
    assert q.status("a").exhausted
    assert not q.status("b").exhausted


# -- /api/quota -----------------------------------------------------------


@pytest.mark.asyncio
async def test_quota_endpoint_starts_at_zero(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/quota")
    assert resp.status_code == 200
    data = resp.json()
    assert data["used"] == 0
    assert data["limit"] >= 1
    assert data["remaining"] == data["limit"]


@pytest.mark.asyncio
async def test_check_decrements_quota(app_with_fake_engine: FastAPI) -> None:
    app_with_fake_engine.state.quota = DailyQuota(limit=5)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        resp = await c.post("/api/check", json={"value": "1.2.3.4"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["byok"] is False
        assert data["quota"]["used"] == 1
        assert data["quota"]["remaining"] == 4


@pytest.mark.asyncio
async def test_quota_exhausted_returns_402(app_with_fake_engine: FastAPI) -> None:
    app_with_fake_engine.state.quota = DailyQuota(limit=2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        for _ in range(2):
            r = await c.post("/api/check", json={"value": "1.2.3.4"})
            assert r.status_code == 200
        r = await c.post("/api/check", json={"value": "1.2.3.4"})
        assert r.status_code == 402
        body = r.json()
        assert body["byok_supported"] is True
        assert body["quota"]["remaining"] == 0
        assert "demo quota" in body["detail"].lower()


# -- BYOK -----------------------------------------------------------------


@pytest_asyncio.fixture
async def mocked_ti_endpoints():
    """Mock every TI endpoint a BYOK lookup might hit, so tests run
    without real network calls."""
    import respx

    with respx.mock(assert_all_called=False) as router:
        router.route(host="check.torproject.org").mock(return_value=httpx.Response(200, text=""))
        router.route(host="urlhaus-api.abuse.ch").mock(
            return_value=httpx.Response(200, json={"query_status": "no_results"})
        )
        router.route(host="threatfox-api.abuse.ch").mock(
            return_value=httpx.Response(200, json={"query_status": "no_result"})
        )
        router.route(host="api.abuseipdb.com").mock(
            return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 0}})
        )
        router.route(host="otx.alienvault.com").mock(return_value=httpx.Response(200, json={}))
        router.route(host="www.virustotal.com").mock(
            return_value=httpx.Response(200, json={"data": {"attributes": {}}})
        )
        yield router


@pytest.mark.asyncio
async def test_byok_bypasses_quota(app_with_fake_engine: FastAPI, mocked_ti_endpoints) -> None:
    """A request with TI keys should not increment the quota counter."""
    app_with_fake_engine.state.quota = DailyQuota(limit=2)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        # Burn both quota units.
        for _ in range(2):
            await c.post("/api/check", json={"value": "1.2.3.4"})
        # Server-key path is now exhausted.
        r = await c.post("/api/check", json={"value": "1.2.3.4"})
        assert r.status_code == 402

        # BYOK request should still go through.
        r = await c.post(
            "/api/check",
            json={
                "value": "1.2.3.4",
                "keys": {"virustotal_api_key": "vtfakekey"},
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["byok"] is True
        # Used count is unchanged.
        assert body["quota"]["used"] == 2


@pytest.mark.asyncio
async def test_byok_keys_are_validated(app_with_fake_engine: FastAPI, mocked_ti_endpoints) -> None:
    """Empty or oversized keys are dropped, falling back to server keys."""
    app_with_fake_engine.state.quota = DailyQuota(limit=5)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        # All keys empty → still server-key path (byok=False, quota burned).
        r = await c.post(
            "/api/check",
            json={
                "value": "1.2.3.4",
                "keys": {"virustotal_api_key": "  ", "otx_api_key": ""},
            },
        )
        assert r.status_code == 200
        assert r.json()["byok"] is False
        assert r.json()["quota"]["used"] == 1

        # Oversized key → dropped.
        r = await c.post(
            "/api/check",
            json={
                "value": "1.2.3.4",
                "keys": {"virustotal_api_key": "x" * 5000},
            },
        )
        assert r.status_code == 200
        assert r.json()["byok"] is False


@pytest.mark.asyncio
async def test_byok_scan_path(app_with_fake_engine: FastAPI, mocked_ti_endpoints) -> None:
    app_with_fake_engine.state.quota = DailyQuota(limit=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        await c.post("/api/check", json={"value": "1.2.3.4"})  # burn the 1
        r = await c.post(
            "/api/scan",
            json={
                "text": "found 1.2.3.4 talking to evil.net",
                "keys": {"otx_api_key": "otx-fake-token"},
            },
        )
        assert r.status_code == 200
        assert r.json()["byok"] is True


@pytest.mark.asyncio
async def test_byok_keys_not_echoed_in_response(
    app_with_fake_engine: FastAPI, mocked_ti_endpoints
) -> None:
    app_with_fake_engine.state.quota = DailyQuota(limit=5)
    secret = "supersecret-vt-token-do-not-leak"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_fake_engine), base_url="http://t"
    ) as c:
        r = await c.post(
            "/api/check",
            json={"value": "1.2.3.4", "keys": {"virustotal_api_key": secret}},
        )
        assert r.status_code == 200
        assert secret not in r.text


@pytest.mark.asyncio
async def test_empty_text_response_includes_quota(client: httpx.AsyncClient) -> None:
    """Empty-scan response should still expose the current quota."""
    resp = await client.post("/api/scan", json={"text": "no indicators here"})
    assert resp.status_code == 200
    data = resp.json()
    assert "quota" in data
    assert data["verdicts"] == []

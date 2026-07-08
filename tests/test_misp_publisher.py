"""Tests for MISPPublisher."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.misp_publisher import MISPPublishError, MISPPublisher
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_BASE = "https://misp.internal"
_EVENTS_URL = f"{_BASE}/events"


def _verdict(value: str = "1.2.3.4", ioc_type: IOCType = IOCType.IPV4) -> IOCVerdict:
    return IOCVerdict(
        ioc=IOC(value=value, type=ioc_type),
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        results=(),
    )


@pytest.mark.asyncio
async def test_push_returns_uuid(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "abc-123", "id": "5"}})
        )
        uuid = await publisher.push([_verdict()])
    assert uuid == "abc-123"


@pytest.mark.asyncio
async def test_push_sends_auth_header(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "mykey", client=http_client)
    with respx.mock() as router:
        route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "x", "id": "1"}})
        )
        await publisher.push([_verdict()])
    req = route.calls.last.request
    assert req.headers.get("Authorization") == "mykey"


@pytest.mark.asyncio
async def test_push_sends_valid_misp_json(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "x", "id": "1"}})
        )
        await publisher.push([_verdict()])
    body = json.loads(route.calls.last.request.content)
    assert "Event" in body
    assert "Attribute" in body["Event"]


@pytest.mark.asyncio
async def test_push_raises_on_http_error(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_EVENTS_URL).mock(return_value=httpx.Response(403))
        with pytest.raises(MISPPublishError):
            await publisher.push([_verdict()])


@pytest.mark.asyncio
async def test_push_custom_event_info(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "z", "id": "2"}})
        )
        await publisher.push([_verdict()], event_info="Incident #42")
    body = json.loads(route.calls.last.request.content)
    assert body["Event"]["info"] == "Incident #42"

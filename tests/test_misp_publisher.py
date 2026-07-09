"""Tests for MISPPublisher."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOC, IOCType
from ioc_hunter.misp_publisher import MISPPublisher, MISPPublishError
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources.base import Verdict

_BASE = "https://misp.internal"
_EVENTS_URL = f"{_BASE}/events"
_SEARCH_URL = f"{_BASE}/attributes/restSearch"
_SIGHTING_URL_PREFIX = f"{_BASE}/sightings/add/"


def _verdict(value: str = "1.2.3.4", ioc_type: IOCType = IOCType.IPV4) -> IOCVerdict:
    return IOCVerdict(
        ioc=IOC(value=value, type=ioc_type),
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        results=(),
    )


def _empty_search() -> dict:
    return {"response": {"Attribute": []}}


def _existing_attr(uuid: str = "attr-uuid-111") -> dict:
    return {"response": {"Attribute": [{"uuid": uuid, "value": "1.2.3.4"}]}}


# --- Basic event creation (no existing attributes) ---


@pytest.mark.asyncio
async def test_push_creates_event_and_returns_uuid(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
        router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "abc-123", "id": "5"}})
        )
        result = await publisher.push([_verdict()])
    assert "abc-123" in result


@pytest.mark.asyncio
async def test_push_sends_auth_header(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "mykey", client=http_client)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
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
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
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
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
        router.post(_EVENTS_URL).mock(return_value=httpx.Response(403))
        with pytest.raises(MISPPublishError):
            await publisher.push([_verdict()])


@pytest.mark.asyncio
async def test_push_custom_event_info(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
        route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "z", "id": "2"}})
        )
        await publisher.push([_verdict()], event_info="Incident #42")
    body = json.loads(route.calls.last.request.content)
    assert body["Event"]["info"] == "Incident #42"


# --- Sighting when IOC already exists ---


@pytest.mark.asyncio
async def test_sighting_added_when_attribute_exists(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_existing_attr("attr-uuid-111"))
        )
        sighting_route = router.post(f"{_SIGHTING_URL_PREFIX}attr-uuid-111").mock(
            return_value=httpx.Response(200, json={"saved": True})
        )
        result = await publisher.push([_verdict()])
    assert sighting_route.called
    assert "sighting" in result.lower()


@pytest.mark.asyncio
async def test_no_new_event_when_sighting_added(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    # assert_all_called=False: events route registered but should NOT be called
    with respx.mock(assert_all_called=False) as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_existing_attr()))
        router.post(f"{_SIGHTING_URL_PREFIX}attr-uuid-111").mock(
            return_value=httpx.Response(200, json={})
        )
        events_route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "x"}})
        )
        await publisher.push([_verdict()])
    assert not events_route.called


@pytest.mark.asyncio
async def test_mixed_push_sighting_and_new_event(http_client: httpx.AsyncClient) -> None:
    v_existing = _verdict("1.2.3.4")
    v_new = _verdict("5.6.7.8")
    publisher = MISPPublisher(_BASE, "key", client=http_client)

    def _search_side_effect(request):
        body = json.loads(request.content)
        value = body.get("value", "")
        if value == "1.2.3.4":
            return httpx.Response(200, json=_existing_attr("attr-aaa"))
        return httpx.Response(200, json=_empty_search())

    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(side_effect=_search_side_effect)
        router.post(f"{_SIGHTING_URL_PREFIX}attr-aaa").mock(
            return_value=httpx.Response(200, json={})
        )
        event_route = router.post(_EVENTS_URL).mock(
            return_value=httpx.Response(200, json={"Event": {"uuid": "new-ev"}})
        )
        result = await publisher.push([v_existing, v_new])
    assert event_route.called
    assert "sighting" in result.lower()
    assert "new-ev" in result


# --- Retry ---


@pytest.mark.asyncio
async def test_event_creation_retries_on_503(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    call_count = 0

    def _side_effect(_request):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"Event": {"uuid": "retry-ok"}})

    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_empty_search()))
        router.post(_EVENTS_URL).mock(side_effect=_side_effect)
        result = await publisher.push([_verdict()])
    assert "retry-ok" in result
    assert call_count == 3


@pytest.mark.asyncio
async def test_sighting_failure_is_non_fatal(http_client: httpx.AsyncClient) -> None:
    publisher = MISPPublisher(_BASE, "key", client=http_client)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_existing_attr("attr-uuid-fail"))
        )
        router.post(f"{_SIGHTING_URL_PREFIX}attr-uuid-fail").mock(return_value=httpx.Response(500))
        result = await publisher.push([_verdict()])
    assert "sighting" in result.lower()

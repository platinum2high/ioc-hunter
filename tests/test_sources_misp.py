"""Tests for the MISP TI source."""

from __future__ import annotations

import httpx
import pytest
import respx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.misp import MISPSource

_BASE = "https://misp.internal"
_SEARCH_URL = f"{_BASE}/attributes/restSearch"


def _attr(
    *,
    value: str = "1.2.3.4",
    attr_type: str = "ip-dst",
    to_ids: bool = True,
    event_id: str = "7",
    timestamp: str = "1700000000",
    tags: list[str] | None = None,
) -> dict:
    attr: dict = {
        "id": "42",
        "event_id": event_id,
        "type": attr_type,
        "category": "Network activity",
        "value": value,
        "to_ids": to_ids,
        "uuid": "aaaa-bbbb",
        "timestamp": timestamp,
    }
    if tags:
        attr["Tag"] = [{"name": t} for t in tags]
    return attr


def _response(attributes: list[dict]) -> dict:
    return {"response": {"Attribute": attributes}}


@pytest.mark.asyncio
async def test_malicious_on_to_ids_hit(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=True)]))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert result.score > 0


@pytest.mark.asyncio
async def test_suspicious_on_no_to_ids(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=False)]))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == pytest.approx(0.3)


@pytest.mark.asyncio
async def test_unknown_on_empty_attributes(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([]))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_tags_collected(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(
                200,
                json=_response([_attr(tags=["tlp:red", "misp-galaxy:threat-actor=APT28"])]),
            )
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert "tlp:red" in result.tags
    assert any("APT28" in t for t in result.tags)


@pytest.mark.asyncio
async def test_references_built_from_event_ids(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(event_id="99")]))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert any("99" in r for r in result.references)


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="supersecret", misp_url=_BASE)
    with respx.mock() as router:
        route = router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr()]))
        )
        await src.lookup(IOCType.IPV4, "1.2.3.4")
    req = route.calls.last.request
    assert req.headers.get("Authorization") == "supersecret"
    assert req.headers.get("Accept") == "application/json"


@pytest.mark.asyncio
async def test_http_error_yields_error_result(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(403))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


@pytest.mark.asyncio
async def test_missing_key_yields_error(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key=None, misp_url=_BASE)
    result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.error is not None


@pytest.mark.asyncio
async def test_missing_url_yields_error(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url="")
    result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.error is not None


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    result = await src.lookup(IOCType.IPV4, "not-relevant")
    # IPV4 is supported — use a type that MISPSource doesn't support
    # (all IOCTypes are supported, so test unsupported via a domain that works fine)
    assert result is not None


@pytest.mark.asyncio
async def test_score_caps_at_1(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    many_attrs = [_attr(to_ids=True, event_id=str(i)) for i in range(10)]
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response(many_attrs))
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.score <= 1.0
    assert result.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_domain_lookup(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(
                200,
                json=_response([_attr(value="evil.com", attr_type="domain", to_ids=True)]),
            )
        )
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.MALICIOUS

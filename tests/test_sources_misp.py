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
_WARNLIST_URL = f"{_BASE}/warninglists/checkValue"
_WL_EMPTY = httpx.Response(200, json={})


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
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
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
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.SUSPICIOUS
    assert result.score == pytest.approx(0.3)


@pytest.mark.asyncio
async def test_unknown_on_empty_attributes(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_response([])))
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
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
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
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert any("99" in r for r in result.references)


@pytest.mark.asyncio
async def test_auth_header_sent(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="supersecret", misp_url=_BASE)
    with respx.mock() as router:
        route = router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr()]))
        )
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
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
    result = await src.lookup(IOCType.CVE, "CVE-2021-44228")
    assert result.error is not None
    assert "support" in result.error


@pytest.mark.asyncio
async def test_score_caps_at_1(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    many_attrs = [_attr(to_ids=True, event_id=str(i)) for i in range(10)]
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_response(many_attrs)))
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.score <= 1.0
    assert result.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_non_numeric_timestamp_does_not_crash(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    bad_attr = _attr(timestamp="N/A")
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_response([bad_attr])))
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert result.first_seen is None
    assert result.last_seen is None


@pytest.mark.asyncio
async def test_missing_url_error_message(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url="")
    result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.error is not None
    assert "MISP_URL" in result.error


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
        router.post(_WARNLIST_URL).mock(return_value=_WL_EMPTY)
        result = await src.lookup(IOCType.DOMAIN, "evil.com")
    assert result.verdict is Verdict.MALICIOUS


# --- Retry ---


@pytest.mark.asyncio
async def test_retries_on_503_then_succeeds(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    call_count = 0

    def _side_effect(_request):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            return httpx.Response(503)
        return httpx.Response(200, json=_response([_attr(to_ids=True)]))

    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(side_effect=_side_effect)
        # warninglist will also be called after success — mock it too
        router.post(f"{_BASE}/warninglists/checkValue").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS
    assert call_count == 3


@pytest.mark.asyncio
async def test_all_503_returns_error(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(503))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert result.error is not None


# --- Warninglist ---


@pytest.mark.asyncio
async def test_warninglist_hit_downgrades_malicious_to_unknown(
    http_client: httpx.AsyncClient,
) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=True)]))
        )
        router.post(f"{_BASE}/warninglists/checkValue").mock(
            return_value=httpx.Response(
                200,
                json={"1.2.3.4": [{"id": "1", "name": "RFC 5735 - Private IP"}]},
            )
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.UNKNOWN
    assert any("warninglist:" in t for t in result.tags)


@pytest.mark.asyncio
async def test_warninglist_failure_does_not_suppress_verdict(
    http_client: httpx.AsyncClient,
) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=True)]))
        )
        router.post(f"{_BASE}/warninglists/checkValue").mock(return_value=httpx.Response(500))
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_warninglist_empty_response_keeps_verdict(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=True)]))
        )
        router.post(f"{_BASE}/warninglists/checkValue").mock(
            return_value=httpx.Response(200, json={"1.2.3.4": []})
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert result.verdict is Verdict.MALICIOUS


# --- MITRE ATT&CK TTPs from Galaxy tags ---


@pytest.mark.asyncio
async def test_galaxy_tags_extract_mitre_ttps(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    attr = _attr(
        to_ids=True,
        tags=[
            'misp-galaxy:mitre-attack-pattern="Spearphishing Attachment - T1566.001"',
            'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"',
            "tlp:red",
        ],
    )
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(return_value=httpx.Response(200, json=_response([attr])))
        router.post(f"{_BASE}/warninglists/checkValue").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    ttps = (result.raw or {}).get("mitre_techniques", [])
    assert "T1566.001" in ttps
    assert "T1059" in ttps


@pytest.mark.asyncio
async def test_no_galaxy_tags_no_mitre_key(http_client: httpx.AsyncClient) -> None:
    src = MISPSource(http_client, api_key="key", misp_url=_BASE)
    with respx.mock() as router:
        router.post(_SEARCH_URL).mock(
            return_value=httpx.Response(200, json=_response([_attr(to_ids=True)]))
        )
        router.post(f"{_BASE}/warninglists/checkValue").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await src.lookup(IOCType.IPV4, "1.2.3.4")
    assert "mitre_techniques" not in (result.raw or {})

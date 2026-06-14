"""Tests for the offline IP classifier source."""

from __future__ import annotations

import httpx
import pytest

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Verdict
from ioc_hunter.sources.netmeta import NetMetaSource


@pytest.mark.asyncio
async def test_rfc1918_private_returns_benign(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "10.0.0.5")
    assert result.verdict is Verdict.BENIGN
    assert "private" in result.tags
    assert result.error is None


@pytest.mark.asyncio
async def test_loopback_returns_benign(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "127.0.0.1")
    assert result.verdict is Verdict.BENIGN
    assert "loopback" in result.tags


@pytest.mark.asyncio
async def test_test_net_range_flagged_suspicious(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "192.0.2.55")
    assert result.verdict is Verdict.SUSPICIOUS
    assert "bogon" in result.tags
    assert "test-net-1" in result.tags


@pytest.mark.asyncio
async def test_reserved_future_block_is_bogon(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "240.10.10.10")
    assert result.verdict is Verdict.SUSPICIOUS
    assert "reserved-future" in result.tags


@pytest.mark.asyncio
async def test_cgnat_recognized(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "100.80.0.1")
    assert result.verdict is Verdict.BENIGN
    assert "cgnat" in result.tags


@pytest.mark.asyncio
async def test_public_ip_returns_unknown(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "8.8.8.8")
    assert result.verdict is Verdict.UNKNOWN
    assert "public" in result.tags
    assert result.error is None


@pytest.mark.asyncio
async def test_ipv6_loopback(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV6, "::1")
    assert result.verdict is Verdict.BENIGN
    assert "loopback" in result.tags


@pytest.mark.asyncio
async def test_ipv6_public_unknown(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV6, "2001:4860:4860::8888")
    assert result.verdict is Verdict.UNKNOWN
    assert "public" in result.tags


@pytest.mark.asyncio
async def test_invalid_ip_returns_error(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.IPV4, "not.an.ip.999")
    assert result.error is not None


@pytest.mark.asyncio
async def test_unsupported_type(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    result = await src.lookup(IOCType.DOMAIN, "example.com")
    assert result.error is not None
    assert "support" in result.error


@pytest.mark.asyncio
async def test_no_key_required(http_client: httpx.AsyncClient) -> None:
    src = NetMetaSource(http_client)
    assert src.is_configured
    assert not src.requires_key

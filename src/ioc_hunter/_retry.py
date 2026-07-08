"""Shared HTTP POST retry helper — exponential backoff on 5xx and transport errors."""

from __future__ import annotations

import asyncio

import httpx

_DELAYS = (0.5, 1.0, 2.0)


async def retry_post(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: dict,
    headers: dict[str, str],
    timeout: httpx.Timeout,
    max_attempts: int = 3,
) -> httpx.Response:
    """POST with automatic retries on transient failures.

    Retries on httpx.TransportError and HTTP 5xx responses.
    Client errors (4xx) are returned immediately without retry.
    After exhausting attempts: raises the last TransportError,
    or returns the last 5xx response for the caller to raise_for_status().
    """
    last_transport_exc: httpx.TransportError | None = None
    resp: httpx.Response | None = None
    for attempt in range(max_attempts):
        try:
            resp = await client.post(url, json=json, headers=headers, timeout=timeout)
            last_transport_exc = None
            if resp.status_code < 500:
                return resp
        except httpx.TransportError as exc:
            last_transport_exc = exc
        if attempt < max_attempts - 1:
            await asyncio.sleep(_DELAYS[attempt])
    if last_transport_exc is not None:
        raise last_transport_exc
    return resp  # type: ignore[return-value]  # last 5xx — caller calls raise_for_status()

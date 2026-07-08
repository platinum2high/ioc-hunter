"""MISP publisher — pushes IOCVerdict results to a MISP instance.

POST /events   → creates a new MISP event from the existing MISP exporter JSON.
"""

from __future__ import annotations

import json

import httpx

from ioc_hunter.exporters.misp import to_misp
from ioc_hunter.scorer import IOCVerdict


class MISPPublishError(Exception):
    pass


class MISPPublisher:
    def __init__(
        self,
        misp_url: str,
        api_key: str,
        *,
        client: httpx.AsyncClient,
    ) -> None:
        self._url = misp_url.rstrip("/")
        self._key = api_key
        self._client = client

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def push(
        self,
        verdicts: list[IOCVerdict],
        *,
        event_info: str = "IOC Hunter findings",
    ) -> str:
        """Push verdicts as a new MISP event. Returns the event UUID."""
        misp_json = json.loads(to_misp(verdicts, event_info=event_info))

        try:
            resp = await self._client.post(
                f"{self._url}/events",
                json=misp_json,
                headers=self._headers,
                timeout=20,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            raise MISPPublishError(f"MISP push failed: {exc}") from exc
        except ValueError as exc:
            raise MISPPublishError(f"MISP returned invalid JSON: {exc}") from exc

        event = payload.get("Event") or {}
        uuid = event.get("uuid") or event.get("id") or "unknown"
        return str(uuid)

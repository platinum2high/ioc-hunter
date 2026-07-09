"""MISP publisher — pushes IOCVerdict results to a MISP instance.

Smart push logic:
  - IOC already has an attribute in MISP → POST /sightings/add (avoids duplicate events)
  - IOC is new to MISP                   → POST /events (current behaviour)
"""

from __future__ import annotations

import contextlib
import json

import httpx

from ioc_hunter._retry import retry_post
from ioc_hunter.exporters.misp import to_misp
from ioc_hunter.scorer import IOCVerdict

_MISP_TIMEOUT = httpx.Timeout(30.0, connect=5.0)


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
        """Push verdicts to MISP. Returns a human-readable result string.

        Existing IOCs receive a sighting; genuinely new ones become an event.
        """
        sighted_count = 0
        new_verdicts: list[IOCVerdict] = []

        for verdict in verdicts:
            attr_uuid = await self._find_attribute_uuid(verdict.ioc.value)
            if attr_uuid:
                await self._add_sighting(attr_uuid)
                sighted_count += 1
            else:
                new_verdicts.append(verdict)

        parts: list[str] = []
        if sighted_count:
            parts.append(f"sightings added ({sighted_count} IOC(s))")
        if new_verdicts:
            uuid = await self._create_event(new_verdicts, event_info=event_info)
            parts.append(f"event {uuid}")
        return " + ".join(parts) if parts else "nothing to push"

    async def _find_attribute_uuid(self, value: str) -> str | None:
        """Return the UUID of the first matching MISP attribute, or None."""
        try:
            resp = await retry_post(
                self._client,
                f"{self._url}/attributes/restSearch",
                json={"value": value, "returnFormat": "json", "limit": 1},
                headers=self._headers,
                timeout=_MISP_TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            attrs: list[dict] = (data.get("response") or {}).get("Attribute") or []
            if attrs:
                return str(attrs[0].get("uuid") or "")
        except (httpx.HTTPError, ValueError):
            pass
        return None

    async def _add_sighting(self, attribute_uuid: str) -> None:
        """Report a sighting for an existing attribute. Failure is non-fatal."""
        with contextlib.suppress(httpx.HTTPError):
            await retry_post(
                self._client,
                f"{self._url}/sightings/add/{attribute_uuid}",
                json={"type": 0, "source": "IOC Hunter"},
                headers=self._headers,
                timeout=_MISP_TIMEOUT,
            )

    async def _create_event(
        self,
        verdicts: list[IOCVerdict],
        *,
        event_info: str,
    ) -> str:
        """Create a new MISP event from verdicts. Returns the event UUID."""
        misp_json = json.loads(to_misp(verdicts, event_info=event_info))
        try:
            resp = await retry_post(
                self._client,
                f"{self._url}/events",
                json=misp_json,
                headers=self._headers,
                timeout=_MISP_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except httpx.HTTPError as exc:
            raise MISPPublishError(f"MISP push failed: {exc}") from exc
        except ValueError as exc:
            raise MISPPublishError(f"MISP returned invalid JSON: {exc}") from exc

        event = payload.get("Event") or {}
        return str(event.get("uuid") or event.get("id") or "unknown")

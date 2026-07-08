"""MISP threat-intel source — queries a private MISP instance.

POST /attributes/restSearch
Authorization: <api_key>
Accept: application/json
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_SEARCH_PATH = "/attributes/restSearch"

_MISP_TYPE_MAP: dict[IOCType, list[str]] = {
    IOCType.IPV4: ["ip-dst", "ip-src", "ip-dst|port", "ip-src|port"],
    IOCType.IPV6: ["ip-dst", "ip-src"],
    IOCType.DOMAIN: ["domain", "hostname", "domain|ip"],
    IOCType.URL: ["url", "uri"],
    IOCType.EMAIL: ["email", "email-src", "email-dst"],
    IOCType.MD5: ["md5", "filename|md5"],
    IOCType.SHA1: ["sha1", "filename|sha1"],
    IOCType.SHA256: ["sha256", "filename|sha256"],
}


class MISPSource(Source):
    name = "misp"
    weight = 1.0
    supported_types = frozenset(_MISP_TYPE_MAP)
    requires_key = True

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        api_key: str | None = None,
        misp_url: str | None = None,
    ) -> None:
        super().__init__(client, api_key=api_key)
        self._misp_url = (misp_url or "").rstrip("/")

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key) and bool(self._misp_url)

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            return self._missing_key(ioc_type, ioc_value)

        url = self._misp_url + _SEARCH_PATH
        headers = {
            "Authorization": self._api_key or "",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload = {
            "value": ioc_value,
            "type": _MISP_TYPE_MAP[ioc_type],
            "returnFormat": "json",
            "limit": 20,
        }

        try:
            resp = await self._client.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return self._error(ioc_type, ioc_value, f"http error: {exc}")
        except ValueError as exc:
            return self._error(ioc_type, ioc_value, f"invalid JSON: {exc}")

        return self._interpret(ioc_type, ioc_value, data)

    def _interpret(
        self,
        ioc_type: IOCType,
        ioc_value: str,
        data: dict[str, Any],
    ) -> SourceResult:
        attributes: list[dict] = (
            (data.get("response") or {}).get("Attribute")
            or data.get("Attribute")
            or []
        )

        if not attributes:
            return SourceResult(
                source=self.name,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                verdict=Verdict.UNKNOWN,
            )

        malicious_count = sum(1 for a in attributes if a.get("to_ids"))
        tags: list[str] = []
        for attr in attributes:
            for tag in attr.get("Tag") or []:
                name = tag.get("name", "")
                if name and name not in tags:
                    tags.append(name)

        timestamps = [int(a["timestamp"]) for a in attributes if a.get("timestamp")]
        first_seen = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(timestamps)))
            if timestamps
            else None
        )
        last_seen = (
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(timestamps)))
            if timestamps
            else None
        )

        event_ids = {a["event_id"] for a in attributes if a.get("event_id")}
        references = tuple(
            f"{self._misp_url}/events/view/{eid}" for eid in sorted(event_ids)
        )

        if malicious_count > 0:
            verdict = Verdict.MALICIOUS
            score = min(1.0, malicious_count / 5.0)
        else:
            verdict = Verdict.SUSPICIOUS
            score = 0.3

        return SourceResult(
            source=self.name,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            verdict=verdict,
            score=score,
            tags=tuple(tags[:20]),
            first_seen=first_seen,
            last_seen=last_seen,
            references=references,
            raw=data,
        )

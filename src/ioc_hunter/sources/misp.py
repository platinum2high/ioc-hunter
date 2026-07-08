"""MISP threat-intel source — queries a private MISP instance.

POST /attributes/restSearch  — attribute lookup with retry
POST /warninglists/checkValue — false-positive suppression
Authorization: <api_key>
Accept: application/json
"""

from __future__ import annotations

import contextlib
import re
import time
from typing import Any

import httpx

from ioc_hunter._retry import retry_post
from ioc_hunter.core.types import IOCType
from ioc_hunter.sources.base import Source, SourceResult, Verdict

_SEARCH_PATH = "/attributes/restSearch"
_WARNINGLIST_PATH = "/warninglists/checkValue"
_MISP_TIMEOUT = httpx.Timeout(30.0, connect=5.0)

# Matches MITRE ATT&CK technique IDs in Galaxy tag names, e.g. T1566 or T1059.001
_GALAXY_TTP_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

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

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self._api_key or "",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def lookup(self, ioc_type: IOCType, ioc_value: str) -> SourceResult:
        if not self.supports(ioc_type):
            return self._unsupported(ioc_type, ioc_value)
        if not self.is_configured:
            if not self._misp_url:
                return self._error(ioc_type, ioc_value, "misp is not configured (missing MISP_URL)")
            return self._missing_key(ioc_type, ioc_value)

        payload = {
            "value": ioc_value,
            "type": _MISP_TYPE_MAP[ioc_type],
            "returnFormat": "json",
            "limit": 20,
        }

        try:
            resp = await retry_post(
                self._client,
                self._misp_url + _SEARCH_PATH,
                json=payload,
                headers=self._headers(),
                timeout=_MISP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return self._error(ioc_type, ioc_value, f"http error: {exc}")
        except ValueError as exc:
            return self._error(ioc_type, ioc_value, f"invalid JSON: {exc}")

        result = self._interpret(ioc_type, ioc_value, data)

        if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            wl_name = await self._check_warninglist(ioc_value)
            if wl_name:
                return SourceResult(
                    source=self.name,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    verdict=Verdict.UNKNOWN,
                    tags=(*result.tags, f"warninglist:{wl_name}"),
                    raw=result.raw,
                )

        return result

    async def _check_warninglist(self, value: str) -> str | None:
        """Return the warninglist name if value matches any MISP warninglist, else None.

        Failure is intentionally silent — a broken warninglist endpoint must not
        suppress a legitimate MALICIOUS verdict.
        """
        try:
            resp = await retry_post(
                self._client,
                self._misp_url + _WARNINGLIST_PATH,
                json={"value": value},
                headers=self._headers(),
                timeout=_MISP_TIMEOUT,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            # MISP returns {"<value>": [{"id": ..., "name": ...}]} or [] or {}
            hits: list[dict] = []
            if isinstance(data, dict):
                hits = data.get(value) or []
            elif isinstance(data, list):
                hits = data
            if hits and isinstance(hits[0], dict):
                return str(hits[0].get("name") or "unknown")
        except (httpx.HTTPError, ValueError, KeyError, IndexError):
            pass
        return None

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

        mitre_ttps: list[str] = list(
            dict.fromkeys(m for t in tags for m in _GALAXY_TTP_RE.findall(t))
        )

        timestamps: list[int] = []
        for a in attributes:
            raw_ts = a.get("timestamp")
            if raw_ts is not None:
                with contextlib.suppress(ValueError, TypeError):
                    timestamps.append(int(raw_ts))
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

        enriched = dict(data)
        if mitre_ttps:
            enriched["mitre_techniques"] = mitre_ttps

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
            raw=enriched,
        )

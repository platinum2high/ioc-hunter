"""FastAPI front — paste-and-check demo for IOC Hunter.

Design notes:

- Thin layer. The Engine is the real work; the API serializes one IOC
  or a small batch in, JSON verdict out. No duplicated parsing.
- No data retention. Requests are not logged, IOCs are not stored
  beyond the lifetime of the request. The SQLite cache holds upstream
  responses keyed by (source, type, value) only — same as the CLI.
- Hard caps everywhere: body size, IOC count per scan, single-IOC
  length. Defeats both accidental and adversarial overuse.
- Process-local rate limit. One Render free dyno = one process.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from ioc_hunter import __version__
from ioc_hunter.cache import TICache
from ioc_hunter.config import Settings
from ioc_hunter.core import IOC, defang, detect_type, extract_iocs, refang
from ioc_hunter.core.types import IOCType
from ioc_hunter.engine import Engine
from ioc_hunter.scorer import IOCVerdict
from ioc_hunter.sources import (
    AbuseIPDBSource,
    NetMetaSource,
    OTXSource,
    Source,
    ThreatFoxSource,
    TorExitSource,
    URLhausSource,
    VirusTotalSource,
)
from ioc_hunter.web.quota import DailyQuota, QuotaStatus
from ioc_hunter.web.rate_limit import RateLimiter

# Hard limits — picked to keep one demo request well below free-dyno
# CPU budget while still being useful.
_MAX_BODY_BYTES = 64 * 1024
_MAX_TEXT_LEN = 32 * 1024
_MAX_IOC_VALUE_LEN = 2048
_MAX_IOCS_PER_SCAN = 25
_MAX_API_KEY_LEN = 256

# Rate limit defaults — overridable via env so we can tighten in prod
# without a code change.
_DEFAULT_RPM = int(os.getenv("IOC_WEB_RATE_LIMIT", "10"))
_DEFAULT_WINDOW = float(os.getenv("IOC_WEB_RATE_WINDOW", "60"))
_DEFAULT_DAILY_QUOTA = int(os.getenv("IOC_WEB_DAILY_QUOTA", "20"))
_BYOK_TIMEOUT = float(os.getenv("IOC_BYOK_TIMEOUT", "12"))

# Keys the client can send in BYOK mode. Maps the JSON field name to
# the Settings dataclass attribute name we override.
_BYOK_FIELDS: dict[str, str] = {
    "abuse_ch_auth_key": "abuse_ch_auth_key",
    "abuseipdb_api_key": "abuseipdb_api_key",
    "otx_api_key": "otx_api_key",
    "virustotal_api_key": "virustotal_api_key",
}


def _build_sources(client: httpx.AsyncClient, settings: Settings) -> list[Source]:
    """Same source set the CLI builds — keyless sources always on,
    keyed sources gracefully degrade to UNKNOWN if env is missing."""
    return [
        NetMetaSource(client),
        TorExitSource(client),
        URLhausSource(client, api_key=settings.abuse_ch_auth_key),
        ThreatFoxSource(client, api_key=settings.abuse_ch_auth_key),
        AbuseIPDBSource(client, api_key=settings.abuseipdb_api_key),
        OTXSource(client, api_key=settings.otx_api_key),
        VirusTotalSource(client, api_key=settings.virustotal_api_key),
    ]


def _serialize_verdict(v: IOCVerdict) -> dict[str, Any]:
    """JSON-safe view of an IOCVerdict. Defangs values so a malicious
    domain copy-pasted from the response doesn't auto-link in clients."""
    return {
        "ioc": {
            "value": defang(v.ioc.value),
            "raw_value": v.ioc.value,
            "type": v.ioc.type.value,
        },
        "verdict": v.verdict.value,
        "confidence": round(v.confidence, 4),
        "tags": list(v.tags[:25]),
        "references": list(v.references[:10]),
        "results": [
            {
                "source": r.source,
                "verdict": r.verdict.value,
                "score": round(r.score, 4),
                "tags": list(r.tags[:10]),
                "error": r.error,
            }
            for r in v.results
        ],
    }


def _extract_byok_keys(payload: dict[str, Any]) -> dict[str, str]:
    """Pull user-supplied TI keys out of a request payload, with validation.

    Returns a dict mapping `_BYOK_FIELDS` field names to non-empty
    string values. Anything missing or empty is dropped. Each key is
    length-capped so a malicious client can't smuggle a huge string
    through the body cap by stuffing it into a key field.
    """
    raw = payload.get("keys")
    if not isinstance(raw, dict) or not raw:
        return {}
    out: dict[str, str] = {}
    for field in _BYOK_FIELDS:
        value = raw.get(field)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped and len(stripped) <= _MAX_API_KEY_LEN:
                out[field] = stripped
    return out


def _quota_response(stat: QuotaStatus) -> dict[str, Any]:
    return {
        "used": stat.used,
        "limit": stat.limit,
        "remaining": stat.remaining,
        "reset_at": stat.reset_at,
    }


def _quota_exhausted_response(stat: QuotaStatus) -> JSONResponse:
    return JSONResponse(
        {
            "detail": (
                "daily demo quota exhausted — add your own API keys to keep "
                "scanning, or come back tomorrow"
            ),
            "byok_supported": True,
            "quota": _quota_response(stat),
        },
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
    )


def _build_byok_settings(base: Settings, byok: dict[str, str]) -> Settings:
    """Return a Settings copy with TI keys replaced by user-supplied values.

    Anything the user didn't supply becomes None — that source then
    short-circuits to "missing key" the same way the CLI does in
    keyless mode.
    """
    return Settings(
        abuse_ch_auth_key=byok.get("abuse_ch_auth_key"),
        abuseipdb_api_key=byok.get("abuseipdb_api_key"),
        otx_api_key=byok.get("otx_api_key"),
        virustotal_api_key=byok.get("virustotal_api_key"),
        shodan_api_key=None,
        cache_ttl=base.cache_ttl,
        cache_dir=base.cache_dir,
        log_level=base.log_level,
        max_concurrency=base.max_concurrency,
    )


async def _run_byok_lookup(
    request: Request,
    iocs: list[IOC],
    byok: dict[str, str],
) -> list[IOCVerdict]:
    """Run an isolated TI lookup using user-supplied keys.

    We spin up a fresh httpx client + Engine for the request, route the
    lookups through it, and tear it down before returning. The shared
    SQLite cache is bypassed so BYOK results never mix with the
    server-key cache (which would let one user infer another's
    yesterday's lookups).
    """
    base: Settings = request.app.state.settings
    temp_settings = _build_byok_settings(base, byok)
    async with httpx.AsyncClient(timeout=_BYOK_TIMEOUT) as temp_client:
        temp_engine = Engine(
            _build_sources(temp_client, temp_settings),
            cache=None,
            max_concurrency=temp_settings.max_concurrency,
        )
        if len(iocs) == 1:
            return [await temp_engine.lookup_one(iocs[0])]
        return await temp_engine.lookup_many(iocs)


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit bucketing.

    Render terminates TLS at its edge and forwards the real client IP
    in X-Forwarded-For. Trust only the *first* (leftmost) entry — the
    rest can be spoofed by the client.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    if request.client is not None:
        return request.client.host
    return "unknown"


def create_app() -> FastAPI:
    """Factory so tests can instantiate independent app instances."""
    settings = Settings.from_env()
    limiter = RateLimiter(
        max_requests=_DEFAULT_RPM,
        window_seconds=_DEFAULT_WINDOW,
    )
    quota = DailyQuota(limit=_DEFAULT_DAILY_QUOTA)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = httpx.AsyncClient(timeout=15.0)
        cache: TICache | None = None
        try:
            cache = TICache(
                settings.cache_dir / "ioc_hunter.db",
                default_ttl=settings.cache_ttl,
            )
        except Exception:
            # Cache is optional; if /app/cache isn't writable we run
            # uncached rather than failing to boot.
            cache = None
        engine = Engine(
            _build_sources(client, settings),
            cache=cache,
            max_concurrency=settings.max_concurrency,
        )
        app.state.http_client = client
        app.state.engine = engine
        app.state.cache = cache
        app.state.settings = settings
        app.state.limiter = limiter
        app.state.quota = quota
        try:
            yield
        finally:
            await client.aclose()
            if cache is not None:
                cache.close()

    app = FastAPI(
        title="IOC Hunter",
        version=__version__,
        description="Paste-and-check threat intelligence demo.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    @app.middleware("http")
    async def enforce_limits(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Body size cap. Content-Length is advisory but quick to check;
        # for chunked uploads we'd need to read-and-count, but the
        # endpoints below already validate parsed lengths.
        if request.method in ("POST", "PUT", "PATCH"):
            cl = request.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > _MAX_BODY_BYTES:
                return JSONResponse(
                    {"detail": "request body too large"},
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                )
        # Rate limit applies only to the JSON API endpoints — static
        # assets and health/sources are cheap.
        if request.url.path.startswith("/api/") and request.url.path not in (
            "/api/sources",
            "/api/openapi.json",
            "/api/docs",
        ):
            ip = _client_ip(request)
            if not request.app.state.limiter.allow(ip):
                return JSONResponse(
                    {"detail": "rate limit exceeded, please slow down"},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
        response = await call_next(request)
        # Conservative CSP for the static page. Inline styles/scripts
        # are allowed because the single-page UI is self-contained.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/sources")
    async def sources(request: Request) -> dict[str, Any]:
        engine: Engine = request.app.state.engine
        return {
            "version": __version__,
            "sources": [
                {
                    "name": s.name,
                    "weight": s.weight,
                    "active": s.is_configured,
                    "requires_key": s.requires_key,
                    "supported_types": sorted(t.value for t in s.supported_types),
                }
                for s in engine._sources
            ],
        }

    @app.get("/api/quota")
    async def quota_status(request: Request) -> dict[str, Any]:
        q: DailyQuota = request.app.state.quota
        ip = _client_ip(request)
        return _quota_response(q.status(ip))

    @app.post("/api/check")
    async def check(request: Request) -> Any:
        payload = await _read_json(request)
        raw_value = payload.get("value")
        type_hint = payload.get("type")
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise HTTPException(status_code=400, detail="'value' is required")
        if len(raw_value) > _MAX_IOC_VALUE_LEN:
            raise HTTPException(status_code=400, detail="'value' is too long")

        value = refang(raw_value.strip())
        if type_hint:
            if not isinstance(type_hint, str):
                raise HTTPException(status_code=400, detail="'type' must be a string")
            try:
                ioc_type = IOCType(type_hint.lower())
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"invalid type: {exc}") from exc
        else:
            detected = detect_type(value)
            if detected is None:
                raise HTTPException(
                    status_code=400,
                    detail="could not auto-detect IOC type; pass 'type' explicitly",
                )
            ioc_type = detected

        ioc = IOC(value=value, type=ioc_type)
        byok = _extract_byok_keys(payload)

        if byok:
            verdicts = await _run_byok_lookup(request, [ioc], byok)
            return {
                "verdict": _serialize_verdict(verdicts[0]),
                "byok": True,
                "quota": _quota_response(request.app.state.quota.status(_client_ip(request))),
            }

        ip = _client_ip(request)
        q: DailyQuota = request.app.state.quota
        pre = q.status(ip)
        if pre.exhausted:
            return _quota_exhausted_response(pre)
        post = q.consume(ip, cost=1)
        engine: Engine = request.app.state.engine
        verdict = await engine.lookup_one(ioc)
        return {
            "verdict": _serialize_verdict(verdict),
            "byok": False,
            "quota": _quota_response(post),
        }

    @app.post("/api/scan")
    async def scan(request: Request) -> Any:
        payload = await _read_json(request)
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(status_code=400, detail="'text' is required")
        if len(text) > _MAX_TEXT_LEN:
            raise HTTPException(status_code=400, detail="'text' is too long")

        iocs = extract_iocs(text)
        if not iocs:
            return {
                "iocs_extracted": 0,
                "cap": _MAX_IOCS_PER_SCAN,
                "verdicts": [],
                "byok": False,
                "quota": _quota_response(request.app.state.quota.status(_client_ip(request))),
            }
        if len(iocs) > _MAX_IOCS_PER_SCAN:
            iocs = iocs[:_MAX_IOCS_PER_SCAN]

        byok = _extract_byok_keys(payload)
        if byok:
            verdicts = await _run_byok_lookup(request, iocs, byok)
            return {
                "iocs_extracted": len(iocs),
                "cap": _MAX_IOCS_PER_SCAN,
                "byok": True,
                "verdicts": [_serialize_verdict(v) for v in verdicts],
                "quota": _quota_response(request.app.state.quota.status(_client_ip(request))),
            }

        ip = _client_ip(request)
        q: DailyQuota = request.app.state.quota
        pre = q.status(ip)
        if pre.exhausted:
            return _quota_exhausted_response(pre)
        post = q.consume(ip, cost=1)
        engine: Engine = request.app.state.engine
        verdicts = await engine.lookup_many(iocs)
        return {
            "iocs_extracted": len(iocs),
            "cap": _MAX_IOCS_PER_SCAN,
            "byok": False,
            "verdicts": [_serialize_verdict(v) for v in verdicts],
            "quota": _quota_response(post),
        }

    # Static front. Mount last so /api/* routes win.
    static_dir = Path(__file__).parent / "static"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


async def _read_json(request: Request) -> dict[str, Any]:
    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="request body too large",
        )
    try:
        import json

        data = json.loads(body or b"{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    return data


app = create_app()

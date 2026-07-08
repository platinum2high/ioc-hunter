"""Runtime configuration loaded from environment variables.

Reads `.env` from the working directory if present (idempotent — already-set
env vars are not overwritten so docker-compose `env_file` and an inherited
shell environment both work).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_DEFAULT_CACHE_TTL = 86_400
_DEFAULT_CACHE_DIR = "./cache"
_DEFAULT_LOG_LEVEL = "INFO"
_DEFAULT_MAX_CONCURRENCY = 8


def _str(name: str) -> str | None:
    raw = os.getenv(name)
    if not raw:
        return None
    val = raw.strip()
    return val or None


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _load_dotenv_once() -> None:
    """Load `./.env` if present. `override=False` so explicit env wins."""
    env_path = Path.cwd() / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)


def _bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class Settings:
    """All runtime configuration in one frozen bag."""

    abuse_ch_auth_key: str | None
    abuseipdb_api_key: str | None
    otx_api_key: str | None
    virustotal_api_key: str | None
    shodan_api_key: str | None

    misp_url: str | None
    misp_key: str | None
    misp_verify_ssl: bool

    cache_ttl: int
    cache_dir: Path
    log_level: str
    max_concurrency: int

    @classmethod
    def from_env(cls) -> Settings:
        _load_dotenv_once()
        return cls(
            abuse_ch_auth_key=_str("ABUSE_CH_AUTH_KEY"),
            abuseipdb_api_key=_str("ABUSEIPDB_API_KEY"),
            otx_api_key=_str("OTX_API_KEY"),
            virustotal_api_key=_str("VIRUSTOTAL_API_KEY"),
            shodan_api_key=_str("SHODAN_API_KEY"),
            misp_url=_str("MISP_URL"),
            misp_key=_str("MISP_KEY"),
            misp_verify_ssl=_bool("MISP_VERIFY_SSL", default=True),
            cache_ttl=_int("IOC_CACHE_TTL", _DEFAULT_CACHE_TTL),
            cache_dir=Path(os.getenv("IOC_CACHE_DIR", _DEFAULT_CACHE_DIR)),
            log_level=os.getenv("IOC_LOG_LEVEL", _DEFAULT_LOG_LEVEL),
            max_concurrency=_int("IOC_MAX_CONCURRENCY", _DEFAULT_MAX_CONCURRENCY),
        )

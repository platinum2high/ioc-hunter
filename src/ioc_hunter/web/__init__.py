"""Optional FastAPI front for IOC Hunter.

Install with `pip install ioc-hunter[web]` and run:

    uvicorn ioc_hunter.web:app --host 0.0.0.0 --port 8000

The web surface is intentionally a *thin* layer over the same Engine
used by the CLI — it does not duplicate parsing, scoring, or source
logic. Keep it that way.
"""

from ioc_hunter.web.app import app, create_app

__all__ = ["app", "create_app"]

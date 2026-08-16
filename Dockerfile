# syntax=docker/dockerfile:1.7
# =============================================================================
# IOC Hunter — multi-stage build for a minimal, non-root runtime image.
# =============================================================================

FROM python:3.14-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# -----------------------------------------------------------------------------

FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="ioc-hunter"
LABEL org.opencontainers.image.description="Async threat intelligence correlation engine."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/platinum2high/ioc-hunter"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IOC_CACHE_DIR=/app/cache

WORKDIR /app

RUN groupadd --system ioc \
    && useradd --system --gid ioc --home-dir /app --shell /sbin/nologin ioc \
    && mkdir -p /app/cache \
    && chown -R ioc:ioc /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

USER ioc

ENTRYPOINT ["ioc-hunter"]
CMD ["--help"]

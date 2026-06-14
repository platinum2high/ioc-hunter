"""Tiny in-memory rate limiter — fixed-window per identifier.

Render's free dyno is a single process, so a process-local limiter is
sufficient. If we ever scale to multiple workers a Redis-backed limiter
would replace this — but we don't, so we don't.

The window is fixed (not sliding) for simplicity: count requests in the
current `window_seconds` bucket; reset on bucket roll.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock


@dataclass(slots=True)
class _Bucket:
    window_start: float
    count: int


class RateLimiter:
    """Process-local fixed-window rate limiter.

    `allow(identifier)` is the only public surface. Returns True if the
    request is allowed, False if it should be rejected with 429.

    The internal map is bounded — when it grows past `max_entries` the
    oldest-window entries are evicted lazily. This stops a flood of
    distinct IPs from inflating memory without bound.
    """

    def __init__(
        self,
        *,
        max_requests: int = 10,
        window_seconds: float = 60.0,
        max_entries: int = 10_000,
    ) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._max_entries = max_entries
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()

    def allow(self, identifier: str) -> bool:
        now = time.time()
        with self._lock:
            self._maybe_evict(now)
            bucket = self._buckets.get(identifier)
            if bucket is None or now - bucket.window_start >= self._window:
                self._buckets[identifier] = _Bucket(window_start=now, count=1)
                return True
            if bucket.count >= self._max:
                return False
            bucket.count += 1
            return True

    def _maybe_evict(self, now: float) -> None:
        if len(self._buckets) < self._max_entries:
            return
        cutoff = now - self._window
        stale = [k for k, b in self._buckets.items() if b.window_start < cutoff]
        for k in stale:
            self._buckets.pop(k, None)
        # If everything is still in-window (unlikely under real load),
        # drop the single oldest entry to make space.
        if len(self._buckets) >= self._max_entries:
            oldest = min(self._buckets, key=lambda k: self._buckets[k].window_start)
            self._buckets.pop(oldest, None)

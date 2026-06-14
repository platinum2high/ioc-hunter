"""Daily per-identifier quota tracker.

Distinct from the per-minute RateLimiter — this one limits *how much
of the owner's TI API budget* a single visitor can burn in a UTC day.
Hitting the cap returns 402, prompting the user to either come back
tomorrow or bring their own keys (BYOK).

Window is fixed and aligned to UTC midnight, not a sliding clock.
That's intentional: makes the "X scans left today" text on the front
easy to reason about, and a quota that resets at predictable wall
time is friendlier UX than one that resets 24 h after first use.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock


@dataclass(slots=True)
class _Day:
    day_index: int  # floor(epoch / 86400) — the UTC day number
    used: int


def _utc_day(now: float) -> int:
    return int(now // 86_400)


@dataclass(frozen=True, slots=True)
class QuotaStatus:
    used: int
    limit: int
    reset_at: float  # epoch seconds for next UTC midnight

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit


class DailyQuota:
    """Process-local per-IP daily quota with lazy eviction."""

    def __init__(
        self,
        *,
        limit: int = 20,
        max_entries: int = 10_000,
    ) -> None:
        self._limit = limit
        self._max_entries = max_entries
        self._days: dict[str, _Day] = {}
        self._lock = Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def status(self, identifier: str) -> QuotaStatus:
        now = time.time()
        today = _utc_day(now)
        with self._lock:
            day = self._days.get(identifier)
            used = day.used if (day is not None and day.day_index == today) else 0
        reset_at = (today + 1) * 86_400.0
        return QuotaStatus(used=used, limit=self._limit, reset_at=reset_at)

    def consume(self, identifier: str, cost: int = 1) -> QuotaStatus:
        """Try to charge `cost` units. Returns the updated status even
        if the consume failed — the caller checks `.exhausted`."""
        now = time.time()
        today = _utc_day(now)
        with self._lock:
            self._maybe_evict(today)
            day = self._days.get(identifier)
            if day is None or day.day_index != today:
                day = _Day(day_index=today, used=0)
                self._days[identifier] = day
            if day.used + cost > self._limit:
                used = day.used
            else:
                day.used += cost
                used = day.used
        reset_at = (today + 1) * 86_400.0
        return QuotaStatus(used=used, limit=self._limit, reset_at=reset_at)

    def _maybe_evict(self, today: int) -> None:
        if len(self._days) < self._max_entries:
            return
        # Drop yesterday's entries first.
        stale = [k for k, d in self._days.items() if d.day_index < today]
        for k in stale:
            self._days.pop(k, None)
        if len(self._days) >= self._max_entries:
            # Fallback: drop the smallest-usage entry to make space.
            victim = min(self._days, key=lambda k: self._days[k].used)
            self._days.pop(victim, None)

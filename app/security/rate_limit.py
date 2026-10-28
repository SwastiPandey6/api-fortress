"""In-memory sliding-window rate limiter.

Limitation (documented): counters live in process memory, so they reset on
restart and are not shared between multiple worker processes. Run the gateway
with a single worker, or replace this class with a Redis-backed limiter for
horizontal scaling.
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int, int]:
        """Register a request. Returns (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(bucket[0] + window - now))
                return False, 0, retry_after
            bucket.append(now)
            remaining = limit - len(bucket)
            if now - self._last_sweep > 300:
                self._sweep(cutoff)
                self._last_sweep = now
            return True, remaining, 0

    def _sweep(self, cutoff: float) -> None:
        for key in [k for k, b in self._hits.items() if not b or b[-1] <= cutoff]:
            del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()
admin_login_limiter = SlidingWindowLimiter()

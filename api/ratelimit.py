"""api/ratelimit.py — Small in-process sliding-window rate limiter.

Protects login (password guessing) and upload (resource exhaustion). State is
per process: a multi-instance deployment would need a shared store (e.g. Redis).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_s: float = 60.0) -> float | None:
        """Record a request. Returns None if allowed, else seconds until a slot frees up."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= window_s:
                q.popleft()
            if len(q) >= limit:
                return max(0.0, window_s - (now - q[0]))
            q.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = RateLimiter()

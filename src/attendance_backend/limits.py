"""Request limits for the ingress boundary.

ponytail: every number here is a provisional safe default, NOT owner policy —
replace once the owner approves capacity/rate figures (`Limits(...)` is fully
configurable, so no code change is needed to adopt them).
"""

import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_request_bytes: int = 256 * 1024  # provisional
    max_batch_items: int = 100  # provisional
    max_requests_per_window: int = 60  # provisional
    window_seconds: int = 60  # provisional


class RateLimiter:
    """Fixed-window counter per verified principal."""

    def __init__(self, limits, clock):
        self._limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._windows = {}

    def check(self, key):
        """Return None when allowed, else the Retry-After seconds (>= 1)."""
        window = self._limits.window_seconds
        with self._lock:
            now = self._clock()
            start, count = self._windows.get(key, (now, 0))
            if now - start >= window:
                start, count = now, 0
            if count + 1 > self._limits.max_requests_per_window:
                self._windows[key] = (start, count)
                return max(1, int(start + window - now) + 1)
            self._windows[key] = (start, count + 1)
            return None

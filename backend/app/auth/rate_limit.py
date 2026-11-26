"""Sliding-window authentication abuse & brute-force rate limiter."""

from __future__ import annotations

from collections import defaultdict, deque
import threading
import time


class LoginRateLimiter:
    """Thread-safe sliding-window failed-login limiter (bounded in memory)."""

    def __init__(self, *, max_failures: int = 8, window_seconds: float = 60.0) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, bucket: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def is_limited(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            bucket = self._failures.get(key)
            if not bucket:
                return False, 0
            self._prune(bucket, now)
            if not bucket:
                self._failures.pop(key, None)
                return False, 0
            return len(bucket) >= self.max_failures, len(bucket)

    def record_failure(self, key: str) -> int:
        now = time.monotonic()
        with self._lock:
            bucket = self._failures[key]
            self._prune(bucket, now)
            bucket.append(now)
            # Cap tracked keys conservatively to prevent unbounded memory growth
            if len(self._failures) > 4096:
                oldest = next(iter(self._failures))
                if oldest != key:
                    self._failures.pop(oldest, None)
            return len(bucket)

    def reset_key(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def reset_all(self) -> None:
        with self._lock:
            self._failures.clear()


login_rate_limiter = LoginRateLimiter(max_failures=8, window_seconds=60.0)

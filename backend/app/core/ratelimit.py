"""Small in-memory sliding-window rate limiter (single-process; resets on restart)."""
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def _prune(self, key: str, window: float) -> Deque[float]:
        q = self._hits[key]
        cutoff = self._clock() - window
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            self._hits.pop(key, None)  # don't grow unbounded across many keys
            return self._hits[key]
        return q

    def allow(self, key: str, limit: int, window: float) -> bool:
        """Record a hit and return True if under the limit; False (and no record) if over."""
        if limit <= 0:
            return True  # limiting disabled
        q = self._prune(key, window)
        if len(q) >= limit:
            return False
        q.append(self._clock())
        return True

    def retry_after(self, key: str, window: float) -> int:
        q = self._hits.get(key)
        if not q:
            return 0
        return max(1, int(q[0] + window - self._clock()) + 1)

    def is_limited(self, key: str, limit: int, window: float) -> bool:
        """Check without recording."""
        if limit <= 0:
            return False
        return len(self._prune(key, window)) >= limit

    def record(self, key: str) -> None:
        self._hits[key].append(self._clock())

    def reset(self) -> None:
        self._hits.clear()


scan_limiter = SlidingWindowLimiter()
auth_fail_limiter = SlidingWindowLimiter()

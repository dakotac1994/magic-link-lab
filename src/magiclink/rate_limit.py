"""Token-bucket rate limiting, per key (IP address, identifier, ...).

Magic-link endpoints are abuse magnets: an attacker can spam link requests to
harass a victim's inbox, or hammer the verify endpoint guessing tokens. The
request path is limited per-IP *and* per-identifier; the verify path is
limited per-IP. Buckets refill continuously so legitimate users are never
permanently locked out.
"""

import threading
import time


class RateLimiter:
    def __init__(self, capacity: int, refill_per_second: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """Consume one token for `key`. True = allowed, False = rate limited."""
        now = time.time() if now is None else now
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity,
                         tokens + (now - last) * self.refill_per_second)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True

    def remaining(self, key: str, now: float | None = None) -> float:
        now = time.time() if now is None else now
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            return min(self.capacity, tokens + (now - last) * self.refill_per_second)


def default_limiters() -> dict[str, RateLimiter]:
    """Sane defaults: 5 link requests/min per IP, 3/min per identifier
    (inbox-harassment protection), 10 verify attempts/min per IP."""
    return {
        "request_per_ip": RateLimiter(capacity=5, refill_per_second=5 / 60),
        "request_per_identifier": RateLimiter(capacity=3, refill_per_second=3 / 60),
        "verify_per_ip": RateLimiter(capacity=10, refill_per_second=10 / 60),
    }

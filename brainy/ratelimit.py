"""Pragmatischer In-Memory-Sliding-Window-Limiter (Single-Process, Phase D).
Kein Redis. Key = token_id bzw. principal_id. Rate zentral via config."""
import threading
import time


class RateLimiter:
    def __init__(self, spec="240/60"):
        n, per = str(spec).split("/")
        self.max = int(n)
        self.per = float(per)
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.time()
        cutoff = now - self.per
        with self._lock:
            q = self._hits.setdefault(key, [])
            while q and q[0] < cutoff:
                q.pop(0)
            if len(q) >= self.max:
                return False
            q.append(now)
            return True

    def reset(self, key=None):
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)

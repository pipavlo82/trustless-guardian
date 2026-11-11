"""Thread-safe bounded single-use nonce storage."""

from collections import OrderedDict
import threading

from .errors import SecurityError


class BoundedNonceStore:
    def __init__(self, capacity=1024, ttl_seconds=600):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity")
        if type(ttl_seconds) is not int or ttl_seconds < 1:
            raise ValueError("ttl_seconds")
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self._entries = OrderedDict()
        self._lock = threading.Lock()

    def _purge(self, now):
        expired = [key for key, expiry in self._entries.items() if expiry <= now]
        for key in expired:
            del self._entries[key]

    def consume(self, namespace, nonce, now, expires_at=None):
        if type(namespace) is not str or not namespace:
            raise SecurityError("NONCE_NAMESPACE")
        if type(nonce) is not str or len(nonce) < 8 or len(nonce) > 256:
            raise SecurityError("NONCE_FORMAT")
        if type(now) not in {int, float}:
            raise TypeError("now")
        key = (namespace, nonce)
        with self._lock:
            self._purge(now)
            if key in self._entries:
                raise SecurityError("REPLAY_DETECTED")
            if len(self._entries) >= self.capacity:
                raise SecurityError("NONCE_STORE_FULL")
            bounded = now + self.ttl_seconds
            if expires_at is not None:
                if type(expires_at) not in {int, float} or expires_at <= now:
                    raise SecurityError("NONCE_EXPIRY")
                bounded = min(bounded, expires_at)
            self._entries[key] = bounded

    def size(self, now):
        with self._lock:
            self._purge(now)
            return len(self._entries)

from __future__ import annotations

from collections import deque
from threading import Lock
import time

from app.core.config import get_settings


_lock = Lock()
_attempts: deque[float] = deque()


def allow_investigation_creation(*, now: float | None = None) -> bool:
    """Apply a bounded process-local sliding-window admission limit.

    This intentionally complements, rather than replaces, authentication and
    the database-backed queue depth limit. A single-user local deployment does
    not need distributed rate-limit infrastructure.
    """
    settings = get_settings()
    current = time.monotonic() if now is None else now
    window = max(0.001, settings.investigation_rate_window_seconds)
    limit = max(1, settings.max_investigations_per_window)
    cutoff = current - window
    with _lock:
        while _attempts and _attempts[0] <= cutoff:
            _attempts.popleft()
        if len(_attempts) >= limit:
            return False
        _attempts.append(current)
        return True


def reset_for_tests() -> None:
    with _lock:
        _attempts.clear()

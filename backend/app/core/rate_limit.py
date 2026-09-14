from collections import deque
from threading import Lock
import time

from app.core.config import get_settings


_lock = Lock()
_attempts: deque[float] = deque()
_public_web_attempts: deque[float] = deque()


def _allow(attempts: deque[float], *, limit: int, window: float, now: float) -> bool:
    cutoff = now - max(0.001, window)
    while attempts and attempts[0] <= cutoff:
        attempts.popleft()
    if len(attempts) >= max(1, limit):
        return False
    attempts.append(now)
    return True


def allow_investigation_creation(*, now: float | None = None) -> bool:
    """Apply a bounded process-local sliding-window investigation admission limit."""
    settings = get_settings()
    current = time.monotonic() if now is None else now
    with _lock:
        return _allow(
            _attempts,
            limit=settings.max_investigations_per_window,
            window=settings.investigation_rate_window_seconds,
            now=current,
        )


def allow_public_web_discovery(*, now: float | None = None) -> bool:
    """Bound direct Public Web API admission for the local single-user service."""
    settings = get_settings()
    current = time.monotonic() if now is None else now
    with _lock:
        return _allow(
            _public_web_attempts,
            limit=settings.max_public_web_requests_per_window,
            window=settings.public_web_rate_window_seconds,
            now=current,
        )


def reset_for_tests() -> None:
    with _lock:
        _attempts.clear()
        _public_web_attempts.clear()

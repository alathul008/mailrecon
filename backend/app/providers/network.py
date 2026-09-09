from __future__ import annotations

from urllib.parse import urlsplit

import httpcore
import httpx

from app.core.security import resolve_public_addresses


class _PinnedBackend(httpcore.AnyIOBackend):
    def __init__(self, hostname: str):
        super().__init__()
        self.hostname = hostname

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self.hostname:
            raise httpcore.ConnectError("Outbound host changed during pinned request")
        addresses = resolve_public_addresses(self.hostname, port)
        last_error = None
        for address in addresses:
            try:
                return await super().connect_tcp(address, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            except Exception as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("No validated public destination available")


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, hostname: str, **kwargs):
        self._pinned_backend = _PinnedBackend(hostname)
        super().__init__(**kwargs)
        self._pool._network_backend = self._pinned_backend


def pinned_transport(url: str) -> PinnedAsyncHTTPTransport:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Only HTTPS URLs with a hostname are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo in URLs is not allowed")
    return PinnedAsyncHTTPTransport(parsed.hostname.rstrip(".").lower(), retries=0)

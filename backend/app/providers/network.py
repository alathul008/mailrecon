from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import httpcore
import httpx

from app.core.security import validate_external_url


class _PinnedBackend(httpcore.AnyIOBackend):
    def __init__(self, hostname: str, address: str):
        super().__init__()
        self.hostname = hostname
        self.address = address

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self.hostname:
            raise httpcore.ConnectError("Outbound host changed during pinned request")
        return await super().connect_tcp(self.address, port, timeout=timeout, local_address=local_address, socket_options=socket_options)


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, hostname: str, address: str, **kwargs):
        self._pinned_backend = _PinnedBackend(hostname, address)
        super().__init__(**kwargs)
        self._pool._network_backend = self._pinned_backend


def _resolve_and_validate(url: str) -> tuple[str, str]:
    validate_external_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Outbound URL has no hostname")
    try:
        addresses = {ai[4][0] for ai in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved") from exc
    public = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValueError("Destination resolves to a non-public address")
        public.append(address)
    if not public:
        raise ValueError("Destination has no public address")
    return host.rstrip(".").lower(), sorted(public)[0]


def pinned_transport(url: str) -> PinnedAsyncHTTPTransport:
    hostname, address = _resolve_and_validate(url)
    return PinnedAsyncHTTPTransport(hostname, address, retries=0)

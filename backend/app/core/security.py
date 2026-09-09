from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https"}


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolve_public_addresses(host: str, port: int = 443) -> tuple[str, ...]:
    try:
        addresses = tuple(sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}))
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved") from exc
    if not addresses or any(not _is_public_ip(addr) for addr in addresses):
        raise ValueError("Destination resolves to a non-public address")
    return addresses


def validate_external_url(url: str) -> str:
    """Validate a public HTTPS URL; the actual connection layer must pin a validated address."""
    p = urlsplit(url)
    if p.scheme.lower() not in ALLOWED_SCHEMES or not p.hostname:
        raise ValueError("Only HTTPS URLs with a hostname are allowed")
    if p.username or p.password:
        raise ValueError("Userinfo in URLs is not allowed")
    host = p.hostname.rstrip(".").lower()
    resolve_public_addresses(host, p.port or 443)
    return url

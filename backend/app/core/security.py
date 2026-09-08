from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"https"}


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_external_url(url: str) -> str:
    """Validate an outbound URL for public HTTPS-only requests.

    This is a defense-in-depth validator. Callers must also disable redirects
    or validate every redirect destination before following it.
    """
    p = urlsplit(url)
    if p.scheme.lower() not in ALLOWED_SCHEMES or not p.hostname:
        raise ValueError("Only HTTPS URLs with a hostname are allowed")
    if p.username or p.password:
        raise ValueError("Userinfo in URLs is not allowed")
    host = p.hostname.rstrip(".").lower()
    try:
        addresses = {ai[4][0] for ai in socket.getaddrinfo(host, p.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("Hostname could not be resolved") from exc
    if not addresses or any(not _is_public_ip(addr) for addr in addresses):
        raise ValueError("Destination resolves to a non-public address")
    return url

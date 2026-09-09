from __future__ import annotations

import httpx
from typing import Any

from app.core.security import validate_external_url
from app.providers.base import ProviderResult


def classify_exception(provider: str, exc: Exception) -> ProviderResult:
    if isinstance(exc, httpx.TimeoutException):
        status = "unavailable"
    elif isinstance(exc, httpx.RequestError):
        status = "unavailable"
    elif isinstance(exc, ValueError):
        status = "error"
    else:
        status = "error"
    return ProviderResult(provider, status, message=f"{provider} request failed: {type(exc).__name__}")


def classify_response(provider: str, response: httpx.Response) -> ProviderResult | None:
    if response.status_code == 429:
        return ProviderResult(provider, "rate_limited", message=f"{provider} rate limited the request")
    if 500 <= response.status_code <= 599:
        return ProviderResult(provider, "unavailable", message=f"{provider} returned HTTP {response.status_code}")
    if 400 <= response.status_code <= 499:
        return ProviderResult(provider, "error", message=f"{provider} returned HTTP {response.status_code}")
    return None


def validate_provider_url(url: str) -> str:
    return validate_external_url(url)


def parse_json(response: httpx.Response, provider: str) -> tuple[Any | None, ProviderResult | None]:
    try:
        return response.json(), None
    except (ValueError, TypeError):
        return None, ProviderResult(provider, "error", message=f"{provider} returned malformed JSON")

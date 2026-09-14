from __future__ import annotations

import httpx
from typing import Any

from app.core.security import validate_external_url
from app.providers.base import ProviderResult


MAX_EXTERNAL_RESPONSE_BYTES = 8 * 1024 * 1024


class ResponseTooLargeError(ValueError):
    """An external response exceeded the project-wide response byte budget."""


async def bounded_get(client: httpx.AsyncClient, url: str, **kwargs: Any) -> httpx.Response:
    """GET an external resource without allowing an oversized body into parsing.

    8 MiB is intentionally large enough for the current passive JSON providers
    while keeping unexpected/chunked responses bounded before JSON/text parsing.
    Content-Length is rejected early; streamed bodies are counted as received.
    The small ``get`` fallback exists only for lightweight test doubles used by
    legacy provider tests; real httpx clients always use the streaming path.
    """
    if not hasattr(client, "stream"):
        response = await client.get(url, **kwargs)
        if len(response.content) > MAX_EXTERNAL_RESPONSE_BYTES:
            raise ResponseTooLargeError("External response exceeded the response-size budget")
        return response

    async with client.stream("GET", url, **kwargs) as response:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError as exc:
                raise ResponseTooLargeError("External response declared an invalid Content-Length") from exc
            if declared < 0 or declared > MAX_EXTERNAL_RESPONSE_BYTES:
                raise ResponseTooLargeError("External response exceeded the response-size budget")

        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_EXTERNAL_RESPONSE_BYTES:
                raise ResponseTooLargeError("External response exceeded the response-size budget")
            chunks.append(chunk)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=b"".join(chunks),
            request=response.request,
            extensions=response.extensions,
        )


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

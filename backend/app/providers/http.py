from __future__ import annotations

import httpx
from typing import Any

from app.core.security import validate_external_url
from app.providers.base import ProviderResult
from app.services.resource_budget import ResourceBudgetExceeded, current_accounting


MAX_EXTERNAL_RESPONSE_BYTES = 8 * 1024 * 1024


class ResponseTooLargeError(ValueError):
    """An external response exceeded the project-wide response byte budget."""


async def bounded_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    infrastructure: bool = False,
    **kwargs: Any,
) -> httpx.Response:
    """GET an external resource with runtime request and response bounds.

    The external-request budget is reserved immediately before the actual HTTP
    operation. Infrastructure callers use the second budget dimension without
    double-counting the same request. Actual received bytes are counted from
    streamed chunks against the shared execution-attempt accounting.
    """
    accounting = current_accounting()
    if accounting is not None:
        if infrastructure and accounting.consume_reserved_infrastructure_request():
            pass
        else:
            accounting.reserve_http_request(infrastructure=infrastructure)

    if not hasattr(client, "stream"):
        response = await client.get(url, **kwargs)
        size = len(response.content)
        if size > MAX_EXTERNAL_RESPONSE_BYTES:
            if accounting is not None:
                accounting.consume_response_bytes(size)
            raise ResponseTooLargeError("External response exceeded the response-size budget")
        if accounting is not None:
            accounting.consume_response_bytes(size)
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
        try:
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > MAX_EXTERNAL_RESPONSE_BYTES:
                    if accounting is not None:
                        accounting.consume_response_bytes(len(chunk))
                    raise ResponseTooLargeError("External response exceeded the response-size budget")
                if accounting is not None:
                    accounting.consume_response_bytes(len(chunk))
                chunks.append(chunk)
        except Exception:
            raise
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=b"".join(chunks),
            request=response.request,
            extensions=response.extensions,
        )


def classify_exception(provider: str, exc: Exception) -> ProviderResult:
    if isinstance(exc, ResourceBudgetExceeded):
        status = "resource_limited"
    elif isinstance(exc, httpx.TimeoutException):
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

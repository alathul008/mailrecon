import asyncio
import ipaddress

import httpx
import pytest

from app.core.security import resolve_public_addresses, validate_external_url
from app.core import rate_limit
from app.providers.base import ProviderContext, ProviderResult
from app.providers.http import MAX_EXTERNAL_RESPONSE_BYTES, ResponseTooLargeError, bounded_get
from app.providers.network import pinned_transport
from app.providers.registry import ProviderDefinition, execute
from app.services.resource_budget import ExecutionResourceBudget


def test_content_length_overflow_is_rejected_before_parsing():
    async def run():
        def handler(request):
            return httpx.Response(200, headers={"content-length": str(MAX_EXTERNAL_RESPONSE_BYTES + 1)}, content=b"{}")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False) as client:
            with pytest.raises(ResponseTooLargeError):
                await bounded_get(client, "https://example.com/")
    asyncio.run(run())


def test_streamed_response_overflow_is_rejected_without_content_length():
    payload = b"x" * (MAX_EXTERNAL_RESPONSE_BYTES + 1)

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield payload

    async def run():
        def handler(request):
            return httpx.Response(200, stream=Stream())
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False) as client:
            with pytest.raises(ResponseTooLargeError):
                await bounded_get(client, "https://example.com/")

    asyncio.run(run())


def test_normal_response_remains_available_for_json_parsing():
    async def run():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
        async with httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False) as client:
            response = await bounded_get(client, "https://example.com/")
            assert response.json() == {"ok": True}

    asyncio.run(run())


def test_provider_registry_applies_explicit_finding_cap():
    definition = ProviderDefinition(
        "Test Provider", "Other", True, ("test",), "none", False, False, True,
        argument_mode="email", max_findings=2,
    )

    class Runner:
        async def run(self, context):
            return ProviderResult("Test Provider", "ok", findings=[{"value": str(i)} for i in range(5)])

    async def run():
        result = await execute(definition, context=ProviderContext("a@example.com", "example.com"), factory=lambda: Runner())
        assert len(result.findings) == 2
        assert "Result limit applied" in result.message

    asyncio.run(run())


def test_resource_budget_covers_bytes_and_existing_dimensions():
    budget = ExecutionResourceBudget()
    budget.validate(provider_calls=6, candidate_probes=4, estimated_external_requests=8, response_bytes=MAX_EXTERNAL_RESPONSE_BYTES)
    with pytest.raises(RuntimeError, match="response-byte"):
        budget.validate(provider_calls=1, candidate_probes=1, estimated_external_requests=1, response_bytes=MAX_EXTERNAL_RESPONSE_BYTES + 1)
    with pytest.raises(RuntimeError, match="persisted-finding"):
        budget.validate(provider_calls=1, candidate_probes=1, estimated_external_requests=1, persisted_findings=budget.max_persisted_findings + 1)


def test_public_web_admission_is_bounded_and_resettable(monkeypatch):
    monkeypatch.setattr("app.core.rate_limit.get_settings", lambda: type("Settings", (), {
        "max_public_web_requests_per_window": 2,
        "public_web_rate_window_seconds": 60.0,
    })())
    rate_limit.reset_for_tests()
    assert rate_limit.allow_public_web_discovery(now=10.0)
    assert rate_limit.allow_public_web_discovery(now=11.0)
    assert not rate_limit.allow_public_web_discovery(now=12.0)
    assert rate_limit.allow_public_web_discovery(now=71.0)
    rate_limit.reset_for_tests()


def test_global_destination_policy_rejects_cgnat_and_mixed_dns(monkeypatch):
    cgnat = "100.64.0.1"
    public = "8.8.8.8"
    monkeypatch.setattr("app.core.security.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", (cgnat, 443))])
    with pytest.raises(ValueError, match="non-public"):
        resolve_public_addresses("shared.example", 443)
    monkeypatch.setattr("app.core.security.socket.getaddrinfo", lambda *args, **kwargs: [
        (2, 1, 6, "", (public, 443)),
        (2, 1, 6, "", ("10.0.0.1", 443)),
    ])
    with pytest.raises(ValueError, match="non-public"):
        validate_external_url("https://mixed.example/")


def test_pinned_transport_rejects_invalid_url_and_uses_pinned_backend():
    with pytest.raises(ValueError):
        pinned_transport("http://example.com/")
    transport = pinned_transport("https://example.com/")
    assert transport._pinned_backend.hostname == "example.com"
    assert transport._pool._network_backend is transport._pinned_backend


def test_https_and_userinfo_rejections(monkeypatch):
    monkeypatch.setattr("app.core.security.socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("8.8.8.8", 443))])
    with pytest.raises(ValueError):
        validate_external_url("http://example.com/")
    with pytest.raises(ValueError):
        validate_external_url("https://user:pass@example.com/")


def test_special_addresses_are_not_global():
    for address in ("127.0.0.1", "169.254.1.1", "192.0.2.1", "100.64.0.1", "::1"):
        assert not ipaddress.ip_address(address).is_global

import asyncio
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from httpx import AsyncClient

from app.osint import dns
from app.providers.base import ProviderContext, ProviderResult
from app.providers.http import bounded_get, classify_response
from app.providers.public_web import PublicWebProvider
from app.services.resource_budget import ResourceBudgetExceeded, ExecutionResourceBudget, bind_accounting


def _mock_client(handler):
    return AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )


def test_http_budget_counts_actual_requests_and_blocks_n_plus_one():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"ok")

    async def run():
        accounting = ExecutionResourceBudget(max_external_requests=2).accounting()
        with bind_accounting(accounting):
            async with _mock_client(handler) as client:
                await bounded_get(client, "https://example.com/1")
                await bounded_get(client, "https://example.com/2")
                with pytest.raises(ResourceBudgetExceeded, match="external-request budget"):
                    await bounded_get(client, "https://example.com/3")
        assert calls == 2
        assert accounting.external_requests == 2

    asyncio.run(run())


def test_http_provider_failure_still_accounts_the_attempt_once():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ReadTimeout("deterministic timeout")
        return httpx.Response(200, content=b"ok")

    async def run():
        accounting = ExecutionResourceBudget(max_external_requests=2).accounting()
        with bind_accounting(accounting):
            async with _mock_client(handler) as client:
                with pytest.raises(httpx.ReadTimeout):
                    await bounded_get(client, "https://example.com/failure")
                await bounded_get(client, "https://example.com/success")
        assert calls == 2
        assert accounting.external_requests == 2

    asyncio.run(run())


def test_concurrent_http_execution_cannot_exceed_budget():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, content=b"ok")

    async def run():
        accounting = ExecutionResourceBudget(max_external_requests=3).accounting()
        with bind_accounting(accounting):
            async with _mock_client(handler) as client:
                async def one(i):
                    try:
                        await bounded_get(client, f"https://example.com/{i}")
                        return True
                    except ResourceBudgetExceeded:
                        return False

                results = await asyncio.gather(*(one(i) for i in range(10)))
        assert sum(results) == 3
        assert calls == 3
        assert accounting.external_requests == 3

    asyncio.run(run())


def test_dns_budget_counts_real_resolver_execution_and_blocks_n_plus_one():
    calls = 0

    class Answer:
        def to_text(self):
            return "93.184.216.34"

    class Resolver:
        async def resolve(self, name, rdtype):
            nonlocal calls
            calls += 1
            return [Answer()]

    async def run():
        accounting = ExecutionResourceBudget(max_dns_queries=2).accounting()
        with bind_accounting(accounting):
            assert await dns._resolve(Resolver(), "example.com", "A") == (["93.184.216.34"], "ok")
            assert await dns._resolve(Resolver(), "example.com", "AAAA") == (["93.184.216.34"], "ok")
            values, status = await dns._resolve(Resolver(), "example.com", "MX")
            assert values == []
            assert status == "resource_limited"
        assert calls == 2
        assert accounting.dns_queries == 2

    asyncio.run(run())


def test_dns_provider_failure_still_accounts_the_attempt_once():
    calls = 0

    class Resolver:
        async def resolve(self, name, rdtype):
            nonlocal calls
            calls += 1
            raise asyncio.TimeoutError("deterministic timeout")

    async def run():
        accounting = ExecutionResourceBudget(max_dns_queries=2).accounting()
        with bind_accounting(accounting):
            values, status = await dns._resolve(Resolver(), "example.com", "A")
            assert values == [] and status == "unavailable"
            values, status = await dns._resolve(Resolver(), "example.com", "AAAA")
            assert values == [] and status == "unavailable"
        assert calls == 2
        assert accounting.dns_queries == 2

    asyncio.run(run())


def test_dns_resource_limit_is_inconclusive_not_negative_evidence():
    assert dns.record_presence([], "resource_limited") is None
    result = ProviderResult("DNS", "resource_limited", message="DNS-query budget exceeded")
    assert result.status == "resource_limited"
    assert not result.findings


def test_infrastructure_http_counts_once_across_both_runtime_dimensions(monkeypatch):
    class FakeClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    async def fake_bounded_get(client, url, **kwargs):
        assert kwargs["infrastructure"] is True
        return httpx.Response(200, json={"handle": "AS15169", "name": "Example"})

    monkeypatch.setattr(dns, "validate_provider_url", lambda url: url)
    monkeypatch.setattr(dns, "pinned_transport", lambda url: None)
    monkeypatch.setattr(dns.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(dns, "bounded_get", fake_bounded_get)

    async def run():
        accounting = ExecutionResourceBudget(max_external_requests=1, max_infrastructure_http_requests=1).accounting()
        with bind_accounting(accounting):
            result = await dns._ip_context("8.8.8.8")
        assert result["status"] == "ok"
        assert accounting.external_requests == 1
        assert accounting.infrastructure_http_requests == 1

    asyncio.run(run())


def test_infrastructure_budget_failure_is_fail_closed_without_network(monkeypatch):
    calls = 0

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

    async def should_not_run(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("HTTP operation must not run after infrastructure budget exhaustion")

    monkeypatch.setattr(dns, "validate_provider_url", lambda url: url)
    monkeypatch.setattr(dns, "pinned_transport", lambda url: None)
    monkeypatch.setattr(dns.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(dns, "bounded_get", should_not_run)

    async def run():
        budget = ExecutionResourceBudget(max_external_requests=2, max_infrastructure_http_requests=1)
        accounting = budget.accounting()
        accounting.reserve_infrastructure_http_request()
        with bind_accounting(accounting):
            result = await dns._ip_context("8.8.8.8")
        assert result["status"] == "resource_limited"
        assert calls == 0
        assert accounting.external_requests == 2
        assert accounting.infrastructure_http_requests == 1

    asyncio.run(run())


def test_public_web_query_result_accounting_is_not_double_counted(monkeypatch):
    responses = [
        {"results": [{"url": "https://example.com/a", "title": "A"}, {"url": "https://example.com/b", "title": "B"}]},
        {"results": [{"url": "https://example.com/c", "title": "C"}]},
    ]
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=responses[calls - 1])

    async def run():
        settings = type("Settings", (), {
            "public_web_search_url": "https://search.example/api",
            "public_web_search_token": None,
            "request_timeout_seconds": 7.0,
        })()
        monkeypatch.setattr("app.providers.public_web.get_settings", lambda: settings)
        monkeypatch.setattr("app.providers.public_web.validate_provider_url", lambda url: url)
        monkeypatch.setattr("app.providers.public_web.pinned_transport", lambda url: None)
        monkeypatch.setattr("app.providers.public_web.httpx.AsyncClient", lambda **kwargs: _mock_client(handler))
        accounting = ExecutionResourceBudget(max_external_requests=2, max_public_web_queries=5).accounting()
        with bind_accounting(accounting):
            result = await PublicWebProvider().run(ProviderContext("alice@example.com", "example.com", ()))
        assert result.status == "ok"
        assert calls == 1
        assert accounting.external_requests == 1
        assert accounting.public_web_queries == 1
        assert accounting.public_web_results == 2

    asyncio.run(run())


def test_rate_limited_provider_result_has_no_negative_finding():
    result = classify_response("Test", httpx.Response(429))
    assert result is not None
    assert result.status == "rate_limited"
    assert not result.findings


def test_historical_attempts_use_isolated_accounting_contexts():
    async def run_one(accounting, url):
        with bind_accounting(accounting):
            async with _mock_client(lambda request: httpx.Response(200, content=b"ok")) as client:
                await bounded_get(client, url)

    async def run():
        first = ExecutionResourceBudget(max_external_requests=1).accounting()
        second = ExecutionResourceBudget(max_external_requests=1).accounting()
        await asyncio.gather(
            run_one(first, "https://example.com/current"),
            run_one(second, "https://example.com/historical"),
        )
        assert first.external_requests == 1
        assert second.external_requests == 1

    asyncio.run(run())


def test_accounting_does_not_store_request_data_or_secrets():
    accounting = ExecutionResourceBudget().accounting()
    representation = repr(accounting)
    assert "Authorization" not in representation
    assert "Bearer" not in representation
    assert "example.com" not in representation
    assert "alice@example.com" not in representation

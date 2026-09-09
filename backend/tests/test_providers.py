import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import Finding, Investigation
from app.providers.base import ProviderResult
from app.providers.github import GitHubProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider
from app.providers.rdap import RDAPProvider
from app.providers import github as github_module
from app.providers import gravatar as gravatar_module
from app.providers import hibp as hibp_module
from app.providers import rdap as rdap_module
from app.providers import http as provider_http
from app.services import orchestrator


class FakeAsyncClient:
    response = None
    exception = None
    seen_timeout = None
    seen_headers = None

    def __init__(self, *args, **kwargs):
        type(self).seen_timeout = kwargs.get("timeout")
        type(self).seen_headers = kwargs.get("headers")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        if type(self).exception:
            raise type(self).exception
        return type(self).response


def response(status=200, json_data=None, content=None):
    if content is not None:
        return httpx.Response(status, content=content)
    return httpx.Response(status, json=json_data)


def patch_client(monkeypatch, modules, status=200, json_data=None, content=None, exception=None):
    FakeAsyncClient.response = response(status, json_data, content)
    FakeAsyncClient.exception = exception
    for module in modules:
        monkeypatch.setattr(module.httpx, "AsyncClient", FakeAsyncClient)
        monkeypatch.setattr(module, "validate_provider_url", lambda url: url)


@pytest.mark.asyncio
async def test_rdap_success_and_event_parsing(monkeypatch):
    patch_client(monkeypatch, [rdap_module], json_data={"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "2025-01-02"}, {"eventAction": "unknown", "eventDate": "x"}]})
    result = await RDAPProvider().run("example.com")
    assert result.status == "ok"
    assert {f["finding_type"] for f in result.findings} == {"domain", "domain_event"}


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(404, "ok"), (429, "rate_limited"), (400, "error"), (403, "error"), (500, "unavailable"), (503, "unavailable")])
async def test_rdap_http_statuses(monkeypatch, status, expected):
    patch_client(monkeypatch, [rdap_module], status=status, json_data={})
    result = await RDAPProvider().run("example.com")
    assert result.status == expected
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [httpx.ReadTimeout("timed out"), httpx.ConnectError("connection failed")])
async def test_rdap_network_failures_are_unavailable(monkeypatch, exception):
    patch_client(monkeypatch, [rdap_module], exception=exception)
    result = await RDAPProvider().run("example.com")
    assert result.status == "unavailable"
    assert result.findings == []


@pytest.mark.asyncio
async def test_rdap_malformed_response_has_no_positive_findings(monkeypatch):
    patch_client(monkeypatch, [rdap_module], content=b"not-json")
    result = await RDAPProvider().run("example.com")
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_rdap_malformed_events_have_no_positive_findings(monkeypatch):
    patch_client(monkeypatch, [rdap_module], json_data={"ldhName": "example.com", "events": {"bad": "shape"}})
    result = await RDAPProvider().run("example.com")
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_gravatar_success(monkeypatch):
    patch_client(monkeypatch, [gravatar_module], json_data={"entry": [{"displayName": "Example User", "profileUrl": "https://gravatar.com/example", "thumbnailUrl": "https://gravatar.com/avatar/x"}]})
    result = await GravatarProvider().run("user@example.com")
    assert result.status == "ok"
    assert {f["finding_type"] for f in result.findings} == {"public_identity", "profile", "avatar"}


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(404, "ok"), (429, "rate_limited"), (400, "error"), (500, "unavailable")])
async def test_gravatar_http_statuses(monkeypatch, status, expected):
    patch_client(monkeypatch, [gravatar_module], status=status, json_data={})
    result = await GravatarProvider().run("user@example.com")
    assert result.status == expected
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [httpx.ReadTimeout("timed out"), httpx.ConnectError("connection failed")])
async def test_gravatar_network_failures_are_unavailable(monkeypatch, exception):
    patch_client(monkeypatch, [gravatar_module], exception=exception)
    result = await GravatarProvider().run("user@example.com")
    assert result.status == "unavailable"
    assert result.findings == []


@pytest.mark.asyncio
async def test_gravatar_malformed_response_has_no_positive_findings(monkeypatch):
    patch_client(monkeypatch, [gravatar_module], content=b"not-json")
    result = await GravatarProvider().run("user@example.com")
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_gravatar_malformed_entry_has_no_positive_findings(monkeypatch):
    patch_client(monkeypatch, [gravatar_module], json_data={"entry": ["not-an-object"]})
    result = await GravatarProvider().run("user@example.com")
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_hibp_without_key_is_unconfigured(monkeypatch):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = None
    try:
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == "unconfigured"
    assert result.findings == []


@pytest.mark.asyncio
async def test_hibp_404_is_legitimate_no_result(monkeypatch):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = "test-key"
    try:
        patch_client(monkeypatch, [hibp_module], status=404, json_data={})
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == "ok"
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(401, "error"), (403, "error"), (429, "rate_limited"), (500, "unavailable")])
async def test_hibp_http_failures(monkeypatch, status, expected):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = "test-key"
    try:
        patch_client(monkeypatch, [hibp_module], status=status, json_data={})
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == expected
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("exception", [httpx.ReadTimeout("timed out"), httpx.ConnectError("connection failed")])
async def test_hibp_network_failures_are_unavailable(monkeypatch, exception):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = "test-key"
    try:
        patch_client(monkeypatch, [hibp_module], exception=exception)
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == "unavailable"
    assert result.findings == []


@pytest.mark.asyncio
async def test_hibp_malformed_json_has_no_positive_findings(monkeypatch):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = "test-key"
    try:
        patch_client(monkeypatch, [hibp_module], content=b"not-json")
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_hibp_incomplete_and_malformed_records_are_not_findings(monkeypatch):
    settings = hibp_module.get_settings()
    original = settings.hibp_api_key
    settings.hibp_api_key = "test-key"
    try:
        patch_client(monkeypatch, [hibp_module], json_data=[{}, "bad", {"Name": "Valid", "BreachDate": "not-a-date"}])
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.hibp_api_key = original
    assert result.status == "ok"
    assert [f["value"] for f in result.findings] == ["Valid"]
    assert result.findings[0]["first_seen"] is None


@pytest.mark.asyncio
async def test_github_success_and_404_no_result(monkeypatch):
    patch_client(monkeypatch, [github_module], json_data={"login": "example", "name": "Example", "html_url": "https://github.com/example", "public_repos": 3})
    result = await GitHubProvider().run(["example"], "user@example.com")
    assert result.status == "ok"
    assert len(result.findings) == 1

    patch_client(monkeypatch, [github_module], status=404, json_data={})
    result = await GitHubProvider().run(["missing"], "user@example.com")
    assert result.status == "ok"
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(429, "rate_limited"), (403, "error"), (500, "unavailable")])
async def test_github_http_failures(monkeypatch, status, expected):
    patch_client(monkeypatch, [github_module], status=status, json_data={})
    result = await GitHubProvider().run(["example"], "user@example.com")
    assert result.status == expected
    assert result.findings == []


@pytest.mark.asyncio
async def test_github_timeout_and_malformed_json(monkeypatch):
    patch_client(monkeypatch, [github_module], exception=httpx.ReadTimeout("timed out"))
    result = await GitHubProvider().run(["example"], "user@example.com")
    assert result.status == "unavailable"
    assert result.findings == []

    patch_client(monkeypatch, [github_module], content=b"not-json")
    result = await GitHubProvider().run(["example"], "user@example.com")
    assert result.status == "error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_provider_timeout_uses_configured_value(monkeypatch):
    settings = hibp_module.get_settings()
    original = settings.request_timeout_seconds
    settings.request_timeout_seconds = 3.25
    try:
        settings.hibp_api_key = "test-key"
        patch_client(monkeypatch, [hibp_module], status=404, json_data={})
        result = await HIBPProvider().run("user@example.com")
    finally:
        settings.request_timeout_seconds = original
    assert result.status == "ok"
    assert FakeAsyncClient.seen_timeout == 3.25


@pytest.mark.asyncio
async def test_provider_execution_isolated_when_one_raises(monkeypatch):
    async def ok_gravatar(self, email):
        return ProviderResult("Gravatar", "ok", message="done")

    async def broken_rdap(self, domain):
        raise RuntimeError("boom")

    async def ok_github(self, candidates, email):
        return ProviderResult("GitHub", "ok", message="done")

    async def unconfigured_hibp(self, email):
        return ProviderResult("Have I Been Pwned", "unconfigured")

    monkeypatch.setattr(orchestrator.GravatarProvider, "run", ok_gravatar)
    monkeypatch.setattr(orchestrator.RDAPProvider, "run", broken_rdap)
    monkeypatch.setattr(orchestrator.GitHubProvider, "run", ok_github)
    monkeypatch.setattr(orchestrator.HIBPProvider, "run", unconfigured_hibp)

    results = await orchestrator.run_providers("user@example.com", "example.com", ["example"])
    assert [result.status if not isinstance(result, Exception) else type(result).__name__ for result in results] == ["ok", "RuntimeError", "ok", "unconfigured"]


def test_privacy_mode_strips_provider_raw_reference():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(target="user@example.com", normalized_email="user@example.com", username="user", domain="example.com", privacy_mode=True)
        db.add(inv)
        db.commit()
        finding_data = {
            "source": "RDAP",
            "finding_type": "domain_event",
            "value": "registration: 2025-01-01",
            "confidence": 0.95,
            "severity": "info",
            "raw_reference": {"eventAction": "registration", "eventDate": "2025-01-01"},
        }
        orchestrator.add_findings(db, inv.id, [finding_data])
        stored = db.query(Finding).one()
        assert stored.raw_reference is None
        assert stored.value == finding_data["value"]


def test_provider_http_helper_reuses_existing_ssrf_policy(monkeypatch):
    called = []

    def validator(url):
        called.append(url)
        return url

    monkeypatch.setattr(provider_http, "validate_external_url", validator)
    assert provider_http.validate_provider_url("https://example.com/resource") == "https://example.com/resource"
    assert called == ["https://example.com/resource"]


@pytest.mark.asyncio
async def test_rdap_ssrf_validation_failure_is_provider_error(monkeypatch):
    monkeypatch.setattr(rdap_module, "validate_provider_url", lambda url: (_ for _ in ()).throw(ValueError("blocked")))
    result = await RDAPProvider().run("example.com")
    assert result.status == "error"
    assert result.findings == []

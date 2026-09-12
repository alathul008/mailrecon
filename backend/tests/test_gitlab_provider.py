import httpx
import pytest

from app.providers.gitlab import GitLabProvider
from app.providers import gitlab as gitlab_module


class FakeAsyncClient:
    response = None
    exception = None

    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        if type(self).exception:
            raise type(self).exception
        return type(self).response


def patch_client(monkeypatch, status=200, json_data=None, exception=None):
    FakeAsyncClient.response = httpx.Response(status, json=json_data or [])
    FakeAsyncClient.exception = exception
    monkeypatch.setattr(gitlab_module.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(gitlab_module, "validate_provider_url", lambda url: url)


@pytest.mark.asyncio
async def test_gitlab_exact_public_email_match(monkeypatch):
    patch_client(monkeypatch, json_data=[{"username": "example", "name": "Example", "public_email": "user@example.com", "web_url": "https://gitlab.com/example"}])
    result = await GitLabProvider().run("user@example.com")
    assert result.status == "ok"
    assert result.findings[0]["finding_type"] == "profile_candidate"
    assert result.findings[0]["evidence_state"] == "corroborated_match"
    assert result.findings[0]["source_url"] == "https://gitlab.com/example"


@pytest.mark.asyncio
async def test_gitlab_nonmatching_public_email_is_not_evidence(monkeypatch):
    patch_client(monkeypatch, json_data=[{"username": "example", "public_email": "other@example.com", "web_url": "https://gitlab.com/example"}])
    result = await GitLabProvider().run("user@example.com")
    assert result.status == "ok"
    assert result.findings == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status,expected", [(429, "rate_limited"), (400, "error"), (500, "unavailable")])
async def test_gitlab_http_statuses(monkeypatch, status, expected):
    patch_client(monkeypatch, status=status)
    result = await GitLabProvider().run("user@example.com")
    assert result.status == expected
    assert result.findings == []


@pytest.mark.asyncio
async def test_gitlab_timeout_is_unavailable(monkeypatch):
    patch_client(monkeypatch, exception=httpx.ReadTimeout("timed out"))
    result = await GitLabProvider().run("user@example.com")
    assert result.status == "unavailable"
    assert result.findings == []

import asyncio

import httpx
import pytest

from app.providers.base import ProviderResult
from app.services import orchestrator


class _FakeProvider:
    def __init__(self, started, cancelled):
        self.started = started
        self.cancelled = cancelled

    async def run(self, *args):
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


@pytest.mark.asyncio
async def test_provider_work_is_cancelled_when_execution_ownership_is_lost(monkeypatch):
    started = asyncio.Event()
    cancelled = asyncio.Event()
    providers = [_FakeProvider(started, cancelled) for _ in range(6)]

    monkeypatch.setattr(orchestrator, "GravatarProvider", lambda: providers[0])
    monkeypatch.setattr(orchestrator, "RDAPProvider", lambda: providers[1])
    monkeypatch.setattr(orchestrator, "GitHubProvider", lambda: providers[2])
    monkeypatch.setattr(orchestrator, "GitLabProvider", lambda: providers[3])
    monkeypatch.setattr(orchestrator, "PublicWebProvider", lambda: providers[4])
    monkeypatch.setattr(orchestrator, "HIBPProvider", lambda: providers[5])

    ownership_checks = iter([True, False])
    monkeypatch.setattr(orchestrator, "execution_is_owned", lambda db, inv_id, token: next(ownership_checks))

    with pytest.raises(orchestrator.ProviderOwnershipLost, match="ownership was lost"):
        await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="attempt-token")

    assert started.is_set()
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_provider_result_is_rejected_after_ownership_loss(monkeypatch):
    started = asyncio.Event()

    class SlowProvider:
        async def run(self, *args):
            started.set()
            await asyncio.Event().wait()
            return ProviderResult("Gravatar", "ok", findings=[{"finding_type": "profile", "value": "stale"}])

    class FastProvider:
        def __init__(self, name): self.name = name
        async def run(self, *args):
            await started.wait()
            return ProviderResult(self.name, "ok")

    monkeypatch.setattr(orchestrator, "GravatarProvider", SlowProvider)
    monkeypatch.setattr(orchestrator, "RDAPProvider", lambda: FastProvider("RDAP"))
    monkeypatch.setattr(orchestrator, "GitHubProvider", lambda: FastProvider("GitHub"))
    monkeypatch.setattr(orchestrator, "GitLabProvider", lambda: FastProvider("GitLab"))
    monkeypatch.setattr(orchestrator, "PublicWebProvider", lambda: FastProvider("Public Web"))
    monkeypatch.setattr(orchestrator, "HIBPProvider", lambda: FastProvider("Have I Been Pwned"))

    ownership_checks = iter([True, False])
    monkeypatch.setattr(orchestrator, "execution_is_owned", lambda db, inv_id, token: next(ownership_checks))

    with pytest.raises(orchestrator.ProviderOwnershipLost):
        await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="stale-token")


@pytest.mark.asyncio
async def test_provider_timeout_is_returned_as_provider_failure(monkeypatch):
    class TimeoutProvider:
        async def run(self, *args): raise httpx.ReadTimeout("provider timeout")

    async def ok(name): return ProviderResult(name, "ok")

    monkeypatch.setattr(orchestrator, "GravatarProvider", TimeoutProvider)
    monkeypatch.setattr(orchestrator, "RDAPProvider", lambda: type("P", (), {"run": lambda self, *args: ok("RDAP")})())
    monkeypatch.setattr(orchestrator, "GitHubProvider", lambda: type("P", (), {"run": lambda self, *args: ok("GitHub")})())
    monkeypatch.setattr(orchestrator, "GitLabProvider", lambda: type("P", (), {"run": lambda self, *args: ok("GitLab")})())
    monkeypatch.setattr(orchestrator, "PublicWebProvider", lambda: type("P", (), {"run": lambda self, *args: ok("Public Web")})())
    monkeypatch.setattr(orchestrator, "HIBPProvider", lambda: type("P", (), {"run": lambda self, *args: ok("Have I Been Pwned")})())

    results = await orchestrator.run_providers("test@example.com", "example.com", ["test"])
    assert isinstance(results[0], httpx.ReadTimeout)


@pytest.mark.asyncio
async def test_external_disclosure_disabled_never_starts_provider_tasks(monkeypatch):
    calls = []

    class UnexpectedProvider:
        async def run(self, *args):
            calls.append(True)
            return ProviderResult("unexpected", "ok")

    monkeypatch.setattr(orchestrator, "GravatarProvider", UnexpectedProvider)
    monkeypatch.setattr(orchestrator, "RDAPProvider", UnexpectedProvider)
    monkeypatch.setattr(orchestrator, "GitHubProvider", UnexpectedProvider)
    monkeypatch.setattr(orchestrator, "GitLabProvider", UnexpectedProvider)
    monkeypatch.setattr(orchestrator, "PublicWebProvider", UnexpectedProvider)
    monkeypatch.setattr(orchestrator, "HIBPProvider", UnexpectedProvider)

    results = await orchestrator.run_providers("test@example.com", "example.com", ["test"], allow_external=False)
    assert calls == []
    assert [result.status for result in results] == ["disabled"] * 6

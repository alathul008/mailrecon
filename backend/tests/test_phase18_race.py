import asyncio
import inspect
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.api.routes import delete_inv
from app.core.config import get_settings
from app.db.session import Base
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.providers.base import ProviderResult
from app.services import lifecycle, orchestrator


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase18_race.db'}", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    return engine


def add_investigation(db):
    inv = Investigation(target="test@example.com", normalized_email="test@example.com", username="test", domain="example.com", status="queued")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def install_fake_providers(monkeypatch, factory):
    def make(name):
        try:
            inspect.signature(factory).bind(name)
        except TypeError:
            return factory()
        return factory(name)

    monkeypatch.setattr(orchestrator, "GravatarProvider", lambda: make("Gravatar"))
    monkeypatch.setattr(orchestrator, "RDAPProvider", lambda: make("RDAP"))
    monkeypatch.setattr(orchestrator, "GitHubProvider", lambda: make("GitHub"))
    monkeypatch.setattr(orchestrator, "HIBPProvider", lambda: make("Have I Been Pwned"))


@pytest.mark.asyncio
async def test_multiple_provider_tasks_are_cancelled_and_drained(monkeypatch):
    names = ("Gravatar", "RDAP", "GitHub", "Have I Been Pwned")
    started = {name: asyncio.Event() for name in names}
    cancelled = {name: asyncio.Event() for name in names}
    provider_tasks = []

    class Provider:
        def __init__(self, name): self.name = name
        async def run(self, *args):
            started[self.name].set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled[self.name].set()
                raise

    install_fake_providers(monkeypatch, Provider)
    real_create_task = orchestrator.asyncio.create_task
    def capture_task(coro):
        task = real_create_task(coro)
        if getattr(coro, "cr_code", None) and coro.cr_code.co_name == "_run_provider_call":
            provider_tasks.append(task)
        return task
    monkeypatch.setattr(orchestrator.asyncio, "create_task", capture_task)
    ownership = iter([True, False])
    monkeypatch.setattr(orchestrator, "execution_is_owned", lambda db, inv_id, token: next(ownership))

    with pytest.raises(orchestrator.ProviderOwnershipLost):
        await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="token")

    assert all(event.is_set() for event in started.values())
    assert all(event.is_set() for event in cancelled.values())
    assert len(provider_tasks) == 4
    assert all(task.done() for task in provider_tasks)


@pytest.mark.asyncio
async def test_provider_completion_before_final_ownership_check_is_rejected(monkeypatch):
    provider_done = asyncio.Event()
    release_monitor = asyncio.Event()
    owned = {"value": True}

    class Provider:
        async def run(self, *args):
            provider_done.set()
            await release_monitor.wait()
            return ProviderResult("Gravatar", "ok", findings=[{"finding_type": "profile", "value": "stale"}])

    install_fake_providers(monkeypatch, Provider)
    ownership_checked = asyncio.Event()

    def ownership_probe(db, inv_id, token):
        ownership_checked.set()
        return owned["value"]

    monkeypatch.setattr(orchestrator, "execution_is_owned", ownership_probe)

    async def drive_race():
        await provider_done.wait()
        owned["value"] = False
        release_monitor.set()

    driver = asyncio.create_task(drive_race())
    try:
        with pytest.raises(orchestrator.ProviderOwnershipLost):
            await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="token")
    finally:
        await driver
    assert owned["value"] is False


@pytest.mark.asyncio
async def test_provider_completion_after_ownership_loss_is_rejected(monkeypatch):
    started = asyncio.Event()
    ownership_lost = asyncio.Event()
    release = asyncio.Event()
    owned = {"value": True}

    class Provider:
        async def run(self, *args):
            started.set()
            await release.wait()
            return ProviderResult("Gravatar", "ok", findings=[{"finding_type": "profile", "value": "stale"}])

    install_fake_providers(monkeypatch, Provider)
    first_check = True

    def ownership_probe(db, inv_id, token):
        nonlocal first_check
        if first_check:
            first_check = False
            return True
        ownership_lost.set()
        return owned["value"]

    monkeypatch.setattr(orchestrator, "execution_is_owned", ownership_probe)

    async def drive_race():
        await started.wait()
        owned["value"] = False
        release.set()

    driver = asyncio.create_task(drive_race())
    try:
        with pytest.raises(orchestrator.ProviderOwnershipLost):
            await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="token")
    finally:
        await driver
    assert ownership_lost.is_set()


@pytest.mark.asyncio
async def test_worker_a_is_fenced_after_worker_b_recovery(monkeypatch, tmp_path):
    engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=Session)
    monkeypatch.setattr(orchestrator, "SessionLocal", SessionLocal)

    with SessionLocal() as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=lifecycle.utcnow())
        inv_id = inv.id
        assert token_a

    started = asyncio.Event()
    release = asyncio.Event()
    class Provider:
        async def run(self, *args):
            started.set()
            await release.wait()
            return ProviderResult("Gravatar", "ok", findings=[{"finding_type": "profile", "value": "stale-a"}])
    install_fake_providers(monkeypatch, Provider)
    worker_a = asyncio.create_task(orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=inv_id, token=token_a))
    await started.wait()

    with SessionLocal() as db:
        stale = lifecycle.utcnow() - timedelta(seconds=get_settings().execution_lease_seconds + 1)
        db.execute(update(Investigation).where(Investigation.id == inv_id).values(execution_heartbeat_at=stale))
        db.commit()
        assert lifecycle.recover_stale_investigations(db) == 1
        token_b = lifecycle.claim_investigation(db, inv_id, now=lifecycle.utcnow())
        assert token_b and token_b != token_a

    release.set()
    with pytest.raises(orchestrator.ProviderOwnershipLost):
        await worker_a

    with SessionLocal() as db:
        current = db.get(Investigation, inv_id)
        assert current.execution_token == token_b
        assert current.status == "running"
        with pytest.raises(RuntimeError, match="lease is no longer owned"):
            orchestrator.add_findings(db, inv_id, [{"source": "Gravatar", "finding_type": "profile", "value": "stale-a", "confidence": 1, "severity": "info"}], token=token_a)
        assert db.scalars(select(Finding).where(Finding.investigation_id == inv_id, Finding.value == "stale-a")).all() == []
        attempts = db.scalars(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id)).all()
        assert len(attempts) == 2
        assert {attempt.status for attempt in attempts} == {"abandoned", "running"}
        assert any(attempt.execution_attempt_id == current.execution_attempt_id and attempt.status == "running" for attempt in attempts)


@pytest.mark.asyncio
async def test_timeout_during_ownership_transition_is_not_accepted(monkeypatch):
    started = asyncio.Event()
    release = asyncio.Event()
    owned = {"value": True}

    class TimeoutProvider:
        async def run(self, *args):
            started.set()
            await release.wait()
            raise httpx.ReadTimeout("provider timeout")
    class SlowProvider:
        async def run(self, *args):
            await asyncio.Event().wait()

    monkeypatch.setattr(orchestrator, "GravatarProvider", TimeoutProvider)
    monkeypatch.setattr(orchestrator, "RDAPProvider", SlowProvider)
    monkeypatch.setattr(orchestrator, "GitHubProvider", SlowProvider)
    monkeypatch.setattr(orchestrator, "HIBPProvider", SlowProvider)
    monkeypatch.setattr(orchestrator, "execution_is_owned", lambda db, inv_id, token: owned["value"])

    async def drive_race():
        await started.wait()
        owned["value"] = False
        release.set()

    driver = asyncio.create_task(drive_race())
    try:
        with pytest.raises(orchestrator.ProviderOwnershipLost):
            await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="token")
    finally:
        await driver


@pytest.mark.asyncio
async def test_deletion_during_active_provider_work_cannot_resurrect_data(monkeypatch, tmp_path):
    engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=Session)
    monkeypatch.setattr(orchestrator, "SessionLocal", SessionLocal)

    with SessionLocal() as db:
        inv = add_investigation(db)
        inv_id = inv.id
        token = lifecycle.claim_investigation(db, inv_id)
        assert token

    started = asyncio.Event()
    release = asyncio.Event()
    class Provider:
        async def run(self, *args):
            started.set()
            await release.wait()
            return ProviderResult("Gravatar", "ok", findings=[{"finding_type": "profile", "value": "deleted-stale"}])
    install_fake_providers(monkeypatch, Provider)
    worker = asyncio.create_task(orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=inv_id, token=token))
    await started.wait()

    with SessionLocal() as db:
        assert delete_inv(inv_id, db)["status"] == "deleted"
    release.set()
    with pytest.raises(orchestrator.ProviderOwnershipLost):
        await worker

    with SessionLocal() as db:
        assert db.get(Investigation, inv_id) is None
        assert db.scalars(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id)).all() == []
        assert db.scalars(select(ModuleRun).where(ModuleRun.investigation_id == inv_id)).all() == []
        assert db.scalars(select(Finding).where(Finding.investigation_id == inv_id)).all() == []


@pytest.mark.asyncio
async def test_cancellation_exception_cannot_turn_ownership_loss_into_success(monkeypatch):
    started = asyncio.Event()
    cleanup_failed = asyncio.Event()
    class Provider:
        async def run(self, *args):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_failed.set()
                raise RuntimeError("unexpected cancellation cleanup failure")
    install_fake_providers(monkeypatch, Provider)
    ownership = iter([True, False])
    monkeypatch.setattr(orchestrator, "execution_is_owned", lambda db, inv_id, token: next(ownership))

    with pytest.raises(orchestrator.ProviderOwnershipLost):
        await orchestrator.run_providers("test@example.com", "example.com", ["test"], inv_id=1, token="token")
    assert started.is_set()
    assert cleanup_failed.is_set()
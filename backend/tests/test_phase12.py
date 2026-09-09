from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.providers import network
from app.providers.base import ProviderResult
from app.services import orchestrator
from app.services.lifecycle import claim_investigation, finish_execution_attempt, recover_stale_investigations


def make_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase12.db'}")
    Base.metadata.create_all(engine)
    return engine


def add_inv(db, **kwargs):
    inv = Investigation(target="test@example.com", normalized_email="test@example.com", username="test", domain="example.com", **kwargs)
    db.add(inv); db.commit(); db.refresh(inv)
    return inv


def test_claim_creates_first_class_attempt_and_preserves_execution_identity(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        token = claim_investigation(db, inv.id)
        current = db.get(Investigation, inv.id)
        attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == current.execution_attempt_id))
        assert token
        assert attempt is not None
        assert attempt.execution_id == current.execution_id
        assert attempt.status == "running"


def test_recovery_marks_attempt_abandoned_and_next_claim_creates_distinct_attempt(tmp_path):
    engine = make_db(tmp_path)
    t0 = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        inv = add_inv(db)
        claim_investigation(db, inv.id, now=t0)
        first = db.get(Investigation, inv.id)
        first_attempt = first.execution_attempt_id
        execution_id = first.execution_id
        assert recover_stale_investigations(db, now=t0 + timedelta(seconds=61)) == 1
        abandoned = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == first_attempt))
        assert abandoned.status == "abandoned"
        assert abandoned.execution_id == execution_id
        claim_investigation(db, inv.id, now=t0 + timedelta(seconds=62))
        second = db.get(Investigation, inv.id)
        assert second.execution_id == execution_id
        assert second.execution_attempt_id != first_attempt
        assert db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == second.execution_attempt_id)).status == "running"


def test_completed_historical_attempt_is_never_rewritten(tmp_path):
    engine = make_db(tmp_path)
    t0 = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        inv = add_inv(db)
        claim_investigation(db, inv.id, now=t0)
        first = db.get(Investigation, inv.id)
        attempt_a = first.execution_attempt_id
        finish_execution_attempt(db, inv.id, attempt_a, "completed", now=t0 + timedelta(seconds=2))
        db.commit()
        first.status = "queued"; first.execution_token = None; first.execution_heartbeat_at = None; db.commit()
        claim_investigation(db, inv.id, now=t0 + timedelta(seconds=3))
        historical = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == attempt_a))
        assert historical.status == "completed"
        assert historical.finished_at is not None


def test_module_transition_graph_rejects_terminal_rewrite(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        token = claim_investigation(db, inv.id)
        orchestrator.set_module(db, inv.id, "rdap", "running", token=token)
        orchestrator.set_module(db, inv.id, "rdap", "completed", "done", token=token)
        with pytest.raises(RuntimeError, match="Invalid ModuleRun transition"):
            orchestrator.set_module(db, inv.id, "rdap", "running", token=token)


def test_finding_projection_distinguishes_current_and_historical_attempts():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = add_inv(db, status="running")
        inv.execution_id = "exec-1"; inv.execution_attempt_id = "attempt-b"; db.commit()
        current = Finding(investigation_id=inv.id, execution_id="exec-1", execution_attempt_id="attempt-b", persistence_key="current", source="test", finding_type="email", value="a", confidence=1, severity="info")
        historical = Finding(investigation_id=inv.id, execution_id="exec-1", execution_attempt_id="attempt-a", persistence_key="historical", source="test", finding_type="email", value="b", confidence=1, severity="info")
        db.add_all([current, historical]); db.commit()
        from app.api.routes import finding_projection
        assert finding_projection(current, "attempt-b")["current_attempt"] is True
        assert finding_projection(historical, "attempt-b")["current_attempt"] is False
        assert finding_projection(historical, "attempt-b")["historical_attempt"] is True


@pytest.mark.asyncio
async def test_public_provider_transport_validates_at_connection_boundary(monkeypatch):
    calls = []
    async def fake_connect(self, host, port, timeout=None, local_address=None, socket_options=None):
        calls.append((host, port))
        raise RuntimeError("stop before network")
    monkeypatch.setattr(network._PinnedBackend, "connect_tcp", fake_connect)
    transport = network.pinned_transport("https://example.com/resource")
    assert transport is not None
    assert calls == []


def test_public_provider_transport_rejects_unsafe_scheme_or_userinfo():
    with pytest.raises(ValueError): network.pinned_transport("http://example.com/")
    with pytest.raises(ValueError): network.pinned_transport("https://user:pass@example.com/")


@pytest.mark.asyncio
async def test_external_provider_disclosure_false_returns_explicit_disabled_results():
    results = await orchestrator.run_providers("user@example.com", "example.com", ["user"], allow_external=False)
    assert [r.status for r in results] == ["disabled", "disabled", "disabled", "disabled"]
    assert all("disclosure disabled" in (r.message or "") for r in results)


def test_privacy_mode_contract_still_strips_raw_reference(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db, privacy_mode=True, external_provider_disclosure=True)
        token = claim_investigation(db, inv.id)
        orchestrator.add_findings(db, inv.id, [dict(source="test", finding_type="domain_event", value="registration", confidence=.9, severity="info", raw_reference={"secret":"payload"})], token)
        stored = db.scalar(select(Finding).where(Finding.investigation_id == inv.id))
        assert stored.raw_reference is None

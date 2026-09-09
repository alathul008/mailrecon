import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, delete, event, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import Base, engine as app_engine
from app.models import Finding, GraphEdge, GraphNode, Investigation, ModuleRun
from app.services import lifecycle
from app.services.orchestrator import mark_investigation_failed


def make_engine(tmp_path):
    db_engine = create_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}")
    event.listen(db_engine, "connect", lambda dbapi_connection, _: dbapi_connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(db_engine)
    return db_engine


def add_investigation(db, status="queued", heartbeat=None):
    inv = Investigation(
        target="test@example.com",
        normalized_email="test@example.com",
        username="test",
        domain="example.com",
        status=status,
        execution_heartbeat_at=heartbeat,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def test_queued_running_completed_lifecycle(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        current = db.get(Investigation, inv.id)
        assert current.status == "running"
        assert current.execution_token == token
        assert lifecycle.execution_is_owned(db, inv.id, token)
        db.execute(
            update(Investigation)
            .where(Investigation.id == inv.id, Investigation.execution_token == token)
            .values(status="completed", completed_at=datetime.now(timezone.utc), execution_token=None, execution_heartbeat_at=None)
        )
        db.commit()
        assert db.get(Investigation, inv.id).status == "completed"
        assert lifecycle.claim_investigation(db, inv.id) is None


def test_failed_investigation_is_terminal(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        db.execute(
            update(Investigation)
            .where(Investigation.id == inv.id, Investigation.execution_token == token)
            .values(status="failed", execution_token=None, execution_heartbeat_at=None)
        )
        db.commit()
        assert lifecycle.claim_investigation(db, inv.id) is None
        assert db.get(Investigation, inv.id).status == "failed"


def test_queued_work_is_recoverable_after_restart(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db, status="queued")
        assert lifecycle.recover_stale_investigations(db) == 0
        assert db.get(Investigation, inv.id).status == "queued"
        assert lifecycle.claim_investigation(db, inv.id)


def test_stale_running_work_is_requeued_deterministically(tmp_path):
    db_engine = make_engine(tmp_path)
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    old = now - timedelta(seconds=get_settings().execution_lease_seconds + 1)
    with Session(db_engine) as db:
        inv = add_investigation(db, status="running", heartbeat=old)
        inv.execution_token = "old-token"
        inv.execution_started_at = old
        db.commit()
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        recovered = db.get(Investigation, inv.id)
        assert recovered.status == "queued"
        assert recovered.execution_token is None
        assert recovered.execution_started_at is None
        assert recovered.execution_heartbeat_at is None


def test_legacy_running_work_without_heartbeat_is_recoverable(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db, status="running")
        inv.execution_token = None
        inv.execution_started_at = None
        inv.execution_heartbeat_at = None
        db.commit()
        assert lifecycle.recover_stale_investigations(db) == 1
        assert db.get(Investigation, inv.id).status == "queued"


def test_only_one_executor_can_claim(tmp_path):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)
    with SessionLocal() as first, SessionLocal() as second:
        inv = add_investigation(first)
        token1 = lifecycle.claim_investigation(first, inv.id)
        token2 = lifecycle.claim_investigation(second, inv.id)
        assert token1
        assert token2 is None
        assert first.get(Investigation, inv.id).execution_token == token1


@pytest.mark.asyncio
async def test_configured_concurrency_is_respected(tmp_path, monkeypatch):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)
    monkeypatch.setattr(lifecycle, "SessionLocal", SessionLocal)
    settings = get_settings()
    old_max = settings.max_concurrency
    old_poll = settings.worker_poll_interval_seconds
    settings.max_concurrency = 2
    settings.worker_poll_interval_seconds = 0.01
    with Session(db_engine) as db:
        for _ in range(5):
            add_investigation(db)

    active = 0
    peak = 0
    completed = 0

    async def fake_run(inv_id, token):
        nonlocal active, peak, completed
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.04)
        active -= 1
        completed += 1

    monkeypatch.setattr("app.services.orchestrator.run_investigation", fake_run)
    stop = asyncio.Event()
    worker = asyncio.create_task(lifecycle.worker_loop(stop))
    try:
        for _ in range(100):
            if completed == 5:
                break
            await asyncio.sleep(0.01)
    finally:
        stop.set()
        await worker
        settings.max_concurrency = old_max
        settings.worker_poll_interval_seconds = old_poll

    assert completed == 5
    assert peak <= 2


def test_delete_queued_investigation(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        db.add_all([
            Finding(investigation_id=inv.id, source="test", finding_type="email", value=inv.target, confidence=1, severity="info"),
            ModuleRun(investigation_id=inv.id, module="email_validation", status="queued"),
        ])
        db.commit()
        db.delete(inv)
        db.commit()
        assert db.get(Investigation, inv.id) is None
        assert db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all() == []
        assert db.scalars(select(ModuleRun).where(ModuleRun.investigation_id == inv.id)).all() == []


def test_delete_running_invalidates_worker_ownership(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        db.delete(inv)
        db.commit()
        assert lifecycle.execution_is_owned(db, inv.id, token) is False


def test_worker_delete_race_is_fenced_by_execution_token(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        db.execute(delete(Investigation).where(Investigation.id == inv.id))
        db.commit()
        assert lifecycle.execution_is_owned(db, inv.id, token) is False


def test_sqlite_foreign_keys_are_enabled_for_application_engine():
    with app_engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_delete_cascades_all_investigation_children(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        db.add_all([
            Finding(investigation_id=inv.id, source="test", finding_type="email", value=inv.target, confidence=1, severity="info"),
            ModuleRun(investigation_id=inv.id, module="email_validation", status="completed"),
            GraphNode(investigation_id=inv.id, node_key="email:test@example.com", node_type="EMAIL", label=inv.target),
            GraphEdge(investigation_id=inv.id, source="email:test@example.com", target="domain:example.com", relation="uses", confidence=1),
        ])
        db.commit()
        db.delete(inv)
        db.commit()
        assert db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all() == []
        assert db.scalars(select(ModuleRun).where(ModuleRun.investigation_id == inv.id)).all() == []
        assert db.scalars(select(GraphNode).where(GraphNode.investigation_id == inv.id)).all() == []
        assert db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == inv.id)).all() == []


def test_completed_modules_remain_completed_after_later_failure(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        completed = ModuleRun(investigation_id=inv.id, module="email_validation", status="completed", message="Validated")
        running = ModuleRun(investigation_id=inv.id, module="risk_calculation", status="running")
        queued = ModuleRun(investigation_id=inv.id, module="graph_build", status="queued")
        db.add_all([completed, running, queued])
        db.commit()
        assert mark_investigation_failed(db, inv.id, token, RuntimeError("late failure"))
        assert db.get(ModuleRun, completed.id).status == "completed"
        assert db.get(ModuleRun, running.id).status == "failed"
        assert db.get(ModuleRun, queued.id).status == "skipped"
        assert db.get(Investigation, inv.id).status == "failed"


def test_stale_attempt_modules_are_abandoned_without_losing_provenance(tmp_path):
    db_engine = make_engine(tmp_path)
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    old = now - timedelta(seconds=get_settings().execution_lease_seconds + 1)
    with Session(db_engine) as db:
        inv = add_investigation(db, status="queued")
        first_token = lifecycle.claim_investigation(db, inv.id, now=old)
        current = db.get(Investigation, inv.id)
        first_execution_id = current.execution_id
        first_attempt_id = current.execution_attempt_id
        running = ModuleRun(
            investigation_id=inv.id,
            execution_id=first_execution_id,
            execution_attempt_id=first_attempt_id,
            module="rdap",
            status="running",
            message="started",
            started_at=old,
        )
        queued = ModuleRun(
            investigation_id=inv.id,
            execution_id=first_execution_id,
            execution_attempt_id=first_attempt_id,
            module="graph_build",
            status="queued",
        )
        completed = ModuleRun(
            investigation_id=inv.id,
            execution_id=first_execution_id,
            execution_attempt_id=first_attempt_id,
            module="email_validation",
            status="completed",
            message="done",
            started_at=old,
            finished_at=old + timedelta(seconds=1),
        )
        other_attempt = ModuleRun(
            investigation_id=inv.id,
            execution_id=first_execution_id,
            execution_attempt_id="other-attempt",
            module="dns_analysis",
            status="running",
        )
        db.add_all([running, queued, completed, other_attempt])
        db.commit()

        assert first_token
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        recovered = db.get(Investigation, inv.id)
        assert recovered.status == "queued"
        assert recovered.execution_token is None
        assert recovered.execution_attempt_id == first_attempt_id
        assert db.get(ModuleRun, running.id).status == "abandoned"
        assert db.get(ModuleRun, queued.id).status == "abandoned"
        assert db.get(ModuleRun, completed.id).status == "completed"
        assert db.get(ModuleRun, running.id).execution_id == first_execution_id
        assert db.get(ModuleRun, running.id).execution_attempt_id == first_attempt_id
        assert db.get(ModuleRun, running.id).started_at.replace(tzinfo=timezone.utc) == old
        assert db.get(ModuleRun, other_attempt.id).status == "running"

        second_token = lifecycle.claim_investigation(db, inv.id, now=now + timedelta(seconds=1))
        second = db.get(Investigation, inv.id)
        assert second_token
        assert second.execution_id == first_execution_id
        assert second.execution_attempt_id
        assert second.execution_attempt_id != first_attempt_id


def test_repeated_stale_recovery_abandons_only_current_attempt(tmp_path):
    db_engine = make_engine(tmp_path)
    lease = get_settings().execution_lease_seconds
    with Session(db_engine) as db:
        t0 = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=t0)
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        run_a = ModuleRun(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id=attempt_a, module="rdap", status="running", started_at=t0)
        db.add(run_a)
        db.commit()
        assert token_a

        assert lifecycle.recover_stale_investigations(db, now=t0 + timedelta(seconds=lease + 1)) == 1
        assert db.get(ModuleRun, run_a.id).status == "abandoned"

        token_b = lifecycle.claim_investigation(db, inv.id, now=t0 + timedelta(seconds=lease + 2))
        attempt_b = db.get(Investigation, inv.id).execution_attempt_id
        run_b = ModuleRun(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id=attempt_b, module="rdap", status="running")
        db.add(run_b)
        db.commit()
        assert token_b
        assert attempt_b != attempt_a

        assert lifecycle.recover_stale_investigations(db, now=t0 + timedelta(seconds=2 * lease + 3)) == 1
        assert db.get(ModuleRun, run_a.id).status == "abandoned"
        assert db.get(ModuleRun, run_b.id).status == "abandoned"

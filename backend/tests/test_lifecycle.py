import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import Base, engine as app_engine
from app.models import Finding, GraphEdge, GraphNode, Investigation, ModuleRun
from app.services import lifecycle


def make_engine(tmp_path):
    db_engine = create_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}")
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
            __import__("sqlalchemy").update(Investigation)
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
            __import__("sqlalchemy").update(Investigation)
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
        db.execute(
            __import__("sqlalchemy").delete(Investigation).where(Investigation.id == inv.id)
        )
        db.commit()
        assert lifecycle.execution_is_owned(db, inv.id, token) is False


def test_sqlite_foreign_keys_are_enabled_for_application_engine():
    with app_engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_delete_cascades_all_investigation_children(tmp_path):
    db_engine = make_engine(tmp_path)
    event.listen(db_engine, "connect", lambda dbapi_connection, _: dbapi_connection.execute("PRAGMA foreign_keys=ON"))
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

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.session import Base, get_db
from app.main import app
from app.models import ExecutionAttempt, Finding, GraphEdge, GraphNode, Investigation, ModuleRun
from app.services.deletion import delete_investigation


def make_engine(tmp_path):
    db_engine = create_engine(f"sqlite:///{tmp_path / 'phase17.db'}", connect_args={"check_same_thread": False})
    event.listen(db_engine, "connect", lambda dbapi_connection, _: dbapi_connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(db_engine)
    return db_engine


def add_investigation(db, *, status="queued"):
    inv = Investigation(
        target="test@example.com",
        normalized_email="test@example.com",
        username="test",
        domain="example.com",
        status=status,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def add_complete_aggregate(db, inv):
    attempt = ExecutionAttempt(
        investigation_id=inv.id,
        execution_id=inv.execution_id,
        execution_attempt_id=f"attempt-{inv.id}",
        status="completed",
    )
    db.add(attempt)
    db.flush()
    db.add_all([
        Finding(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id=attempt.execution_attempt_id,
            source="test",
            finding_type="email",
            value=inv.target,
            confidence=1,
            severity="info",
        ),
        ModuleRun(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id=attempt.execution_attempt_id,
            module="email_validation",
            status="completed",
        ),
        GraphNode(
            investigation_id=inv.id,
            node_key=f"email:{inv.target}",
            node_type="EMAIL",
            label=inv.target,
        ),
        GraphNode(
            investigation_id=inv.id,
            node_key="domain:example.com",
            node_type="DOMAIN",
            label="example.com",
        ),
        GraphEdge(
            investigation_id=inv.id,
            source=f"email:{inv.target}",
            target="domain:example.com",
            relation="uses",
            confidence=1,
        ),
    ])
    db.commit()
    return attempt


def test_delete_investigation_requires_authentication(tmp_path):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)

    def override_get_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        settings = get_settings()
        original = settings.api_key
        settings.api_key = "test-secret-key"
        try:
            with SessionLocal() as db:
                inv = add_investigation(db)
            with TestClient(app) as client:
                assert client.delete(f"/api/investigations/{inv.id}").status_code == 401
                response = client.delete(
                    f"/api/investigations/{inv.id}",
                    headers={"Authorization": "Bearer test-secret-key"},
                )
            assert response.status_code == 200
            assert response.json() == {"id": inv.id, "status": "deleted"}
        finally:
            settings.api_key = original
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_delete_complete_aggregate_and_preserve_other_investigation(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        first = add_investigation(db)
        second = add_investigation(db)
        add_complete_aggregate(db, first)
        add_complete_aggregate(db, second)
        first_id = first.id
        second_id = second.id

        assert delete_investigation(db, first_id) is True

        assert db.get(Investigation, first_id) is None
        assert db.scalars(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == first_id)).all() == []
        assert db.scalars(select(ModuleRun).where(ModuleRun.investigation_id == first_id)).all() == []
        assert db.scalars(select(Finding).where(Finding.investigation_id == first_id)).all() == []
        assert db.scalars(select(GraphNode).where(GraphNode.investigation_id == first_id)).all() == []
        assert db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == first_id)).all() == []
        assert db.get(Investigation, second_id) is not None
        assert db.scalars(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == second_id)).all()
        assert db.scalars(select(Finding).where(Finding.investigation_id == second_id)).all()
        assert db.scalars(select(GraphNode).where(GraphNode.investigation_id == second_id)).all()
        assert db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == second_id)).all()


def test_delete_nonexistent_and_repeated_delete_are_deterministic(tmp_path):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        assert delete_investigation(db, inv.id + 999999) is False
        assert db.get(Investigation, inv.id) is not None
        assert delete_investigation(db, inv.id) is True
        assert delete_investigation(db, inv.id) is False


def test_delete_rolls_back_on_commit_failure(tmp_path, monkeypatch):
    db_engine = make_engine(tmp_path)
    with Session(db_engine) as db:
        inv = add_investigation(db)
        inv_id = inv.id

        original_commit = db.commit
        rollback_called = False
        original_rollback = db.rollback

        def failing_commit():
            raise RuntimeError("injected commit failure")

        def tracking_rollback():
            nonlocal rollback_called
            rollback_called = True
            return original_rollback()

        monkeypatch.setattr(db, "commit", failing_commit)
        monkeypatch.setattr(db, "rollback", tracking_rollback)
        with pytest.raises(RuntimeError, match="injected commit failure"):
            delete_investigation(db, inv_id)
        assert rollback_called is True
        monkeypatch.setattr(db, "commit", original_commit)
        assert db.get(Investigation, inv_id) is not None


def test_active_worker_cannot_persist_after_investigation_deletion(tmp_path):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)
    ready = threading.Event()
    deleted = threading.Event()

    with SessionLocal() as db:
        inv = add_investigation(db, status="running")
        inv.execution_token = "worker-token"
        db.commit()
        inv_id = inv.id

    def worker_attempts_late_write():
        with SessionLocal() as worker_db:
            worker_db.get(Investigation, inv_id)
            ready.set()
            assert deleted.wait(timeout=2)
            worker_db.add(
                Finding(
                    investigation_id=inv_id,
                    execution_id="worker-execution",
                    source="worker",
                    finding_type="late_write",
                    value="must fail",
                    confidence=1,
                    severity="info",
                )
            )
            with pytest.raises(IntegrityError):
                worker_db.commit()
            worker_db.rollback()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(worker_attempts_late_write)
        assert ready.wait(timeout=2)
        with SessionLocal() as delete_db:
            assert delete_investigation(delete_db, inv_id) is True
        deleted.set()
        future.result(timeout=5)

    with SessionLocal() as db:
        assert db.get(Investigation, inv_id) is None
        assert db.scalars(select(Finding).where(Finding.investigation_id == inv_id)).all() == []


def test_read_delete_race_does_not_recreate_investigation(tmp_path):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)
    ready = threading.Event()
    deleted = threading.Event()

    with SessionLocal() as db:
        inv = add_investigation(db)
        inv_id = inv.id

    def reader():
        with SessionLocal() as reader_db:
            assert reader_db.get(Investigation, inv_id) is not None
            ready.set()
            assert deleted.wait(timeout=2)
            assert reader_db.get(Investigation, inv_id) is None

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(reader)
        assert ready.wait(timeout=2)
        with SessionLocal() as delete_db:
            assert delete_investigation(delete_db, inv_id) is True
        deleted.set()
        future.result(timeout=5)

    with SessionLocal() as db:
        assert db.get(Investigation, inv_id) is None


def test_deletion_endpoint_returns_404_without_disclosing_missing_investigation(tmp_path):
    db_engine = make_engine(tmp_path)
    SessionLocal = sessionmaker(db_engine, expire_on_commit=False, class_=Session)

    def override_get_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        settings = get_settings()
        original = settings.api_key
        settings.api_key = "test-secret-key"
        try:
            with TestClient(app) as client:
                response = client.delete(
                    "/api/investigations/999999",
                    headers={"Authorization": "Bearer test-secret-key"},
                )
            assert response.status_code == 404
            assert response.json() == {"detail": "Investigation not found"}
        finally:
            settings.api_key = original
    finally:
        app.dependency_overrides.pop(get_db, None)

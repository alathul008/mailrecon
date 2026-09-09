from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import ExecutionAttempt, GraphEdge, GraphNode, Investigation
from app.schemas.schemas import InvestigationCreate


def migration_config(db_path):
    cfg = Config()
    cfg.set_main_option("script_location", "backend/alembic")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def make_db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'phase16.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


def add_inv(db):
    inv = Investigation(
        target="test@example.com",
        normalized_email="test@example.com",
        username="test",
        domain="example.com",
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def test_new_investigation_disclosure_defaults_false_and_opt_in_is_preserved():
    default = InvestigationCreate(email="test@example.com")
    explicit = InvestigationCreate(email="test@example.com", external_provider_disclosure=True)
    assert default.external_provider_disclosure is False
    assert explicit.external_provider_disclosure is True

    model_default = Investigation(
        target="default@example.com",
        normalized_email="default@example.com",
        username="default",
        domain="example.com",
    )
    model_opt_in = Investigation(
        target="optin@example.com",
        normalized_email="optin@example.com",
        username="optin",
        domain="example.com",
        external_provider_disclosure=True,
    )
    assert model_default.external_provider_disclosure is False
    assert model_opt_in.external_provider_disclosure is True


def test_phase16_migration_adds_investigation_current_attempt_fk(tmp_path):
    db_path = tmp_path / "valid.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "0007")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    inspector = inspect(engine)
    fks = {fk["name"]: fk for fk in inspector.get_foreign_keys("investigations")}
    fk = fks["fk_investigations_execution_attempt_investigation"]
    assert fk["referred_table"] == "execution_attempts"
    assert tuple(fk["constrained_columns"]) == ("id", "execution_attempt_id")
    assert tuple(fk["referred_columns"]) == ("investigation_id", "execution_attempt_id")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0008"


def test_phase16_migration_refuses_invalid_current_attempt_reference(tmp_path):
    db_path = tmp_path / "ambiguous.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "0007")
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO investigations (target, normalized_email, username, domain, status, privacy_mode, external_provider_disclosure, created_at, execution_id, execution_attempt_id) "
            "VALUES ('one@example.com', 'one@example.com', 'one', 'example.com', 'running', 0, 0, CURRENT_TIMESTAMP, 'exec-one', 'attempt-two')"
        ))
        conn.execute(text(
            "INSERT INTO investigations (target, normalized_email, username, domain, status, privacy_mode, external_provider_disclosure, created_at, execution_id, execution_attempt_id) "
            "VALUES ('two@example.com', 'two@example.com', 'two', 'example.com', 'queued', 0, 0, CURRENT_TIMESTAMP, 'exec-two', NULL)"
        ))
        inv_two = conn.execute(text("SELECT id FROM investigations WHERE execution_id='exec-two'")).scalar_one()
        conn.execute(text(
            "INSERT INTO execution_attempts (investigation_id, execution_id, execution_attempt_id, status, started_at) "
            "VALUES (:inv, 'exec-two', 'attempt-two', 'completed', CURRENT_TIMESTAMP)"
        ), {"inv": inv_two})

    with pytest.raises(RuntimeError, match="does not belong to that investigation"):
        command.upgrade(cfg, "head")

    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0007"


def test_phase16_current_attempt_fk_rejects_cross_investigation_reference(tmp_path):
    db_path = tmp_path / "runtime.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_path}")

    with Session(engine) as db:
        first = add_inv(db)
        second = add_inv(db)
        attempt = ExecutionAttempt(
            investigation_id=second.id,
            execution_id=second.execution_id,
            execution_attempt_id="attempt-second",
            status="running",
        )
        db.add(attempt)
        db.commit()
        first.execution_attempt_id = "attempt-second"
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_phase16_current_attempt_fk_allows_belonging_attempt_and_preserves_history(tmp_path):
    db_path = tmp_path / "valid-runtime.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_path}")

    with Session(engine) as db:
        inv = add_inv(db)
        attempt_one = ExecutionAttempt(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id="attempt-one",
            status="abandoned",
        )
        attempt_two = ExecutionAttempt(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id="attempt-two",
            status="running",
        )
        db.add_all([attempt_one, attempt_two])
        db.flush()
        inv.execution_attempt_id = attempt_two.execution_attempt_id
        db.commit()
        db.refresh(inv)
        assert inv.execution_attempt_id == "attempt-two"
        assert {x.execution_attempt_id for x in db.scalars(select(ExecutionAttempt)).all()} == {"attempt-one", "attempt-two"}


def test_phase16_current_attempt_fk_allows_existing_delete_cycle(tmp_path):
    db_path = tmp_path / "delete-runtime.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_path}")

    with Session(engine) as db:
        inv = add_inv(db)
        attempt = ExecutionAttempt(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id="attempt-delete",
            status="completed",
        )
        db.add(attempt)
        db.flush()
        inv.execution_attempt_id = attempt.execution_attempt_id
        db.commit()
        db.execute(text("DELETE FROM investigations WHERE id=:id"), {"id": inv.id})
        db.commit()
        assert db.scalar(select(Investigation).where(Investigation.id == inv.id)) is None
        assert db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.id == attempt.id)) is None


def test_phase16_graph_database_failure_preserves_previous_graph(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        db.add_all([
            GraphNode(investigation_id=inv.id, node_key="email:test@example.com", node_type="EMAIL", label="test@example.com"),
            GraphNode(investigation_id=inv.id, node_key="domain:example.com", node_type="DOMAIN", label="example.com"),
            GraphEdge(investigation_id=inv.id, source="email:test@example.com", target="domain:example.com", relation="uses", confidence=1.0),
        ])
        db.commit()

        try:
            db.query(GraphEdge).filter(GraphEdge.investigation_id == inv.id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id == inv.id).delete(synchronize_session=False)
            db.add(GraphNode(investigation_id=inv.id, node_key="email:new@example.com", node_type="EMAIL", label="new@example.com"))
            db.add(GraphNode(investigation_id=inv.id, node_key="email:new@example.com", node_type="EMAIL", label="duplicate"))
            db.flush()
            pytest.fail("graph rebuild should have failed on duplicate identity")
        except IntegrityError:
            db.rollback()

        assert db.scalars(select(GraphNode).where(GraphNode.investigation_id == inv.id)).all()[0].node_key == "email:test@example.com"
        assert db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == inv.id)).all()[0].relation == "uses"


def test_phase16_graph_non_database_failure_rolls_back_previous_graph(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        db.add_all([
            GraphNode(investigation_id=inv.id, node_key="email:test@example.com", node_type="EMAIL", label="test@example.com"),
            GraphEdge(investigation_id=inv.id, source="email:test@example.com", target="domain:example.com", relation="uses", confidence=1.0),
        ])
        db.commit()

        try:
            db.query(GraphEdge).filter(GraphEdge.investigation_id == inv.id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id == inv.id).delete(synchronize_session=False)
            db.add(GraphNode(investigation_id=inv.id, node_key="email:new@example.com", node_type="EMAIL", label="new@example.com"))
            db.flush()
            raise ValueError("deterministic graph-build failure")
        except ValueError:
            db.rollback()

        nodes = db.scalars(select(GraphNode).where(GraphNode.investigation_id == inv.id)).all()
        edges = db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == inv.id)).all()
        assert [(n.node_key, n.label) for n in nodes] == [("email:test@example.com", "test@example.com")]
        assert [(e.source, e.target, e.relation) for e in edges] == [("email:test@example.com", "domain:example.com", "uses")]


def test_phase16_hash_lock_is_integrity_enforced():
    lock = Path("backend/requirements.lock").read_text(encoding="utf-8")
    assert "--require-hashes" in lock
    assert lock.count("--hash=sha256:") >= lock.count("==")


def test_phase16_documentation_describes_secure_disclosure_default():
    docs = Path("docs/provider-disclosure.md").read_text(encoding="utf-8")
    assert "`false` (default)" in docs
    assert "explicit per-investigation opt-in" in docs
    assert "Existing persisted investigations retain their stored disclosure setting" in docs

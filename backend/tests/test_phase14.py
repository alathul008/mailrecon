from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


def migration_config(db_path):
    cfg = Config()
    cfg.set_main_option("script_location", "backend/alembic")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_phase14_migration_adds_attempt_scoped_foreign_keys(tmp_path):
    db_path = tmp_path / "valid.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "0006")

    command.upgrade(cfg, "head")
    engine = create_engine(f"sqlite:///{db_path}")
    inspector = inspect(engine)
    assert "fk_findings_execution_attempt_investigation" in {
        fk["name"] for fk in inspector.get_foreign_keys("findings")
    }
    assert "fk_module_runs_execution_attempt_investigation" in {
        fk["name"] for fk in inspector.get_foreign_keys("module_runs")
    }
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0007"


def test_phase14_migration_refuses_cross_investigation_attempt_reference(tmp_path):
    db_path = tmp_path / "ambiguous.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "0006")
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO investigations (target, normalized_email, username, domain, status, privacy_mode, external_provider_disclosure, created_at, execution_id) "
            "VALUES ('one@example.com', 'one@example.com', 'one', 'example.com', 'queued', 0, 1, CURRENT_TIMESTAMP, 'exec-one')"
        ))
        conn.execute(text(
            "INSERT INTO investigations (target, normalized_email, username, domain, status, privacy_mode, external_provider_disclosure, created_at, execution_id) "
            "VALUES ('two@example.com', 'two@example.com', 'two', 'example.com', 'queued', 0, 1, CURRENT_TIMESTAMP, 'exec-two')"
        ))
        inv_one = conn.execute(text("SELECT id FROM investigations WHERE execution_id='exec-one'")).scalar_one()
        inv_two = conn.execute(text("SELECT id FROM investigations WHERE execution_id='exec-two'")).scalar_one()
        conn.execute(text(
            "INSERT INTO execution_attempts (investigation_id, execution_id, execution_attempt_id, status, started_at) "
            "VALUES (:inv, 'exec-two', 'attempt-two', 'completed', CURRENT_TIMESTAMP)"
        ), {"inv": inv_two})
        conn.execute(text(
            "INSERT INTO findings (investigation_id, execution_id, execution_attempt_id, source, finding_type, value, confidence, severity, collected_at) "
            "VALUES (:inv, 'exec-one', 'attempt-two', 'test', 'provenance', 'ambiguous', 1.0, 'info', CURRENT_TIMESTAMP)"
        ), {"inv": inv_one})

    with pytest.raises(RuntimeError, match="does not belong to the referenced investigation"):
        command.upgrade(cfg, "head")

    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0006"


def test_phase14_browser_key_lifecycle_uses_session_storage_only():
    api_source = Path("frontend/src/services/api.ts").read_text()
    security_source = Path("SECURITY.md").read_text()
    assert "window.sessionStorage" in api_source
    assert "window.localStorage" not in api_source
    assert "Rotation" in security_source
    assert "restart" in security_source


def test_phase14_runtime_image_removes_installation_tooling():
    dockerfile = Path("Dockerfile").read_text()
    assert "pip uninstall -y pip setuptools" in dockerfile
    assert "requirements.lock" in dockerfile
    assert "pip install --no-cache-dir --requirement requirements.lock" in dockerfile


def test_phase14_claim_guard_is_present():
    lifecycle = Path("backend/app/services/lifecycle.py").read_text()
    assert "queued ModuleRun with ambiguous execution-attempt provenance" in lifecycle
    assert "left a queued ModuleRun without execution-attempt provenance" in lifecycle

import pytest
from alembic import command
from alembic.config import Config
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.api.routes import csv_safe, create
from app.core.config import get_settings
from app.db.session import Base
from app.schemas.schemas import InvestigationCreate
from app.services import schema


def migration_config(db_path):
    cfg = Config()
    cfg.set_main_option("script_location", "backend/alembic")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_csv_safe_neutralizes_formula_prefixes():
    for value in ["=1+1", "+1+1", "-1+1", "@SUM(A1)", "\t=1+1", "\n+1+1"]:
        assert csv_safe(value).startswith("'")
    assert csv_safe("ordinary evidence") == "ordinary evidence"
    assert csv_safe(None) is None


@pytest.mark.asyncio
async def test_investigation_queue_depth_is_enforced(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'queue.db'}")
    Base.metadata.create_all(engine)
    settings = get_settings()
    old_limit = settings.max_queue_depth
    settings.max_queue_depth = 1
    try:
        with Session(engine) as db:
            first = await create(InvestigationCreate(email="one@example.com"), db)
            assert first["status"] == "queued"
            with pytest.raises(HTTPException) as exc:
                await create(InvestigationCreate(email="two@example.com"), db)
            assert exc.value.status_code == 429
    finally:
        settings.max_queue_depth = old_limit


def test_runtime_schema_bootstrap_reaches_head_and_detects_physical_drift(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'schema.db'}")
    monkeypatch.setattr(schema, "engine", engine)
    settings = get_settings()
    old_url = settings.database_url
    settings.database_url = f"sqlite:///{tmp_path / 'schema.db'}"
    try:
        schema.ensure_schema()
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0003"

        with engine.begin() as conn:
            conn.execute(text("DROP INDEX ix_investigations_execution_attempt_id"))
            conn.execute(text("ALTER TABLE investigations DROP COLUMN execution_attempt_id"))

        with pytest.raises(RuntimeError, match="columns diverge"):
            schema.ensure_schema()
    finally:
        settings.database_url = old_url


def test_runtime_schema_rejects_missing_execution_integrity_index(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'index-drift.db'}")
    monkeypatch.setattr(schema, "engine", engine)
    settings = get_settings()
    old_url = settings.database_url
    settings.database_url = f"sqlite:///{tmp_path / 'index-drift.db'}"
    try:
        schema.ensure_schema()
        with engine.begin() as conn:
            conn.execute(text("DROP INDEX uq_module_runs_attempt_module"))

        with engine.connect() as conn:
            assert "execution_attempt_id" in {
                column["name"] for column in schema.inspect(engine).get_columns("module_runs")
            }

        with pytest.raises(RuntimeError, match="execution indexes diverge"):
            schema.ensure_schema()
    finally:
        settings.database_url = old_url


def test_runtime_schema_bootstraps_unversioned_phase6_database(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    cfg = migration_config(db_path)
    command.upgrade(cfg, "0002")
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE alembic_version"))

    monkeypatch.setattr(schema, "engine", engine)
    settings = get_settings()
    old_url = settings.database_url
    settings.database_url = f"sqlite:///{db_path}"
    try:
        schema.ensure_schema()
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == "0003"
    finally:
        settings.database_url = old_url

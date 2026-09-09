from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from app.core.config import get_settings
from app.db.session import engine, Base
from app.models import models  # noqa: F401


LEGACY_TABLES = {"investigations", "findings", "module_runs", "graph_nodes", "graph_edges"}


def _config() -> Config:
    root = Path(__file__).resolve().parents[3]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "backend" / "alembic"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    return cfg


def _current_heads() -> set[str]:
    with engine.connect() as connection:
        return set(MigrationContext.configure(connection).get_current_heads())


def _heads(cfg: Config) -> set[str]:
    return set(ScriptDirectory.from_config(cfg).get_heads())


def _infer_unversioned_revision() -> str:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names()) - {"alembic_version"}
    if not tables:
        return "base"
    if tables != LEGACY_TABLES:
        raise RuntimeError("Unversioned database has an unknown table layout; refusing automatic schema mutation")

    investigation_columns = {c["name"] for c in inspector.get_columns("investigations")}
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    module_columns = {c["name"] for c in inspector.get_columns("module_runs")}

    if {"execution_id", "execution_attempt_id"} <= investigation_columns and {"execution_id", "execution_attempt_id", "persistence_key"} <= finding_columns and {"execution_id", "execution_attempt_id"} <= module_columns:
        return "0003"
    if {"execution_token", "execution_started_at", "execution_heartbeat_at"} <= investigation_columns:
        return "0002"
    return "0001"


def _validate_physical_schema() -> None:
    inspector = inspect(engine)
    actual_tables = set(inspector.get_table_names()) - {"alembic_version"}
    expected_tables = set(Base.metadata.tables)
    if actual_tables != expected_tables:
        raise RuntimeError(f"Database tables diverge from ORM metadata: expected {sorted(expected_tables)}, got {sorted(actual_tables)}")
    for table_name, table in Base.metadata.tables.items():
        actual_columns = {c["name"] for c in inspector.get_columns(table_name)}
        expected_columns = set(table.columns.keys())
        if actual_columns != expected_columns:
            raise RuntimeError(f"Database columns diverge for {table_name}: expected {sorted(expected_columns)}, got {sorted(actual_columns)}")


def ensure_schema() -> None:
    cfg = _config()
    current = _current_heads()
    heads = _heads(cfg)

    if not current:
        inferred = _infer_unversioned_revision()
        if inferred != "base":
            command.stamp(cfg, inferred)
        command.upgrade(cfg, "head")
    elif current != heads:
        command.upgrade(cfg, "head")

    final_heads = _current_heads()
    if final_heads != heads:
        raise RuntimeError(f"Database migration state is not at Alembic head: expected {sorted(heads)}, got {sorted(final_heads)}")
    _validate_physical_schema()

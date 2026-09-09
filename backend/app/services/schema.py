from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from app.core.config import get_settings
from app.db.session import engine, Base
from app.models import models  # noqa: F401

LEGACY_TABLES = {"investigations", "findings", "module_runs", "graph_nodes", "graph_edges"}

REQUIRED_EXECUTION_INDEXES = {
    "ix_investigations_execution_token": ("investigations", ("execution_token",), False),
    "ix_investigations_execution_heartbeat_at": ("investigations", ("execution_heartbeat_at",), False),
    "uq_investigations_execution_id": ("investigations", ("execution_id",), True),
    "uq_findings_execution_persistence": ("findings", ("investigation_id", "execution_id", "persistence_key"), True),
    "uq_module_runs_attempt_module": ("module_runs", ("investigation_id", "execution_attempt_id", "module"), True),
    "ix_investigations_execution_attempt_id": ("investigations", ("execution_attempt_id",), False),
    "ix_findings_execution_id": ("findings", ("execution_id",), False),
    "ix_findings_execution_attempt_id": ("findings", ("execution_attempt_id",), False),
    "ix_module_runs_execution_id": ("module_runs", ("execution_id",), False),
    "ix_module_runs_execution_attempt_id": ("module_runs", ("execution_attempt_id",), False),
}

REQUIRED_EXECUTION_FOREIGN_KEYS = {
    "investigations": {"fk_investigations_execution_attempt_investigation": ("execution_attempts", ("id", "execution_attempt_id"), ("investigation_id", "execution_attempt_id"))},
    "findings": {"fk_findings_execution_attempt_investigation": ("execution_attempts", ("investigation_id", "execution_attempt_id"), ("investigation_id", "execution_attempt_id"))},
    "module_runs": {"fk_module_runs_execution_attempt_investigation": ("execution_attempts", ("investigation_id", "execution_attempt_id"), ("investigation_id", "execution_attempt_id"))},
}

SQLITE_INVESTIGATION_ATTEMPT_TRIGGERS = {
    "trg_investigations_current_attempt_guard_insert",
    "trg_investigations_current_attempt_guard_update",
    "trg_execution_attempts_current_investigation_guard_delete",
}

REQUIRED_GRAPH_UNIQUENESS = {
    "graph_nodes": {"uq_graph_nodes_investigation_node_key": ("investigation_id", "node_key")},
    "graph_edges": {"uq_graph_edges_investigation_identity": ("investigation_id", "source", "target", "relation")},
}


def _config() -> Config:
    cfg = Config(); cfg.set_main_option("script_location", str(Path(__file__).resolve().parents[2] / "alembic")); cfg.set_main_option("sqlalchemy.url", get_settings().database_url); return cfg

def _current_heads() -> set[str]:
    with engine.connect() as connection: return set(MigrationContext.configure(connection).get_current_heads())

def _heads(cfg: Config) -> set[str]: return set(ScriptDirectory.from_config(cfg).get_heads())

def _infer_unversioned_revision() -> str:
    inspector = inspect(engine); tables = set(inspector.get_table_names()) - {"alembic_version"}
    if not tables: return "base"
    if tables != LEGACY_TABLES: raise RuntimeError("Unversioned database has an unknown table layout; refusing automatic schema mutation")
    investigation_columns = {c["name"] for c in inspector.get_columns("investigations")}; finding_columns = {c["name"] for c in inspector.get_columns("findings")}; module_columns = {c["name"] for c in inspector.get_columns("module_runs")}
    if {"execution_id", "execution_attempt_id"} <= investigation_columns and {"execution_id", "execution_attempt_id", "persistence_key"} <= finding_columns and {"execution_id", "execution_attempt_id"} <= module_columns: return "0003"
    if {"execution_token", "execution_started_at", "execution_heartbeat_at"} <= investigation_columns: return "0002"
    return "0001"

def _validate_physical_schema() -> None:
    inspector = inspect(engine); dialect_name = engine.dialect.name; actual_tables = set(inspector.get_table_names()) - {"alembic_version"}; expected_tables = set(Base.metadata.tables)
    if actual_tables != expected_tables: raise RuntimeError(f"Database tables diverge from ORM metadata: expected {sorted(expected_tables)}, got {sorted(actual_tables)}")
    for table_name, table in Base.metadata.tables.items():
        actual_columns = {c["name"] for c in inspector.get_columns(table_name)}; expected_columns = set(table.columns.keys())
        if actual_columns != expected_columns: raise RuntimeError(f"Database columns diverge for {table_name}: expected {sorted(expected_columns)}, got {sorted(actual_columns)}")
    indexes_by_table = {table_name: {index["name"]: index for index in inspector.get_indexes(table_name)} for table_name in expected_tables}
    missing_or_drifted = []
    for index_name, (table_name, expected_columns, expected_unique) in REQUIRED_EXECUTION_INDEXES.items():
        actual = indexes_by_table[table_name].get(index_name)
        if actual is None or tuple(actual["column_names"]) != expected_columns or bool(actual.get("unique", False)) != expected_unique: missing_or_drifted.append(index_name)
    if missing_or_drifted: raise RuntimeError(f"Database execution indexes diverge from Alembic contract: {sorted(missing_or_drifted)}")
    foreign_key_drift = []
    for table_name, constraints in REQUIRED_EXECUTION_FOREIGN_KEYS.items():
        actual = {fk["name"]: (fk["referred_table"], tuple(fk["constrained_columns"]), tuple(fk["referred_columns"])) for fk in inspector.get_foreign_keys(table_name)}
        for name, expected in constraints.items():
            if dialect_name == "sqlite" and table_name == "investigations": continue
            if actual.get(name) != expected: foreign_key_drift.append(name)
    if foreign_key_drift: raise RuntimeError(f"Database execution foreign keys diverge from Alembic contract: {sorted(foreign_key_drift)}")
    if dialect_name == "sqlite":
        with engine.connect() as connection:
            actual_triggers = {row[0] for row in connection.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'"))}
        missing_triggers = SQLITE_INVESTIGATION_ATTEMPT_TRIGGERS - actual_triggers
        if missing_triggers: raise RuntimeError(f"Database SQLite execution-attempt guards diverge from Alembic contract: {sorted(missing_triggers)}")
    graph_constraints = {table: {item["name"]: tuple(item["column_names"]) for item in inspect(engine).get_unique_constraints(table)} for table in REQUIRED_GRAPH_UNIQUENESS}
    graph_drift = []
    for table_name, constraints in REQUIRED_GRAPH_UNIQUENESS.items():
        for name, columns in constraints.items():
            if graph_constraints[table_name].get(name) != columns: graph_drift.append(name)
    if graph_drift: raise RuntimeError(f"Database graph uniqueness constraints diverge from Alembic contract: {sorted(graph_drift)}")

def ensure_schema() -> None:
    cfg = _config(); current = _current_heads(); heads = _heads(cfg)
    if not current:
        inferred = _infer_unversioned_revision()
        if inferred != "base": command.stamp(cfg, inferred)
        command.upgrade(cfg, "head")
    elif current != heads: command.upgrade(cfg, "head")
    final_heads = _current_heads()
    if final_heads != heads: raise RuntimeError(f"Database migration state is not at Alembic head: expected {sorted(heads)}, got {sorted(final_heads)}")
    _validate_physical_schema()

from sqlalchemy import create_engine, inspect, text
from alembic import command
from alembic.config import Config


def migration_config(db_path):
    cfg = Config("alembic.ini")
    cfg.config_file_name = None
    cfg.set_main_option("script_location", "backend/alembic")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def test_phase7_migration_upgrades_legacy_schema_and_downgrades_cleanly(tmp_path):
    db_path = tmp_path / "migration.db"
    cfg = migration_config(db_path)

    command.upgrade(cfg, "0001")
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO investigations (target, normalized_email, username, domain, status, privacy_mode, created_at) VALUES ('legacy@example.com', 'legacy@example.com', 'legacy', 'example.com', 'queued', 0, CURRENT_TIMESTAMP)"))
        investigation_id = conn.execute(text("SELECT id FROM investigations")).scalar_one()
        conn.execute(text("INSERT INTO findings (investigation_id, source, finding_type, value, confidence, severity, collected_at) VALUES (:id, 'legacy', 'email', 'legacy@example.com', 1.0, 'info', CURRENT_TIMESTAMP)"), {"id": investigation_id})
        conn.execute(text("INSERT INTO module_runs (investigation_id, module, status) VALUES (:id, 'email_validation', 'queued')"), {"id": investigation_id})

    command.upgrade(cfg, "head")
    inspector = inspect(engine)
    investigation_columns = {c["name"] for c in inspector.get_columns("investigations")}
    finding_columns = {c["name"] for c in inspector.get_columns("findings")}
    module_columns = {c["name"] for c in inspector.get_columns("module_runs")}
    assert "execution_id" in investigation_columns
    assert {"execution_id", "persistence_key"} <= finding_columns
    assert "execution_id" in module_columns
    with engine.connect() as conn:
        execution_id = conn.execute(text("SELECT execution_id FROM investigations WHERE id=:id"), {"id": investigation_id}).scalar_one()
        assert execution_id
        assert conn.execute(text("SELECT execution_id FROM findings WHERE investigation_id=:id"), {"id": investigation_id}).scalar_one() == execution_id
        assert conn.execute(text("SELECT execution_id FROM module_runs WHERE investigation_id=:id"), {"id": investigation_id}).scalar_one() == execution_id
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert version == "0003"

    command.downgrade(cfg, "0002")
    inspector = inspect(engine)
    assert "execution_id" not in {c["name"] for c in inspector.get_columns("investigations")}
    assert "execution_id" not in {c["name"] for c in inspector.get_columns("module_runs")}
    assert "persistence_key" not in {c["name"] for c in inspector.get_columns("findings")}

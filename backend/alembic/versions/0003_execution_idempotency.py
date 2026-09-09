from alembic import op
import sqlalchemy as sa
import uuid

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("investigations", sa.Column("execution_id", sa.String(36), nullable=True))
    op.add_column("findings", sa.Column("execution_id", sa.String(36), nullable=True))
    op.add_column("findings", sa.Column("persistence_key", sa.String(64), nullable=True))
    op.add_column("module_runs", sa.Column("execution_id", sa.String(36), nullable=True))

    conn = op.get_bind()
    investigations = conn.execute(sa.text("SELECT id FROM investigations WHERE execution_id IS NULL")).fetchall()
    for row in investigations:
        execution_id = str(uuid.uuid4())
        conn.execute(sa.text("UPDATE investigations SET execution_id=:execution_id WHERE id=:id"), {"execution_id": execution_id, "id": row.id})

    conn.execute(sa.text("UPDATE findings SET execution_id=(SELECT execution_id FROM investigations WHERE investigations.id=findings.investigation_id) WHERE execution_id IS NULL"))
    conn.execute(sa.text("UPDATE module_runs SET execution_id=(SELECT execution_id FROM investigations WHERE investigations.id=module_runs.investigation_id) WHERE execution_id IS NULL"))

    op.create_unique_constraint("uq_investigations_execution_id", "investigations", ["execution_id"])
    op.create_unique_constraint("uq_findings_execution_persistence", "findings", ["investigation_id", "execution_id", "persistence_key"])
    op.create_unique_constraint("uq_module_runs_execution_module", "module_runs", ["investigation_id", "execution_id", "module"])
    op.create_index("ix_findings_execution_id", "findings", ["execution_id"])
    op.create_index("ix_module_runs_execution_id", "module_runs", ["execution_id"])


def downgrade():
    op.drop_index("ix_module_runs_execution_id", table_name="module_runs")
    op.drop_index("ix_findings_execution_id", table_name="findings")
    op.drop_constraint("uq_module_runs_execution_module", "module_runs", type_="unique")
    op.drop_constraint("uq_findings_execution_persistence", "findings", type_="unique")
    op.drop_constraint("uq_investigations_execution_id", "investigations", type_="unique")
    op.drop_column("module_runs", "execution_id")
    op.drop_column("findings", "persistence_key")
    op.drop_column("findings", "execution_id")
    op.drop_column("investigations", "execution_id")

from alembic import op
import sqlalchemy as sa
import uuid
from datetime import datetime, timezone

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _now():
    return datetime.now(timezone.utc)


def upgrade():
    op.create_table(
        "execution_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("investigation_id", sa.Integer(), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("execution_id", sa.String(36), nullable=False),
        sa.Column("execution_attempt_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_reason", sa.String(500), nullable=True),
        sa.UniqueConstraint("investigation_id", "execution_attempt_id", name="uq_execution_attempt_identity"),
        sa.UniqueConstraint("execution_attempt_id", name="uq_execution_attempt_id"),
    )
    op.create_index("ix_execution_attempts_investigation_id", "execution_attempts", ["investigation_id"])
    op.create_index("ix_execution_attempts_execution_id", "execution_attempts", ["execution_id"])
    op.create_index("ix_execution_attempts_execution_attempt_id", "execution_attempts", ["execution_attempt_id"])

    bind = op.get_bind()
    investigations = bind.execute(sa.text("SELECT id, execution_id, execution_attempt_id, status, execution_started_at, completed_at FROM investigations"))
    rows = list(investigations)
    for inv_id, execution_id, current_attempt, inv_status, started_at, completed_at in rows:
        if not execution_id:
            execution_id = str(uuid.uuid4())
            bind.execute(sa.text("UPDATE investigations SET execution_id=:execution_id WHERE id=:id"), {"execution_id": execution_id, "id": inv_id})
        attempt_ids = set()
        if current_attempt:
            attempt_ids.add(current_attempt)
        for table in ("module_runs", "findings"):
            result = bind.execute(sa.text(f"SELECT DISTINCT execution_attempt_id FROM {table} WHERE investigation_id=:id AND execution_attempt_id IS NOT NULL"), {"id": inv_id})
            attempt_ids.update(r[0] for r in result if r[0])
        for attempt_id in sorted(attempt_ids):
            is_current = attempt_id == current_attempt
            if is_current:
                status = "running" if inv_status == "running" else "completed" if inv_status == "completed" else "failed" if inv_status == "failed" else "abandoned"
                finished = completed_at if status in {"completed", "failed", "abandoned"} else None
                recovered = None
            else:
                status = "abandoned"
                finished = None
                recovered = None
            bind.execute(sa.text("""
                INSERT INTO execution_attempts
                (investigation_id, execution_id, execution_attempt_id, status, started_at, finished_at, recovered_at, recovery_reason)
                VALUES (:investigation_id, :execution_id, :attempt_id, :status, :started_at, :finished_at, :recovered_at, :reason)
            """), {
                "investigation_id": inv_id,
                "execution_id": execution_id,
                "attempt_id": attempt_id,
                "status": status,
                "started_at": started_at or _now(),
                "finished_at": finished,
                "recovered_at": recovered,
                "reason": "Historical attempt reconstructed during migration" if not is_current else None,
            })

    op.add_column("investigations", sa.Column("external_provider_disclosure", sa.Boolean(), nullable=True, server_default=sa.true()))
    bind.execute(sa.text("UPDATE investigations SET external_provider_disclosure = 1 WHERE external_provider_disclosure IS NULL"))
    with op.batch_alter_table("investigations") as batch:
        batch.alter_column("external_provider_disclosure", nullable=False, server_default=None)


def downgrade():
    op.drop_column("investigations", "external_provider_disclosure")
    op.drop_index("ix_execution_attempts_execution_attempt_id", table_name="execution_attempts")
    op.drop_index("ix_execution_attempts_execution_id", table_name="execution_attempts")
    op.drop_index("ix_execution_attempts_investigation_id", table_name="execution_attempts")
    op.drop_table("execution_attempts")

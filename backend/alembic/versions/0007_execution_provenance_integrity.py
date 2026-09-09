from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def _validate_attempt_references(bind):
    checks = (
        ("investigations", "current attempt", "i.id", "i.execution_attempt_id", "i.execution_id"),
        ("findings", "finding", "f.investigation_id", "f.execution_attempt_id", "f.execution_id"),
        ("module_runs", "module run", "m.investigation_id", "m.execution_attempt_id", "m.execution_id"),
    )
    for table, label, investigation_column, attempt_column, execution_column in checks:
        rows = bind.execute(
            sa.text(
                f"""
                SELECT {investigation_column}, {attempt_column}, {execution_column}
                FROM {table} AS {table[0]}
                LEFT JOIN execution_attempts AS ea
                  ON ea.investigation_id = {investigation_column}
                 AND ea.execution_attempt_id = {attempt_column}
                WHERE {attempt_column} IS NOT NULL
                  AND ea.id IS NULL
                ORDER BY {investigation_column}, {attempt_column}
                """
            )
        ).fetchall()
        if rows:
            raise RuntimeError(
                f"Ambiguous {label} provenance: execution_attempt_id does not belong to the referenced investigation; "
                f"rows={rows[:5]!r}"
            )

        mismatch_rows = bind.execute(
            sa.text(
                f"""
                SELECT {investigation_column}, {attempt_column}, {execution_column}, ea.execution_id
                FROM {table} AS {table[0]}
                JOIN execution_attempts AS ea
                  ON ea.investigation_id = {investigation_column}
                 AND ea.execution_attempt_id = {attempt_column}
                WHERE {attempt_column} IS NOT NULL
                  AND {execution_column} IS NOT NULL
                  AND {execution_column} != ea.execution_id
                ORDER BY {investigation_column}, {attempt_column}
                """
            )
        ).fetchall()
        if mismatch_rows:
            raise RuntimeError(
                f"Ambiguous {label} provenance: execution_id conflicts with execution attempt; "
                f"rows={mismatch_rows[:5]!r}"
            )


def upgrade():
    bind = op.get_bind()
    _validate_attempt_references(bind)

    with op.batch_alter_table("findings") as batch:
        batch.create_foreign_key(
            "fk_findings_execution_attempt_investigation",
            "execution_attempts",
            ["investigation_id", "execution_attempt_id"],
            ["investigation_id", "execution_attempt_id"],
        )

    with op.batch_alter_table("module_runs") as batch:
        batch.create_foreign_key(
            "fk_module_runs_execution_attempt_investigation",
            "execution_attempts",
            ["investigation_id", "execution_attempt_id"],
            ["investigation_id", "execution_attempt_id"],
        )


def downgrade():
    with op.batch_alter_table("module_runs") as batch:
        batch.drop_constraint("fk_module_runs_execution_attempt_investigation", type_="foreignkey")
    with op.batch_alter_table("findings") as batch:
        batch.drop_constraint("fk_findings_execution_attempt_investigation", type_="foreignkey")

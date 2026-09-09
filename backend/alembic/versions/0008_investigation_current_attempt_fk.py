from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

CONSTRAINT_NAME = "fk_investigations_execution_attempt_investigation"


def _validate_current_attempt_references(bind):
    rows = bind.execute(
        sa.text(
            """
            SELECT i.id, i.execution_attempt_id, i.execution_id
            FROM investigations AS i
            LEFT JOIN execution_attempts AS ea
              ON ea.investigation_id = i.id
             AND ea.execution_attempt_id = i.execution_attempt_id
            WHERE i.execution_attempt_id IS NOT NULL
              AND ea.id IS NULL
            ORDER BY i.id, i.execution_attempt_id
            """
        )
    ).fetchall()
    if rows:
        raise RuntimeError(
            "Ambiguous current-attempt provenance: investigation execution_attempt_id "
            f"does not belong to that investigation; rows={rows[:5]!r}"
        )

    mismatch_rows = bind.execute(
        sa.text(
            """
            SELECT i.id, i.execution_attempt_id, i.execution_id, ea.execution_id
            FROM investigations AS i
            JOIN execution_attempts AS ea
              ON ea.investigation_id = i.id
             AND ea.execution_attempt_id = i.execution_attempt_id
            WHERE i.execution_attempt_id IS NOT NULL
              AND i.execution_id IS NOT NULL
              AND i.execution_id != ea.execution_id
            ORDER BY i.id, i.execution_attempt_id
            """
        )
    ).fetchall()
    if mismatch_rows:
        raise RuntimeError(
            "Ambiguous current-attempt provenance: investigation execution_id "
            f"conflicts with its execution attempt; rows={mismatch_rows[:5]!r}"
        )


def upgrade():
    bind = op.get_bind()
    _validate_current_attempt_references(bind)
    constraint = sa.ForeignKeyConstraint(
        ["id", "execution_attempt_id"],
        ["execution_attempts.investigation_id", "execution_attempts.execution_attempt_id"],
        name=CONSTRAINT_NAME,
        deferrable=True,
        initially="DEFERRED",
    )

    if bind.dialect.name == "sqlite":
        # SQLite cannot ALTER TABLE to add a constraint. Recreate only this
        # table, after preflight has proved all existing references valid.
        # PRAGMA foreign_keys is intentionally left under Alembic's migration
        # connection; batch mode requires referential enforcement to be off
        # while the old table is replaced.
        with op.batch_alter_table(
            "investigations",
            recreate="always",
            table_args=(constraint,),
        ):
            pass
    else:
        op.create_foreign_key(
            CONSTRAINT_NAME,
            "investigations",
            "execution_attempts",
            ["id", "execution_attempt_id"],
            ["investigation_id", "execution_attempt_id"],
            deferrable=True,
            initially="DEFERRED",
        )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("investigations") as batch:
            batch.drop_constraint(CONSTRAINT_NAME, type="foreignkey")
    else:
        op.drop_constraint(CONSTRAINT_NAME, "investigations", type_="foreignkey")

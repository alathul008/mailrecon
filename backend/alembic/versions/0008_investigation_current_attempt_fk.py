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

    if bind.dialect.name == "sqlite":
        metadata = sa.MetaData()
        investigations = sa.Table("investigations", metadata, autoload_with=bind)
        execution_attempts = sa.Table("execution_attempts", metadata, autoload_with=bind)
        investigations.append_constraint(
            sa.ForeignKeyConstraint(
                ["id", "execution_attempt_id"],
                [
                    execution_attempts.c.investigation_id,
                    execution_attempts.c.execution_attempt_id,
                ],
                name=CONSTRAINT_NAME,
            )
        )
        with op.batch_alter_table(
            "investigations",
            recreate="always",
            copy_from=investigations,
        ):
            pass
    else:
        op.create_foreign_key(
            CONSTRAINT_NAME,
            "investigations",
            "execution_attempts",
            ["id", "execution_attempt_id"],
            ["investigation_id", "execution_attempt_id"],
        )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        metadata = sa.MetaData()
        investigations = sa.Table("investigations", metadata, autoload_with=bind)
        fk = next(
            constraint
            for constraint in investigations.constraints
            if isinstance(constraint, sa.ForeignKeyConstraint)
            and [element.target_fullname for element in constraint.elements]
            == ["execution_attempts.investigation_id", "execution_attempts.execution_attempt_id"]
        )
        investigations.constraints.remove(fk)
        with op.batch_alter_table(
            "investigations",
            recreate="always",
            copy_from=investigations,
        ):
            pass
    else:
        op.drop_constraint(CONSTRAINT_NAME, "investigations", type_="foreignkey")

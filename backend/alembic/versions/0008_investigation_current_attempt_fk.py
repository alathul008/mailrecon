from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

CONSTRAINT_NAME = "fk_investigations_execution_attempt_investigation"
SQLITE_GUARD_INSERT = "trg_investigations_current_attempt_guard_insert"
SQLITE_GUARD_UPDATE = "trg_investigations_current_attempt_guard_update"
SQLITE_GUARD_DELETE = "trg_execution_attempts_current_investigation_guard_delete"


def _validate_current_attempt_references(bind):
    rows = bind.execute(sa.text("""
        SELECT i.id, i.execution_attempt_id, i.execution_id
        FROM investigations AS i
        LEFT JOIN execution_attempts AS ea
          ON ea.investigation_id = i.id
         AND ea.execution_attempt_id = i.execution_attempt_id
        WHERE i.execution_attempt_id IS NOT NULL
          AND ea.id IS NULL
        ORDER BY i.id, i.execution_attempt_id
    """)).fetchall()
    if rows:
        raise RuntimeError(
            "Ambiguous current-attempt provenance: investigation execution_attempt_id "
            f"does not belong to that investigation; rows={rows[:5]!r}"
        )

    mismatch_rows = bind.execute(sa.text("""
        SELECT i.id, i.execution_attempt_id, i.execution_id, ea.execution_id
        FROM investigations AS i
        JOIN execution_attempts AS ea
          ON ea.investigation_id = i.id
         AND ea.execution_attempt_id = i.execution_attempt_id
        WHERE i.execution_attempt_id IS NOT NULL
          AND i.execution_id IS NOT NULL
          AND i.execution_id != ea.execution_id
        ORDER BY i.id, i.execution_attempt_id
    """)).fetchall()
    if mismatch_rows:
        raise RuntimeError(
            "Ambiguous current-attempt provenance: investigation execution_id "
            f"conflicts with its execution attempt; rows={mismatch_rows[:5]!r}"
        )


def upgrade():
    bind = op.get_bind()
    _validate_current_attempt_references(bind)

    if bind.dialect.name == "sqlite":
        # SQLite batch recreation cannot safely add this circular composite
        # relationship to existing databases. Triggers enforce the same
        # investigation-scoped invariant without rewriting the table.
        op.execute(sa.text(f"""
            CREATE TRIGGER {SQLITE_GUARD_INSERT}
            BEFORE INSERT ON investigations
            WHEN NEW.execution_attempt_id IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'investigation current execution attempt does not belong to investigation')
                WHERE NOT EXISTS (
                    SELECT 1 FROM execution_attempts
                    WHERE investigation_id = NEW.id
                      AND execution_attempt_id = NEW.execution_attempt_id
                );
                SELECT RAISE(ABORT, 'investigation execution_id does not match current execution attempt')
                WHERE EXISTS (
                    SELECT 1 FROM execution_attempts
                    WHERE investigation_id = NEW.id
                      AND execution_attempt_id = NEW.execution_attempt_id
                      AND NEW.execution_id IS NOT NULL
                      AND execution_id != NEW.execution_id
                );
            END
        """))
        op.execute(sa.text(f"""
            CREATE TRIGGER {SQLITE_GUARD_UPDATE}
            BEFORE UPDATE OF execution_attempt_id, execution_id ON investigations
            WHEN NEW.execution_attempt_id IS NOT NULL
            BEGIN
                SELECT RAISE(ABORT, 'investigation current execution attempt does not belong to investigation')
                WHERE NOT EXISTS (
                    SELECT 1 FROM execution_attempts
                    WHERE investigation_id = NEW.id
                      AND execution_attempt_id = NEW.execution_attempt_id
                );
                SELECT RAISE(ABORT, 'investigation execution_id does not match current execution attempt')
                WHERE EXISTS (
                    SELECT 1 FROM execution_attempts
                    WHERE investigation_id = NEW.id
                      AND execution_attempt_id = NEW.execution_attempt_id
                      AND NEW.execution_id IS NOT NULL
                      AND execution_id != NEW.execution_id
                );
            END
        """))
        op.execute(sa.text(f"""
            CREATE TRIGGER {SQLITE_GUARD_DELETE}
            BEFORE DELETE ON execution_attempts
            WHEN EXISTS (
                SELECT 1 FROM investigations
                WHERE id = OLD.investigation_id
                  AND execution_attempt_id = OLD.execution_attempt_id
            )
            BEGIN
                SELECT RAISE(ABORT, 'cannot delete current execution attempt');
            END
        """))
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
        for trigger_name in (SQLITE_GUARD_DELETE, SQLITE_GUARD_UPDATE, SQLITE_GUARD_INSERT):
            op.execute(sa.text(f"DROP TRIGGER IF EXISTS {trigger_name}"))
    else:
        op.drop_constraint(CONSTRAINT_NAME, "investigations", type_="foreignkey")

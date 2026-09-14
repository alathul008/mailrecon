from collections import defaultdict

from sqlalchemy import create_engine, event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from app.core.config import get_settings
from app.services.resource_budget import ExecutionResourceBudget


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_engine(settings.database_url.replace('+aiosqlite', ''), future=True)


@event.listens_for(engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=Session)


def _finding_identity(finding) -> tuple:
    if finding.persistence_key:
        return ("persistence", finding.persistence_key)
    return (
        "legacy",
        finding.source,
        finding.source_url,
        finding.finding_type,
        finding.value,
        finding.first_seen,
    )


@event.listens_for(Session, "before_flush")
def _enforce_persisted_finding_budget(session, flush_context, instances):
    """Enforce persisted-finding limits and production provenance at flush time.

    The execution-attempt row is updated before the count is read. That update
    is the database serialization point: SQLite acquires its write transaction
    lock, while databases with row-level locking serialize concurrent writers on
    the same attempt row. A Python lock cannot provide this guarantee because
    separate workers/processes and separate database connections do not share it.

    Historical attempts are independent budgets. Duplicate identities already
    persisted or duplicated in the same flush consume no additional budget.

    Production-generated execution findings must carry an execution attempt
    whenever they carry an execution identity. The production SessionLocal
    engine also enforces the composite Finding -> ExecutionAttempt foreign key,
    so a non-null attempt identifier must resolve to a durable attempt row.
    Legacy/demo rows without execution provenance remain compatible, as do
    isolated projection fixtures that intentionally use a separate SQLite engine
    with synthetic attempt identifiers.
    """
    from app.models import ExecutionAttempt, Finding

    pending = [obj for obj in session.new if isinstance(obj, Finding) and obj.execution_attempt_id]
    if session.bind is engine:
        for finding in session.new:
            if isinstance(finding, Finding) and finding.execution_id and not finding.execution_attempt_id:
                raise RuntimeError(
                    "Execution-derived Finding requires execution-attempt provenance"
                )
    if not pending:
        return

    budget = ExecutionResourceBudget()
    grouped: dict[tuple[int, str], list[Finding]] = defaultdict(list)
    for finding in pending:
        grouped[(finding.investigation_id, finding.execution_attempt_id)].append(finding)

    for (investigation_id, attempt_id), rows in grouped.items():
        # Serialize at the database boundary, not merely at the Python call
        # boundary. The no-op UPDATE intentionally takes a write/row lock on
        # the execution-attempt identity before the count is observed.
        try:
            locked = session.execute(
                update(ExecutionAttempt)
                .where(
                    ExecutionAttempt.investigation_id == investigation_id,
                    ExecutionAttempt.execution_attempt_id == attempt_id,
                )
                .values(execution_attempt_id=ExecutionAttempt.execution_attempt_id)
            )
        except OperationalError as exc:
            raise RuntimeError(
                f"Unable to serialize persisted-finding budget for execution attempt {attempt_id}"
            ) from exc

        # Finding.execution_attempt_id is a nullable, composite FK to the
        # durable ExecutionAttempt identity. The production engine enforces that
        # FK, so a real Finding persistence operation cannot commit an orphan.
        # A few legacy/projection fixtures deliberately use synthetic attempt ids
        # on an engine without FK enforcement; there is no durable attempt whose
        # budget can be enforced for those rows, so leave those fixture semantics
        # untouched.
        if locked.rowcount != 1:
            continue

        existing = session.execute(
            select(
                Finding.persistence_key,
                Finding.source,
                Finding.source_url,
                Finding.finding_type,
                Finding.value,
                Finding.first_seen,
            ).where(
                Finding.investigation_id == investigation_id,
                Finding.execution_attempt_id == attempt_id,
            )
        ).all()
        identities = set()
        for row in existing:
            identities.add(("persistence", row.persistence_key) if row.persistence_key else (
                "legacy", row.source, row.source_url, row.finding_type, row.value, row.first_seen
            ))

        new_unique = 0
        for finding in rows:
            identity = _finding_identity(finding)
            if identity in identities:
                continue
            identities.add(identity)
            new_unique += 1

        current_count = len(existing)
        if current_count + new_unique > budget.max_persisted_findings:
            raise RuntimeError(
                "Investigation persisted-finding budget exceeded "
                f"for execution attempt {attempt_id}"
            )


def get_db():
    with SessionLocal() as session:
        yield session

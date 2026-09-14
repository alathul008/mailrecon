from collections import defaultdict
from threading import Lock

from sqlalchemy import create_engine, event, func, select
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
_FINDING_BUDGET_LOCK = Lock()


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
    """Enforce the per-attempt persisted-finding limit at the real flush boundary.

    The lock serializes concurrent sessions in the current single-process local
    deployment while the transaction contains the count-and-insert operation.
    Historical attempts are independent budgets. Duplicate identities already
    persisted or duplicated in the same flush consume no additional budget.
    """
    from app.models import Finding

    pending = [obj for obj in session.new if isinstance(obj, Finding) and obj.execution_attempt_id]
    if not pending:
        return

    budget = ExecutionResourceBudget()
    grouped: dict[tuple[int, str], list[Finding]] = defaultdict(list)
    for finding in pending:
        grouped[(finding.investigation_id, finding.execution_attempt_id)].append(finding)

    with _FINDING_BUDGET_LOCK:
        for (investigation_id, attempt_id), rows in grouped.items():
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

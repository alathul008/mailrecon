import asyncio
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select, update

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import Investigation, ModuleRun


def utcnow():
    return datetime.now(timezone.utc)


def _stale_before(now: datetime) -> datetime:
    return now - timedelta(seconds=get_settings().execution_lease_seconds)


def recover_stale_investigations(db, *, now=None) -> int:
    now = now or utcnow()
    stale_before = _stale_before(now)
    result = db.execute(
        update(Investigation)
        .where(
            Investigation.status == "running",
            or_(
                Investigation.execution_heartbeat_at.is_(None),
                Investigation.execution_heartbeat_at < stale_before,
            ),
        )
        .values(
            status="queued",
            execution_token=None,
            execution_started_at=None,
            execution_heartbeat_at=None,
            completed_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return result.rowcount


def claim_investigation(db, inv_id: int, *, now=None) -> str | None:
    now = now or utcnow()
    token = secrets.token_hex(24)
    stale_before = _stale_before(now)
    generated_execution_id = str(uuid.uuid4())
    generated_attempt_id = str(uuid.uuid4())
    result = db.execute(
        update(Investigation)
        .where(
            Investigation.id == inv_id,
            or_(
                Investigation.status == "queued",
                and_(
                    Investigation.status == "running",
                    or_(
                        Investigation.execution_heartbeat_at.is_(None),
                        Investigation.execution_heartbeat_at < stale_before,
                    ),
                ),
            ),
        )
        .values(
            status="running",
            execution_id=func.coalesce(Investigation.execution_id, generated_execution_id),
            execution_attempt_id=generated_attempt_id,
            execution_token=token,
            execution_started_at=now,
            execution_heartbeat_at=now,
            completed_at=None,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        return None

    inv = db.get(Investigation, inv_id)
    if not inv:
        db.rollback()
        raise RuntimeError("Investigation claim disappeared")
    db.refresh(inv)
    if not inv.execution_id:
        db.rollback()
        raise RuntimeError("Investigation claim has no durable logical execution identity")
    if not inv.execution_attempt_id:
        db.rollback()
        raise RuntimeError("Investigation claim has incomplete execution-attempt provenance")

    # API-created queued module rows intentionally have no worker attempt yet.
    # Bind those rows to this claim atomically so the first worker updates the
    # existing queue records instead of creating duplicate attempt rows. Rows
    # from an earlier attempt remain untouched during stale recovery.
    db.execute(
        update(ModuleRun)
        .where(
            ModuleRun.investigation_id == inv_id,
            ModuleRun.execution_attempt_id.is_(None),
        )
        .values(
            execution_id=inv.execution_id,
            execution_attempt_id=inv.execution_attempt_id,
        )
    )
    db.commit()
    return token


def fence_execution(db, inv_id: int, token: str) -> tuple[str, str]:
    """Acquire the investigation row lock and fence the worker token atomically.

    The ownership check and subsequent persistence must share one database
    transaction. A successful conditional UPDATE locks the investigation row
    until the caller commits, so stale recovery cannot reclaim the row between
    validation and mutation.
    """
    result = db.execute(
        update(Investigation)
        .where(
            Investigation.id == inv_id,
            Investigation.status == "running",
            Investigation.execution_token == token,
        )
        .values(execution_heartbeat_at=utcnow())
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        db.rollback()
        raise RuntimeError("Investigation execution lease is no longer owned")

    row = db.execute(
        select(Investigation.execution_id, Investigation.execution_attempt_id)
        .where(Investigation.id == inv_id)
    ).one_or_none()
    if row is None:
        db.rollback()
        raise RuntimeError("Investigation execution lease disappeared")
    execution_id, execution_attempt_id = row
    if not execution_id or not execution_attempt_id:
        db.rollback()
        raise RuntimeError("Investigation has incomplete execution provenance")
    return execution_id, execution_attempt_id


def heartbeat_investigation(db, inv_id: int, token: str, *, now=None) -> bool:
    now = now or utcnow()
    result = db.execute(
        update(Investigation)
        .where(
            Investigation.id == inv_id,
            Investigation.status == "running",
            Investigation.execution_token == token,
        )
        .values(execution_heartbeat_at=now)
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return result.rowcount == 1


def execution_is_owned(db, inv_id: int, token: str) -> bool:
    return db.scalar(
        select(Investigation.id).where(
            Investigation.id == inv_id,
            Investigation.status == "running",
            Investigation.execution_token == token,
        )
    ) is not None


def _queued_ids(db, limit: int) -> list[int]:
    return list(
        db.scalars(
            select(Investigation.id)
            .where(Investigation.status == "queued")
            .order_by(Investigation.created_at.asc(), Investigation.id.asc())
            .limit(limit)
        )
    )


async def worker_loop(stop_event: asyncio.Event):
    settings = get_settings()
    active: set[asyncio.Task] = set()

    async def execute(inv_id: int, token: str):
        from app.services.orchestrator import run_investigation
        await run_investigation(inv_id, token)

    while not stop_event.is_set():
        with SessionLocal() as db:
            recover_stale_investigations(db)
            available = max(0, settings.max_concurrency - len(active))
            candidates = _queued_ids(db, available) if available else []
            claimed = []
            for inv_id in candidates:
                token = claim_investigation(db, inv_id)
                if token:
                    claimed.append((inv_id, token))

        for inv_id, token in claimed:
            task = asyncio.create_task(execute(inv_id, token))
            active.add(task)
            task.add_done_callback(active.discard)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=settings.worker_poll_interval_seconds)
        except asyncio.TimeoutError:
            pass

    if active:
        await asyncio.gather(*active, return_exceptions=True)

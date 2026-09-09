import asyncio
import secrets
import uuid
from datetime import datetime,timedelta,timezone
from sqlalchemy import and_,func,or_,select,update
from app.core.config import get_settings
from app.db.session import SessionLocal
from app.models import Investigation,ExecutionAttempt,ModuleRun

def utcnow():return datetime.now(timezone.utc)
def _as_utc(value):
    if value is None:return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
def _stale_before(now):return now-timedelta(seconds=get_settings().execution_lease_seconds)
def _mark_attempt_abandoned(db,inv_id,attempt_id,*,now=None,reason="Execution lease expired"):
    now=now or utcnow();db.execute(update(ExecutionAttempt).where(ExecutionAttempt.investigation_id==inv_id,ExecutionAttempt.execution_attempt_id==attempt_id,ExecutionAttempt.status=="running").values(status="abandoned",finished_at=now,recovered_at=now,recovery_reason=reason));db.execute(update(ModuleRun).where(ModuleRun.investigation_id==inv_id,ModuleRun.execution_attempt_id==attempt_id,ModuleRun.status.in_(("queued","running"))).values(status="abandoned",finished_at=now).execution_options(synchronize_session=False))
def finish_execution_attempt(db,inv_id,attempt_id,status,*,now=None,reason=None):
    if status not in {"completed","failed"}:raise ValueError("ExecutionAttempt terminal status must be completed or failed")
    now=now or utcnow();r=db.execute(update(ExecutionAttempt).where(ExecutionAttempt.investigation_id==inv_id,ExecutionAttempt.execution_attempt_id==attempt_id,ExecutionAttempt.status=="running").values(status=status,finished_at=now,recovery_reason=reason).execution_options(synchronize_session=False));return r.rowcount==1
def recover_stale_investigations(db,*,now=None):
    now=now or utcnow();cutoff=_stale_before(now);stale=db.execute(select(Investigation.id,Investigation.execution_attempt_id).where(Investigation.status=="running",or_(Investigation.execution_heartbeat_at.is_(None),Investigation.execution_heartbeat_at<cutoff))).all();recovered=0
    for inv_id,attempt_id in stale:
        r=db.execute(update(Investigation).where(Investigation.id==inv_id,Investigation.status=="running",or_(Investigation.execution_heartbeat_at.is_(None),Investigation.execution_heartbeat_at<cutoff)).values(status="queued",execution_token=None,execution_started_at=None,execution_heartbeat_at=None,completed_at=None).execution_options(synchronize_session=False))
        if r.rowcount!=1:continue
        if attempt_id:_mark_attempt_abandoned(db,inv_id,attempt_id,now=now)
        recovered+=1
    db.commit();return recovered
def _create_attempt(db,inv_id,execution_id,attempt_id,*,now,status="running"):db.add(ExecutionAttempt(investigation_id=inv_id,execution_id=execution_id,execution_attempt_id=attempt_id,status=status,started_at=now))
def claim_investigation(db,inv_id,*,now=None):
    now=now or utcnow();token=secrets.token_hex(24);cutoff=_stale_before(now);generated_execution_id=str(uuid.uuid4());generated_attempt_id=str(uuid.uuid4());current=db.execute(select(Investigation.execution_id,Investigation.execution_attempt_id,Investigation.status,Investigation.execution_heartbeat_at).where(Investigation.id==inv_id)).one_or_none()
    if current is None:return None
    old_execution_id,old_attempt_id,old_status,old_heartbeat=current;old_heartbeat=_as_utc(old_heartbeat);stale_claim=old_status=="running" and (old_heartbeat is None or old_heartbeat<cutoff)
    r=db.execute(update(Investigation).where(Investigation.id==inv_id,or_(Investigation.status=="queued",and_(Investigation.status=="running",or_(Investigation.execution_heartbeat_at.is_(None),Investigation.execution_heartbeat_at<cutoff)))).values(status="running",execution_id=func.coalesce(Investigation.execution_id,generated_execution_id),execution_attempt_id=generated_attempt_id,execution_token=token,execution_started_at=now,execution_heartbeat_at=now,completed_at=None).execution_options(synchronize_session=False))
    if r.rowcount!=1:db.rollback();return None
    refreshed=db.execute(select(Investigation.execution_id,Investigation.execution_attempt_id).where(Investigation.id==inv_id)).one_or_none()
    if not refreshed or not refreshed[0] or not refreshed[1]:db.rollback();raise RuntimeError("Investigation claim has incomplete execution provenance")
    execution_id,execution_attempt_id=refreshed
    inv=db.get(Investigation,inv_id)
    if inv is not None:
        inv.execution_id=execution_id;inv.execution_attempt_id=execution_attempt_id;inv.execution_token=token;inv.status="running";inv.execution_started_at=now;inv.execution_heartbeat_at=now;inv.completed_at=None
    if stale_claim and old_attempt_id:_mark_attempt_abandoned(db,inv_id,old_attempt_id,now=now,reason="Superseded by a new worker claim")
    _create_attempt(db,inv_id,execution_id,execution_attempt_id,now=now);db.execute(update(ModuleRun).where(ModuleRun.investigation_id==inv_id,ModuleRun.execution_attempt_id.is_(None)).values(execution_id=execution_id,execution_attempt_id=execution_attempt_id));db.commit();return token
def fence_execution(db,inv_id,token):
    r=db.execute(update(Investigation).where(Investigation.id==inv_id,Investigation.status=="running",Investigation.execution_token==token).values(execution_heartbeat_at=utcnow()).execution_options(synchronize_session=False))
    if r.rowcount!=1:db.rollback();raise RuntimeError("Investigation execution lease is no longer owned")
    row=db.execute(select(Investigation.execution_id,Investigation.execution_attempt_id).where(Investigation.id==inv_id)).one_or_none()
    if row is None:db.rollback();raise RuntimeError("Investigation execution lease disappeared")
    if not row[0] or not row[1]:db.rollback();raise RuntimeError("Investigation has incomplete execution provenance")
    return row[0],row[1]
def heartbeat_investigation(db,inv_id,token,*,now=None):
    now=now or utcnow();r=db.execute(update(Investigation).where(Investigation.id==inv_id,Investigation.status=="running",Investigation.execution_token==token).values(execution_heartbeat_at=now).execution_options(synchronize_session=False));db.commit();return r.rowcount==1
def execution_is_owned(db,inv_id,token):return db.scalar(select(Investigation.id).where(Investigation.id==inv_id,Investigation.status=="running",Investigation.execution_token==token)) is not None
def _queued_ids(db,limit):return list(db.scalars(select(Investigation.id).where(Investigation.status=="queued").order_by(Investigation.created_at.asc(),Investigation.id.asc()).limit(limit)))
async def worker_loop(stop_event):
    settings=get_settings();active=set()
    async def execute(inv_id,token):
        from app.services.orchestrator import run_investigation
        await run_investigation(inv_id,token)
    while not stop_event.is_set():
        with SessionLocal() as db:
            recover_stale_investigations(db);available=max(0,settings.max_concurrency-len(active));candidates=_queued_ids(db,available) if available else [];claimed=[]
            for inv_id in candidates:
                token=claim_investigation(db,inv_id)
                if token:claimed.append((inv_id,token))
        for inv_id,token in claimed:
            task=asyncio.create_task(execute(inv_id,token));active.add(task);task.add_done_callback(active.discard)
        try:await asyncio.wait_for(stop_event.wait(),timeout=settings.worker_poll_interval_seconds)
        except asyncio.TimeoutError:pass
    if active:await asyncio.gather(*active,return_exceptions=True)

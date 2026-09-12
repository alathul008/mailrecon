import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.session import get_db
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.providers.registry import provider_definitions
from app.services.execution_outcome import aggregate_execution_outcome

router = APIRouter(prefix="/api")

_PROVIDER_BY_MODULE = {
    item.module: item.name
    for item in provider_definitions(orchestrated=True)
    if item.factory is not None and item.module
}


def _error_class(message: str | None) -> str | None:
    if not message:
        return None
    match = re.search(r"(?:Provider exception:|Investigation failed:)\s*([A-Za-z_][A-Za-z0-9_]*)", message)
    return match.group(1) if match else None


def _load_current(db: Session, inv_id: int):
    inv = db.scalar(select(Investigation).where(Investigation.id == inv_id))
    if not inv:
        raise HTTPException(404, "Investigation not found")
    attempt = None
    if inv.execution_attempt_id:
        attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == inv.execution_attempt_id))
    modules = db.scalars(select(ModuleRun).where(ModuleRun.investigation_id == inv_id)).all()
    provider_statuses = db.scalars(
        select(Finding.value).where(
            Finding.investigation_id == inv_id,
            Finding.execution_attempt_id == inv.execution_attempt_id,
            Finding.finding_type == "provider_status",
        )
    ).all() if inv.execution_attempt_id else []
    return inv, attempt, modules, list(provider_statuses)


@router.get("/investigations/{inv_id}/execution", dependencies=[Depends(require_api_key)])
def execution_summary(inv_id: int, db: Session = Depends(get_db)):
    inv, attempt, modules, provider_statuses = _load_current(db, inv_id)
    outcome = aggregate_execution_outcome(inv, attempt, modules, provider_statuses)
    current_modules = [m for m in modules if m.execution_attempt_id == inv.execution_attempt_id]
    providers = []
    for module in current_modules:
        provider = _PROVIDER_BY_MODULE.get(module.module)
        if provider:
            providers.append({
                "provider": provider,
                "module": module.module,
                "status": module.status,
                "message": module.message,
                "started_at": module.started_at,
                "finished_at": module.finished_at,
            })
    return {
        "investigation_id": inv.id,
        "execution_id": inv.execution_id,
        "execution_attempt_id": inv.execution_attempt_id,
        "attempt_status": attempt.status if attempt else None,
        "outcome": outcome,
        "semantics": {
            "completed": "All required execution work completed without provider/module warnings.",
            "completed_with_warnings": "Execution completed, but one or more provider/module operations were operationally degraded.",
            "failed": "The current execution attempt failed or was abandoned; this is not a negative intelligence result.",
            "no_findings": "A successful execution with no findings remains successful.",
        },
        "provider_statuses": provider_statuses,
        "providers": providers,
    }


@router.get("/investigations/{inv_id}/telemetry", dependencies=[Depends(require_api_key)])
def execution_telemetry(inv_id: int, db: Session = Depends(get_db)):
    inv, attempt, modules, _ = _load_current(db, inv_id)
    rows = []
    for module in modules:
        if not inv.execution_attempt_id or module.execution_attempt_id != inv.execution_attempt_id:
            continue
        started = module.started_at
        finished = module.finished_at
        duration_ms = None
        if started and finished:
            duration_ms = max(0, int((finished - started).total_seconds() * 1000))
        rows.append({
            "investigation_id": inv.id,
            "execution_attempt_id": module.execution_attempt_id,
            "module": module.module,
            "provider": _PROVIDER_BY_MODULE.get(module.module),
            "started_at": started,
            "finished_at": finished,
            "duration_ms": duration_ms,
            "operational_status": module.status,
            "error_class": _error_class(module.message),
        })
    return {
        "investigation_id": inv.id,
        "execution_attempt_id": attempt.execution_attempt_id if attempt else None,
        "generated_at": datetime.now(timezone.utc),
        "rows": rows,
        "semantics": "structured execution telemetry derived from durable ModuleRun timestamps and operational states; secrets and provider payloads are excluded",
    }

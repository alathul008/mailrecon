from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.session import get_db
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.api.routes import evidence_state, finding_projection, module_projection
from app.services.attempt_comparison import compare_attempts
from app.services.execution_outcome import aggregate_execution_outcome

router = APIRouter(prefix="/api")


def _investigation_or_404(db: Session, inv_id: int) -> Investigation:
    inv = db.get(Investigation, inv_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    return inv


def _attempt_or_404(db: Session, inv_id: int, attempt_id: str) -> ExecutionAttempt:
    attempt = db.scalar(select(ExecutionAttempt).where(
        ExecutionAttempt.investigation_id == inv_id,
        ExecutionAttempt.execution_attempt_id == attempt_id,
    ))
    if attempt is None:
        raise HTTPException(404, "Execution attempt not found")
    return attempt


def _attempt_outcome(db: Session, inv: Investigation, attempt: ExecutionAttempt) -> str:
    modules = db.scalars(select(ModuleRun).where(
        ModuleRun.investigation_id == inv.id,
        ModuleRun.execution_attempt_id == attempt.execution_attempt_id,
    )).all()
    statuses = db.scalars(select(Finding.value).where(
        Finding.investigation_id == inv.id,
        Finding.execution_attempt_id == attempt.execution_attempt_id,
        Finding.finding_type == "provider_status",
    )).all()
    return aggregate_execution_outcome(inv, attempt, modules, list(statuses))


@router.get("/investigations/{inv_id}/attempts", dependencies=[Depends(require_api_key)])
def list_attempts(inv_id: int, db: Session = Depends(get_db)):
    inv = _investigation_or_404(db, inv_id)
    attempts = db.scalars(select(ExecutionAttempt).where(
        ExecutionAttempt.investigation_id == inv.id,
    ).order_by(ExecutionAttempt.started_at.desc(), ExecutionAttempt.id.desc())).all()
    return [
        {
            "execution_id": attempt.execution_id,
            "execution_attempt_id": attempt.execution_attempt_id,
            "status": attempt.status,
            "started_at": attempt.started_at,
            "finished_at": attempt.finished_at,
            "recovered_at": attempt.recovered_at,
            "recovery_reason": attempt.recovery_reason,
            "current": attempt.execution_attempt_id == inv.execution_attempt_id,
            "outcome": _attempt_outcome(db, inv, attempt),
        }
        for attempt in attempts
    ]


@router.get("/investigations/{inv_id}/attempts/{attempt_id}", dependencies=[Depends(require_api_key)])
def attempt_detail(inv_id: int, attempt_id: str, db: Session = Depends(get_db)):
    inv = _investigation_or_404(db, inv_id)
    attempt = _attempt_or_404(db, inv_id, attempt_id)
    modules = db.scalars(select(ModuleRun).where(
        ModuleRun.investigation_id == inv.id,
        ModuleRun.execution_attempt_id == attempt.execution_attempt_id,
    ).order_by(ModuleRun.module.asc(), ModuleRun.id.asc())).all()
    findings = db.scalars(select(Finding).where(
        Finding.investigation_id == inv.id,
        Finding.execution_attempt_id == attempt.execution_attempt_id,
    ).order_by(Finding.source.asc(), Finding.finding_type.asc(), Finding.value.asc(), Finding.id.asc())).all()
    return {
        "investigation_id": inv.id,
        "attempt": {
            "execution_id": attempt.execution_id,
            "execution_attempt_id": attempt.execution_attempt_id,
            "status": attempt.status,
            "started_at": attempt.started_at,
            "finished_at": attempt.finished_at,
            "recovered_at": attempt.recovered_at,
            "recovery_reason": attempt.recovery_reason,
            "current": attempt.execution_attempt_id == inv.execution_attempt_id,
            "outcome": _attempt_outcome(db, inv, attempt),
        },
        "modules": [module_projection(module, inv.execution_attempt_id) for module in modules],
        "findings": [finding_projection(finding, inv.execution_attempt_id) for finding in findings],
        "provider_statuses": [finding.value for finding in findings if finding.finding_type == "provider_status"],
        "provenance": {
            "execution_id": attempt.execution_id,
            "execution_attempt_id": attempt.execution_attempt_id,
            "investigation_id": inv.id,
            "current_execution_attempt_id": inv.execution_attempt_id,
            "identity_confirmation": False,
        },
    }


@router.get("/investigations/{inv_id}/attempt-comparison", dependencies=[Depends(require_api_key)])
def attempt_comparison(
    inv_id: int,
    before_attempt_id: str = Query(..., min_length=1),
    after_attempt_id: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    _investigation_or_404(db, inv_id)
    try:
        return compare_attempts(db, inv_id, before_attempt_id, after_attempt_id)
    except (LookupError, ValueError) as exc:
        raise HTTPException(404 if isinstance(exc, LookupError) else 422, str(exc)) from exc

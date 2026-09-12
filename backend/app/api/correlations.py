from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.session import get_db
from app.models import Finding, Investigation
from app.osint.correlation import correlate_email_findings

router = APIRouter(prefix="/api")


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "source": f.source,
        "source_url": f.source_url,
        "finding_type": f.finding_type,
        "value": f.value,
        "confidence": f.confidence,
        "evidence_state": f.evidence_state,
        "notes": f.notes,
        "raw_reference": f.raw_reference,
        "execution_id": f.execution_id,
        "execution_attempt_id": f.execution_attempt_id,
    }


@router.get("/investigations/{inv_id}/correlations", dependencies=[Depends(require_api_key)])
def correlations(inv_id: int, db: Session = Depends(get_db)):
    inv = db.scalar(select(Investigation).where(Investigation.id == inv_id))
    if not inv:
        raise HTTPException(404, "Investigation not found")

    current_attempt_id = inv.execution_attempt_id
    query = select(Finding).where(Finding.investigation_id == inv_id)
    if current_attempt_id:
        query = query.where(Finding.execution_attempt_id == current_attempt_id)
    else:
        query = query.where(Finding.execution_attempt_id.is_(None))
    findings = db.scalars(query.order_by(Finding.id.asc())).all()
    result = correlate_email_findings([_finding_dict(f) for f in findings])
    result["investigation_id"] = inv_id
    result["execution_id"] = inv.execution_id
    result["execution_attempt_id"] = current_attempt_id
    result["provenance"] = {
        "type": "current_execution_attempt",
        "execution_id": inv.execution_id,
        "execution_attempt_id": current_attempt_id,
        "semantics": "current_derived_view",
        "historical_findings": "retained_in_persistence_but_excluded_from_current_correlation",
    }
    return result

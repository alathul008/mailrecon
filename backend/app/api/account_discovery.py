from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.session import get_db
from app.models import Finding, Investigation
from app.osint.service_catalog import SERVICE_CATALOG, build_account_discovery_matrix

router = APIRouter(prefix="/api")


def _finding_dict(f: Finding) -> dict:
    evidence_state = f.evidence_state
    if not evidence_state and isinstance(f.raw_reference, dict):
        evidence_state = f.raw_reference.get("evidence_state")
    if not evidence_state and f.notes and "Evidence state: " in f.notes:
        evidence_state = f.notes.split("Evidence state: ", 1)[1].split(".", 1)[0].strip()
    raw = f.raw_reference if isinstance(f.raw_reference, dict) else {}
    return {
        "id": f.id,
        "source": f.source,
        "source_url": f.source_url,
        "finding_type": f.finding_type,
        "value": f.value,
        "confidence": f.confidence,
        "evidence_state": evidence_state,
        "service": raw.get("service") if isinstance(raw.get("service"), str) else None,
    }


@router.get("/service-catalog", dependencies=[Depends(require_api_key)])
def service_catalog():
    return [
        {
            "service": item.name,
            "category": item.category,
            "supported": item.supported,
            "provider": item.provider,
            "discovery_methods": list(item.discovery_methods),
        }
        for item in SERVICE_CATALOG
    ]


@router.get("/investigations/{inv_id}/account-discovery", dependencies=[Depends(require_api_key)])
def account_discovery(inv_id: int, db: Session = Depends(get_db)):
    inv = db.scalar(select(Investigation).where(Investigation.id == inv_id))
    if not inv:
        raise HTTPException(404, "Investigation not found")
    findings = db.scalars(
        select(Finding)
        .where(Finding.investigation_id == inv_id)
        .order_by(Finding.id.asc())
    ).all()
    rows = build_account_discovery_matrix([_finding_dict(f) for f in findings])
    return {
        "investigation_id": inv_id,
        "target": inv.normalized_email or inv.target,
        "semantics": {
            "status": "operational_or_evidence_state",
            "identity": "correlation_does_not_confirm_identity",
            "negative_results": "no_public_evidence_is_not_account_nonexistence",
            "public_web": "service labels are derived from public result domains; they are not provider account confirmation",
        },
        "services": rows,
    }

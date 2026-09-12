from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.auth import require_api_key
from app.osint.email import analyze_email, username_candidates
from app.providers.base import ProviderContext, ProviderResult
from app.providers.public_web import PublicWebProvider
from app.providers.registry import execute, provider_definition

router = APIRouter(prefix="/api")


@router.get("/public-web/discovery", dependencies=[Depends(require_api_key)])
async def public_web_discovery(
    email: str = Query(..., min_length=3, max_length=320),
    candidates: str = Query("", max_length=1000),
):
    """Run bounded public-web discovery through the canonical provider contract."""
    try:
        analysis = analyze_email(email.strip())
    except ValueError as exc:
        raise HTTPException(422, f"Invalid email: {exc}") from exc
    candidate_values = [item.strip() for item in candidates.split(",") if item.strip()][:4]
    derived_candidates = username_candidates(analysis["username"])
    selected_candidates = tuple(dict.fromkeys([*candidate_values, *derived_candidates]))[:4]
    context = ProviderContext(email=analysis["email"], domain=analysis["domain"], candidates=selected_candidates)
    result = await execute(provider_definition("Public Web"), context=context, factory=PublicWebProvider)
    return {
        "provider": result.provider,
        "status": result.status,
        "message": result.message,
        "checked_at": result.checked_at,
        "findings": result.findings,
        "semantics": {
            "public_only": True,
            "identity": "public search correlation does not confirm identity",
            "possible_match": "public_web_reference findings remain possible matches and do not confirm ownership",
            "storage": "page contents are not stored by this provider",
            "contract": "canonical ProviderContext and ProviderResult",
        },
    }

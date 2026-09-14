from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.auth import require_api_key
from app.core.rate_limit import allow_public_web_discovery
from app.osint.email import analyze_email, username_candidates
from app.providers.base import ProviderContext, ProviderResult
from app.providers.public_web import PublicWebProvider
from app.providers.registry import execute, provider_definition
from app.services.resource_budget import ExecutionResourceBudget

router = APIRouter(prefix="/api")


@router.get("/public-web/discovery", dependencies=[Depends(require_api_key)])
async def public_web_discovery(
    email: str = Query(..., min_length=3, max_length=320),
    candidates: str = Query("", max_length=1000),
):
    """Run bounded public-web discovery through the canonical provider contract."""
    if not allow_public_web_discovery():
        raise HTTPException(429, "Public Web discovery rate limit exceeded; retry later")
    try:
        analysis = analyze_email(email.strip())
    except ValueError as exc:
        raise HTTPException(422, f"Invalid email: {exc}") from exc
    budget = ExecutionResourceBudget()
    candidate_values = [item.strip() for item in candidates.split(",") if item.strip()][:budget.max_candidate_probes]
    derived_candidates = username_candidates(analysis["username"])
    selected_candidates = tuple(dict.fromkeys([*candidate_values, *derived_candidates]))[:budget.max_candidate_probes]
    query_count = min(1 + len(selected_candidates), budget.max_public_web_queries)
    budget.validate(
        provider_calls=1,
        candidate_probes=len(selected_candidates),
        estimated_external_requests=query_count,
    )
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
            "resource_bounds": {
                "candidate_probes": len(selected_candidates),
                "search_queries": query_count,
                "results_per_query": budget.max_public_web_results_per_query,
                "response_bytes": budget.max_response_bytes,
            },
        },
    }

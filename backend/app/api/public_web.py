from fastapi import APIRouter, Depends, Query

from app.core.auth import require_api_key
from app.providers.public_web import PublicWebProvider

router = APIRouter(prefix="/api")


@router.get("/public-web/discovery", dependencies=[Depends(require_api_key)])
async def public_web_discovery(
    email: str = Query(..., min_length=3, max_length=320),
    candidates: str = Query("", max_length=1000),
):
    """Run bounded public-web discovery without persisting page contents.

    Investigation execution remains responsible for durable evidence. This
    endpoint provides an explicit analyst preview while the provider rollout
    is expanded incrementally.
    """
    candidate_values = [item.strip() for item in candidates.split(",") if item.strip()][:4]
    result = await PublicWebProvider().run(email.strip(), candidate_values)
    return {
        "provider": result.provider,
        "status": result.status,
        "message": result.message,
        "checked_at": result.checked_at,
        "findings": result.findings,
        "semantics": {
            "public_only": True,
            "identity": "public search correlation does not confirm identity",
            "storage": "page contents are not stored by this provider",
        },
    }

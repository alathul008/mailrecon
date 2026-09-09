from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.db.session import get_db
from app.services.deletion import delete_investigation

router = APIRouter(prefix="/api")


@router.delete("/investigations/{investigation_id}", dependencies=[Depends(require_api_key)])
def delete_investigation_endpoint(
    investigation_id: int,
    db: Session = Depends(get_db),
):
    deleted = delete_investigation(db, investigation_id)
    if not deleted:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"id": investigation_id, "status": "deleted"}

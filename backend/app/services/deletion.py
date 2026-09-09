from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Investigation


def delete_investigation(db: Session, investigation_id: int) -> bool:
    """Atomically delete one investigation aggregate using database FK cascades."""
    try:
        result = db.execute(
            delete(Investigation).where(Investigation.id == investigation_id)
        )
        if result.rowcount != 1:
            db.rollback()
            return False
        db.commit()
        return True
    except Exception:
        db.rollback()
        raise

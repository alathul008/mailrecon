from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import Investigation, ModuleRun
from app.services import lifecycle
from app.services.orchestrator import set_module


def make_engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path / 'fencing.db'}")


def add_investigation(db):
    inv = Investigation(
        target="alice@example.com",
        normalized_email="alice@example.com",
        username="alice",
        domain="example.com",
        status="queued",
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def test_validated_stale_worker_is_rejected_at_persistence_boundary(tmp_path):
    engine = make_engine(tmp_path)
    Base.metadata.create_all(engine)
    old = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    now = old + timedelta(seconds=120)

    with Session(engine) as db_a:
        inv = add_investigation(db_a)
        token_a = lifecycle.claim_investigation(db_a, inv.id, now=old)
        assert token_a
        attempt_a = db_a.get(Investigation, inv.id).execution_attempt_id

        # Worker A validates ownership, then pauses before persistence.
        assert lifecycle.execution_is_owned(db_a, inv.id, token_a) is True

        with Session(engine) as db_b:
            assert lifecycle.recover_stale_investigations(db_b, now=now) == 1
            token_b = lifecycle.claim_investigation(db_b, inv.id, now=now)
            assert token_b and token_b != token_a
            current = db_b.get(Investigation, inv.id)
            assert current.execution_attempt_id != attempt_a
            set_module(db_b, inv.id, "email_validation", "running", token=token_b)
            b_attempt = current.execution_attempt_id

        # Worker A now reaches the actual persistence boundary with a stale token.
        with pytest.raises(RuntimeError, match="no longer owned"):
            set_module(db_a, inv.id, "rdap", "running", token=token_a)

        db_a.rollback()
        with Session(engine) as verify:
            rows = verify.scalars(
                select(ModuleRun)
                .where(ModuleRun.investigation_id == inv.id)
                .order_by(ModuleRun.id)
            ).all()
            assert len(rows) == 1
            assert rows[0].module == "email_validation"
            assert rows[0].execution_attempt_id == b_attempt
            assert rows[0].status == "running"
            assert all(row.execution_attempt_id != attempt_a for row in rows)

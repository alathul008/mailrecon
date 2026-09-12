from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.osint.correlation import correlate_email_findings
from app.services import lifecycle
from app.services.execution_outcome import aggregate_execution_outcome
from app.services.resource_budget import ExecutionResourceBudget


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase35.db'}")
    Base.metadata.create_all(engine)
    return engine


def add_investigation(db):
    inv = Investigation(target="alice@example.com", normalized_email="alice@example.com", username="alice", domain="example.com", status="queued")
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def add_finding(db, inv, attempt, value, finding_type="profile_candidate", collected_at=None):
    collected_at = collected_at or datetime.now(timezone.utc)
    db.add(Finding(
        investigation_id=inv.id,
        execution_id=inv.execution_id,
        execution_attempt_id=attempt,
        source="phase35-test",
        source_url="https://example.test/evidence",
        finding_type=finding_type,
        value=value,
        confidence=0.8,
        severity="info",
        collected_at=collected_at,
        notes="Evidence state: possible_match.",
    ))
    db.commit()


def test_current_correlation_excludes_historical_attempt(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=now - timedelta(minutes=5))
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        add_finding(db, inv, attempt_a, "historical")
        db.get(Investigation, inv.id).execution_heartbeat_at = now - timedelta(minutes=5)
        db.commit()
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        current = db.get(Investigation, inv.id)
        attempt_b = current.execution_attempt_id
        add_finding(db, current, attempt_b, "current")

        rows = db.scalars(select(Finding).where(Finding.investigation_id == inv.id, Finding.execution_attempt_id == attempt_b)).all()
        result = correlate_email_findings([{
            "id": row.id, "finding_type": row.finding_type, "value": row.value,
            "confidence": row.confidence, "evidence_state": row.evidence_state,
            "source": row.source, "raw_reference": row.raw_reference,
        } for row in rows])
        values = {rel["target"] for rel in result["relationships"]}
        assert "current" in values
        assert "historical" not in values
        assert db.scalar(select(Finding.id).where(Finding.execution_attempt_id == attempt_a)) is not None
        assert attempt_a != attempt_b


def test_abandoned_attempt_cannot_be_current_correlation(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=now - timedelta(minutes=5))
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        add_finding(db, inv, attempt_a, "abandoned")
        db.get(Investigation, inv.id).execution_heartbeat_at = now - timedelta(minutes=5)
        db.commit()
        lifecycle.recover_stale_investigations(db, now=now)
        lifecycle.claim_investigation(db, inv.id, now=now)
        current = db.get(Investigation, inv.id)
        assert current.execution_attempt_id != attempt_a
        assert db.scalar(select(ExecutionAttempt.status).where(ExecutionAttempt.execution_attempt_id == attempt_a)) == "abandoned"


def test_aggregate_outcome_distinguishes_success_partial_and_failure(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        current = db.get(Investigation, inv.id)
        attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == current.execution_attempt_id))
        modules = [ModuleRun(investigation_id=inv.id, execution_id=current.execution_id, execution_attempt_id=current.execution_attempt_id, module="github", status="completed"), ModuleRun(investigation_id=inv.id, execution_id=current.execution_id, execution_attempt_id=current.execution_attempt_id, module="gitlab", status="completed")]
        db.add_all(modules); db.commit()
        attempt.status = "completed"; current.status = "completed"; db.commit()
        assert aggregate_execution_outcome(current, attempt, modules, ["ok", "ok"]) == "completed"
        assert aggregate_execution_outcome(current, attempt, modules, ["ok", "unavailable", "rate_limited", "ok"]) == "completed_with_warnings"
        modules[0].status = "failed"
        assert aggregate_execution_outcome(current, attempt, modules, ["ok"]) == "completed_with_warnings"
        attempt.status = "failed"; current.status = "failed"
        assert aggregate_execution_outcome(current, attempt, modules, ["ok"]) == "failed"


def test_no_findings_success_is_not_failure(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        lifecycle.claim_investigation(db, inv.id)
        current = db.get(Investigation, inv.id)
        attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == current.execution_attempt_id))
        attempt.status = "completed"; current.status = "completed"; db.commit()
        assert aggregate_execution_outcome(current, attempt, [], []) == "completed"


def test_resource_budget_preserves_existing_candidate_and_request_bounds():
    budget = ExecutionResourceBudget()
    budget.validate(provider_calls=6, candidate_probes=4, estimated_external_requests=30)
    with pytest.raises(RuntimeError):
        budget.validate(provider_calls=9, candidate_probes=4, estimated_external_requests=30)
    with pytest.raises(RuntimeError):
        budget.validate(provider_calls=6, candidate_probes=5, estimated_external_requests=30)
    with pytest.raises(RuntimeError):
        budget.validate(provider_calls=6, candidate_probes=4, estimated_external_requests=33)

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import Finding, Investigation, ModuleRun
from app.risk.engine import calculate
from app.services import lifecycle
from app.services.orchestrator import add_findings, set_module


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'idempotency.db'}")
    Base.metadata.create_all(engine)
    return engine


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


def test_initial_claim_adopts_precreated_queue_rows_into_attempt(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        queued = ModuleRun(
            investigation_id=inv.id,
            execution_id=inv.execution_id,
            execution_attempt_id=None,
            module="email_validation",
            status="queued",
        )
        db.add(queued)
        db.commit()

        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        current = db.get(Investigation, inv.id)
        adopted = db.get(ModuleRun, queued.id)
        assert adopted.execution_id == current.execution_id
        assert adopted.execution_attempt_id == current.execution_attempt_id
        assert adopted.status == "queued"

        set_module(db, inv.id, "email_validation", "running", token=token)
        rows = db.scalars(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.module == "email_validation",
        )).all()
        assert len(rows) == 1
        assert rows[0].id == queued.id
        assert rows[0].status == "running"


def test_initial_claim_creates_attempt_identity_and_module_provenance(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        execution_id = inv.execution_id
        assert inv.execution_attempt_id is None
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        current = db.get(Investigation, inv.id)
        assert current.execution_id == execution_id
        assert current.execution_attempt_id
        assert current.execution_token == token

        set_module(db, inv.id, "email_validation", "running", token=token)
        module = db.scalar(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.module == "email_validation",
            ModuleRun.execution_attempt_id == current.execution_attempt_id,
        ))
        assert module.execution_id == execution_id
        assert module.execution_attempt_id == current.execution_attempt_id
        assert module.status == "running"


def test_recovery_creates_new_attempt_but_preserves_logical_identity(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=120)
    with Session(engine) as db:
        inv = add_investigation(db)
        execution_id = inv.execution_id
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        assert token_a
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        assert attempt_a
        set_module(db, inv.id, "email_validation", "completed", token=token_a)

        module_a = db.scalar(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.module == "email_validation",
            ModuleRun.execution_attempt_id == attempt_a,
        ))
        assert module_a
        module_a_snapshot = (
            module_a.id,
            module_a.execution_id,
            module_a.execution_attempt_id,
            module_a.status,
            module_a.message,
            module_a.started_at,
            module_a.finished_at,
        )

        add_findings(db, inv.id, [{
            "source": "test",
            "source_url": "https://example.test/evidence",
            "finding_type": "profile_candidate",
            "value": "https://example.test/alice",
            "confidence": 0.72,
            "severity": "info",
            "first_seen": old,
            "last_seen": old,
            "collected_at": old,
            "notes": "Evidence state: possible_match.",
            "raw_reference": None,
        }], token_a)
        before = db.scalar(select(Finding.id).where(Finding.investigation_id == inv.id))
        assert before

        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        recovered = db.get(Investigation, inv.id)
        assert recovered.execution_id == execution_id
        assert recovered.execution_attempt_id == attempt_a

        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        assert token_b and token_b != token_a
        recovered = db.get(Investigation, inv.id)
        attempt_b = recovered.execution_attempt_id
        assert recovered.execution_id == execution_id
        assert attempt_b and attempt_b != attempt_a

        set_module(db, inv.id, "email_validation", "running", token=token_b)
        module_a_after_claim = db.scalar(select(ModuleRun).where(ModuleRun.id == module_a.id))
        assert module_a_after_claim
        assert (
            module_a_after_claim.id,
            module_a_after_claim.execution_id,
            module_a_after_claim.execution_attempt_id,
            module_a_after_claim.status,
            module_a_after_claim.message,
            module_a_after_claim.started_at,
            module_a_after_claim.finished_at,
        ) == module_a_snapshot

        set_module(db, inv.id, "email_validation", "completed", token=token_b)
        modules = db.scalars(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.module == "email_validation",
        ).order_by(ModuleRun.id)).all()
        assert [m.execution_attempt_id for m in modules] == [attempt_a, attempt_b]
        assert all(m.execution_id == execution_id for m in modules)

        add_findings(db, inv.id, [{
            "source": "test",
            "source_url": "https://example.test/evidence",
            "finding_type": "profile_candidate",
            "value": "https://example.test/alice",
            "confidence": 0.72,
            "severity": "info",
            "first_seen": old,
            "last_seen": now,
            "collected_at": now,
            "notes": "Evidence state: possible_match.",
            "raw_reference": None,
        }], token_b)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        assert len(findings) == 1
        assert findings[0].execution_id == execution_id
        assert findings[0].execution_attempt_id == attempt_a
        assert findings[0].persistence_key


def test_separate_investigations_remain_distinct_acquisitions(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        first = add_investigation(db)
        second = add_investigation(db)
        assert first.execution_id != second.execution_id
        first_token = lifecycle.claim_investigation(db, first.id)
        second_token = lifecycle.claim_investigation(db, second.id)
        assert first_token and second_token
        first_attempt = db.get(Investigation, first.id).execution_attempt_id
        second_attempt = db.get(Investigation, second.id).execution_attempt_id
        assert first_attempt != second_attempt
        finding_data = {
            "source": "test",
            "source_url": None,
            "finding_type": "breach",
            "value": "Example-2026",
            "confidence": 1.0,
            "severity": "high",
            "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "last_seen": None,
            "collected_at": datetime.now(timezone.utc),
            "notes": "Historical breach exposure only.",
            "raw_reference": None,
        }
        add_findings(db, first.id, [finding_data], first_token)
        add_findings(db, second.id, [finding_data], second_token)
        rows = db.scalars(select(Finding).order_by(Finding.id)).all()
        assert len(rows) == 2
        assert {r.investigation_id for r in rows} == {first.id, second.id}
        assert {r.execution_id for r in rows} == {first.execution_id, second.execution_id}
        assert {r.execution_attempt_id for r in rows} == {first_attempt, second_attempt}


def test_risk_is_invariant_when_recovery_replays_same_evidence(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=120)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        assert token_a
        data = [{
            "source": "test",
            "source_url": None,
            "finding_type": "breach",
            "value": "Example-2026",
            "confidence": 1.0,
            "severity": "high",
            "first_seen": datetime(2026, 1, 1, tzinfo=timezone.utc),
            "last_seen": None,
            "collected_at": old,
            "notes": "Historical breach exposure only.",
            "raw_reference": None,
        }]
        add_findings(db, inv.id, data, token_a)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        before = calculate({}, [{"finding_type": f.finding_type, "value": f.value, "confidence": f.confidence, "notes": f.notes, "raw_reference": f.raw_reference} for f in findings])

        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        assert token_b and token_b != token_a
        add_findings(db, inv.id, data, token_b)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        after = calculate({}, [{"finding_type": f.finding_type, "value": f.value, "confidence": f.confidence, "notes": f.notes, "raw_reference": f.raw_reference} for f in findings])
        assert (before.score, before.level, before.dimensions, before.factors) == (after.score, after.level, after.dimensions, after.factors)
        assert len(findings) == 1


def test_stale_worker_is_fenced_after_recovery(tmp_path):
    engine = make_engine(tmp_path)
    old = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    now = old + timedelta(seconds=120)
    with Session(engine) as db:
        inv = add_investigation(db)
        old_token = lifecycle.claim_investigation(db, inv.id, now=old)
        assert old_token
        old_attempt = db.get(Investigation, inv.id).execution_attempt_id
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        new_token = lifecycle.claim_investigation(db, inv.id, now=now)
        assert new_token and new_token != old_token
        new_attempt = db.get(Investigation, inv.id).execution_attempt_id
        assert new_attempt and new_attempt != old_attempt
        assert lifecycle.execution_is_owned(db, inv.id, old_token) is False
        assert lifecycle.execution_is_owned(db, inv.id, new_token) is True
        assert lifecycle.heartbeat_investigation(db, inv.id, old_token, now=now) is False


def test_persistence_key_is_scoped_to_logical_execution_not_global(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        first = add_investigation(db)
        token = lifecycle.claim_investigation(db, first.id)
        add_findings(db, first.id, [{
            "source": "test", "source_url": None, "finding_type": "email", "value": first.target,
            "confidence": 1.0, "severity": "info", "first_seen": None, "last_seen": None,
            "collected_at": datetime.now(timezone.utc), "notes": None, "raw_reference": None,
        }], token)
        duplicate = db.scalar(select(Finding).where(Finding.investigation_id == first.id))
        assert duplicate.persistence_key
        assert duplicate.execution_attempt_id == db.get(Investigation, first.id).execution_attempt_id
        unique_constraints = inspect(engine).get_unique_constraints("findings")
        assert any(c["name"] == "uq_findings_execution_persistence" for c in unique_constraints)
        module_constraints = inspect(engine).get_unique_constraints("module_runs")
        assert any(c["name"] == "uq_module_runs_attempt_module" for c in module_constraints)


def test_stale_worker_cannot_persist_under_new_attempt(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=120)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        assert token_a
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        set_module(db, inv.id, "email_validation", "completed", "Attempt A completed", token_a)

        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        assert token_b and token_b != token_a
        current = db.get(Investigation, inv.id)
        attempt_b = current.execution_attempt_id
        assert attempt_b and attempt_b != attempt_a

        set_module(db, inv.id, "email_validation", "running", "Attempt B running", token_b)
        add_findings(db, inv.id, [{
            "source": "attempt-b",
            "source_url": "https://example.test/b",
            "finding_type": "profile_candidate",
            "value": "https://example.test/b",
            "confidence": 0.8,
            "severity": "info",
            "first_seen": now,
            "last_seen": now,
            "collected_at": now,
            "notes": "Evidence state: possible_match.",
            "raw_reference": None,
        }], token_b)

        module_b = db.scalar(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.execution_attempt_id == attempt_b,
            ModuleRun.module == "email_validation",
        ))
        finding_b = db.scalar(select(Finding).where(
            Finding.investigation_id == inv.id,
            Finding.execution_attempt_id == attempt_b,
        ))
        module_b_snapshot = (module_b.id, module_b.status, module_b.message, module_b.finished_at)
        finding_b_snapshot = (finding_b.id, finding_b.value, finding_b.persistence_key)

        with pytest.raises(RuntimeError, match="no longer owned"):
            set_module(db, inv.id, "rdap", "running", "stale worker", token_a)
        with pytest.raises(RuntimeError, match="no longer owned"):
            add_findings(db, inv.id, [{
                "source": "attempt-a",
                "source_url": "https://example.test/a",
                "finding_type": "profile_candidate",
                "value": "https://example.test/a",
                "confidence": 0.8,
                "severity": "info",
                "first_seen": old,
                "last_seen": old,
                "collected_at": old,
                "notes": "Evidence state: possible_match.",
                "raw_reference": None,
            }], token_a)

        db.expire_all()
        module_b = db.get(ModuleRun, module_b.id)
        finding_b = db.get(Finding, finding_b.id)
        assert (module_b.id, module_b.status, module_b.message, module_b.finished_at) == module_b_snapshot
        assert (finding_b.id, finding_b.value, finding_b.persistence_key) == finding_b_snapshot
        assert db.scalar(select(ModuleRun).where(
            ModuleRun.investigation_id == inv.id,
            ModuleRun.execution_attempt_id == attempt_b,
            ModuleRun.module == "rdap",
        )) is None
        assert db.scalar(select(Finding).where(
            Finding.investigation_id == inv.id,
            Finding.execution_attempt_id == attempt_a,
        )) is None

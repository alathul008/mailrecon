from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select, text
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


def test_execution_identity_is_durable_and_module_provenance_is_bound(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        execution_id = inv.execution_id
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        current = db.get(Investigation, inv.id)
        assert current.execution_id == execution_id
        assert current.execution_token == token

        set_module(db, inv.id, "email_validation", "running", token=token)
        module = db.scalar(select(ModuleRun).where(ModuleRun.investigation_id == inv.id, ModuleRun.module == "email_validation"))
        assert module.execution_id == execution_id
        assert module.status == "running"


def test_recovery_reuses_execution_identity_and_does_not_duplicate_findings(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    old = now - timedelta(seconds=120)
    with Session(engine) as db:
        inv = add_investigation(db)
        execution_id = inv.execution_id
        token = lifecycle.claim_investigation(db, inv.id, now=old)
        assert token
        set_module(db, inv.id, "email_validation", "completed", token=token)
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
        }], token)
        before = db.scalar(select(Finding).where(Finding.investigation_id == inv.id).with_only_columns(Finding.id))
        assert before

        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        recovered = db.get(Investigation, inv.id)
        assert recovered.execution_id == execution_id
        new_token = lifecycle.claim_investigation(db, inv.id, now=now)
        assert new_token and new_token != token
        assert db.get(Investigation, inv.id).execution_id == execution_id

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
        }], new_token)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        assert len(findings) == 1
        assert findings[0].execution_id == execution_id
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


def test_risk_is_invariant_when_recovery_replays_same_evidence(tmp_path):
    engine = make_engine(tmp_path)
    with Session(engine) as db:
        inv = add_investigation(db)
        token = lifecycle.claim_investigation(db, inv.id)
        assert token
        data = [{
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
        }]
        add_findings(db, inv.id, data, token)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        before = calculate({}, [{"finding_type": f.finding_type, "value": f.value, "confidence": f.confidence, "notes": f.notes, "raw_reference": f.raw_reference} for f in findings])
        add_findings(db, inv.id, data, token)
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
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        new_token = lifecycle.claim_investigation(db, inv.id, now=now)
        assert new_token and new_token != old_token
        assert lifecycle.execution_is_owned(db, inv.id, old_token) is False
        assert lifecycle.execution_is_owned(db, inv.id, new_token) is True
        assert lifecycle.heartbeat_investigation(db, inv.id, old_token, now=now) is False


def test_persistence_key_is_scoped_to_execution_not_global(tmp_path):
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
        indexes = db.execute(text("PRAGMA index_list(findings)")).all()
        assert any("uq_findings_execution_persistence" in str(row) for row in indexes)

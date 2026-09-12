from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import ExecutionAttempt, Finding, GraphEdge, GraphNode, Investigation
from app.services import lifecycle
from app.services.orchestrator import add_findings
from app.api.routes import graph, report, risk, timeline

# Phase 34 regression coverage keeps historical findings while isolating current projections.


def make_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase34.db'}")
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


def finding_data(value, collected_at):
    return {
        "source": "phase34-test",
        "source_url": "https://example.test/evidence",
        "finding_type": "profile_candidate",
        "value": value,
        "confidence": 0.8,
        "severity": "info",
        "first_seen": collected_at,
        "last_seen": collected_at,
        "collected_at": collected_at,
        "notes": "Evidence state: possible_match.",
        "raw_reference": None,
    }


def risk_factor(value, collected_at):
    return {
        "source": "phase34-test",
        "source_url": None,
        "finding_type": "risk_factor",
        "value": value,
        "confidence": 1.0,
        "severity": "medium",
        "collected_at": collected_at,
        "notes": "Score delta: +12; dimension=identity_exposure",
        "raw_reference": None,
    }


def test_current_risk_and_report_exclude_historical_risk_factors_but_retain_findings(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(minutes=5)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        add_findings(db, inv.id, [finding_data("https://example.test/historical", old), risk_factor("historical-risk", old)], token_a)

        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        current = db.get(Investigation, inv.id)
        attempt_b = current.execution_attempt_id
        assert attempt_b != attempt_a
        add_findings(db, inv.id, [finding_data("https://example.test/current", now), risk_factor("current-risk", now)], token_b)
        current.risk_score = 12
        current.risk_level = "LOW"
        db.commit()

        risk_view = risk(inv.id, db)
        assert [factor["reason"] for factor in risk_view["factors"]] == ["current-risk"]

        report_view = report(inv.id, "json", db)
        assert report_view["risk_factors"] == [{"delta": 12, "reason": "current-risk"}]
        values = {item["value"] for item in report_view["findings"]}
        assert "https://example.test/historical" in values
        assert "https://example.test/current" in values
        by_value = {item["value"]: item for item in report_view["findings"]}
        assert by_value["https://example.test/historical"]["historical_attempt"] is True
        assert by_value["https://example.test/current"]["current_attempt"] is True
        assert {row.execution_attempt_id for row in db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()} == {attempt_a, attempt_b}


def test_current_graph_excludes_historical_only_nodes_and_timeline_keeps_both(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(minutes=5)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        add_findings(db, inv.id, [finding_data("https://example.test/historical", old)], token_a)
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        attempt_b = db.get(Investigation, inv.id).execution_attempt_id
        add_findings(db, inv.id, [finding_data("https://example.test/current", now)], token_b)

        db.add_all([
            GraphNode(investigation_id=inv.id, node_key="email:alice@example.com", node_type="EMAIL", label="alice@example.com"),
            GraphNode(investigation_id=inv.id, node_key="domain:example.com", node_type="DOMAIN", label="example.com"),
            GraphNode(investigation_id=inv.id, node_key="username:alice", node_type="USERNAME", label="alice"),
            GraphNode(investigation_id=inv.id, node_key="profile:https://example.test/historical", node_type="PROFILE", label="historical"),
            GraphNode(investigation_id=inv.id, node_key="profile:https://example.test/current", node_type="PROFILE", label="current"),
        ])
        db.add_all([
            GraphEdge(investigation_id=inv.id, source="email:alice@example.com", target="domain:example.com", relation="uses", confidence=1.0),
            GraphEdge(investigation_id=inv.id, source="email:alice@example.com", target="profile:https://example.test/historical", relation="possible_profile", confidence=0.8),
            GraphEdge(investigation_id=inv.id, source="email:alice@example.com", target="profile:https://example.test/current", relation="possible_profile", confidence=0.8),
        ])
        db.commit()

        graph_view = graph(inv.id, db)
        node_ids = {node["id"] for node in graph_view["nodes"]}
        assert "profile:https://example.test/historical" not in node_ids
        assert "profile:https://example.test/current" in node_ids
        assert all(edge["target"] != "profile:https://example.test/historical" for edge in graph_view["edges"])
        assert graph_view["provenance"]["execution_attempt_id"] == attempt_b

        timeline_view = timeline(inv.id, db)
        values = {event["value"] for event in timeline_view}
        assert "https://example.test/historical" in values
        assert "https://example.test/current" in values
        states = {event["value"]: event["current_attempt"] for event in timeline_view if event["value"] in values}
        assert states["https://example.test/historical"] is False
        assert states["https://example.test/current"] is True
        assert attempt_a != attempt_b


def test_empty_current_attempt_has_no_current_risk_factors_and_history_remains_queryable(tmp_path):
    engine = make_engine(tmp_path)
    now = datetime.now(timezone.utc)
    old = now - timedelta(minutes=5)
    with Session(engine) as db:
        inv = add_investigation(db)
        token_a = lifecycle.claim_investigation(db, inv.id, now=old)
        attempt_a = db.get(Investigation, inv.id).execution_attempt_id
        add_findings(db, inv.id, [risk_factor("historical-risk", old)], token_a)
        assert lifecycle.recover_stale_investigations(db, now=now) == 1
        token_b = lifecycle.claim_investigation(db, inv.id, now=now)
        attempt_b = db.get(Investigation, inv.id).execution_attempt_id
        db.commit()

        risk_view = risk(inv.id, db)
        assert risk_view["factors"] == []
        rows = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        assert len(rows) == 1
        assert rows[0].execution_attempt_id == attempt_a
        assert attempt_b != attempt_a
        assert db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == attempt_a)).status == "abandoned"

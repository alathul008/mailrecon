from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import Finding, Investigation, GraphNode, GraphEdge
from app.osint.email import (
    EVIDENCE_CORROBORATED,
    EVIDENCE_CONFIRMED,
    EVIDENCE_DERIVED,
    EVIDENCE_OBSERVED,
    EVIDENCE_POSSIBLE,
    EVIDENCE_SOURCE_ASSOCIATED,
)
from app.services.orchestrator import add_findings
from app.api.routes import timeline


EVIDENCE_STATES = {
    EVIDENCE_DERIVED,
    EVIDENCE_POSSIBLE,
    EVIDENCE_CORROBORATED,
    EVIDENCE_SOURCE_ASSOCIATED,
    EVIDENCE_OBSERVED,
    EVIDENCE_CONFIRMED,
}


def make_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def add_investigation(db, *, privacy_mode=False):
    inv = Investigation(
        target="john.smith@example.com",
        normalized_email="john.smith@example.com",
        username="john.smith",
        domain="example.com",
        privacy_mode=privacy_mode,
    )
    db.add(inv)
    db.commit()
    return inv


def add_finding(db, inv_id, *, source="DNS", finding_type="mx", value="mail.example.com", state=EVIDENCE_OBSERVED, collected_at=None, first_seen=None, last_seen=None, raw_reference=None):
    finding = Finding(
        investigation_id=inv_id,
        source=source,
        finding_type=finding_type,
        value=value,
        confidence=0.9,
        severity="info",
        notes=f"Evidence state: {state}. test evidence.",
        collected_at=collected_at or datetime.now(timezone.utc),
        first_seen=first_seen,
        last_seen=last_seen,
        raw_reference=raw_reference,
    )
    db.add(finding)
    db.commit()
    return finding


def test_timeline_filters_processing_and_assessment_findings():
    with Session(make_db()) as db:
        inv = add_investigation(db)
        add_finding(db, inv.id, finding_type="mx", value="mail.example.com")
        for finding_type in ("provider_status", "risk_factor", "risk_dimension", "ai_summary", "classification", "username_candidate", "domain_correlation"):
            add_finding(db, inv.id, finding_type=finding_type, value=finding_type)

        events = timeline(inv.id, db)
        assert [event["value"] for event in events] == ["mail.example.com"]
        assert all(event["kind"] == "finding" for event in events)


def test_timeline_preserves_all_evidence_states_and_does_not_expose_raw_reference():
    with Session(make_db()) as db:
        inv = add_investigation(db)
        for index, state in enumerate(EVIDENCE_STATES):
            add_finding(
                db,
                inv.id,
                source="TestProvider",
                finding_type="profile_candidate",
                value=f"profile-{index}",
                state=state,
                raw_reference={"secret_payload": "must not be serialized"},
            )

        events = timeline(inv.id, db)
        assert {event["evidence_state"] for event in events} == EVIDENCE_STATES
        assert all("raw_reference" not in event for event in events)
        assert all(event["confidence"] == 0.9 for event in events)


def test_timeline_uses_first_seen_for_observation_time_and_preserves_collection_and_last_seen():
    collected = datetime(2026, 9, 9, 6, 0)
    first_seen = collected - timedelta(days=10)
    last_seen = collected - timedelta(days=1)
    with Session(make_db()) as db:
        inv = add_investigation(db)
        add_finding(
            db,
            inv.id,
            collected_at=collected,
            first_seen=first_seen,
            last_seen=last_seen,
        )

        event = timeline(inv.id, db)[0]
        assert event["timestamp"] == first_seen
        assert event["last_seen"] == last_seen
        assert event["collected_at"] == collected


def test_timeline_uses_rdap_domain_event_date_not_collection_time():
    collected = datetime(2026, 9, 9, 6, 0, tzinfo=timezone.utc)
    event_date = datetime(2025, 1, 2, 0, 0, tzinfo=timezone.utc)
    with Session(make_db()) as db:
        inv = add_investigation(db)
        add_finding(
            db,
            inv.id,
            source="RDAP",
            finding_type="domain_event",
            value="registration: 2025-01-02T00:00:00Z",
            collected_at=collected,
            first_seen=event_date,
            raw_reference={"eventAction": "registration", "eventDate": "2025-01-02T00:00:00Z"},
        )

        event = timeline(inv.id, db)[0]
        assert event["timestamp"] == event_date
        assert event["timestamp"] != collected
        assert event["collected_at"] == collected


def test_timeline_order_is_deterministic_for_equal_timestamps_and_repeated_calls():
    timestamp = datetime(2026, 9, 9, 6, 0)
    with Session(make_db()) as db:
        inv = add_investigation(db)
        first = add_finding(db, inv.id, value="first", collected_at=timestamp)
        second = add_finding(db, inv.id, value="second", collected_at=timestamp)
        older = add_finding(db, inv.id, value="older", collected_at=timestamp - timedelta(seconds=1))

        first_result = timeline(inv.id, db)
        second_result = timeline(inv.id, db)
        assert [event["id"] for event in first_result] == [second.id, first.id, older.id]
        assert [event["id"] for event in first_result] == [event["id"] for event in second_result]


def test_timeline_deduplicates_only_exact_semantic_duplicates():
    timestamp = datetime(2026, 9, 9, 6, 0)
    with Session(make_db()) as db:
        inv = add_investigation(db)
        add_finding(db, inv.id, source="GitHub", finding_type="profile_candidate", value="johnsmith", state=EVIDENCE_POSSIBLE, collected_at=timestamp)
        add_finding(db, inv.id, source="GitHub", finding_type="profile_candidate", value="johnsmith", state=EVIDENCE_POSSIBLE, collected_at=timestamp)
        add_finding(db, inv.id, source="GitHub", finding_type="profile_candidate", value="johnsmith", state=EVIDENCE_CORROBORATED, collected_at=timestamp)
        add_finding(db, inv.id, source="GitHub", finding_type="profile_candidate", value="johnsmith", state=EVIDENCE_POSSIBLE, collected_at=timestamp + timedelta(seconds=1))

        events = timeline(inv.id, db)
        assert len(events) == 3
        assert {event["evidence_state"] for event in events} == {EVIDENCE_POSSIBLE, EVIDENCE_CORROBORATED}
        assert sum(event["evidence_state"] == EVIDENCE_POSSIBLE for event in events) == 2


def test_timeline_preserves_separate_collection_times_for_same_first_seen():
    first_seen = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    first_collection = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
    second_collection = datetime(2026, 9, 9, 0, 0, tzinfo=timezone.utc)
    with Session(make_db()) as db:
        inv = add_investigation(db)
        add_finding(
            db,
            inv.id,
            source="GitHub",
            finding_type="profile_candidate",
            value="johnsmith",
            state=EVIDENCE_POSSIBLE,
            first_seen=first_seen,
            collected_at=first_collection,
        )
        add_finding(
            db,
            inv.id,
            source="GitHub",
            finding_type="profile_candidate",
            value="johnsmith",
            state=EVIDENCE_POSSIBLE,
            first_seen=first_seen,
            collected_at=second_collection,
        )

        events = timeline(inv.id, db)
        assert len(events) == 2
        assert {event["collected_at"] for event in events} == {first_collection, second_collection}
        assert all(event["timestamp"] == first_seen for event in events)


def test_privacy_mode_continues_to_suppress_weak_profile_correlations():
    with Session(make_db()) as db:
        inv = add_investigation(db, privacy_mode=True)
        weak = {
            "source": "GitHub",
            "finding_type": "profile_candidate",
            "value": "https://github.com/johnsmith",
            "confidence": 0.95,
            "severity": "info",
            "notes": f"Evidence state: {EVIDENCE_POSSIBLE}. username only",
            "raw_reference": {"login": "johnsmith"},
        }
        add_findings(db, inv.id, [weak])
        assert timeline(inv.id, db) == []
        assert db.query(Finding).count() == 0


def test_graph_relationships_are_not_projected_as_duplicate_timeline_events():
    with Session(make_db()) as db:
        inv = add_investigation(db)
        db.add_all([
            GraphNode(investigation_id=inv.id, node_key="email:john.smith@example.com", node_type="EMAIL", label="john.smith@example.com"),
            GraphNode(investigation_id=inv.id, node_key="profile:https://github.com/johnsmith", node_type="PROFILE", label="johnsmith"),
            GraphEdge(investigation_id=inv.id, source="email:john.smith@example.com", target="profile:https://github.com/johnsmith", relation="possible_profile", confidence=0.2),
        ])
        add_finding(db, inv.id, source="GitHub", finding_type="profile_candidate", value="https://github.com/johnsmith", state=EVIDENCE_POSSIBLE)
        db.commit()

        events = timeline(inv.id, db)
        assert len(events) == 1
        assert events[0]["value"] == "https://github.com/johnsmith"

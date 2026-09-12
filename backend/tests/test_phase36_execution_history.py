from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import Base, get_db
from app.main import app
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun


def seed(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase36.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(target="alice@example.com", normalized_email="alice@example.com", username="alice", domain="example.com", status="completed", risk_score=55, risk_level="MEDIUM")
        other = Investigation(target="bob@example.com", normalized_email="bob@example.com", username="bob", domain="example.com", status="completed")
        db.add_all([inv, other]); db.commit(); db.refresh(inv); db.refresh(other)
        a = ExecutionAttempt(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-a", status="abandoned", started_at=datetime(2026, 9, 1, tzinfo=timezone.utc), finished_at=datetime(2026, 9, 1, 1, tzinfo=timezone.utc), recovered_at=datetime(2026, 9, 1, 1, tzinfo=timezone.utc), recovery_reason="worker lease expired")
        b = ExecutionAttempt(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-b", status="completed", started_at=datetime(2026, 9, 2, tzinfo=timezone.utc), finished_at=datetime(2026, 9, 2, 1, tzinfo=timezone.utc))
        foreign = ExecutionAttempt(investigation_id=other.id, execution_id=other.execution_id, execution_attempt_id="attempt-foreign", status="completed", started_at=datetime(2026, 9, 2, tzinfo=timezone.utc))
        db.add_all([a, b, foreign]); db.flush(); inv.execution_attempt_id = "attempt-b"
        db.add_all([
            Finding(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-a", source="GitHub", finding_type="profile_candidate", value="https://github.com/alice", confidence=.8, severity="info", notes="Evidence state: possible_match."),
            Finding(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-a", source="Risk", finding_type="risk_dimension", value="identity_exposure=4", confidence=1, severity="info"),
            Finding(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-b", source="GitHub", finding_type="provider_status", value="rate_limited", confidence=1, severity="warning", notes="provider limit"),
            Finding(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-b", source="Risk", finding_type="risk_dimension", value="identity_exposure=6", confidence=1, severity="info"),
            Finding(investigation_id=other.id, execution_id=other.execution_id, execution_attempt_id="attempt-foreign", source="SecretSource", finding_type="secret", value="never-return-this", confidence=1, severity="high", raw_reference={"Authorization": "Bearer super-secret"}),
        ])
        db.add_all([
            ModuleRun(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-a", module="github", status="abandoned", message="worker lease expired"),
            ModuleRun(investigation_id=inv.id, execution_id=inv.execution_id, execution_attempt_id="attempt-b", module="github", status="completed", message="ok"),
        ])
        db.commit()
    return engine, inv.id, other.id


def client_for(engine):
    def override():
        with Session(engine) as db: yield db
    app.dependency_overrides[get_db] = override
    settings = get_settings(); original = settings.api_key; settings.api_key = "phase36-test-key"
    return TestClient(app), settings, original


def test_history_http_boundary_and_ownership(tmp_path):
    engine, inv_id, other_id = seed(tmp_path); client, settings, original = client_for(engine)
    try:
        assert client.get(f"/api/investigations/{inv_id}/attempts").status_code == 401
        headers = {"Authorization": "Bearer phase36-test-key"}
        history = client.get(f"/api/investigations/{inv_id}/attempts", headers=headers)
        assert history.status_code == 200 and [x["execution_attempt_id"] for x in history.json()] == ["attempt-b", "attempt-a"]
        assert client.get("/api/investigations/999999/attempts", headers=headers).status_code == 404
        assert client.get(f"/api/investigations/{inv_id}/attempts/attempt-a", headers=headers).status_code == 200
        assert client.get(f"/api/investigations/{inv_id}/attempts/attempt-missing", headers=headers).status_code == 404
        assert client.get(f"/api/investigations/{inv_id}/attempts/attempt-foreign", headers=headers).status_code == 404
        assert client.get(f"/api/investigations/{other_id}/attempts/attempt-foreign", headers=headers).status_code == 200
    finally:
        app.dependency_overrides.clear(); settings.api_key = original


def test_attempt_detail_is_attempt_scoped_and_does_not_expose_raw_reference(tmp_path):
    engine, inv_id, _ = seed(tmp_path); client, settings, original = client_for(engine)
    try:
        headers = {"Authorization": "Bearer phase36-test-key"}
        data = client.get(f"/api/investigations/{inv_id}/attempts/attempt-a", headers=headers).json()
        assert {x["execution_attempt_id"] for x in data["findings"]} == {"attempt-a"}
        assert {x["execution_attempt_id"] for x in data["modules"]} == {"attempt-a"}
        assert data["provenance"]["execution_attempt_id"] == "attempt-a"
        assert "raw_reference" not in str(data)
        assert "super-secret" not in str(data)
    finally:
        app.dependency_overrides.clear(); settings.api_key = original


def test_comparison_is_same_investigation_only_deterministic_and_failure_is_not_removal(tmp_path):
    engine, inv_id, other_id = seed(tmp_path); client, settings, original = client_for(engine)
    try:
        headers = {"Authorization": "Bearer phase36-test-key"}
        url = f"/api/investigations/{inv_id}/attempt-comparison?before_attempt_id=attempt-a&after_attempt_id=attempt-b"
        first = client.get(url, headers=headers); second = client.get(url, headers=headers)
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        data = first.json()
        assert data["intelligence"]["removed"] == []
        assert len(data["intelligence"]["operationally_inconclusive"]) == 1
        assert data["operational"]["providers"][0]["after"] == ["rate_limited"]
        assert data["risk"]["before_dimensions"]["identity_exposure"] == 4
        assert data["risk"]["after_dimensions"]["identity_exposure"] == 6
        assert data["risk"]["dimension_deltas"] == {"identity_exposure": 2}
        assert data["provenance"]["identity_confirmation"] is False
        cross = client.get(f"/api/investigations/{inv_id}/attempt-comparison?before_attempt_id=attempt-a&after_attempt_id=attempt-foreign", headers=headers)
        assert cross.status_code == 404
        same = client.get(f"/api/investigations/{inv_id}/attempt-comparison?before_attempt_id=attempt-a&after_attempt_id=attempt-a", headers=headers)
        assert same.status_code == 422
    finally:
        app.dependency_overrides.clear(); settings.api_key = original

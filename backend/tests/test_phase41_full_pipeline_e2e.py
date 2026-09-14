from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.db.session import Base, get_db
from app.main import app
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.osint import dns
from app.osint.email import EVIDENCE_OBSERVED, EVIDENCE_SOURCE_ASSOCIATED
from app.providers.base import ProviderResult, finding
from app.providers.registry import provider_definitions
from app.services import lifecycle, orchestrator
from app.services.lifecycle import claim_investigation


class DeterministicProvider:
    def __init__(self, name):
        self.name = name

    async def run(self, context):
        if self.name == "Gravatar":
            findings = [
                finding(
                    self.name,
                    "public_identity",
                    "Alice Example",
                    0.8,
                    "info",
                    "https://provider.invalid/gravatar",
                    notes=f"Evidence state: {EVIDENCE_SOURCE_ASSOCIATED}. Association is not identity confirmation.",
                    raw_reference={
                        "evidence_state": EVIDENCE_SOURCE_ASSOCIATED,
                        "provider_payload": "SECRET-SHOULD-NOT-LEAK",
                    },
                )
            ]
        elif self.name == "RDAP":
            findings = [
                finding(
                    self.name,
                    "domain",
                    "ldhName: example.com",
                    0.98,
                    "info",
                    "https://provider.invalid/rdap",
                    evidence_state=EVIDENCE_OBSERVED,
                )
            ]
        elif self.name == "GitHub":
            findings = [
                finding(
                    self.name,
                    "profile",
                    "https://github.com/alice",
                    0.8,
                    "info",
                    "https://provider.invalid/github",
                    notes=f"Evidence state: {EVIDENCE_SOURCE_ASSOCIATED}. Public account association is not human-identity confirmation.",
                    raw_reference={
                        "login": "alice",
                        "provider_payload": "SECRET-SHOULD-NOT-LEAK",
                        "evidence_state": EVIDENCE_SOURCE_ASSOCIATED,
                    },
                )
            ]
        elif self.name == "GitLab":
            return ProviderResult(self.name, "rate_limited", message="deterministic test rate limit")
        elif self.name == "Have I Been Pwned":
            findings = [
                finding(
                    self.name,
                    "breach",
                    "ExampleForum-2024",
                    0.99,
                    "high",
                    "https://provider.invalid/hibp",
                    notes="Historical breach exposure only; no active compromise assertion.",
                    raw_reference={"data_classes": ["Email addresses"], "provider_payload": "SECRET-SHOULD-NOT-LEAK"},
                    first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
                )
            ]
        else:
            findings = [
                finding(
                    self.name,
                    "public_web_reference",
                    "https://example.com/alice",
                    0.5,
                    "info",
                    "https://provider.invalid/search",
                    notes="Public search reference only. Evidence state: possible_match.",
                    raw_reference={"provider_payload": "SECRET-SHOULD-NOT-LEAK"},
                    evidence_state="possible_match",
                )
            ]
        return ProviderResult(self.name, "ok", findings=findings, message="deterministic passive provider result")


def _test_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase41.db'}", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine, expire_on_commit=False)
    return engine, Session


def test_authoritative_full_pipeline_is_durable_and_provider_network_free(monkeypatch, tmp_path):
    """Exercise the real lifecycle/orchestrator/provider/API pipeline with no external network."""
    engine, Session = _test_db(tmp_path)

    def override_get_db():
        with Session() as db:
            yield db

    async def fake_dns(_domain):
        return {
            "A": ["93.184.216.34"],
            "AAAA": [],
            "MX": ["10 mail.example.com"],
            "NS": [],
            "CNAME": [],
            "SPF_status": "ok",
            "SPF_analysis": {"policy": "-all"},
            "DMARC_status": "ok",
            "DMARC_analysis": {"policy": "quarantine"},
            "DKIM_analysis": [],
            "DNSSEC": True,
            "MX_PROVIDER": "Example Mail",
            "NS_PROVIDER": None,
            "IP_CONTEXT": [],
        }

    monkeypatch.setattr(orchestrator, "SessionLocal", Session)
    monkeypatch.setattr(lifecycle, "SessionLocal", Session)
    monkeypatch.setattr(orchestrator, "resolve", fake_dns)
    monkeypatch.setattr(orchestrator.OllamaProvider, "summarize", lambda *args, **kwargs: "Deterministic local summary")
    monkeypatch.setattr(orchestrator, "PROVIDER_FACTORY_RESOLVERS", {
        definition.name: (lambda name=definition.name: DeterministicProvider(name))
        for definition in provider_definitions(orchestrated=True)
        if definition.factory is not None
    })

    settings = get_settings()
    old_key = settings.api_key
    settings.api_key = "phase41-test-key"
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as client:
            assert client.get("/api/investigations").status_code == 401
            headers = {"Authorization": "Bearer phase41-test-key"}

            created = client.post(
                "/api/investigations",
                json={"email": "alice@example.com", "privacy_mode": False, "external_provider_disclosure": True},
                headers=headers,
            )
            assert created.status_code == 200
            inv_id = created.json()["id"]

            with Session() as db:
                token = claim_investigation(db, inv_id, now=datetime(2026, 9, 14, 12, tzinfo=timezone.utc))
            assert token

            import asyncio
            asyncio.run(orchestrator.run_investigation(inv_id, token))

            with Session() as db:
                inv = db.get(Investigation, inv_id)
                assert inv.status == "completed"
                assert inv.execution_id
                assert inv.execution_attempt_id
                attempt = db.scalar(select(ExecutionAttempt).where(
                    ExecutionAttempt.investigation_id == inv_id,
                    ExecutionAttempt.execution_attempt_id == inv.execution_attempt_id,
                ))
                assert attempt is not None
                assert attempt.execution_id == inv.execution_id
                assert attempt.status == "completed"

                modules = db.scalars(select(ModuleRun).where(
                    ModuleRun.investigation_id == inv_id,
                    ModuleRun.execution_attempt_id == inv.execution_attempt_id,
                )).all()
                assert modules
                assert all(m.execution_id == inv.execution_id for m in modules)
                assert all(m.execution_attempt_id == inv.execution_attempt_id for m in modules)
                assert any(m.module == "public_profile_discovery" and m.status == "completed" for m in modules)
                assert any(m.module == "gitlab" and m.status == "completed" for m in modules)

                findings = db.scalars(select(Finding).where(
                    Finding.investigation_id == inv_id,
                    Finding.execution_attempt_id == inv.execution_attempt_id,
                )).all()
                assert findings
                assert all(f.execution_id == inv.execution_id for f in findings)
                assert any(f.finding_type == "breach" for f in findings)
                assert any(f.finding_type == "provider_status" and f.value == "rate_limited" for f in findings)
                assert all(f.raw_reference is None or "provider_payload" not in f.raw_reference for f in findings)

            execution = client.get(f"/api/investigations/{inv_id}/execution", headers=headers)
            assert execution.status_code == 200
            execution_data = execution.json()
            assert execution_data["execution_id"] == inv.execution_id
            assert execution_data["execution_attempt_id"] == inv.execution_attempt_id
            assert "rate_limited" in execution_data["provider_statuses"]

            correlations = client.get(f"/api/investigations/{inv_id}/correlations", headers=headers)
            assert correlations.status_code == 200
            correlation_data = correlations.json()
            assert correlation_data["execution_attempt_id"] == inv.execution_attempt_id
            assert any(r["relationship"] == "username_to_public_account" for r in correlation_data["relationships"])
            assert all("identity confirmation" not in r["explanation"].lower() for r in correlation_data["relationships"])

            risk = client.get(f"/api/investigations/{inv_id}/risk", headers=headers)
            assert risk.status_code == 200
            assert risk.json()["score"] == inv.risk_score
            assert risk.json()["level"] == inv.risk_level

            graph = client.get(f"/api/investigations/{inv_id}/graph", headers=headers)
            assert graph.status_code == 200
            graph_data = graph.json()
            assert graph_data["semantics"] == "current_derived_view"
            assert graph_data["provenance"]["execution_attempt_id"] == inv.execution_attempt_id
            assert any(n["id"] == "email:alice@example.com" for n in graph_data["nodes"])
            assert any(n["id"] == "profile:https://github.com/alice" for n in graph_data["nodes"])
            assert any(e["relation"] == "uses" for e in graph_data["edges"])

            timeline = client.get(f"/api/investigations/{inv_id}/timeline", headers=headers)
            assert timeline.status_code == 200
            timeline_data = timeline.json()
            assert any(e["finding_type"] == "breach" if "finding_type" in e else e["label"] == "breach" for e in timeline_data)
            assert all(e["execution_attempt_id"] == inv.execution_attempt_id for e in timeline_data)

            report = client.get(f"/api/investigations/{inv_id}/report?format=json", headers=headers)
            assert report.status_code == 200
            report_data = report.json()
            assert report_data["provenance"]["execution_attempt_id"] == inv.execution_attempt_id
            assert any(f["finding_type"] == "breach" for f in report_data["findings"])
            assert "SECRET-SHOULD-NOT-LEAK" not in report.text
            assert all("raw_reference" not in f for f in report_data["findings"])

            with Session() as db:
                inv = db.get(Investigation, inv_id)
                historical = ExecutionAttempt(
                    investigation_id=inv_id,
                    execution_id=inv.execution_id,
                    execution_attempt_id="historical-attempt",
                    status="completed",
                    started_at=datetime(2026, 9, 13, tzinfo=timezone.utc),
                    finished_at=datetime(2026, 9, 13, 1, tzinfo=timezone.utc),
                )
                db.add(historical)
                db.flush()
                db.add(Finding(
                    investigation_id=inv_id,
                    execution_id=inv.execution_id,
                    execution_attempt_id="historical-attempt",
                    source="HistoricalTest",
                    finding_type="breach",
                    value="HistoricalOnly-DoNotLeak",
                    confidence=1.0,
                    severity="high",
                ))
                db.commit()

            current_graph = client.get(f"/api/investigations/{inv_id}/graph", headers=headers).json()
            assert all(n["label"] != "HistoricalOnly-DoNotLeak" for n in current_graph["nodes"])
            current_risk = client.get(f"/api/investigations/{inv_id}/risk", headers=headers).json()
            assert all(f["reason"] != "HistoricalOnly-DoNotLeak" for f in current_risk["factors"])
            current_correlations = client.get(f"/api/investigations/{inv_id}/correlations", headers=headers).json()
            assert all(r["target"] != "HistoricalOnly-DoNotLeak" for r in current_correlations["relationships"])
    finally:
        app.dependency_overrides.clear()
        settings.api_key = old_key
        engine.dispose()

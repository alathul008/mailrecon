import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import Finding, Investigation
from app.osint.email import (
    EVIDENCE_CORROBORATED,
    EVIDENCE_DERIVED,
    EVIDENCE_POSSIBLE,
    EVIDENCE_SOURCE_ASSOCIATED,
    username_candidates,
)
from app.providers.github import GitHubProvider
from app.providers.gravatar import GravatarProvider
from app.providers import github as github_module
from app.providers import gravatar as gravatar_module
from app.risk.engine import calculate
from app.services.orchestrator import add_findings, _finding_evidence_state, _rdap_domain_consistency, _graph_relation
from app.providers.base import ProviderResult
import httpx


class FakeClient:
    response = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return type(self).response


def response(status=200, json_data=None):
    return httpx.Response(status, json=json_data)


def patch_client(monkeypatch, module, json_data):
    FakeClient.response = response(json_data=json_data)
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(module, "validate_provider_url", lambda url: url)


def test_username_normalization_is_deterministic_and_collision_prone_but_derived():
    assert username_candidates("John.Doe+tag") == ["john-doe", "john.doe", "john_doe", "johndoe"]
    assert username_candidates("john-doe") == ["john-doe", "john.doe", "john_doe", "johndoe"]
    assert set(username_candidates("john.doe")) == set(username_candidates("john-doe"))


def test_evidence_states_are_not_numeric_confidence():
    rows = [
        {"notes": f"Evidence state: {EVIDENCE_DERIVED}. hypothesis only", "confidence": 0.0},
        {"notes": f"Evidence state: {EVIDENCE_POSSIBLE}. weak correlation", "confidence": 0.95},
        {"notes": f"Evidence state: {EVIDENCE_CORROBORATED}. exact public email", "confidence": 0.95},
        {"notes": f"Evidence state: {EVIDENCE_SOURCE_ASSOCIATED}. source association", "confidence": 0.99},
    ]
    assert [_finding_evidence_state(type("Row", (), row)()) for row in rows] == [EVIDENCE_DERIVED, EVIDENCE_POSSIBLE, EVIDENCE_CORROBORATED, EVIDENCE_SOURCE_ASSOCIATED]


def test_confidence_does_not_override_evidence_state():
    analysis = {"disposable": False, "suspicious_chars": False, "idn": False, "has_dmarc": True, "has_spf": True, "dnssec": None}
    weak = [{"finding_type": "profile_candidate", "value": "https://github.com/johnsmith", "confidence": 0.99, "notes": f"Evidence state: {EVIDENCE_POSSIBLE}. username only"}]
    assert calculate(analysis, weak).dimensions["identity_exposure"] == 0


def test_risk_ignores_weak_profile_evidence_but_accepts_corroborated_profile():
    analysis = {"disposable": False, "suspicious_chars": False, "idn": False, "has_dmarc": True, "has_spf": True, "dnssec": None}
    weak = [{"finding_type": "profile_candidate", "value": "https://github.com/johnsmith", "confidence": 0.95, "notes": f"Evidence state: {EVIDENCE_POSSIBLE}. username only"}]
    strong = [{"finding_type": "profile_candidate", "value": "https://github.com/johnsmith", "confidence": 0.95, "notes": f"Evidence state: {EVIDENCE_CORROBORATED}. exact public email"}]
    assert calculate(analysis, weak).dimensions["identity_exposure"] == 0
    assert calculate(analysis, strong).dimensions["identity_exposure"] == 8


def test_unknown_dnssec_has_no_penalty():
    analysis = {"disposable": False, "suspicious_chars": False, "idn": False, "has_dmarc": None, "has_spf": None, "dnssec": None}
    result = calculate(analysis, [])
    assert result.score == 0
    assert result.dimensions["domain_security"] == 0
    assert not any("DNSSEC" in f["reason"] for f in result.factors)


def test_rdap_domain_mismatch_is_warning_not_identity_assertion():
    result = _rdap_domain_consistency(
        "example.com",
        ProviderResult("RDAP", "ok", findings=[{"finding_type": "domain", "value": "ldhName: other.example"}]),
    )
    assert result is not None
    assert result["finding_type"] == "domain_correlation"
    assert "mismatch" in result["value"]
    assert result["severity"] == "warning"


def test_graph_relations_preserve_evidence_state():
    assert _graph_relation("profile_candidate", EVIDENCE_DERIVED) == "possible_profile"
    assert _graph_relation("profile_candidate", EVIDENCE_POSSIBLE) == "possible_profile"
    assert _graph_relation("profile_candidate", EVIDENCE_CORROBORATED) == "corroborated_profile"
    assert _graph_relation("public_identity", EVIDENCE_SOURCE_ASSOCIATED) == "source_associated_identity"
    assert _graph_relation("breach", None) == "historical_breach_exposure"
    assert _graph_relation("profile_candidate", EVIDENCE_CORROBORATED) != "associated_identity"


@pytest.mark.asyncio
async def test_github_username_only_is_possible_and_exact_email_is_corroborated(monkeypatch):
    patch_client(monkeypatch, github_module, {"login": "johnsmith", "name": "John Smith", "html_url": "https://github.com/johnsmith"})
    result = await GitHubProvider().run(["johnsmith"], "john.smith@example.com")
    assert result.findings[0]["confidence"] == 0.45
    assert EVIDENCE_POSSIBLE in result.findings[0]["notes"]

    patch_client(monkeypatch, github_module, {"login": "johnsmith", "name": "John Smith", "email": "john.smith@example.com", "html_url": "https://github.com/johnsmith"})
    result = await GitHubProvider().run(["johnsmith"], "john.smith@example.com")
    assert result.findings[0]["confidence"] == 0.95
    assert EVIDENCE_CORROBORATED in result.findings[0]["notes"]
    assert "confirmed" not in result.findings[0]["notes"].lower()


@pytest.mark.asyncio
async def test_gravatar_attributes_are_source_associated_not_confirmed_identity(monkeypatch):
    patch_client(monkeypatch, gravatar_module, {"entry": [{"displayName": "John Smith", "profileUrl": "https://gravatar.com/john"}]})
    result = await GravatarProvider().run("john.smith@example.com")
    assert {f["finding_type"] for f in result.findings} == {"public_identity", "profile"}
    assert all(EVIDENCE_SOURCE_ASSOCIATED in f["notes"] for f in result.findings)
    assert all("confirmed" not in f["notes"].lower() for f in result.findings)


def test_privacy_mode_suppresses_weak_profile_correlations():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(target="john.smith@example.com", normalized_email="john.smith@example.com", username="john.smith", domain="example.com", privacy_mode=True)
        db.add(inv)
        db.commit()
        weak = {"source": "GitHub", "finding_type": "profile_candidate", "value": "https://github.com/johnsmith", "confidence": 0.95, "severity": "info", "notes": f"Evidence state: {EVIDENCE_POSSIBLE}. username only", "raw_reference": {"login": "johnsmith"}}
        add_findings(db, inv.id, [weak])
        assert db.query(Finding).count() == 0


def test_privacy_mode_keeps_corroborated_profile_but_strips_raw_reference():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(target="john.smith@example.com", normalized_email="john.smith@example.com", username="john.smith", domain="example.com", privacy_mode=True)
        db.add(inv)
        db.commit()
        strong = {"source": "GitHub", "finding_type": "profile_candidate", "value": "https://github.com/johnsmith", "confidence": 0.95, "severity": "info", "notes": f"Evidence state: {EVIDENCE_CORROBORATED}. exact public email", "raw_reference": {"login": "johnsmith", "email": "john.smith@example.com"}}
        add_findings(db, inv.id, [strong])
        stored = db.query(Finding).one()
        assert stored.raw_reference is None
        assert _finding_evidence_state(stored) == EVIDENCE_CORROBORATED


def test_historical_breach_does_not_mean_active_compromise():
    result = calculate(
        {"disposable": False, "suspicious_chars": False, "idn": False, "has_dmarc": True, "has_spf": True, "dnssec": None},
        [{"finding_type": "breach", "value": "Example-2024", "confidence": 0.99, "notes": "Historical breach exposure only; not active compromise."}],
    )
    assert result.dimensions["breach_exposure"] == 18
    assert all("active compromise" not in f["reason"].lower() for f in result.factors)

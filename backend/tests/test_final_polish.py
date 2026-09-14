from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import Base, validate_finding_execution_provenance
from app.main import app
from app.models import Finding


def test_openapi_exposes_authoritative_core_response_models():
    schema = app.openapi()
    assert schema["paths"]["/api/investigations/{inv_id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/InvestigationOut")
    assert schema["paths"]["/api/investigations/{inv_id}/findings"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["items"]["$ref"].endswith("/FindingOut")
    assert schema["paths"]["/api/investigations/{inv_id}/graph"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("/GraphOut")


def test_core_investigation_response_semantics_remain_compatible():
    settings = get_settings()
    original = settings.api_key
    settings.api_key = "test-secret-key"
    try:
        with TestClient(app) as client:
            response = client.get(
                "/api/investigations/999999",
                headers={"Authorization": "Bearer test-secret-key"},
            )
            assert response.status_code == 404
    finally:
        settings.api_key = original


def test_csp_uses_explicit_configured_connect_origins():
    settings = get_settings()
    original = settings.csp_connect_src
    settings.csp_connect_src = "https://api.example.com https://api.internal.example"
    try:
        with TestClient(app) as client:
            header = client.get("/api/health").headers["content-security-policy"]
            assert "connect-src 'self' https://api.example.com https://api.internal.example" in header
            assert "connect-src *" not in header
    finally:
        settings.csp_connect_src = original


def test_finding_provenance_invariant_allows_legacy_rows_without_execution_identity():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        legacy = Finding(
            investigation_id=1,
            source="legacy",
            finding_type="email",
            value="legacy@example.com",
            confidence=1.0,
            severity="info",
        )
        # The helper checks only the production execution-derived invariant; the
        # legacy fixture remains intentionally compatible.
        validate_finding_execution_provenance(legacy)


def test_finding_provenance_invariant_rejects_execution_without_attempt():
    finding = Finding(
        investigation_id=1,
        execution_id="execution-1",
        source="test",
        finding_type="email",
        value="user@example.com",
        confidence=1.0,
        severity="info",
    )
    try:
        validate_finding_execution_provenance(finding)
    except RuntimeError as exc:
        assert str(exc) == "Execution-derived Finding requires execution-attempt provenance"
    else:
        raise AssertionError("Expected execution-derived Finding without attempt provenance to fail")

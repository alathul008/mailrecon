import pytest

from app.osint.service_catalog import build_account_discovery_matrix
from app.providers.base import ProviderContext
from app.providers.public_web import PublicWebProvider


@pytest.mark.asyncio
async def test_public_web_is_explicitly_unconfigured_without_endpoint(monkeypatch):
    class Settings:
        public_web_search_url = None
        public_web_search_token = None

    monkeypatch.setattr("app.providers.public_web.get_settings", lambda: Settings())
    result = await PublicWebProvider().run(ProviderContext(email="target@example.com", domain="example.com", candidates=("target", "target_dev")))
    assert result.status == "unconfigured"
    assert result.findings == []


def test_public_web_query_plan_is_bounded_and_exact_email_first():
    context = ProviderContext(email="target@example.com", domain="example.com", candidates=("target", "target_dev", "third", "fourth", "fifth"))
    queries = PublicWebProvider()._queries(context)
    assert queries == [
        '"target@example.com"',
        '"target"',
        '"target_dev"',
        '"third"',
        '"fourth"',
    ]


def test_public_web_evidence_is_possible_not_identity_confirmation():
    findings = [{"source":"Public Web","finding_type":"public_web_reference","value":"Example public result","confidence":0.55,"evidence_state":"possible_match","source_url":"https://example.test/public-result"}]
    matrix = build_account_discovery_matrix(findings)
    row = next(item for item in matrix if item["service"] == "Public Web")
    assert row["status"] == "POSSIBLE"
    assert row["evidence"][0]["finding_type"] == "public_web_reference"
    assert row["evidence"][0]["evidence_state"] == "possible_match"

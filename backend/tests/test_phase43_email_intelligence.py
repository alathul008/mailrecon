import pytest

from app.providers.base import ProviderResult
from app.providers.email_intelligence import EmailIntelligenceProvider
from app.providers.public_profile_network import PublicProfileNetworkProvider
from app.providers.registry import provider_definition


def test_email_intelligence_is_registered_for_dedicated_execution():
    definition = provider_definition("Email Intelligence")
    assert definition.supported is True
    assert definition.account_discovery is False
    assert definition.orchestrated is False
    assert definition.argument_mode == "email"
    assert definition.module == "email_intelligence"
    assert definition.factory is EmailIntelligenceProvider


@pytest.mark.asyncio
async def test_email_intelligence_surfaces_profiles_breaches_and_public_accounts(monkeypatch):
    async def fake_get_json(self, url, headers, *, not_found_ok=False):
        if "emailrep.io" in url:
            return {"reputation": "high", "details": {"profiles": ["github", "linkedin", "spotify"], "data_breach": True, "credentials_leaked": True}}, None
        return {"status": "success", "breaches": [["Adobe", "LinkedIn"]]}, None

    async def fake_public_profiles(self, context):
        return ProviderResult("Public Profile Network", "ok", findings=[{"source":"Public Profile Network","source_url":"https://dev.to/user","finding_type":"profile_candidate","value":"user","confidence":0.72,"severity":"info","evidence_state":"observed","notes":"Public Dev.to profile observed.","raw_reference":None,"collected_at":None}], message="1 public username profiles observed across 6 services")

    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", fake_get_json)
    monkeypatch.setattr(PublicProfileNetworkProvider, "run", fake_public_profiles)
    result = await EmailIntelligenceProvider().run(type("Context", (), {"email":"user@example.com","domain":"example.com","candidates":("user",)})())
    assert result.status == "ok"
    assert {f["value"] for f in result.findings if f["finding_type"] == "profile_observation"} == {"github", "linkedin", "spotify"}
    assert {f["value"] for f in result.findings if f["finding_type"] == "breach"} == {"Adobe", "LinkedIn"}
    assert {f["value"] for f in result.findings if f["finding_type"] == "exposure_signal"} == {"data_breach", "credentials_leaked"}
    assert any(f["finding_type"] == "profile_candidate" and f["source"] == "Public Profile Network" for f in result.findings)


@pytest.mark.asyncio
async def test_email_intelligence_source_failure_is_unavailable(monkeypatch):
    async def failed_get_json(self, url, headers, *, not_found_ok=False):
        return None, ProviderResult("Email Intelligence", "unavailable", message="offline")
    async def unavailable_public_profiles(self, context):
        return ProviderResult("Public Profile Network", "unavailable", message="offline")
    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", failed_get_json)
    monkeypatch.setattr(PublicProfileNetworkProvider, "run", unavailable_public_profiles)
    result = await EmailIntelligenceProvider().run(type("Context", (), {"email":"user@example.com","domain":"example.com","candidates":("user",)})())
    assert result.status == "unavailable"
    assert result.findings == []


@pytest.mark.asyncio
async def test_email_intelligence_accepts_xposedornot_no_breach_404(monkeypatch):
    async def fake_get_json(self, url, headers, *, not_found_ok=False):
        if "emailrep.io" in url: return {"reputation":"high","details":{"profiles":[]}}, None
        assert not_found_ok is True
        return {}, None
    async def no_public_profiles(self, context):
        return ProviderResult("Public Profile Network", "ok", message="0 public username profiles observed across 6 services")
    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", fake_get_json)
    monkeypatch.setattr(PublicProfileNetworkProvider, "run", no_public_profiles)
    result = await EmailIntelligenceProvider().run(type("Context", (), {"email":"clean@example.com","domain":"example.com","candidates":("clean",)})())
    assert result.status == "ok"
    assert any(f["finding_type"] == "breach_summary" and f["value"] == "0" for f in result.findings)

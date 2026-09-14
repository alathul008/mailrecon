import pytest

from app.providers.base import ProviderResult
from app.providers.email_intelligence import EmailIntelligenceProvider


@pytest.mark.asyncio
async def test_email_intelligence_surfaces_profiles_and_breaches(monkeypatch):
    async def fake_get_json(self, url, headers, *, not_found_ok=False):
        if "emailrep.io" in url:
            return {
                "reputation": "high",
                "details": {
                    "profiles": ["github", "linkedin", "spotify"],
                    "data_breach": True,
                    "credentials_leaked": True,
                },
            }, None
        return {"status": "success", "breaches": [["Adobe", "LinkedIn"]]}, None

    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", fake_get_json)
    result = await EmailIntelligenceProvider().run(
        type("Context", (), {"email": "user@example.com", "domain": "example.com", "candidates": ("user",)})()
    )
    assert result.status == "ok"
    assert {f["value"] for f in result.findings if f["finding_type"] == "profile_observation"} == {"github", "linkedin", "spotify"}
    assert {f["value"] for f in result.findings if f["finding_type"] == "breach"} == {"Adobe", "LinkedIn"}
    assert {f["value"] for f in result.findings if f["finding_type"] == "exposure_signal"} == {"data_breach", "credentials_leaked"}


@pytest.mark.asyncio
async def test_email_intelligence_source_failure_is_unavailable(monkeypatch):
    async def failed_get_json(self, url, headers, *, not_found_ok=False):
        return None, ProviderResult("Email Intelligence", "unavailable", message="offline")

    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", failed_get_json)
    result = await EmailIntelligenceProvider().run(
        type("Context", (), {"email": "user@example.com", "domain": "example.com", "candidates": ("user",)})()
    )
    assert result.status == "unavailable"
    assert result.findings == []


@pytest.mark.asyncio
async def test_email_intelligence_accepts_xposedornot_no_breach_404(monkeypatch):
    async def fake_get_json(self, url, headers, *, not_found_ok=False):
        if "emailrep.io" in url:
            return {"reputation": "high", "details": {"profiles": []}}, None
        assert not_found_ok is True
        return {}, None

    monkeypatch.setattr(EmailIntelligenceProvider, "_get_json", fake_get_json)
    result = await EmailIntelligenceProvider().run(
        type("Context", (), {"email": "clean@example.com", "domain": "example.com", "candidates": ("clean",)})()
    )
    assert result.status == "ok"
    assert any(f["finding_type"] == "breach_summary" and f["value"] == "0" for f in result.findings)

import asyncio
from datetime import datetime, timezone

from app.osint.account_discovery import default_providers, discover_public_accounts, normalize_target
from app.osint.service_catalog import build_account_discovery_matrix
from app.providers.base import ProviderResult, finding


class FakeProvider:
    def __init__(self, name, result=None, exc=None):
        self.name = name
        self.result = result
        self.exc = exc

    async def run(self, email, candidates=None):
        if self.exc:
            raise self.exc
        return self.result


def test_email_normalization_and_username_extraction():
    target = normalize_target("  User.Name+test@Example.COM ")
    assert target.email == "User.Name+test@example.com"
    assert target.username == "User.Name+test"
    assert target.domain == "example.com"


def test_default_provider_selection_is_explicit():
    assert [provider.name for provider in default_providers()] == ["Gravatar", "GitHub", "GitLab", "Have I Been Pwned"]


def test_provider_success_and_evidence_preservation_are_deterministic():
    checked = datetime.now(timezone.utc)
    provider = FakeProvider("GitHub", ProviderResult("GitHub", "ok", [finding("GitHub", "profile_candidate", "https://github.com/example", .45, source_url="https://github.com/example", notes="Evidence state: possible_match.")], checked_at=checked))
    result = asyncio.run(discover_public_accounts("User@Example.com", providers=(provider,)))
    assert result["target"].email == "User@example.com"
    assert result["providers"][0]["status"] == "OK"
    assert result["providers"][0]["checked_at"] == checked
    assert result["findings"][0]["evidence_state"] == "possible_match"


def test_failure_timeout_and_unconfigured_statuses_never_become_negative_evidence():
    providers = (FakeProvider("Failure", exc=RuntimeError("boom")), FakeProvider("Timeout", exc=asyncio.TimeoutError()), FakeProvider("Unconfigured", ProviderResult("Unconfigured", "unconfigured", message="missing key")))
    result = asyncio.run(discover_public_accounts("user@example.com", providers=providers))
    assert [row["status"] for row in result["providers"]] == ["ERROR", "ERROR", "UNCONFIGURED"]
    assert result["findings"] == []


def test_no_public_evidence_is_distinct_from_unavailable():
    findings = [{"source": "GitHub", "finding_type": "provider_status", "value": "ok", "confidence": 1.0}, {"source": "GitLab", "finding_type": "provider_status", "value": "unavailable", "confidence": 1.0}]
    rows = build_account_discovery_matrix(findings)
    assert next(r for r in rows if r["service"] == "GitHub")["status"] == "NO PUBLIC EVIDENCE"
    assert next(r for r in rows if r["service"] == "GitLab")["status"] == "UNAVAILABLE"


def test_corroborated_match_and_confidence_are_preserved():
    rows = build_account_discovery_matrix([{"source": "GitLab", "finding_type": "profile_candidate", "value": "https://gitlab.com/example", "confidence": .95, "evidence_state": "corroborated_match", "source_url": "https://gitlab.com/example", "notes": "exact public email match"}])
    row = next(r for r in rows if r["service"] == "GitLab")
    assert row["status"] == "FOUND"
    assert row["confidence"] == .95
    assert row["evidence"][0]["evidence_state"] == "corroborated_match"
    assert row["evidence"][0]["source_url"] == "https://gitlab.com/example"


def test_duplicate_findings_are_removed():
    provider = FakeProvider("GitHub", ProviderResult("GitHub", "ok", [finding("GitHub", "profile_candidate", "https://github.com/example", .45), finding("GitHub", "profile_candidate", "https://github.com/example", .45)]))
    result = asyncio.run(discover_public_accounts("user@example.com", providers=(provider,)))
    assert len(result["findings"]) == 1


def test_privacy_mode_external_disclosure_disables_all_providers():
    provider = FakeProvider("GitHub", ProviderResult("GitHub", "ok", [finding("GitHub", "profile_candidate", "https://github.com/example")]))
    result = asyncio.run(discover_public_accounts("user@example.com", providers=(provider,), allow_external=False))
    assert result["findings"] == []
    assert result["providers"][0]["status"] == "DISABLED"


def test_gaming_services_remain_unsupported():
    rows = build_account_discovery_matrix([])
    for service in ("Steam", "Epic Games", "EA", "Ubisoft", "Battle.net", "Xbox", "PlayStation", "Nintendo", "Twitch"):
        row = next(r for r in rows if r["service"] == service)
        assert row["supported"] is False
        assert row["status"] == "UNAVAILABLE"
        assert row["evidence"] == []

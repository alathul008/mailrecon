import pytest

from app.osint.service_catalog import SERVICE_CATALOG, build_account_discovery_matrix
from app.providers.registry import OPERATIONAL_STATES, PROVIDER_REGISTRY, provider_definitions


def test_provider_registry_is_unique_and_covers_orchestrated_and_account_discovery_sets():
    names = [item.name for item in PROVIDER_REGISTRY]
    assert len(names) == len(set(names))
    assert {item.name for item in provider_definitions(orchestrated=True) if item.factory} == {
        "RDAP", "Gravatar", "GitHub", "GitLab", "Have I Been Pwned", "Public Web"
    }
    assert {item.name for item in provider_definitions(account_discovery=True)} == {
        "Gravatar", "GitHub", "GitLab", "Have I Been Pwned", "Public Web"
    }
    for item in PROVIDER_REGISTRY:
        assert item.supported is True or item.name in {"DNS", "Ollama"}
    assert OPERATIONAL_STATES == ("ok", "unconfigured", "rate_limited", "unavailable", "error", "disabled")


def test_service_catalog_derives_implemented_provider_metadata_and_gitlab_is_supported():
    rows = {item.name: item for item in SERVICE_CATALOG}
    assert rows["GitLab"].supported is True
    assert rows["GitLab"].provider == "GitLab"
    assert rows["Public Web"].supported is True
    assert rows["Steam"].supported is False
    assert rows["Steam"].provider is None


def test_account_matrix_preserves_full_evidence_contract():
    findings = [
        {
            "id": 41,
            "source": "GitLab",
            "source_url": "https://gitlab.com/example",
            "finding_type": "profile_candidate",
            "value": "https://gitlab.com/example",
            "confidence": 0.95,
            "evidence_state": "corroborated_match",
            "notes": "Exact public email association.",
            "collected_at": "2026-09-12T00:00:00+00:00",
        },
        {
            "id": 42,
            "source": "GitLab",
            "source_url": None,
            "finding_type": "provider_status",
            "value": "ok",
            "confidence": 1.0,
            "evidence_state": None,
            "notes": "1 public GitLab profile matches",
            "collected_at": "2026-09-12T00:00:00+00:00",
        },
    ]
    row = next(item for item in build_account_discovery_matrix(findings) if item["service"] == "GitLab")
    assert row["status"] == "FOUND"
    assert row["provider_status"] == "ok"
    assert row["checked_at"] == "2026-09-12T00:00:00+00:00"
    evidence = row["evidence"][0]
    assert evidence == {
        "finding_id": 41,
        "finding_type": "profile_candidate",
        "evidence_state": "corroborated_match",
        "confidence": 0.95,
        "source": "GitLab",
        "source_url": "https://gitlab.com/example",
        "notes": "Exact public email association.",
        "collected_at": "2026-09-12T00:00:00+00:00",
    }


def test_provider_failures_never_project_as_negative_account_evidence():
    for status, expected in (("unavailable", "UNAVAILABLE"), ("unconfigured", "UNCONFIGURED"), ("rate_limited", "RATE LIMITED"), ("error", "ERROR"), ("disabled", "DISABLED")):
        matrix = build_account_discovery_matrix([
            {"source": "Public Web", "finding_type": "provider_status", "value": status},
        ])
        row = next(item for item in matrix if item["service"] == "Public Web")
        assert row["status"] == expected


def test_public_web_possible_evidence_correlates_without_identity_confirmation():
    from app.osint.correlation import correlate

    result = correlate(
        "target@example.com",
        "example.com",
        [{
            "id": 9,
            "source": "Public Web",
            "finding_type": "public_web_reference",
            "value": "Public result",
            "confidence": 0.55,
            "evidence_state": "possible_match",
            "source_url": "https://example.com/result",
            "notes": "Public search correlation; not identity confirmation.",
        }],
    )
    relationship = next(item for item in result["relationships"] if item["relationship"] == "public_web_observation")
    assert relationship["evidence_state"] == "possible_match"
    assert relationship["confidence"] == 0.55
    assert "does not confirm account ownership" in relationship["limitations"]

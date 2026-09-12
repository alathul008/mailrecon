from app.core.config import Settings
from app.osint.service_catalog import build_account_discovery_matrix


def test_mailrecon_api_key_environment_alias(monkeypatch):
    monkeypatch.setenv("MAILRECON_API_KEY", "test-secret")
    settings = Settings(_env_file=None)
    assert settings.api_key == "test-secret"


def test_account_matrix_keeps_provider_failure_out_of_evidence():
    rows = build_account_discovery_matrix([
        {
            "id": 1,
            "source": "GitHub",
            "finding_type": "provider_status",
            "value": "unavailable",
            "confidence": 1.0,
            "evidence_state": None,
            "source_url": None,
        }
    ])
    github = next(row for row in rows if row["service"] == "GitHub")
    assert github["status"] == "UNAVAILABLE"
    assert github["identifier"] is None
    assert github["evidence"] == []


def test_account_matrix_distinguishes_possible_from_correlated():
    rows = build_account_discovery_matrix([
        {
            "id": 7,
            "source": "GitHub",
            "finding_type": "profile_candidate",
            "value": "https://github.com/example",
            "confidence": 0.45,
            "evidence_state": "possible_match",
            "source_url": "https://github.com/example",
        }
    ])
    github = next(row for row in rows if row["service"] == "GitHub")
    assert github["status"] == "POSSIBLE"
    assert github["confidence"] == 0.45

    rows = build_account_discovery_matrix([
        {
            "id": 8,
            "source": "GitHub",
            "finding_type": "profile_candidate",
            "value": "https://github.com/example",
            "confidence": 0.95,
            "evidence_state": "corroborated_match",
            "source_url": "https://github.com/example",
        }
    ])
    github = next(row for row in rows if row["service"] == "GitHub")
    assert github["status"] == "FOUND"


def test_unsupported_gaming_services_are_explicitly_unavailable():
    rows = build_account_discovery_matrix([])
    steam = next(row for row in rows if row["service"] == "Steam")
    assert steam["supported"] is False
    assert steam["status"] == "UNAVAILABLE"
    assert steam["identifier"] is None

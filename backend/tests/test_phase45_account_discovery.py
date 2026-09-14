import pytest

from app.osint.service_catalog import build_account_discovery_matrix
from app.providers.public_profile_network import PublicProfileNetworkProvider


def _finding(source, finding_type, value, confidence=0.72, evidence_state="observed", source_url="https://dev.to/user"):
    return {
        "id": 1,
        "source": source,
        "source_url": source_url,
        "finding_type": finding_type,
        "value": value,
        "confidence": confidence,
        "evidence_state": evidence_state,
        "notes": "test evidence",
        "collected_at": None,
    }


def test_public_profile_rows_are_possible_not_found():
    rows = build_account_discovery_matrix([
        _finding("Email Intelligence", "provider_status", "ok"),
        _finding("Public Profile Network", "profile_candidate", "user", source_url="https://dev.to/user"),
    ])
    row = next(row for row in rows if row["service"] == "Dev.to")
    assert row["status"] == "POSSIBLE"
    assert row["provider"] == "Public Profile Network"
    assert row["identifier"] == "user"


@pytest.mark.asyncio
async def test_public_profile_network_maps_successful_services(monkeypatch):
    async def fake_json_probe(self, service, url, *, params=None):
        if service in {"Dev.to", "Hugging Face"}:
            return "found", {"username": "alice", "id": 7}, None
        return "not_found", None, None

    monkeypatch.setattr(PublicProfileNetworkProvider, "_json_probe", fake_json_probe)
    result = await PublicProfileNetworkProvider().run(
        type("Context", (), {"email": "alice@example.com", "domain": "example.com", "candidates": ("alice",)})()
    )
    assert result.status == "ok"
    profiles = [f for f in result.findings if f["finding_type"] == "profile_candidate"]
    assert {f["source_url"] for f in profiles} == {"https://dev.to/alice", "https://huggingface.co/alice"}
    assert all(f["evidence_state"] == "observed" for f in profiles)

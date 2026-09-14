from app.osint.service_catalog import build_account_discovery_matrix


def _finding(source, finding_type, value, confidence=0.9, evidence_state="source_associated", source_url="https://example.com"):
    return {
        "id": 1,
        "source": source,
        "source_url": source_url,
        "finding_type": finding_type,
        "value": value,
        "confidence": confidence,
        "evidence_state": evidence_state,
        "notes": "deterministic test evidence",
        "collected_at": None,
    }


def test_emailrep_profiles_become_discovered_account_rows():
    rows = build_account_discovery_matrix([
        _finding("Email Intelligence", "provider_status", "ok"),
        _finding("EmailRep", "profile_observation", "github"),
        _finding("EmailRep", "profile_observation", "linkedin", 0.88),
        _finding("EmailRep", "profile_observation", "github", 0.91),
    ])
    discovered = {row["service"]: row for row in rows if row["status"] == "FOUND"}
    assert discovered["github"]["provider"] == "Email Intelligence"
    assert discovered["github"]["identifier"] == "github"
    assert discovered["github"]["evidence"][0]["source_url"] == "https://github.com"
    assert discovered["linkedin"]["status"] == "FOUND"
    assert len([row for row in rows if row["service"] == "github"]) == 1


def test_emailrep_profile_is_not_treated_as_identity_confirmation():
    rows = build_account_discovery_matrix([
        _finding("Email Intelligence", "provider_status", "ok"),
        _finding("EmailRep", "profile_observation", "spotify"),
    ])
    row = next(row for row in rows if row["service"] == "spotify")
    assert row["status"] == "FOUND"
    assert row["evidence"][0]["evidence_state"] == "source_associated"

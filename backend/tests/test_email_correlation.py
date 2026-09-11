from app.osint.correlation import CORRELATED, correlate_email_findings
from app.osint.email import EVIDENCE_CORROBORATED, EVIDENCE_DERIVED, EVIDENCE_OBSERVED


def test_username_derivation_is_explicit_and_deterministic():
    findings = [
        {"id": 2, "source": "MailRecon", "finding_type": "username_candidate", "value": "alexmorgan", "confidence": 0.0, "evidence_state": EVIDENCE_DERIVED},
        {"id": 1, "source": "MailRecon", "finding_type": "email", "value": "alex.morgan@example.test", "confidence": 1.0, "evidence_state": EVIDENCE_OBSERVED},
        {"id": 3, "source": "MailRecon", "finding_type": "username_candidate", "value": "alex_morgan", "confidence": 0.0, "evidence_state": EVIDENCE_DERIVED},
    ]
    first = correlate_email_findings(findings)
    second = correlate_email_findings(list(reversed(findings)))
    assert first == second
    assert [r["target"] for r in first["relationships"] if r["relationship"] == "derived_username"] == ["alex_morgan", "alexmorgan"]
    assert all(r["evidence_state"] == EVIDENCE_DERIVED for r in first["relationships"] if r["relationship"] == "derived_username")


def test_public_account_requires_observation_and_does_not_become_identity():
    result = correlate_email_findings([
        {"id": 1, "source": "MailRecon", "finding_type": "email", "value": "alex.morgan@example.test", "confidence": 1.0, "evidence_state": EVIDENCE_OBSERVED},
        {"id": 2, "source": "MailRecon", "finding_type": "username_candidate", "value": "alex.morgan", "confidence": 0.0, "evidence_state": EVIDENCE_DERIVED},
        {"id": 3, "source": "GitHub", "finding_type": "profile_candidate", "value": "https://github.com/alex.morgan", "confidence": 0.2, "evidence_state": "possible_match", "raw_reference": {"login": "alex.morgan", "evidence_state": "possible_match"}},
    ])
    rel = next(r for r in result["relationships"] if r["relationship"] == "username_to_public_account")
    assert rel["evidence_state"] == CORRELATED
    assert rel["supporting_finding_ids"] == [3]
    assert "not proof" in rel["limitations"].lower()
    assert all("confirmed_person" not in r["relationship"] for r in result["relationships"])


def test_exact_public_email_is_correlated_as_source_corroboration():
    result = correlate_email_findings([
        {"id": 1, "source": "MailRecon", "finding_type": "email", "value": "alex@example.test", "confidence": 1.0, "evidence_state": EVIDENCE_OBSERVED},
        {"id": 2, "source": "GitHub", "finding_type": "profile_candidate", "value": "https://github.com/alex", "confidence": 0.95, "evidence_state": EVIDENCE_CORROBORATED, "raw_reference": {"login": "alex", "evidence_state": EVIDENCE_CORROBORATED}},
    ])
    rel = next(r for r in result["relationships"] if r["relationship"] == "corroborated_public_account")
    assert rel["evidence_state"] == EVIDENCE_CORROBORATED
    assert rel["confidence"] == 0.95


def test_historical_breach_is_not_current_compromise():
    result = correlate_email_findings([
        {"id": 1, "source": "MailRecon", "finding_type": "email", "value": "alex@example.test", "confidence": 1.0, "evidence_state": EVIDENCE_OBSERVED},
        {"id": 9, "source": "Have I Been Pwned", "finding_type": "breach", "value": "ExampleBreach", "confidence": 0.99, "evidence_state": EVIDENCE_OBSERVED},
    ])
    rel = next(r for r in result["relationships"] if r["relationship"] == "historical_breach_exposure")
    assert "current compromise" in rel["limitations"]


def test_conflicting_provider_observations_are_preserved():
    result = correlate_email_findings([
        {"id": 1, "source": "ProviderA", "finding_type": "classification", "value": "provider=Consumer", "confidence": 0.8, "evidence_state": EVIDENCE_OBSERVED},
        {"id": 2, "source": "ProviderB", "finding_type": "classification", "value": "provider=Enterprise", "confidence": 0.8, "evidence_state": EVIDENCE_OBSERVED},
    ])
    assert len(result["conflicts"]) == 1
    assert result["conflicts"][0]["finding_ids"] == [1, 2]
    assert set(result["conflicts"][0]["values"]) == {"provider=consumer", "provider=enterprise"}

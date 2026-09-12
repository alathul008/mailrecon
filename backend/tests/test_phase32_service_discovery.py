from app.osint.service_discovery import service_for_url, service_query_plan
from app.osint.service_catalog import build_account_discovery_matrix
from app.providers.public_web import PublicWebProvider


def test_public_service_url_classification_is_domain_bounded():
    assert service_for_url("https://steamcommunity.com/id/example").name == "Steam"
    assert service_for_url("https://subdomain.github.com/example").name == "GitHub"
    assert service_for_url("https://notgithub.com/example") is None


def test_service_query_plan_is_bounded_and_service_scoped():
    plan = service_query_plan("target@example.com", ["target", "dev"])
    assert plan[0] == ('"target@example.com"', None)
    assert ('"target@example.com" site:steamcommunity.com', "Steam") in plan
    assert len(plan) == 21


def test_public_web_evidence_populates_game_service_without_identity_claim():
    findings = [{"id": 101, "source": "Public Web", "finding_type": "public_web_reference", "value": "Example Steam profile", "confidence": 0.55, "evidence_state": "possible_match", "source_url": "https://steamcommunity.com/id/example", "service": "Steam"}]
    matrix = build_account_discovery_matrix(findings)
    steam = next(item for item in matrix if item["service"] == "Steam")
    assert steam["status"] == "POSSIBLE"
    assert steam["supported"] is False
    assert steam["evidence"][0]["finding_id"] == 101


def test_public_web_general_query_plan_remains_compatible():
    queries = PublicWebProvider()._queries("target@example.com", ["target", "target_dev", "third", "fourth", "fifth"])
    assert queries == ['"target@example.com"', '"target"', '"target_dev"', '"third"', '"fourth"']

import asyncio
import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun
from app.osint import dns as dns_osint
from app.providers.base import ProviderResult
from app.providers.public_web import PublicWebProvider
from app.providers.rdap import RDAPProvider
from app.services import orchestrator
from app.services.resource_budget import ExecutionResourceBudget


def test_resource_budget_distinguishes_dns_and_infrastructure_http():
    budget = ExecutionResourceBudget()
    budget.validate(provider_calls=6, candidate_probes=4, estimated_external_requests=32, dns_queries=15, infrastructure_http_requests=2)
    for kwargs, message in [
        ({"provider_calls": 9, "candidate_probes": 4, "estimated_external_requests": 32}, "provider-call"),
        ({"provider_calls": 6, "candidate_probes": 5, "estimated_external_requests": 32}, "candidate-probe"),
        ({"provider_calls": 6, "candidate_probes": 4, "estimated_external_requests": 33}, "external-request"),
        ({"provider_calls": 6, "candidate_probes": 4, "estimated_external_requests": 32, "dns_queries": 16}, "DNS-query"),
        ({"provider_calls": 6, "candidate_probes": 4, "estimated_external_requests": 32, "infrastructure_http_requests": 3}, "infrastructure HTTP"),
    ]:
        try:
            budget.validate(**kwargs)
        except RuntimeError as exc:
            assert message in str(exc)
        else:
            raise AssertionError(f"expected {message} budget failure")


def test_dns_normalizes_email_auth_and_provider_context(monkeypatch):
    domain = "example.test"
    responses = {(domain, kind): [] for kind in ("A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY")}
    responses[(domain, "A")] = ["192.0.2.10"]
    responses[(domain, "MX")] = ["10 mx.google.com."]
    responses[(domain, "NS")] = ["ns1.cloudflare.com."]
    responses[(domain, "TXT")] = ["v=spf1 include:_spf.google.com -all"]
    responses[(domain, "DS")] = ["12345 13 2 abcdef"]
    responses[(f"_dmarc.{domain}", "TXT")] = ["v=DMARC1; p=reject; pct=50; adkim=s; aspf=r; rua=mailto:d@example.test"]
    for selector in dns_osint.DKIM_SELECTORS:
        responses[(f"{selector}._domainkey.{domain}", "TXT")] = []
    responses[(f"selector1._domainkey.{domain}", "TXT")] = ["v=DKIM1; k=rsa; p=abc"]

    class FakeRecord:
        def __init__(self, value): self.value = value
        def to_text(self): return self.value

    class FakeAnswer:
        def __init__(self, values): self.values = [FakeRecord(value) for value in values]
        def __iter__(self): return iter(self.values)

    class FakeResolver:
        lifetime = None
        async def resolve(self, name, rdtype): return FakeAnswer(responses[(name, rdtype)])

    async def no_ip_context(address):
        return {"ip": address, "status": "ok", "asn": "AS64500", "network": "Example Network", "organization": "Example Org"}

    monkeypatch.setattr(dns_osint.dns.asyncresolver, "Resolver", FakeResolver)
    monkeypatch.setattr(dns_osint, "_ip_context", no_ip_context)
    result = asyncio.run(dns_osint.resolve(domain))
    assert result["SPF_analysis"]["includes"] == ["_spf.google.com"]
    assert result["SPF_analysis"]["policy"] == "-all"
    assert result["DMARC_analysis"] == {"present": True, "policy": "reject", "pct": 50, "alignment_dkim": "s", "alignment_spf": "r", "reporting_uris": True}
    assert result["DKIM_analysis"][0]["selector"] == "selector1"
    assert result["DNSSEC"] is True
    assert result["MX_PROVIDER"] == "Google Workspace"
    assert result["NS_PROVIDER"] == "Cloudflare"
    assert result["IP_CONTEXT"][0]["asn"] == "AS64500"


def test_rdap_enrichment_does_not_persist_raw_payload(monkeypatch):
    payload = {
        "ldhName": "example.com",
        "status": ["active"],
        "port43": "whois.example-registry.test",
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-02T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2025-01-02T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.example.com."}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
    }

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def get(self, url): return httpx.Response(200, json=payload)

    monkeypatch.setattr("app.providers.rdap.httpx.AsyncClient", lambda **kwargs: FakeClient())
    result = asyncio.run(RDAPProvider().run(type("Context", (), {"domain": "example.com"})()))
    values = {(f["finding_type"], f["value"]) for f in result.findings}
    assert ("registrar", "Example Registrar") in values
    assert ("domain_status", "active") in values
    assert ("nameserver", "ns1.example.com") in values
    assert all(f["raw_reference"] is None for f in result.findings)


def test_public_web_normalization_is_deterministic_and_bounded(monkeypatch):
    payload = {"results": [
        {"engine": "searx", "title": "Example", "url": "https://Example.com/path#fragment", "content": "snippet"},
        {"engine": "searx", "title": "Duplicate", "url": "https://example.com/path#other", "content": "duplicate"},
    ]}

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def get(self, url): return httpx.Response(200, json=payload)

    settings = __import__("app.core.config", fromlist=["get_settings"]).get_settings()
    old_endpoint, old_token = settings.public_web_search_url, settings.public_web_search_token
    settings.public_web_search_url = "https://search.example.test/search"
    settings.public_web_search_token = None
    monkeypatch.setattr("app.providers.public_web.httpx.AsyncClient", lambda **kwargs: FakeClient())
    try:
        context = type("Context", (), {"email": "alice@example.com", "candidates": ("alice", "alice_example", "alice-example", "alice")})()
        result = asyncio.run(PublicWebProvider().run(context))
        assert result.status == "ok"
        assert len(result.findings) == 1
        assert result.findings[0]["value"] == "https://example.com/path"
        reference = result.findings[0]["raw_reference"]
        assert reference["result_identity"]
        assert reference["query_type"] in {"exact_email", "derived_username"}
        assert reference["canonical_url"] == "https://example.com/path"
        assert "page_body" not in reference
    finally:
        settings.public_web_search_url, settings.public_web_search_token = old_endpoint, old_token


def test_durable_execution_path_preserves_attempt_and_operational_failure(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'phase37-e2e.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(target="alice@example.com", normalized_email="alice@example.com", username="alice", domain="example.com", status="running", execution_token="token", execution_attempt_id="attempt-1", execution_id="execution-1")
        db.add(inv); db.flush()
        db.add(ExecutionAttempt(investigation_id=inv.id, execution_id="execution-1", execution_attempt_id="attempt-1", status="running", started_at=datetime.now(timezone.utc)))
        for module in orchestrator.MODULES:
            db.add(ModuleRun(investigation_id=inv.id, execution_id="execution-1", execution_attempt_id="attempt-1", module=module, status="queued"))
        db.commit(); inv_id = inv.id

    fake_dns = {
        "A": ["192.0.2.10"], "AAAA": [], "MX": ["10 mx.example.test."], "NS": [], "CNAME": [], "SPF": [], "SPF_status": "no_result", "SPF_analysis": {"present": False, "mechanisms": [], "includes": [], "qualifiers": [], "policy": None},
        "DMARC": [], "DMARC_status": "no_result", "DMARC_analysis": {"present": False, "policy": None, "pct": None, "alignment_dkim": None, "alignment_spf": None, "reporting_uris": False},
        "DKIM": [], "DKIM_status": "no_result", "DKIM_analysis": [], "DS": [], "DNSSEC": False, "DNSSEC_status": "no_result", "IP_CONTEXT": [], "MX_PROVIDER": None, "NS_PROVIDER": None,
    }
    monkeypatch.setattr(orchestrator, "resolve", lambda domain: fake_dns)

    async def fake_run_providers(*args, **kwargs):
        return [ProviderResult("Gravatar", "rate_limited", message="rate limit"), ProviderResult("RDAP", "ok"), ProviderResult("GitHub", "ok"), ProviderResult("GitLab", "ok"), ProviderResult("Have I Been Pwned", "unconfigured"), ProviderResult("Public Web", "unconfigured")]

    monkeypatch.setattr(orchestrator, "run_providers", fake_run_providers)
    monkeypatch.setattr(orchestrator.OllamaProvider, "summarize", lambda self, target, findings: asyncio.sleep(0, result=None))

    with Session(engine) as db:
        asyncio.run(orchestrator.run_investigation(inv_id, "token"))
        inv = db.get(Investigation, inv_id)
        findings = db.scalars(select(Finding).where(Finding.investigation_id == inv_id)).all()
        assert inv.status == "completed"
        assert {f.execution_attempt_id for f in findings} == {"attempt-1"}
        assert any(f.finding_type == "provider_status" and f.value == "rate_limited" for f in findings)
        assert not any(f.finding_type == "account_absent" for f in findings)

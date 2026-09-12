import httpx
import pytest
from urllib.parse import unquote_plus

from app.providers.base import ProviderContext, ProviderResult
from app.providers import public_web as public_web_module
from app.providers import registry
from app.providers.github import GitHubProvider
from app.providers.gitlab import GitLabProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider
from app.providers.public_web import PublicWebProvider
from app.providers.rdap import RDAPProvider
from app.osint.service_catalog import SERVICE_CATALOG

CONTEXT = ProviderContext(email="user@example.com", domain="example.com", candidates=("user", "example"))


def test_registry_contract_invariants_and_catalogue_consistency():
    registry.validate_registry()
    names = [item.name for item in registry.PROVIDER_REGISTRY]
    assert len(names) == len(set(names))
    assert set(registry.INVOCATION_MODES) == {"email", "domain", "candidates"}
    executable = registry.provider_definitions(orchestrated=True)
    assert {item.name for item in executable if item.factory} == {"Gravatar", "RDAP", "GitHub", "GitLab", "Have I Been Pwned", "Public Web"}
    account_discovery = registry.provider_definitions(account_discovery=True)
    assert {item.name for item in account_discovery} == {"Gravatar", "GitHub", "GitLab", "Have I Been Pwned", "Public Web"}
    catalog = {item.name: item for item in SERVICE_CATALOG if item.provider}
    for definition in account_discovery:
        assert definition.name in catalog
        assert catalog[definition.name].provider == definition.name
        assert catalog[definition.name].supported == definition.supported


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_class,provider_name", [(GravatarProvider,"Gravatar"),(RDAPProvider,"RDAP"),(GitHubProvider,"GitHub"),(GitLabProvider,"GitLab"),(HIBPProvider,"Have I Been Pwned"),(PublicWebProvider,"Public Web")])
async def test_each_executable_provider_accepts_canonical_context_through_registry(monkeypatch, provider_class, provider_name):
    seen=[]
    async def run(self,context): seen.append(context); return ProviderResult(provider_name,"ok")
    monkeypatch.setattr(provider_class,"run",run)
    result=await registry.execute(registry.provider_definition(provider_name),context=CONTEXT)
    assert result.status=="ok"; assert seen==[CONTEXT]


@pytest.mark.asyncio
async def test_public_web_registry_execution_uses_email_and_candidates_correctly(monkeypatch):
    settings=public_web_module.get_settings(); original_url=settings.public_web_search_url; original_token=settings.public_web_search_token; settings.public_web_search_url="https://search.example.test/search"; settings.public_web_search_token=None
    class FakeAsyncClient:
        queries=[]
        def __init__(self,*args,**kwargs): self.headers=kwargs["headers"]; self.follow_redirects=kwargs["follow_redirects"]; self.trust_env=kwargs["trust_env"]; self.transport=kwargs["transport"]
        async def __aenter__(self): return self
        async def __aexit__(self,exc_type,exc,tb): return False
        async def get(self,url,*args,**kwargs):
            FakeAsyncClient.queries.append(url)
            return httpx.Response(200,json={"results":[{"title":"Public reference","url":"https://example.org/reference","engine":"local"}]})
    monkeypatch.setattr(public_web_module.httpx,"AsyncClient",FakeAsyncClient); monkeypatch.setattr(public_web_module,"validate_provider_url",lambda url:url); monkeypatch.setattr(public_web_module,"pinned_transport",lambda url:object())
    try: result=await registry.execute(registry.provider_definition("Public Web"),context=CONTEXT)
    finally: settings.public_web_search_url=original_url; settings.public_web_search_token=original_token
    decoded=[unquote_plus(url) for url in FakeAsyncClient.queries]
    assert result.status=="ok"; assert result.findings; assert all(f["evidence_state"]=="possible_match" for f in result.findings); assert all(f["confidence"]==0.55 for f in result.findings)
    assert any('"user@example.com"' in url for url in decoded); assert any('"user"' in url for url in decoded); assert any('"example"' in url for url in decoded)


@pytest.mark.asyncio
@pytest.mark.parametrize("status",["unconfigured","rate_limited","unavailable","error","disabled"])
async def test_registry_operational_failures_never_become_negative_evidence(status):
    async def run(context): return ProviderResult("Public Web",status)
    class FakeProvider: pass
    FakeProvider.run=staticmethod(run)
    result=await registry.execute(registry.provider_definition("Public Web"),context=CONTEXT,factory=FakeProvider)
    assert result.status==status; assert result.findings==[]

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from app.core.config import get_settings
from app.providers.github import GitHubProvider
from app.providers.gitlab import GitLabProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider
from app.providers.public_web import PublicWebProvider
from app.providers.rdap import RDAPProvider

OPERATIONAL_STATES = ("ok", "unconfigured", "rate_limited", "unavailable", "error", "disabled")

@dataclass(frozen=True)
class ProviderDefinition:
    name: str
    category: str
    supported: bool
    discovery_methods: tuple[str, ...]
    configuration: str
    external_network: bool
    account_discovery: bool
    orchestrated: bool
    factory: Callable[[], Any] | None = None
    argument_mode: str = "email"
    module: str | None = None
    factory_symbol: str | None = None

PROVIDER_REGISTRY: tuple[ProviderDefinition, ...] = (
    ProviderDefinition("DNS", "Network", True, ("dns_resolution",), "none", True, False, True),
    ProviderDefinition("RDAP", "Network", True, ("rdap_lookup",), "none", True, False, True, RDAPProvider, "domain", "rdap", "RDAPProvider"),
    ProviderDefinition("Gravatar", "Avatar", True, ("public_hash_lookup",), "none", True, True, True, GravatarProvider, "email", "gravatar", "GravatarProvider"),
    ProviderDefinition("GitHub", "Developer", True, ("public_profile_api",), "optional GITHUB_TOKEN", True, True, True, GitHubProvider, "candidates", "public_profile_discovery", "GitHubProvider"),
    ProviderDefinition("GitLab", "Developer", True, ("public_profile_api",), "none", True, True, True, GitLabProvider, "email", "gitlab", "GitLabProvider"),
    ProviderDefinition("Have I Been Pwned", "Other", True, ("breach_metadata_api",), "optional HIBP_API_KEY", True, True, True, HIBPProvider, "email", "breach_sources", "HIBPProvider"),
    ProviderDefinition("Public Web", "Other", True, ("public_search_api",), "optional PUBLIC_WEB_SEARCH_URL", True, True, True, PublicWebProvider, "candidates", "public_web", "PublicWebProvider"),
    ProviderDefinition("Ollama", "Local AI", True, ("local_model_api",), "optional local model", False, False, False),
)

def provider_definitions(*, orchestrated: bool | None = None, account_discovery: bool | None = None) -> tuple[ProviderDefinition, ...]:
    definitions = PROVIDER_REGISTRY
    if orchestrated is not None:
        definitions = tuple(item for item in definitions if item.orchestrated is orchestrated)
    if account_discovery is not None:
        definitions = tuple(item for item in definitions if item.account_discovery is account_discovery)
    return definitions

def provider_definition(name: str) -> ProviderDefinition:
    for definition in PROVIDER_REGISTRY:
        if definition.name == name:
            return definition
    raise KeyError(f"Unknown provider: {name}")

def provider_names(*, orchestrated: bool | None = None, account_discovery: bool | None = None) -> tuple[str, ...]:
    return tuple(item.name for item in provider_definitions(orchestrated=orchestrated, account_discovery=account_discovery))

def configured_status(definition: ProviderDefinition) -> str:
    settings = get_settings()
    if definition.name == "GitHub": return "configured" if settings.github_token else "available"
    if definition.name == "Have I Been Pwned": return "configured" if settings.hibp_api_key else "unconfigured"
    if definition.name == "Public Web": return "configured" if settings.public_web_search_url else "unconfigured"
    if definition.name == "Ollama": return "configured" if settings.enable_ollama else "disabled"
    return "available"

def instantiate(definition: ProviderDefinition, factory: Callable[[], Any] | None = None) -> Any:
    selected = factory or definition.factory
    if selected is None:
        raise RuntimeError(f"Provider {definition.name} has no executable factory")
    return selected()

async def execute(definition: ProviderDefinition, *, email: str, domain: str, candidates: list[str], factory: Callable[[], Any] | None = None):
    provider = instantiate(definition, factory)
    if definition.argument_mode == "domain": return await provider.run(domain)
    if definition.argument_mode == "candidates": return await provider.run(candidates, email)
    return await provider.run(email)

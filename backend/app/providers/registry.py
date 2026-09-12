from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from app.core.config import get_settings
from app.providers.base import ProviderContext, ProviderResult
from app.providers.github import GitHubProvider
from app.providers.gitlab import GitLabProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider
from app.providers.public_web import PublicWebProvider
from app.providers.rdap import RDAPProvider

OPERATIONAL_STATES = ("ok", "unconfigured", "rate_limited", "unavailable", "error", "disabled")
INVOCATION_MODES = ("email", "domain", "candidates")


class ProviderRunner(Protocol):
    async def run(self, context: ProviderContext) -> ProviderResult: ...


ProviderFactory = Callable[[], ProviderRunner]


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
    factory: ProviderFactory | None = None
    argument_mode: str = "email"
    module: str | None = None

    @property
    def executable(self) -> bool:
        return self.factory is not None


PROVIDER_REGISTRY: tuple[ProviderDefinition, ...] = (
    ProviderDefinition("Gravatar", "Avatar", True, ("public_hash_lookup",), "none", True, True, True, GravatarProvider, "email", "gravatar"),
    ProviderDefinition("RDAP", "Network", True, ("rdap_lookup",), "none", True, False, True, RDAPProvider, "domain", "rdap"),
    ProviderDefinition("GitHub", "Developer", True, ("public_profile_api",), "optional GITHUB_TOKEN", True, True, True, GitHubProvider, "candidates", "public_profile_discovery"),
    ProviderDefinition("GitLab", "Developer", True, ("public_profile_api",), "none", True, True, True, GitLabProvider, "email", "gitlab"),
    ProviderDefinition("Have I Been Pwned", "Other", True, ("breach_metadata_api",), "optional HIBP_API_KEY", True, True, True, HIBPProvider, "email", "breach_sources"),
    ProviderDefinition("Public Web", "Other", True, ("public_search_api",), "optional PUBLIC_WEB_SEARCH_URL", True, True, True, PublicWebProvider, "candidates", "public_web"),
    # DNS is an orchestrator-owned local module, not an executable ProviderRunner.
    ProviderDefinition("DNS", "Network", True, ("dns_resolution",), "none", True, False, True),
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
    if definition.name == "GitHub":
        return "configured" if settings.github_token else "available"
    if definition.name == "Have I Been Pwned":
        return "configured" if settings.hibp_api_key else "unconfigured"
    if definition.name == "Public Web":
        return "configured" if settings.public_web_search_url else "unconfigured"
    if definition.name == "Ollama":
        return "configured" if settings.enable_ollama else "disabled"
    return "available"


def instantiate(definition: ProviderDefinition, factory: ProviderFactory | None = None) -> ProviderRunner:
    selected = factory or definition.factory
    if selected is None:
        raise RuntimeError(f"Provider {definition.name} has no executable factory")
    provider = selected()
    if not callable(getattr(provider, "run", None)):
        raise TypeError(f"Provider {definition.name} factory did not produce a runnable provider")
    return provider


async def execute(
    definition: ProviderDefinition,
    *,
    context: ProviderContext,
    factory: ProviderFactory | None = None,
) -> ProviderResult:
    if definition.argument_mode not in INVOCATION_MODES:
        raise ValueError(f"Provider {definition.name} has unsupported invocation mode: {definition.argument_mode}")
    provider = instantiate(definition, factory)
    result = await provider.run(context)
    if not isinstance(result, ProviderResult):
        raise TypeError(f"Provider {definition.name} returned {type(result).__name__}, expected ProviderResult")
    if result.provider != definition.name:
        raise ValueError(f"Provider {definition.name} returned result for {result.provider}")
    return result


def validate_registry() -> None:
    names = [item.name for item in PROVIDER_REGISTRY]
    if len(names) != len(set(names)):
        raise ValueError("Provider registry contains duplicate provider names")
    for item in PROVIDER_REGISTRY:
        if item.argument_mode not in INVOCATION_MODES:
            raise ValueError(f"Provider {item.name} has unsupported invocation mode")
        if item.account_discovery and not item.supported:
            raise ValueError(f"Account-discovery provider {item.name} must be supported")
        if item.account_discovery and item.factory is None:
            raise ValueError(f"Account-discovery provider {item.name} has no executable factory")
        if item.factory is not None and not callable(item.factory):
            raise ValueError(f"Provider {item.name} factory is not callable")


validate_registry()

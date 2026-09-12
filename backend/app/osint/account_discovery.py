from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from app.osint.email import analyze_email, username_candidates
from app.providers.base import ProviderResult
from app.providers.github import GitHubProvider
from app.providers.gitlab import GitLabProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider

PROVIDER_STATUS_LABELS = {"ok": "OK", "unconfigured": "UNCONFIGURED", "rate_limited": "RATE LIMITED", "unavailable": "UNAVAILABLE", "error": "ERROR", "disabled": "DISABLED"}

@dataclass(frozen=True)
class DiscoveryTarget:
    email: str
    username: str
    domain: str

class AccountProvider(Protocol):
    name: str
    async def run(self, email: str, candidates: list[str]) -> ProviderResult: ...

class _Adapter:
    def __init__(self, provider: Any, *, candidates: bool = False):
        self.provider = provider
        self.name = provider.name
        self._candidates = candidates

    async def run(self, email: str, candidates: list[str]) -> ProviderResult:
        if self._candidates:
            return await self.provider.run(candidates, email)
        return await self.provider.run(email)

def normalize_target(email: str) -> DiscoveryTarget:
    analysis = analyze_email(email)
    return DiscoveryTarget(email=analysis["email"], username=analysis["username"], domain=analysis["domain"])

def default_providers() -> tuple[AccountProvider, ...]:
    return (_Adapter(GravatarProvider()), _Adapter(GitHubProvider(), candidates=True), _Adapter(GitLabProvider()), _Adapter(HIBPProvider()))

def _provider_status_result(provider: AccountProvider, status: str, message: str | None, checked_at: datetime) -> dict[str, Any]:
    return {"provider": provider.name, "status": PROVIDER_STATUS_LABELS.get(status, status.upper()), "status_code": status, "checked_at": checked_at, "message": message}

async def discover_public_accounts(email: str, *, providers: tuple[AccountProvider, ...] | None = None, allow_external: bool = True) -> dict[str, Any]:
    target = normalize_target(email)
    selected = providers or default_providers()
    checked_at = datetime.now(timezone.utc)
    if not allow_external:
        return {"target": target, "providers": [_provider_status_result(p, "disabled", "External provider disclosure disabled", checked_at) for p in selected], "findings": []}
    candidates = username_candidates(target.username)

    async def run(provider: AccountProvider) -> tuple[AccountProvider, ProviderResult | Exception]:
        try:
            return provider, await provider.run(target.email, candidates)
        except Exception as exc:
            return provider, exc

    results = await asyncio.gather(*(run(provider) for provider in selected))
    statuses: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for provider, result in results:
        if isinstance(result, Exception):
            statuses.append(_provider_status_result(provider, "error", f"Provider raised {type(result).__name__}", checked_at))
            continue
        statuses.append(_provider_status_result(provider, result.status, result.message, result.checked_at))
        findings.extend(result.findings)
    return {"target": target, "providers": statuses, "findings": _dedupe_findings(findings)}

def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    output: list[dict[str, Any]] = []
    for item in findings:
        key = (item.get("source"), item.get("finding_type"), item.get("value"), item.get("source_url"))
        if key in seen: continue
        seen.add(key); output.append(item)
    return output

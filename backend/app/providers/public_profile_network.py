from __future__ import annotations

import asyncio
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_POSSIBLE
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import bounded_get, classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class PublicProfileNetworkProvider:
    """Passive username-based discovery across public profile networks.

    A positive result means that a public profile exists for the derived
    username. It is deliberately POSSIBLE evidence: username reuse alone does
    not establish that the profile belongs to the email owner.
    """

    name = "Public Profile Network"

    async def _json_probe(self, service: str, url: str, *, params: dict[str, str] | None = None) -> tuple[str, dict | None, str | None]:
        settings = get_settings()
        validate_provider_url(url)
        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            headers={"accept": "application/json", "user-agent": "MailRecon/1.2 passive profile discovery"},
            follow_redirects=False,
            trust_env=False,
            transport=pinned_transport(url),
        ) as client:
            response = await bounded_get(client, url, params=params)
        if response.status_code == 404:
            return "not_found", None, None
        failure = classify_response(self.name, response)
        if failure:
            return failure.status, None, failure.message
        data, parse_failure = parse_json(response, self.name)
        if parse_failure:
            return parse_failure.status, None, f"{service}: {parse_failure.message}"
        return "found", data if isinstance(data, dict) else {"data": data}, None

    async def _page_probe(self, service: str, url: str) -> tuple[str, dict | None, str | None]:
        settings = get_settings()
        validate_provider_url(url)
        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            headers={"accept": "text/html,application/xhtml+xml", "user-agent": "MailRecon/1.2 passive profile discovery"},
            follow_redirects=False,
            trust_env=False,
            transport=pinned_transport(url),
        ) as client:
            response = await bounded_get(client, url)
        if response.status_code == 404:
            return "not_found", None, None
        failure = classify_response(self.name, response)
        if failure:
            return failure.status, None, failure.message
        if 200 <= response.status_code < 300:
            return "found", {"http_status": response.status_code}, None
        return "unknown", None, f"{service}: unexpected HTTP {response.status_code}"

    async def _probe(self, service: str, username: str) -> tuple[str, str, str, dict | None, str | None]:
        encoded = quote(username, safe="")
        try:
            if service == "Reddit":
                status, data, message = await self._json_probe(service, f"https://www.reddit.com/user/{encoded}/about.json")
                url = f"https://www.reddit.com/user/{encoded}/"
            elif service == "Dev.to":
                status, data, message = await self._json_probe(service, f"https://dev.to/api/users/{encoded}")
                url = f"https://dev.to/{encoded}"
            elif service == "Codeberg":
                status, data, message = await self._json_probe(service, f"https://codeberg.org/api/v1/users/{encoded}")
                url = f"https://codeberg.org/{encoded}"
            elif service == "Keybase":
                status, data, message = await self._json_probe(
                    service,
                    "https://keybase.io/_/api/1.0/user/lookup.json",
                    params={"usernames": username, "fields": "basics,profile,proofs_summary"},
                )
                if status == "found" and isinstance(data, dict) and not data.get("them"):
                    status = "not_found"
                url = f"https://keybase.io/{encoded}"
            elif service == "Hugging Face":
                status, data, message = await self._json_probe(service, f"https://huggingface.co/api/users/{encoded}")
                url = f"https://huggingface.co/{encoded}"
            elif service == "npm":
                status, data, message = await self._json_probe(service, f"https://registry.npmjs.org/-/user/org.couchdb.user:{encoded}")
                url = f"https://www.npmjs.com/~{encoded}"
            elif service == "Stack Overflow":
                status, data, message = await self._json_probe(
                    service,
                    "https://api.stackexchange.com/2.3/users",
                    params={"site": "stackoverflow", "inname": username, "pagesize": "20"},
                )
                if status == "found":
                    items = data.get("items") if isinstance(data, dict) else None
                    if not isinstance(items, list) or not any(
                        isinstance(item, dict) and str(item.get("display_name", "")).casefold() == username.casefold()
                        for item in items
                    ):
                        status = "not_found"
                url = f"https://stackoverflow.com/users"
            elif service == "Medium":
                status, data, message = await self._page_probe(service, f"https://medium.com/@{encoded}")
                url = f"https://medium.com/@{encoded}"
            else:
                return service, "unknown", "", None, "Unsupported probe"
            return service, status, url, data, message
        except Exception as exc:
            return service, "error", url if "url" in locals() else "", None, f"{service}: {type(exc).__name__}"

    async def run(self, context: ProviderContext) -> ProviderResult:
        username = context.candidates[0] if context.candidates else context.email.split("@", 1)[0]
        services = ("Reddit", "Dev.to", "Codeberg", "Keybase", "Hugging Face", "npm", "Stack Overflow", "Medium")
        results = await asyncio.gather(*(self._probe(service, username) for service in services))
        findings: list[dict] = []
        found = 0
        unavailable = 0
        for service, status, profile_url, data, message in results:
            if status == "found":
                found += 1
                details = {k: data.get(k) for k in ("username", "name", "login", "id") if isinstance(data, dict) and data.get(k) is not None}
                findings.append(
                    finding(
                        self.name,
                        "profile_candidate",
                        username,
                        0.72,
                        "info",
                        profile_url,
                        notes=(
                            f"Evidence state: {EVIDENCE_POSSIBLE}. Public {service} profile observed for the derived username. "
                            "Username reuse is not proof that the profile belongs to the target email owner."
                        ),
                        raw_reference={"service": service, "username": username, "profile": details, "evidence_state": EVIDENCE_POSSIBLE},
                    )
                )
            elif status in {"error", "rate_limited", "unavailable"}:
                unavailable += 1
                findings.append(
                    finding(
                        self.name,
                        "service_status",
                        f"{service}:{status}",
                        1.0,
                        "warning",
                        profile_url or None,
                        notes=message or f"{service} could not be checked.",
                    )
                )
            else:
                findings.append(
                    finding(
                        self.name,
                        "service_status",
                        f"{service}:no_public_evidence",
                        1.0,
                        "info",
                        profile_url or None,
                        notes=f"No public {service} profile was observed for the derived username. This is not proof that no account exists.",
                    )
                )
        status = "ok" if found or unavailable < len(services) else "unavailable"
        return ProviderResult(
            self.name,
            status,
            findings=findings,
            message=f"{found} public username profiles observed across {len(services)} services" + (f"; {unavailable} services unavailable" if unavailable else ""),
        )

from __future__ import annotations

import asyncio
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_OBSERVED
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import bounded_get, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class PublicProfileNetworkProvider:
    """Passive username discovery across public profile pages and APIs."""

    name = "Public Profile Network"

    _SITES = (
        ("GitHub", "Developer", "https://github.com/{u}"),
        ("GitLab", "Developer", "https://gitlab.com/{u}"),
        ("Reddit", "Social & Community", "https://www.reddit.com/user/{u}/"),
        ("Dev.to", "Developer", "https://dev.to/{u}"),
        ("Codeberg", "Developer", "https://codeberg.org/{u}"),
        ("Keybase", "Identity", "https://keybase.io/{u}"),
        ("Hugging Face", "AI & Developer", "https://huggingface.co/{u}"),
        ("Bitbucket", "Developer", "https://bitbucket.org/{u}"),
        ("Medium", "Publishing", "https://medium.com/@{u}"),
        ("Vimeo", "Media", "https://vimeo.com/{u}"),
        ("Flickr", "Photography", "https://www.flickr.com/people/{u}/"),
        ("SoundCloud", "Music", "https://soundcloud.com/{u}"),
        ("Patreon", "Creator", "https://www.patreon.com/{u}"),
        ("Buy Me a Coffee", "Creator", "https://buymeacoffee.com/{u}"),
        ("Linktree", "Social & Creator", "https://linktr.ee/{u}"),
        ("About.me", "Identity", "https://about.me/{u}"),
        ("Behance", "Design", "https://www.behance.net/{u}"),
        ("Dribbble", "Design", "https://dribbble.com/{u}"),
        ("Product Hunt", "Product & Tech", "https://www.producthunt.com/@{u}"),
        ("Kaggle", "Data Science", "https://www.kaggle.com/{u}"),
        ("npm", "Developer", "https://www.npmjs.com/~{u}"),
        ("PyPI", "Developer", "https://pypi.org/user/{u}/"),
        ("Docker Hub", "Developer", "https://hub.docker.com/u/{u}"),
        ("CodePen", "Developer", "https://codepen.io/{u}"),
        ("Replit", "Developer", "https://replit.com/@{u}"),
        ("Instructables", "Maker", "https://www.instructables.com/member/{u}/"),
        ("Wattpad", "Publishing", "https://www.wattpad.com/user/{u}"),
        ("Goodreads", "Publishing", "https://www.goodreads.com/{u}"),
        ("Steam", "Gaming", "https://steamcommunity.com/id/{u}"),
        ("Twitch", "Streaming", "https://www.twitch.tv/{u}"),
        ("Pinterest", "Social & Visual", "https://www.pinterest.com/{u}/"),
        ("Tumblr", "Publishing", "https://{u}.tumblr.com/"),
        ("X", "Social", "https://x.com/{u}"),
        ("Instagram", "Social", "https://www.instagram.com/{u}/"),
        ("Threads", "Social", "https://www.threads.net/@{u}"),
        ("YouTube", "Video", "https://www.youtube.com/@{u}"),
    )

    async def _page_probe(self, service: str, url: str) -> tuple[str, str | None]:
        settings = get_settings()
        validate_provider_url(url)
        try:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                headers={"accept": "text/html,application/xhtml+xml", "user-agent": "MailRecon/1.3 passive public-profile discovery"},
                follow_redirects=False,
                trust_env=False,
                transport=pinned_transport(url),
            ) as client:
                response = await bounded_get(client, url)
            if response.status_code == 404:
                return "not_found", None
            failure = classify_response(self.name, response)
            if failure:
                return failure.status, failure.message
            if 200 <= response.status_code < 300:
                return "found", None
            return "unknown", f"{service}: unexpected HTTP {response.status_code}"
        except Exception as exc:
            return "error", f"{service}: {type(exc).__name__}"

    async def _json_probe(self, service: str, url: str, *, params: dict[str, str] | None = None) -> tuple[str, dict | None, str | None]:
        settings = get_settings()
        validate_provider_url(url)
        try:
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                headers={"accept": "application/json", "user-agent": "MailRecon/1.3 passive public-profile discovery"},
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
                return parse_failure.status, None, parse_failure.message
            return "found", data if isinstance(data, dict) else {"data": data}, None
        except Exception as exc:
            return "error", None, f"{service}: {type(exc).__name__}"

    async def _probe(self, service: str, category: str, template: str, username: str):
        encoded = quote(username, safe="")
        url = template.format(u=encoded)
        api_map = {
            "Dev.to": f"https://dev.to/api/users/{encoded}",
            "Codeberg": f"https://codeberg.org/api/v1/users/{encoded}",
            "Hugging Face": f"https://huggingface.co/api/users/{encoded}",
        }
        if service in api_map:
            status, data, message = await self._json_probe(service, api_map[service])
            return service, category, status, url, data, message
        if service == "Keybase":
            status, data, message = await self._json_probe(
                service,
                "https://keybase.io/_/api/1.0/user/lookup.json",
                params={"usernames": username, "fields": "basics,profile,proofs_summary"},
            )
            if status == "found" and isinstance(data, dict) and not data.get("them"):
                status = "not_found"
            return service, category, status, url, data, message
        status, message = await self._page_probe(service, url)
        return service, category, status, url, None, message

    async def run(self, context: ProviderContext) -> ProviderResult:
        username = (context.candidates[0] if context.candidates else context.email.split("@", 1)[0]).strip()
        if not username:
            return ProviderResult(self.name, "unavailable", message="No derived username was available")
        results = await asyncio.gather(*(self._probe(*site, username) for site in self._SITES))
        findings: list[dict] = []
        found = 0
        unavailable = 0
        for service, category, status, profile_url, data, message in results:
            if status == "found":
                found += 1
                details = {}
                if isinstance(data, dict):
                    for key in ("username", "login", "name", "id", "fullName"):
                        if data.get(key) is not None:
                            details[key] = data.get(key)
                findings.append(
                    finding(
                        self.name,
                        "profile_candidate",
                        username,
                        0.72,
                        "info",
                        profile_url,
                        notes=f"Evidence state: {EVIDENCE_OBSERVED}. Public {service} profile was observed for the derived username. The email-to-profile relationship remains a possible correlation and is not identity confirmation.",
                        raw_reference={"service": service, "category": category, "username": username, "profile": details, "evidence_state": EVIDENCE_OBSERVED},
                    )
                )
            elif status in {"error", "rate_limited", "unavailable"}:
                unavailable += 1
                findings.append(finding(self.name, "service_status", f"{service}:{status}", 1.0, "warning", profile_url, notes=message or f"{service} could not be checked."))
            else:
                findings.append(finding(self.name, "service_status", f"{service}:no_public_evidence", 1.0, "info", profile_url, notes=f"No public {service} profile was observed for the derived username. This is not proof that no account exists."))
        status = "ok" if found or unavailable < len(results) else "unavailable"
        return ProviderResult(self.name, status, findings=findings, message=f"{found} public profiles observed across {len(results)} services" + (f"; {unavailable} services unavailable" if unavailable else ""))

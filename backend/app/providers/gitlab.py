from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_CORROBORATED
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class GitLabProvider:
    """Discover GitLab users only through GitLab's public-email user lookup."""

    name = "GitLab"
    endpoint = "https://gitlab.com/api/v4/users"

    async def run(self, context: ProviderContext) -> ProviderResult:
        settings = get_settings()
        try:
            validate_provider_url(self.endpoint)
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                headers={"accept": "application/json", "user-agent": "MailRecon"},
                follow_redirects=False,
                trust_env=False,
                transport=pinned_transport(self.endpoint),
            ) as client:
                response = await client.get(self.endpoint, params={"search": context.email})
            failure = classify_response(self.name, response)
            if failure:
                return failure
            data, parse_failure = parse_json(response, self.name)
            if parse_failure:
                return parse_failure
            if not isinstance(data, list):
                return ProviderResult(self.name, "error", message="GitLab user lookup response was malformed")

            normalized_email = context.email.strip().lower()
            findings = []
            for user in data:
                if not isinstance(user, dict):
                    continue
                public_email = user.get("public_email")
                username = user.get("username")
                web_url = user.get("web_url")
                if not isinstance(public_email, str) or public_email.strip().lower() != normalized_email:
                    continue
                if not isinstance(username, str) or not username:
                    continue
                if not isinstance(web_url, str) or not web_url.startswith("https://gitlab.com/"):
                    web_url = f"https://gitlab.com/{quote(username, safe='')}"
                findings.append(
                    finding(
                        self.name,
                        "profile_candidate",
                        web_url,
                        0.95,
                        "info",
                        web_url,
                        notes=(
                            f"Evidence state: {EVIDENCE_CORROBORATED}. "
                            "GitLab returned an exact public-email match; this associates the public email "
                            "with the GitLab profile but does not prove human identity."
                        ),
                        raw_reference={
                            "username": username,
                            "name": user.get("name"),
                            "public_email": public_email,
                            "evidence_state": EVIDENCE_CORROBORATED,
                        },
                    )
                )
            return ProviderResult(
                self.name,
                "ok",
                findings=findings,
                message=f"{len(findings)} public GitLab profile matches",
            )
        except Exception as exc:
            return classify_exception(self.name, exc)

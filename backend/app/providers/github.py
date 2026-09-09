import httpx

from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json
from app.providers.network import public_provider_client
from app.osint.email import EVIDENCE_CORROBORATED, EVIDENCE_POSSIBLE


class GitHubProvider:
    name = "GitHub"

    async def run(self, candidates: list[str], email: str) -> ProviderResult:
        settings = get_settings()
        headers = {"accept": "application/vnd.github+json", "user-agent": "MailRecon"}
        if settings.github_token:
            headers["authorization"] = f"Bearer {settings.github_token}"
        findings = []
        try:
            for username in candidates[:8]:
                url = f"https://api.github.com/users/{username}"
                async with public_provider_client(url, timeout=settings.request_timeout_seconds, headers=headers) as client:
                    response = await client.get(url)
                if response.status_code == 404:
                    continue
                failure = classify_response(self.name, response)
                if failure:
                    return failure
                data, parse_failure = parse_json(response, self.name)
                if parse_failure:
                    return parse_failure
                if not isinstance(data, dict):
                    return ProviderResult(self.name, "error", message="GitHub profile response was malformed")
                login = data.get("login")
                if not isinstance(login, str) or not login:
                    continue
                score = 0.2
                evidence_state = EVIDENCE_POSSIBLE
                evidence = ["public GitHub username matches a generated candidate"]
                public_email = data.get("email")
                if isinstance(public_email, str) and public_email.strip().lower() == email.lower():
                    score = 0.95
                    evidence_state = EVIDENCE_CORROBORATED
                    evidence.append("public profile email exactly matches target")
                name = data.get("name")
                if evidence_state == EVIDENCE_POSSIBLE and isinstance(name, str) and any(p in name.lower() for p in username.lower().replace("_", " ").replace("-", " ").split()):
                    score = 0.45
                    evidence.append("profile display name overlaps a username token")
                html_url = data.get("html_url")
                if not isinstance(html_url, str) or not html_url:
                    html_url = username
                findings.append(finding(self.name, "profile_candidate", html_url, score, "info", html_url if isinstance(html_url, str) and html_url.startswith("http") else None, notes=f"Evidence state: {evidence_state}. Username correlation is not proof of human identity.", raw_reference={"login": login, "name": name, "public_repos": data.get("public_repos"), "evidence": evidence, "evidence_state": evidence_state}))
            return ProviderResult(self.name, "ok", findings=findings, message=f"{len(findings)} possible public profile matches")
        except Exception as exc:
            return classify_exception(self.name, exc)

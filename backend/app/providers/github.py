import httpx

from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url


class GitHubProvider:
    name = "GitHub"

    async def run(self, candidates: list[str], email: str) -> ProviderResult:
        settings = get_settings()
        headers = {"accept": "application/vnd.github+json", "user-agent": "MailRecon"}
        if settings.github_token:
            headers["authorization"] = f"Bearer {settings.github_token}"
        findings = []
        try:
            async with httpx.AsyncClient(timeout=10.0, headers=headers, follow_redirects=False) as client:
                for username in candidates[:8]:
                    url = f"https://api.github.com/users/{username}"
                    validate_provider_url(url)
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
                    score = 0.35
                    evidence = ["public GitHub username matches a generated candidate"]
                    public_email = data.get("email")
                    if isinstance(public_email, str) and public_email.lower() == email.lower():
                        score = 0.95
                        evidence.append("public profile email exactly matches target")
                    name = data.get("name")
                    if isinstance(name, str) and any(p in name.lower() for p in username.lower().replace("_", " ").replace("-", " ").split()):
                        score = min(0.7, score + 0.2)
                    html_url = data.get("html_url")
                    if not isinstance(html_url, str) or not html_url:
                        html_url = username
                    findings.append(
                        finding(
                            self.name,
                            "profile_candidate",
                            html_url,
                            score,
                            "info",
                            html_url if isinstance(html_url, str) and html_url.startswith("http") else None,
                            notes="Possible match; username alone is not proof of identity.",
                            raw_reference={"login": login, "name": name, "public_repos": data.get("public_repos"), "evidence": evidence},
                        )
                    )
            return ProviderResult(self.name, "ok", findings=findings, message=f"{len(findings)} possible public profile matches")
        except Exception as exc:
            return classify_exception(self.name, exc)

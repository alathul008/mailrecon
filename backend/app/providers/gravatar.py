import hashlib

import httpx

from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url


class GravatarProvider:
    name = "Gravatar"

    async def run(self, email: str) -> ProviderResult:
        settings = get_settings()
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/{h}.json"
        try:
            validate_provider_url(url)
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False) as client:
                response = await client.get(url)
            if response.status_code == 404:
                return ProviderResult(self.name, "ok", message="No public Gravatar profile")
            failure = classify_response(self.name, response)
            if failure:
                return failure
            data, parse_failure = parse_json(response, self.name)
            if parse_failure:
                return parse_failure
            if not isinstance(data, dict) or not isinstance(data.get("entry", []), list):
                return ProviderResult(self.name, "error", message="Gravatar response structure was malformed")
            entries = data.get("entry", [])
            if not entries:
                return ProviderResult(self.name, "ok", message="No public Gravatar profile")
            entry = entries[0]
            if not isinstance(entry, dict):
                return ProviderResult(self.name, "error", message="Gravatar profile record was malformed")

            findings = []
            display_name = entry.get("displayName")
            profile_url = entry.get("profileUrl")
            thumbnail_url = entry.get("thumbnailUrl")
            if isinstance(display_name, str) and display_name:
                findings.append(finding(self.name, "public_identity", display_name, 0.8, "info", url, notes="Returned by public Gravatar profile."))
            if isinstance(profile_url, str) and profile_url:
                findings.append(finding(self.name, "profile", profile_url, 0.95, "info", url))
            if isinstance(thumbnail_url, str) and thumbnail_url:
                findings.append(finding(self.name, "avatar", thumbnail_url, 0.9, "info", url))
            return ProviderResult(self.name, "ok", findings=findings, message="Public Gravatar profile found")
        except Exception as exc:
            return classify_exception(self.name, exc)

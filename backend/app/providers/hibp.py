from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url


class HIBPProvider:
    name = "Have I Been Pwned"

    async def run(self, email: str) -> ProviderResult:
        settings = get_settings()
        if not settings.hibp_api_key:
            return ProviderResult(self.name, "unconfigured", message="Provider unavailable — configure HIBP_API_KEY")

        headers = {"hibp-api-key": settings.hibp_api_key, "user-agent": settings.hibp_user_agent}
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(email, safe="")
        try:
            validate_provider_url(url)
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers, follow_redirects=False) as client:
                response = await client.get(url, params={"truncateResponse": "false"})
            if response.status_code == 404:
                return ProviderResult(self.name, "ok", message="No known breaches returned by HIBP")
            failure = classify_response(self.name, response)
            if failure:
                return failure
            data, parse_failure = parse_json(response, self.name)
            if parse_failure:
                return parse_failure
            if not isinstance(data, list):
                return ProviderResult(self.name, "error", message="HIBP response was not a breach list")

            findings = []
            for breach in data:
                if not isinstance(breach, dict):
                    continue
                name = breach.get("Name")
                if not isinstance(name, str) or not name:
                    continue
                breach_date = breach.get("BreachDate")
                first_seen = None
                if isinstance(breach_date, str) and breach_date:
                    try:
                        parsed = datetime.fromisoformat(breach_date)
                        first_seen = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
                    except ValueError:
                        breach_date = None
                raw_reference = {
                    "domain": breach.get("Domain"),
                    "date": breach_date,
                    "data_classes": breach.get("DataClasses", []),
                }
                findings.append(
                    finding(
                        self.name,
                        "breach",
                        name,
                        0.99,
                        "high",
                        "https://haveibeenpwned.com/",
                        notes="Historical breach exposure metadata only; this does not establish active compromise, current credential validity, or password disclosure.",
                        raw_reference=raw_reference,
                        first_seen=first_seen,
                    )
                )
            return ProviderResult(self.name, "ok", findings=findings, message=f"{len(findings)} breach records returned")
        except Exception as exc:
            return classify_exception(self.name, exc)

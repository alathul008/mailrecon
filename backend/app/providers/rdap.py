import httpx
from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url


class RDAPProvider:
    name = "RDAP"

    async def run(self, domain: str) -> ProviderResult:
        settings = get_settings()
        url = f"https://rdap.org/domain/{domain}"
        try:
            validate_provider_url(url)
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False) as client:
                response = await client.get(url)
            if response.status_code == 404:
                return ProviderResult(self.name, "ok", message="No public RDAP registration returned")
            failure = classify_response(self.name, response)
            if failure:
                return failure
            data, parse_failure = parse_json(response, self.name)
            if parse_failure:
                return parse_failure
            if not isinstance(data, dict):
                return ProviderResult(self.name, "error", message="RDAP response was not an object")

            findings = []
            ldh_name = data.get("ldhName")
            if isinstance(ldh_name, str) and ldh_name:
                findings.append(finding(self.name, "domain", f"ldhName: {ldh_name}", 0.98, "info", url))

            events = data.get("events", [])
            if events is None:
                events = []
            if not isinstance(events, list):
                return ProviderResult(self.name, "error", message="RDAP events field was malformed")
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = event.get("eventAction")
                if action in {"registration", "expiration", "last changed"}:
                    event_date = event.get("eventDate")
                    if not isinstance(event_date, str):
                        continue
                    findings.append(
                        finding(
                            self.name,
                            "domain_event",
                            f"{action}: {event_date}",
                            0.95,
                            "info",
                            url,
                            raw_reference=event,
                        )
                    )
            return ProviderResult(self.name, "ok", findings=findings, message="Public RDAP metadata collected")
        except Exception as exc:
            return classify_exception(self.name, exc)

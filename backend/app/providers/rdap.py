from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_OBSERVED
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class RDAPProvider:
    name = "RDAP"

    @staticmethod
    def _date(value: str | None) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @staticmethod
    def _event_map(events: list[dict]) -> dict[str, str]:
        out = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            date = event.get("eventDate")
            if isinstance(action, str) and isinstance(date, str) and action in {"registration", "expiration", "last changed"}:
                out[action] = date
        return out

    @staticmethod
    def _nameservers(data: dict) -> list[str]:
        values = data.get("nameservers")
        if not isinstance(values, list):
            return []
        return sorted({
            item.get("ldhName").rstrip(".")
            for item in values
            if isinstance(item, dict) and isinstance(item.get("ldhName"), str) and item.get("ldhName")
        })

    @staticmethod
    def _registrar(data: dict) -> str | None:
        entities = data.get("entities")
        if not isinstance(entities, list):
            return None
        for entity in entities:
            if not isinstance(entity, dict) or "registrar" not in entity.get("roles", []):
                continue
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"} and isinstance(field[3], str) and field[3]:
                        return field[3]
        return None

    async def run(self, context: ProviderContext) -> ProviderResult:
        settings = get_settings()
        url = f"https://rdap.org/domain/{context.domain}"
        try:
            validate_provider_url(url)
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False, trust_env=False, transport=pinned_transport(url)) as client:
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
                findings.append(finding(self.name, "domain", f"ldhName: {ldh_name}", 0.98, "info", url, evidence_state=EVIDENCE_OBSERVED))

            events = data.get("events", []) or []
            if not isinstance(events, list):
                return ProviderResult(self.name, "error", message="RDAP events field was malformed")
            event_map = self._event_map(events)
            for action, event_date in event_map.items():
                first_seen = self._date(event_date)
                findings.append(finding(self.name, "domain_event", f"{action}: {event_date}", 0.95, "info", url, first_seen=first_seen, evidence_state=EVIDENCE_OBSERVED))

            registrar = self._registrar(data)
            if registrar:
                findings.append(finding(self.name, "registrar", registrar, 0.95, "info", url, notes="Public RDAP registrar metadata; not proof of domain ownership.", evidence_state=EVIDENCE_OBSERVED))
            registry = data.get("registry")
            if isinstance(registry, str) and registry:
                findings.append(finding(self.name, "registry", registry, 0.85, "info", url, evidence_state=EVIDENCE_OBSERVED))
            statuses = data.get("status")
            if isinstance(statuses, list):
                for status in sorted({str(item) for item in statuses if item}):
                    findings.append(finding(self.name, "domain_status", status, 0.95, "info", url, evidence_state=EVIDENCE_OBSERVED))
            for nameserver in self._nameservers(data):
                findings.append(finding(self.name, "nameserver", nameserver, 0.95, "info", url, evidence_state=EVIDENCE_OBSERVED))

            return ProviderResult(self.name, "ok", findings=findings, message="Public RDAP registration metadata collected without persisting the raw response")
        except Exception as exc:
            return classify_exception(self.name, exc)

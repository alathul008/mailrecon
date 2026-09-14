from __future__ import annotations

from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_CORROBORATED, EVIDENCE_OBSERVED, EVIDENCE_SOURCE_ASSOCIATED
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import bounded_get, classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class EmailIntelligenceProvider:
    """Free email-centric enrichment: EmailRep reputation/profiles + XposedOrNot breaches."""

    name = "Email Intelligence"

    async def _get_json(self, url: str, headers: dict[str, str], *, not_found_ok: bool = False) -> tuple[object | None, ProviderResult | None]:
        settings = get_settings()
        validate_provider_url(url)
        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            headers=headers,
            follow_redirects=False,
            trust_env=False,
            transport=pinned_transport(url),
        ) as client:
            response = await bounded_get(client, url)
        if not_found_ok and response.status_code == 404:
            return {}, None
        failure = classify_response(self.name, response)
        if failure:
            return None, failure
        data, parse_failure = parse_json(response, self.name)
        if parse_failure:
            return None, parse_failure
        return data, None

    async def run(self, context: ProviderContext) -> ProviderResult:
        settings = get_settings()
        findings: list[dict] = []
        successes = 0
        messages: list[str] = []
        headers = {"accept": "application/json", "user-agent": "MailRecon/1.1 email intelligence"}
        if settings.emailrep_api_key:
            headers["Key"] = settings.emailrep_api_key

        try:
            emailrep_url = f"https://emailrep.io/{quote(context.email, safe='')}?summary=true"
            emailrep, emailrep_failure = await self._get_json(emailrep_url, headers)
            if emailrep_failure:
                messages.append(f"EmailRep: {emailrep_failure.message or emailrep_failure.status}")
            elif isinstance(emailrep, dict):
                successes += 1
                details = emailrep.get("details") if isinstance(emailrep.get("details"), dict) else {}
                reputation = emailrep.get("reputation")
                if isinstance(reputation, str):
                    findings.append(
                        finding(
                            "EmailRep",
                            "email_reputation",
                            reputation,
                            0.9,
                            "warning" if reputation in {"low", "none"} else "info",
                            "https://emailrep.io/",
                            notes="EmailRep reputation signal. This is reputation intelligence, not proof of identity or account ownership.",
                            evidence_state=EVIDENCE_OBSERVED,
                            raw_reference={
                                "suspicious": emailrep.get("suspicious"),
                                "references": emailrep.get("references"),
                                "first_seen": details.get("first_seen"),
                                "last_seen": details.get("last_seen"),
                            },
                        )
                    )
                profiles = details.get("profiles")
                if isinstance(profiles, list):
                    for profile in profiles[:100]:
                        if not isinstance(profile, str) or not profile.strip():
                            continue
                        service = profile.strip()
                        findings.append(
                            finding(
                                "EmailRep",
                                "profile_observation",
                                service,
                                0.88,
                                "info",
                                "https://emailrep.io/",
                                notes="EmailRep reports this online profile as associated with the email. This is source-associated evidence, not identity confirmation.",
                                evidence_state=EVIDENCE_SOURCE_ASSOCIATED,
                                raw_reference={"service": service, "source": "EmailRep"},
                            )
                        )
                for key in ("data_breach", "credentials_leaked", "credentials_leaked_recent", "malicious_activity", "malicious_activity_recent", "blacklisted", "spam", "disposable"):
                    value = details.get(key)
                    if isinstance(value, bool) and value:
                        findings.append(
                            finding(
                                "EmailRep",
                                "exposure_signal",
                                key,
                                0.9,
                                "warning",
                                "https://emailrep.io/",
                                notes=f"EmailRep reports {key}=true. This is a third-party exposure signal; underlying records are not stored by MailRecon.",
                                evidence_state=EVIDENCE_OBSERVED,
                            )
                        )
            else:
                messages.append("EmailRep returned an unexpected response shape")

            xon_url = f"https://api.xposedornot.com/v1/check-email/{quote(context.email, safe='')}"
            xon, xon_failure = await self._get_json(
                xon_url,
                {"accept": "application/json", "user-agent": "MailRecon/1.1 breach intelligence"},
                not_found_ok=True,
            )
            if xon_failure:
                messages.append(f"XposedOrNot: {xon_failure.message or xon_failure.status}")
            elif isinstance(xon, dict):
                successes += 1
                raw_breaches = xon.get("breaches")
                breach_names: list[str] = []
                if isinstance(raw_breaches, list):
                    for group in raw_breaches:
                        if isinstance(group, list):
                            breach_names.extend(item for item in group if isinstance(item, str))
                        elif isinstance(group, str):
                            breach_names.append(group)
                for breach_name in dict.fromkeys(breach_names):
                    findings.append(
                        finding(
                            "XposedOrNot",
                            "breach",
                            breach_name,
                            0.95,
                            "warning",
                            "https://xposedornot.com/",
                            notes="Known breach exposure reported by XposedOrNot. MailRecon does not retrieve or persist passwords or breach-record contents.",
                            evidence_state=EVIDENCE_CORROBORATED,
                            raw_reference={"breach": breach_name},
                        )
                    )
                findings.append(
                    finding(
                        "XposedOrNot",
                        "breach_summary",
                        str(len(dict.fromkeys(breach_names))),
                        0.95,
                        "warning" if breach_names else "info",
                        "https://xposedornot.com/",
                        notes="Number of breach sources returned by the public XposedOrNot email endpoint.",
                        evidence_state=EVIDENCE_OBSERVED,
                    )
                )
            else:
                messages.append("XposedOrNot returned an unexpected response shape")

            if successes == 0:
                return ProviderResult(self.name, "unavailable", findings=findings, message="; ".join(messages) or "Email intelligence sources were unavailable")
            status_message = "EmailRep and XposedOrNot completed" if successes == 2 else f"{successes}/2 email intelligence sources completed"
            if messages:
                status_message += "; " + "; ".join(messages)
            return ProviderResult(self.name, "ok", findings=findings, message=status_message)
        except Exception as exc:
            return classify_exception(self.name, exc)

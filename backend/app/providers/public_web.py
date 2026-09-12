from urllib.parse import quote_plus, urlparse

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_POSSIBLE
from app.osint.service_discovery import service_for_url, service_query_plan
from app.providers.base import ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


class PublicWebProvider:
    """Optional public-web search adapter for a JSON search endpoint.

    Search-index discovery is public-only. Provider-specific queries are
    bounded and are never sent to login, recovery, or authenticated APIs.
    Only public result metadata is returned; page bodies are never stored.
    """

    name = "Public Web"

    def _queries(self, email: str, candidates: list[str]) -> list[tuple[str, str | None]]:
        return service_query_plan(email, candidates)

    @staticmethod
    def _results(data: object) -> list[dict]:
        if not isinstance(data, dict):
            return []
        results = data.get("results")
        return [item for item in results if isinstance(item, dict)] if isinstance(results, list) else []

    async def run(self, email: str, candidates: list[str]) -> ProviderResult:
        settings = get_settings()
        endpoint = settings.public_web_search_url
        if not endpoint:
            return ProviderResult(
                self.name,
                "unconfigured",
                message="No operator-configured public-web JSON search endpoint is configured.",
            )

        try:
            parsed = urlparse(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Public-web search endpoint must be an HTTP(S) URL")
            validate_provider_url(endpoint)
            headers = {"accept": "application/json", "user-agent": "MailRecon"}
            if settings.public_web_search_token:
                headers["authorization"] = f"Bearer {settings.public_web_search_token}"

            findings = []
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                headers=headers,
                follow_redirects=False,
                trust_env=False,
                transport=pinned_transport(endpoint),
            ) as client:
                for query, requested_service in self._queries(email, candidates):
                    url = f"{endpoint}?q={quote_plus(query)}&format=json"
                    validate_provider_url(url)
                    response = await client.get(url)
                    failure = classify_response(self.name, response)
                    if failure:
                        return failure
                    data, parse_failure = parse_json(response, self.name)
                    if parse_failure:
                        return parse_failure
                    for item in self._results(data)[:10]:
                        result_url = item.get("url")
                        title = item.get("title")
                        if not isinstance(result_url, str) or not result_url.startswith(("http://", "https://")):
                            continue
                        validate_provider_url(result_url)
                        matched_service = service_for_url(result_url)
                        service = matched_service.name if matched_service else requested_service
                        value = title.strip() if isinstance(title, str) and title.strip() else result_url
                        findings.append(
                            finding(
                                self.name,
                                "public_web_reference",
                                value,
                                0.55,
                                "info",
                                result_url,
                                notes=(
                                    "Public search result matched an exact email or derived candidate query. "
                                    f"Evidence state: {EVIDENCE_POSSIBLE}. Search correlation is not identity confirmation."
                                ),
                                raw_reference={
                                    "query": query,
                                    "url": result_url,
                                    "title": title,
                                    "source": item.get("engine") or item.get("source"),
                                    "service": service,
                                    "category": matched_service.category if matched_service else None,
                                    "evidence_state": EVIDENCE_POSSIBLE,
                                },
                                evidence_state=EVIDENCE_POSSIBLE,
                            )
                        )
            deduped = []
            seen = set()
            for item in findings:
                key = (item.get("source_url"), item.get("value"))
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(item)
            return ProviderResult(
                self.name,
                "ok",
                findings=deduped,
                message=f"Collected {len(deduped)} public search references without storing page contents.",
            )
        except Exception as exc:
            return classify_exception(self.name, exc)

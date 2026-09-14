import hashlib
from urllib.parse import quote_plus, urlsplit, urlunsplit

import httpx

from app.core.config import get_settings
from app.osint.email import EVIDENCE_POSSIBLE
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.http import classify_exception, classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport
from app.services.resource_budget import ExecutionResourceBudget


class PublicWebProvider:
    """Optional public-web JSON search adapter with deterministic normalized results."""

    name = "Public Web"

    def _queries(self, context: ProviderContext) -> list[tuple[str, str]]:
        queries = [(f'"{context.email}"', "exact_email")]
        queries.extend((f'"{candidate}"', "derived_username") for candidate in context.candidates[:4])
        return list(dict.fromkeys(queries))

    @staticmethod
    def _results(data: object) -> list[dict]:
        if not isinstance(data, dict):
            return []
        results = data.get("results")
        return [item for item in results if isinstance(item, dict)] if isinstance(results, list) else []

    @staticmethod
    def _canonical_url(value: str) -> str:
        parsed = urlsplit(value)
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        netloc = host
        if port and not ((parsed.scheme.lower() == "https" and port == 443) or (parsed.scheme.lower() == "http" and port == 80)):
            netloc = f"{host}:{port}"
        path = parsed.path or "/"
        return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))

    @classmethod
    def _normalized(cls, item: dict, query: str, query_type: str, rank: int) -> dict | None:
        result_url = item.get("url")
        if not isinstance(result_url, str) or not result_url.startswith(("http://", "https://")):
            return None
        canonical = cls._canonical_url(result_url)
        parsed = urlsplit(canonical)
        title = item.get("title") if isinstance(item.get("title"), str) else None
        snippet = item.get("content") or item.get("snippet")
        if not isinstance(snippet, str):
            snippet = None
        engine = item.get("engine") or item.get("source") or "unknown"
        engine = str(engine)
        identity = hashlib.sha256(f"{engine.lower()}|{canonical.lower()}".encode()).hexdigest()[:24]
        return {
            "result_identity": identity,
            "engine": engine,
            "query_type": query_type,
            "query": query,
            "rank": rank,
            "title": title.strip() if title else canonical,
            "url": result_url,
            "canonical_url": canonical,
            "domain": parsed.hostname.lower() if parsed.hostname else None,
            "snippet": snippet.strip() if snippet else None,
        }

    async def run(self, context: ProviderContext) -> ProviderResult:
        settings = get_settings()
        endpoint = settings.public_web_search_url
        if not endpoint:
            return ProviderResult(self.name, "unconfigured", message="No operator-configured public-web JSON search endpoint is configured.")
        budget = ExecutionResourceBudget()
        queries = self._queries(context)[:budget.max_public_web_queries]
        try:
            parsed = urlsplit(endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Public-web search endpoint must be an HTTP(S) URL")
            validate_provider_url(endpoint)
            headers = {"accept": "application/json", "user-agent": "MailRecon"}
            if settings.public_web_search_token:
                headers["authorization"] = f"Bearer {settings.public_web_search_token}"

            normalized: list[dict] = []
            seen: set[str] = set()
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, headers=headers, follow_redirects=False, trust_env=False, transport=pinned_transport(endpoint)) as client:
                for query, query_type in queries:
                    url = f"{endpoint}?q={quote_plus(query)}&format=json"
                    validate_provider_url(url)
                    response = await client.get(url)
                    failure = classify_response(self.name, response)
                    if failure:
                        return failure
                    data, parse_failure = parse_json(response, self.name)
                    if parse_failure:
                        return parse_failure
                    for rank, item in enumerate(self._results(data)[:budget.max_public_web_results_per_query], start=1):
                        result = self._normalized(item, query, query_type, rank)
                        if not result or result["result_identity"] in seen:
                            continue
                        seen.add(result["result_identity"])
                        normalized.append(result)

            findings = []
            for result in normalized:
                findings.append(finding(
                    self.name,
                    "public_web_reference",
                    result["canonical_url"],
                    0.55,
                    "info",
                    result["canonical_url"],
                    notes="Normalized public search metadata; result correlation is a possible match and is not identity confirmation.",
                    raw_reference={k: result[k] for k in ("result_identity", "engine", "query_type", "rank", "title", "canonical_url", "domain", "snippet")},
                    evidence_state=EVIDENCE_POSSIBLE,
                ))
            return ProviderResult(self.name, "ok", findings=findings, message=f"Collected {len(findings)} deterministic public search references without storing page contents.")
        except Exception as exc:
            return classify_exception(self.name, exc)

from urllib.parse import urlparse

import httpx
from app.core.config import get_settings


def _allowed_ollama_hosts(raw: str) -> set[str]:
    return {host.strip().lower().rstrip(".") for host in raw.split(",") if host.strip()}


def validate_ollama_url(url: str, allowed_hosts: str) -> str:
    """Allow only explicitly trusted local/private Ollama endpoints.

    This is intentionally separate from the public-provider validator: Ollama is
    a trusted local/private service and does not require a public HTTPS address.
    Host authorization is exact, so a configured private endpoint must be added
    explicitly to OLLAMA_ALLOWED_HOSTS.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("OLLAMA_BASE_URL must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("OLLAMA_BASE_URL must not contain URL credentials")
    if not parsed.hostname:
        raise ValueError("OLLAMA_BASE_URL must contain a hostname")
    host = parsed.hostname.lower().rstrip(".")
    if host not in _allowed_ollama_hosts(allowed_hosts):
        raise ValueError("OLLAMA_BASE_URL host is not in OLLAMA_ALLOWED_HOSTS")
    return url.rstrip("/")


class OllamaProvider:
    name="Ollama"
    async def summarize(self, target:str, evidence:list[dict]) -> str | None:
        s=get_settings()
        if not s.enable_ollama: return None
        try:
            base_url = validate_ollama_url(s.ollama_base_url, s.ollama_allowed_hosts)
        except ValueError:
            return None
        compact=[{"type":x.get("finding_type"),"value":x.get("value"),"confidence":x.get("confidence"),"severity":x.get("severity"),"source":x.get("source")} for x in evidence]
        prompt=("You are an OSINT analyst. Summarize ONLY the supplied evidence. "
                "Do not infer identity, invent facts, expose credentials, or claim an account exists from ambiguous evidence. "
                "State uncertainty. Target: "+target+"\nEvidence:\n"+str(compact))
        try:
            # Ollama is governed by its explicit host allowlist. Do not inherit
            # HTTP(S)_PROXY/NO_PROXY environment routing, which could otherwise
            # redirect a request outside that configured network boundary.
            async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
                r=await client.post(f"{base_url}/api/generate",json={"model":s.ollama_model,"prompt":prompt,"stream":False})
                r.raise_for_status(); data=r.json(); return data.get("response")
        except Exception:
            return None

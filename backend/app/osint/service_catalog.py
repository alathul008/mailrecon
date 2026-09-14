from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from app.providers.registry import provider_definitions

@dataclass(frozen=True)
class ServiceDefinition:
    name: str
    category: str
    discovery_methods: tuple[str, ...]
    supported: bool = False
    provider: str | None = None

_IMPLEMENTED_SERVICES: tuple[ServiceDefinition, ...] = tuple(
    ServiceDefinition(
        item.name,
        item.category,
        item.discovery_methods,
        item.supported,
        item.name,
    )
    for item in provider_definitions(account_discovery=True)
)

_UNSUPPORTED_SERVICES: tuple[ServiceDefinition, ...] = (
    ServiceDefinition("Steam", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Epic Games", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("EA", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Ubisoft", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Battle.net", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Xbox", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("PlayStation", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Nintendo", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Twitch", "Gaming", ("public_profile_page",), False),
)

SERVICE_CATALOG: tuple[ServiceDefinition, ...] = _IMPLEMENTED_SERVICES + _UNSUPPORTED_SERVICES

_PUBLIC_NETWORK_HOSTS = {
    "reddit": ("Reddit", "Social & Community"),
    "dev.to": ("Dev.to", "Developer"),
    "codeberg.org": ("Codeberg", "Developer"),
    "keybase.io": ("Keybase", "Identity"),
    "huggingface.co": ("Hugging Face", "AI & Developer"),
}


def _provider_status(findings: list[dict[str, Any]], provider: str | None) -> str | None:
    if not provider:
        return None
    for item in findings:
        if item.get("source") == provider and item.get("finding_type") == "provider_status":
            return str(item.get("value"))
    return None


def _service_status(defn: ServiceDefinition, findings: list[dict[str, Any]]) -> str:
    provider_status = _provider_status(findings, defn.provider)
    if provider_status == "unconfigured": return "UNCONFIGURED"
    if provider_status == "rate_limited": return "RATE LIMITED"
    if provider_status == "unavailable": return "UNAVAILABLE"
    if provider_status == "error": return "ERROR"
    if provider_status == "disabled": return "DISABLED"

    matches = [
        f for f in findings
        if f.get("source") == defn.provider
        and f.get("finding_type") in {"profile_candidate", "public_profile", "public_identity", "profile", "public_web_reference", "profile_observation"}
    ]
    if matches:
        if any(f.get("evidence_state") in {"corroborated_match", "source_associated"} for f in matches): return "FOUND"
        return "POSSIBLE"
    if defn.supported and provider_status == "ok": return "NO PUBLIC EVIDENCE"
    if not defn.supported: return "UNAVAILABLE"
    return "UNKNOWN"


def _profile_home(service: str) -> str | None:
    hosts = {
        "github": "https://github.com",
        "gitlab": "https://gitlab.com",
        "twitter": "https://x.com",
        "x": "https://x.com",
        "linkedin": "https://www.linkedin.com",
        "instagram": "https://www.instagram.com",
        "facebook": "https://www.facebook.com",
        "reddit": "https://www.reddit.com",
        "pinterest": "https://www.pinterest.com",
        "flickr": "https://www.flickr.com",
        "vimeo": "https://vimeo.com",
        "spotify": "https://open.spotify.com",
        "myspace": "https://myspace.com",
        "twitch": "https://www.twitch.tv",
        "youtube": "https://www.youtube.com",
        "angellist": "https://wellfound.com",
        "patreon": "https://www.patreon.com",
        "discord": "https://discord.com",
        "steam": "https://steamcommunity.com",
        "medium": "https://medium.com",
        "github gist": "https://gist.github.com",
    }
    return hosts.get(service.lower().strip())


def _emailrep_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    provider_status = _provider_status(findings, "Email Intelligence")
    for f in findings:
        if f.get("source") != "EmailRep" or f.get("finding_type") != "profile_observation":
            continue
        service = str(f.get("value") or "").strip()
        key = service.casefold()
        if not service or key in seen:
            continue
        seen.add(key)
        rows.append({
            "category": "Online Profile",
            "service": service,
            "status": "FOUND",
            "supported": True,
            "provider": "Email Intelligence",
            "discovery_methods": ["EmailRep email-to-profile observation"],
            "identifier": service,
            "confidence": float(f.get("confidence")) if f.get("confidence") is not None else None,
            "provider_status": provider_status,
            "checked_at": f.get("collected_at"),
            "evidence": [{
                "finding_id": f.get("id"),
                "finding_type": f.get("finding_type"),
                "evidence_state": f.get("evidence_state"),
                "confidence": f.get("confidence"),
                "source": f.get("source"),
                "source_url": _profile_home(service) or f.get("source_url"),
                "notes": f.get("notes"),
            }],
        })
    return rows


def _public_network_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for f in findings:
        if f.get("source") != "Public Profile Network" or f.get("finding_type") != "profile_candidate":
            continue
        source_url = str(f.get("source_url") or "")
        host = urlparse(source_url).netloc.lower().removeprefix("www.")
        service_meta = _PUBLIC_NETWORK_HOSTS.get(host)
        if not service_meta:
            continue
        service, category = service_meta
        if service in seen:
            continue
        seen.add(service)
        rows.append({
            "category": category,
            "service": service,
            "status": "POSSIBLE",
            "supported": True,
            "provider": "Public Profile Network",
            "discovery_methods": ["passive username profile lookup"],
            "identifier": f.get("value"),
            "confidence": float(f.get("confidence")) if f.get("confidence") is not None else None,
            "provider_status": _provider_status(findings, "Email Intelligence") or "ok",
            "checked_at": f.get("collected_at"),
            "evidence": [{
                "finding_id": f.get("id"),
                "finding_type": f.get("finding_type"),
                "evidence_state": f.get("evidence_state"),
                "confidence": f.get("confidence"),
                "source": f.get("source"),
                "source_url": source_url,
                "notes": f.get("notes"),
            }],
        })
    return rows


def build_account_discovery_matrix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for definition in SERVICE_CATALOG:
        service_findings = [f for f in findings if f.get("source") == definition.provider]
        matches = [
            f for f in service_findings
            if f.get("finding_type") in {"profile_candidate", "public_profile", "public_identity", "profile", "public_web_reference", "profile_observation"}
        ]
        status = _service_status(definition, findings)
        matrix.append({
            "category": definition.category,
            "service": definition.name,
            "status": status,
            "supported": definition.supported,
            "provider": definition.provider,
            "discovery_methods": list(definition.discovery_methods),
            "identifier": matches[0].get("value") if matches else None,
            "confidence": max((float(f.get("confidence", 0.0)) for f in matches), default=None),
            "provider_status": next((f.get("value") for f in service_findings if f.get("finding_type") == "provider_status"), None),
            "checked_at": max((f.get("collected_at") for f in service_findings if f.get("finding_type") == "provider_status" and f.get("collected_at") is not None), default=None),
            "evidence": [
                {
                    "finding_id": f.get("id"),
                    "finding_type": f.get("finding_type"),
                    "evidence_state": f.get("evidence_state"),
                    "confidence": f.get("confidence"),
                    "source": f.get("source"),
                    "source_url": f.get("source_url"),
                    "notes": f.get("notes"),
                    "collected_at": f.get("collected_at"),
                }
                for f in matches
            ],
        })
    matrix.extend(_emailrep_rows(findings))
    matrix.extend(_public_network_rows(findings))
    return matrix

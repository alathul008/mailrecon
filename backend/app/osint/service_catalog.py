from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ServiceDefinition:
    name: str
    category: str
    discovery_methods: tuple[str, ...]
    supported: bool = False
    provider: str | None = None


SERVICE_CATALOG: tuple[ServiceDefinition, ...] = (
    ServiceDefinition("GitHub", "Developer", ("public_profile_api",), True, "GitHub"),
    ServiceDefinition("GitLab", "Developer", ("public_email_user_lookup",), True, "GitLab"),
    ServiceDefinition("Steam", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Epic Games", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("EA", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Ubisoft", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Battle.net", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Xbox", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("PlayStation", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Nintendo", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Twitch", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Gravatar", "Avatar", ("public_hash_lookup",), True, "Gravatar"),
    ServiceDefinition("Have I Been Pwned", "Other", ("breach_metadata_api",), True, "Have I Been Pwned"),
)


def _provider_status(findings: list[dict[str, Any]], provider: str | None) -> dict[str, Any] | None:
    if not provider:
        return None
    for item in findings:
        if item.get("source") == provider and item.get("finding_type") == "provider_status":
            raw = item.get("raw_reference") if isinstance(item.get("raw_reference"), dict) else {}
            return {"status": str(item.get("value")), "checked_at": item.get("collected_at") or raw.get("checked_at"), "message": item.get("notes")}
    return None


def _service_status(defn: ServiceDefinition, findings: list[dict[str, Any]]) -> str:
    provider_status = _provider_status(findings, defn.provider)
    code = provider_status["status"] if provider_status else None
    if code == "unconfigured": return "UNCONFIGURED"
    if code == "rate_limited": return "RATE LIMITED"
    if code == "unavailable": return "UNAVAILABLE"
    if code == "error": return "ERROR"
    if code == "disabled": return "DISABLED"
    matches = [
        f for f in findings
        if f.get("source") == defn.provider
        and f.get("finding_type") in {"profile_candidate", "public_identity", "profile"}
    ]
    if matches:
        if any(f.get("evidence_state") == "corroborated_match" for f in matches): return "FOUND"
        return "POSSIBLE"
    if defn.supported and code == "ok": return "NO PUBLIC EVIDENCE"
    if not defn.supported: return "UNAVAILABLE"
    return "UNAVAILABLE"


def build_account_discovery_matrix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for definition in SERVICE_CATALOG:
        service_findings = [f for f in findings if f.get("source") == definition.provider]
        matches = [f for f in service_findings if f.get("finding_type") in {"profile_candidate", "public_identity", "profile"}]
        provider = _provider_status(findings, definition.provider)
        matrix.append({
            "category": definition.category,
            "service": definition.name,
            "status": _service_status(definition, findings),
            "supported": definition.supported,
            "discovery_methods": list(definition.discovery_methods),
            "identifier": matches[0].get("value") if matches else None,
            "confidence": max((float(f.get("confidence", 0.0)) for f in matches), default=None),
            "provider_status": provider["status"] if provider else None,
            "checked_at": provider["checked_at"] if provider else None,
            "evidence": [
                {
                    "finding_id": f.get("id"),
                    "finding_type": f.get("finding_type"),
                    "evidence_state": f.get("evidence_state"),
                    "confidence": f.get("confidence"),
                    "source": f.get("source"),
                    "source_url": f.get("source_url"),
                    "notes": f.get("notes"),
                }
                for f in matches
            ],
        })
    return matrix

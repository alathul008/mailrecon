from dataclasses import dataclass
from typing import Any

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

# Unsupported services remain explicit catalogue entries so the UI can state
# that they were not checked. Implemented services are derived from the
# canonical provider registry and cannot silently drift from provider state.
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
        and f.get("finding_type") in {"profile_candidate", "public_identity", "profile", "public_web_reference"}
    ]
    if matches:
        if any(f.get("evidence_state") == "corroborated_match" for f in matches): return "FOUND"
        return "POSSIBLE"
    if defn.supported and provider_status == "ok": return "NO PUBLIC EVIDENCE"
    if not defn.supported: return "UNAVAILABLE"
    return "UNKNOWN"


def build_account_discovery_matrix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for definition in SERVICE_CATALOG:
        service_findings = [f for f in findings if f.get("source") == definition.provider]
        matches = [
            f for f in service_findings
            if f.get("finding_type") in {"profile_candidate", "public_identity", "profile", "public_web_reference"}
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
    return matrix

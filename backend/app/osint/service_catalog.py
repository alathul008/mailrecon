from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ServiceDefinition:
    name: str
    category: str
    discovery_methods: tuple[str, ...]
    supported: bool = False
    provider: str | None = None


# The catalogue is deliberately declarative. A service is not considered
# discoverable merely because it appears here; only a provider with an
# implemented, legitimate public discovery method can produce evidence.
SERVICE_CATALOG: tuple[ServiceDefinition, ...] = (
    ServiceDefinition("GitHub", "Developer", ("public_profile_api",), True, "GitHub"),
    ServiceDefinition("GitLab", "Developer", ("public_profile_api",), False, "GitLab"),
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
    ServiceDefinition("Public Web", "Other", ("public_search_api",), True, "Public Web"),
)


def _provider_status(findings: list[dict[str, Any]], provider: str | None) -> str | None:
    if not provider:
        return None
    for item in findings:
        if item.get("source") == provider and item.get("finding_type") == "provider_status":
            return str(item.get("value"))
    return None


def _service_status(defn: ServiceDefinition, findings: list[dict[str, Any]]) -> str:
    provider_status = _provider_status(findings, defn.provider)
    if provider_status == "unconfigured":
        return "UNCONFIGURED"
    if provider_status == "rate_limited":
        return "RATE LIMITED"
    if provider_status == "unavailable":
        return "UNAVAILABLE"
    if provider_status == "error":
        return "ERROR"
    if provider_status == "disabled":
        return "DISABLED"

    matches = [
        f for f in findings
        if f.get("source") == defn.provider
        and f.get("finding_type") in {"profile_candidate", "public_identity", "profile", "public_web_reference"}
    ]
    if matches:
        if any(f.get("evidence_state") == "corroborated_match" for f in matches):
            return "FOUND"
        return "POSSIBLE"
    if defn.supported and provider_status == "ok":
        return "NO PUBLIC EVIDENCE"
    if not defn.supported:
        return "UNAVAILABLE"
    return "UNKNOWN"


def build_account_discovery_matrix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Project persisted evidence into an analyst-facing service matrix.

    Operational provider state and evidence state remain separate. In
    particular, an unavailable/unconfigured provider never becomes a negative
    account finding.
    """
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
            "discovery_methods": list(definition.discovery_methods),
            "identifier": matches[0].get("value") if matches else None,
            "confidence": max((float(f.get("confidence", 0.0)) for f in matches), default=None),
            "evidence": [
                {
                    "finding_id": f.get("id"),
                    "finding_type": f.get("finding_type"),
                    "evidence_state": f.get("evidence_state"),
                    "source_url": f.get("source_url"),
                }
                for f in matches
            ],
        })
    return matrix

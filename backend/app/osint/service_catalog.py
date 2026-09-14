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
    ServiceDefinition(item.name, item.category, item.discovery_methods, item.supported, item.name)
    for item in provider_definitions(account_discovery=True)
)

_PUBLIC_NETWORK_SERVICES: tuple[ServiceDefinition, ...] = (
    ServiceDefinition("GitHub", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("GitLab", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Reddit", "Social & Community", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Dev.to", "Developer", ("public profile API",), True, "Public Profile Network"),
    ServiceDefinition("Codeberg", "Developer", ("public profile API",), True, "Public Profile Network"),
    ServiceDefinition("Keybase", "Identity", ("public profile API",), True, "Public Profile Network"),
    ServiceDefinition("Hugging Face", "AI & Developer", ("public profile API",), True, "Public Profile Network"),
    ServiceDefinition("Bitbucket", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Medium", "Publishing", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Vimeo", "Media", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Flickr", "Photography", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("SoundCloud", "Music", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Patreon", "Creator", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Buy Me a Coffee", "Creator", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Linktree", "Social & Creator", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("About.me", "Identity", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Behance", "Design", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Dribbble", "Design", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Product Hunt", "Product & Tech", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Kaggle", "Data Science", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("npm", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("PyPI", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Docker Hub", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("CodePen", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Replit", "Developer", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Instructables", "Maker", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Wattpad", "Publishing", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Goodreads", "Publishing", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Steam", "Gaming", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Twitch", "Streaming", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Pinterest", "Social & Visual", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Tumblr", "Publishing", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("X", "Social", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Instagram", "Social", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("Threads", "Social", ("passive public profile",), True, "Public Profile Network"),
    ServiceDefinition("YouTube", "Video", ("passive public profile",), True, "Public Profile Network"),
)

_UNSUPPORTED_SERVICES: tuple[ServiceDefinition, ...] = (
    ServiceDefinition("Epic Games", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("EA", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Ubisoft", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Battle.net", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Xbox", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("PlayStation", "Gaming", ("public_profile_page",), False),
    ServiceDefinition("Nintendo", "Gaming", ("public_profile_page",), False),
)

# The registry-backed providers remain first-class; the public profile network is
# represented here as a bounded, real coverage catalog for the account UI.
SERVICE_CATALOG: tuple[ServiceDefinition, ...] = _IMPLEMENTED_SERVICES + _PUBLIC_NETWORK_SERVICES + _UNSUPPORTED_SERVICES


def _provider_status(findings: list[dict[str, Any]], provider: str | None) -> str | None:
    if not provider:
        return None
    for item in findings:
        if item.get("source") == provider and item.get("finding_type") == "provider_status":
            return str(item.get("value"))
    return None


def _public_service_status(name: str, findings: list[dict[str, Any]]) -> str | None:
    prefix = f"{name}:"
    for item in findings:
        if item.get("source") == "Public Profile Network" and item.get("finding_type") == "service_status" and str(item.get("value") or "").startswith(prefix):
            value = str(item.get("value"))
            if value.endswith(":no_public_evidence"):
                return "NO PUBLIC EVIDENCE"
            if ":rate_limited" in value:
                return "RATE LIMITED"
            if ":unavailable" in value:
                return "UNAVAILABLE"
            if ":error" in value:
                return "ERROR"
            return "UNKNOWN"
    return None


def _service_status(defn: ServiceDefinition, findings: list[dict[str, Any]]) -> str:
    if defn.provider == "Public Profile Network":
        matches = [f for f in findings if f.get("source") == defn.provider and f.get("finding_type") == "profile_candidate" and str(f.get("source_url") or "")]
        if any(_service_from_url(f.get("source_url")) == defn.name for f in matches):
            return "POSSIBLE"
        return _public_service_status(defn.name, findings) or "UNKNOWN"
    provider_status = _provider_status(findings, defn.provider)
    if provider_status == "unconfigured": return "UNCONFIGURED"
    if provider_status == "rate_limited": return "RATE LIMITED"
    if provider_status == "unavailable": return "UNAVAILABLE"
    if provider_status == "error": return "ERROR"
    if provider_status == "disabled": return "DISABLED"
    matches = [f for f in findings if f.get("source") == defn.provider and f.get("finding_type") in {"profile_candidate", "public_profile", "public_identity", "profile", "public_web_reference", "profile_observation"}]
    if matches:
        if any(f.get("evidence_state") in {"corroborated_match", "source_associated"} for f in matches): return "FOUND"
        return "POSSIBLE"
    if defn.supported and provider_status == "ok": return "NO PUBLIC EVIDENCE"
    if not defn.supported: return "UNAVAILABLE"
    return "UNKNOWN"


def _service_from_url(source_url: Any) -> str | None:
    host = urlparse(str(source_url or "")).netloc.lower().removeprefix("www.")
    return {
        "github.com": "GitHub", "gitlab.com": "GitLab", "reddit.com": "Reddit", "dev.to": "Dev.to",
        "codeberg.org": "Codeberg", "keybase.io": "Keybase", "huggingface.co": "Hugging Face",
        "bitbucket.org": "Bitbucket", "medium.com": "Medium", "vimeo.com": "Vimeo",
        "flickr.com": "Flickr", "soundcloud.com": "SoundCloud", "patreon.com": "Patreon",
        "buymeacoffee.com": "Buy Me a Coffee", "linktr.ee": "Linktree", "about.me": "About.me",
        "behance.net": "Behance", "dribbble.com": "Dribbble", "producthunt.com": "Product Hunt",
        "kaggle.com": "Kaggle", "npmjs.com": "npm", "pypi.org": "PyPI", "hub.docker.com": "Docker Hub",
        "codepen.io": "CodePen", "replit.com": "Replit", "instructables.com": "Instructables",
        "wattpad.com": "Wattpad", "goodreads.com": "Goodreads", "steamcommunity.com": "Steam",
        "twitch.tv": "Twitch", "pinterest.com": "Pinterest", "tumblr.com": "Tumblr", "x.com": "X",
        "instagram.com": "Instagram", "threads.net": "Threads", "youtube.com": "YouTube",
    }.get(host)


def _profile_home(service: str) -> str | None:
    hosts = {"github": "https://github.com", "gitlab": "https://gitlab.com", "twitter": "https://x.com", "x": "https://x.com", "linkedin": "https://www.linkedin.com", "instagram": "https://www.instagram.com", "facebook": "https://www.facebook.com", "reddit": "https://www.reddit.com", "pinterest": "https://www.pinterest.com", "flickr": "https://www.flickr.com", "vimeo": "https://vimeo.com", "spotify": "https://open.spotify.com", "myspace": "https://myspace.com", "twitch": "https://www.twitch.tv", "youtube": "https://www.youtube.com", "angellist": "https://wellfound.com", "patreon": "https://www.patreon.com", "discord": "https://discord.com", "steam": "https://steamcommunity.com", "medium": "https://medium.com", "github gist": "https://gist.github.com"}
    return hosts.get(service.lower().strip())


def _emailrep_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    provider_status = _provider_status(findings, "Email Intelligence")
    for f in findings:
        if f.get("source") != "EmailRep" or f.get("finding_type") != "profile_observation": continue
        service = str(f.get("value") or "").strip(); key = service.casefold()
        if not service or key in seen: continue
        seen.add(key)
        rows.append({"category":"Online Profile","service":service,"status":"FOUND","supported":True,"provider":"Email Intelligence","discovery_methods":["EmailRep email-to-profile observation"],"identifier":service,"confidence":float(f.get("confidence")) if f.get("confidence") is not None else None,"provider_status":provider_status,"checked_at":f.get("collected_at"),"evidence":[{"finding_id":f.get("id"),"finding_type":f.get("finding_type"),"evidence_state":f.get("evidence_state"),"confidence":f.get("confidence"),"source":f.get("source"),"source_url":_profile_home(service) or f.get("source_url"),"notes":f.get("notes")}]})
    return rows


def build_account_discovery_matrix(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: list[dict[str, Any]] = []
    for definition in SERVICE_CATALOG:
        service_findings = [f for f in findings if f.get("source") == definition.provider]
        matches = [f for f in service_findings if f.get("finding_type") in {"profile_candidate", "public_profile", "public_identity", "profile", "public_web_reference", "profile_observation"}]
        matrix.append({"category":definition.category,"service":definition.name,"status":_service_status(definition,findings),"supported":definition.supported,"provider":definition.provider,"discovery_methods":list(definition.discovery_methods),"identifier":matches[0].get("value") if matches else None,"confidence":max((float(f.get("confidence",0.0)) for f in matches),default=None),"provider_status":next((f.get("value") for f in service_findings if f.get("finding_type")=="provider_status"),None),"checked_at":max((f.get("collected_at") for f in service_findings if f.get("finding_type")=="provider_status" and f.get("collected_at") is not None),default=None),"evidence":[{"finding_id":f.get("id"),"finding_type":f.get("finding_type"),"evidence_state":f.get("evidence_state"),"confidence":f.get("confidence"),"source":f.get("source"),"source_url":f.get("source_url"),"notes":f.get("notes"),"collected_at":f.get("collected_at")} for f in matches]})
    matrix.extend(_emailrep_rows(findings))
    return matrix

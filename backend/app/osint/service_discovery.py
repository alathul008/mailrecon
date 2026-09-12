from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class PublicService:
    name: str
    category: str
    domains: tuple[str, ...]


PUBLIC_SERVICES: tuple[PublicService, ...] = (
    PublicService("GitHub", "Developer", ("github.com",)),
    PublicService("GitLab", "Developer", ("gitlab.com",)),
    PublicService("Steam", "Gaming", ("steamcommunity.com",)),
    PublicService("Epic Games", "Gaming", ("epicgames.com", "fortnite.com")),
    PublicService("EA", "Gaming", ("ea.com", "answers.ea.com")),
    PublicService("Ubisoft", "Gaming", ("ubisoft.com",)),
    PublicService("Battle.net", "Gaming", ("battle.net",)),
    PublicService("Xbox", "Gaming", ("xbox.com",)),
    PublicService("PlayStation", "Gaming", ("playstation.com",)),
    PublicService("Nintendo", "Gaming", ("nintendo.com",)),
    PublicService("Twitch", "Gaming", ("twitch.tv",)),
    PublicService("Discord", "Communication", ("discord.com", "discordapp.com")),
    PublicService("Reddit", "Social", ("reddit.com",)),
    PublicService("X", "Social", ("x.com", "twitter.com")),
    PublicService("LinkedIn", "Professional", ("linkedin.com",)),
    PublicService("Stack Overflow", "Developer", ("stackoverflow.com",)),
    PublicService("Dev.to", "Developer", ("dev.to",)),
    PublicService("Medium", "Publishing", ("medium.com",)),
)


def service_for_url(value: str) -> PublicService | None:
    try:
        hostname = (urlparse(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    for service in PUBLIC_SERVICES:
        if any(hostname == domain or hostname.endswith(f".{domain}") for domain in service.domains):
            return service
    return None


def service_query_plan(email: str, candidates: list[str]) -> list[tuple[str, str | None]]:
    """Return a deterministic, bounded public-search plan.

    Queries only target public search indexes. This is not account/login
    enumeration and deliberately never probes provider authentication flows.
    """
    queries: list[tuple[str, str | None]] = [(f'"{email}"', None)]
    queries.extend((f'"{candidate}"', None) for candidate in candidates[:4])
    for service in PUBLIC_SERVICES:
        site = service.domains[0]
        queries.append((f'"{email}" site:{site}', service.name))
    return list(dict.fromkeys(queries))

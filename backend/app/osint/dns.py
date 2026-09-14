import asyncio
import ipaddress
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.core.config import get_settings
from app.providers.http import classify_response, parse_json, validate_provider_url
from app.providers.network import pinned_transport


MAX_INFRA_IPS = 2
DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "dkim", "mail")


def _parse_kv(record: str) -> dict[str, str]:
    parts = {}
    for token in record.split(";"):
        token = token.strip()
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        parts[key.strip().lower()] = value.strip()
    return parts


def _parse_spf(records: list[str]) -> dict:
    mechanisms: list[str] = []
    includes: list[str] = []
    qualifiers: list[str] = []
    policy = None
    for record in records:
        tokens = record.split()[1:]
        for token in tokens:
            qualifier = token[0] if token[:1] in {"+", "-", "~", "?"} else "+"
            mechanism = token[1:] if token[:1] in {"+", "-", "~", "?"} else token
            qualifiers.append(f"{qualifier}{mechanism}")
            if mechanism.startswith("include:"):
                includes.append(mechanism.split(":", 1)[1])
            if mechanism in {"all", "-all", "~all", "?all", "+all"} or mechanism.endswith("all"):
                policy = f"{qualifier}all"
            mechanisms.append(mechanism)
    return {"present": bool(records), "mechanisms": sorted(set(mechanisms)), "includes": sorted(set(includes)), "qualifiers": sorted(set(qualifiers)), "policy": policy}


def _parse_dmarc(records: list[str]) -> dict:
    parsed = _parse_kv(records[0]) if records else {}
    return {
        "present": bool(records),
        "policy": parsed.get("p"),
        "pct": int(parsed["pct"]) if parsed.get("pct", "").isdigit() else None,
        "alignment_dkim": parsed.get("adkim"),
        "alignment_spf": parsed.get("aspf"),
        "reporting_uris": bool(parsed.get("rua") or parsed.get("ruf")),
    }


def _parse_dkim(records: list[str]) -> list[dict[str, str]]:
    out = []
    for record in records:
        selector, _, value = record.partition(": ")
        if not value:
            continue
        parsed = _parse_kv(value)
        out.append({"selector": selector, "key_type": parsed.get("k"), "key_present": bool(parsed.get("p")), "record": value})
    return out


def _classify_host(value: str, patterns: dict[str, str]) -> str | None:
    lowered = value.lower().rstrip(".")
    for pattern, provider in patterns.items():
        if pattern in lowered:
            return provider
    return None


def _classify_mail_provider(mx_records: list[str]) -> str | None:
    return _classify_host(" ".join(mx_records), {
        "google.com": "Google Workspace",
        "googlemail.com": "Google Workspace",
        "outlook.com": "Microsoft 365",
        "protection.outlook.com": "Microsoft 365",
        "protonmail.ch": "Proton Mail",
        "protonmail.com": "Proton Mail",
        "zoho.com": "Zoho Mail",
        "yahoodns.net": "Yahoo Mail",
        "icloud.com": "Apple Mail",
    })


def _classify_dns_provider(records: list[str]) -> str | None:
    return _classify_host(" ".join(records), {
        "cloudflare.com": "Cloudflare",
        "awsdns": "Amazon Route 53",
        "googledomains.com": "Google Cloud DNS",
        "google.com": "Google Cloud DNS",
        "azure-dns": "Microsoft Azure DNS",
        "digitalocean.com": "DigitalOcean",
    })


async def _resolve(resolver, name, rdtype):
    try:
        answer = await resolver.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answer], "ok"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], "no_result"
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return [], "unavailable"
    except Exception:
        return [], "error"


def record_presence(values, status):
    """Return True/False for an answered DNS query, None when unavailable/error."""
    if status in {"unavailable", "error"} or status is False:
        return None
    return bool(values)


async def _ip_context(address: str) -> dict | None:
    try:
        parsed = ipaddress.ip_address(address)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
            return None
        url = f"https://rdap.org/ip/{quote(address, safe=':')}"
        validate_provider_url(url)
        settings = get_settings()
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False, trust_env=False, transport=pinned_transport(url)) as client:
            response = await client.get(url)
        failure = classify_response("IP Infrastructure", response)
        if failure:
            return {"ip": address, "status": failure.status, "message": failure.message}
        data, parse_failure = parse_json(response, "IP Infrastructure")
        if parse_failure or not isinstance(data, dict):
            return {"ip": address, "status": "error", "message": "IP RDAP response was malformed"}
        entities = data.get("entities") if isinstance(data.get("entities"), list) else []
        names = []
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"} and isinstance(field[3], str):
                        names.append(field[3])
        return {
            "ip": address,
            "status": "ok",
            "asn": data.get("handle") if isinstance(data.get("handle"), str) and data.get("handle", "").upper().startswith("AS") else None,
            "network": data.get("name") if isinstance(data.get("name"), str) else None,
            "organization": names[0] if names else None,
        }
    except Exception as exc:
        return {"ip": address, "status": "error", "message": type(exc).__name__}


async def resolve(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY"]
    results = await asyncio.gather(*[_resolve(resolver, domain, kind) for kind in record_types])
    out = {}
    statuses = {}
    for kind, (values, status) in zip(record_types, results):
        if status is True:
            status = "ok"
        elif status is False:
            status = "unavailable"
        out[kind] = values
        statuses[kind] = status

    txt = out.get("TXT", [])
    out["SPF"] = [x for x in txt if x.lower().startswith("v=spf1")]
    out["SPF_status"] = statuses["TXT"]
    out["SPF_analysis"] = _parse_spf(out["SPF"])

    dmarc, dmarc_status = await _resolve(resolver, f"_dmarc.{domain}", "TXT")
    if dmarc_status is True:
        dmarc_status = "ok"
    elif dmarc_status is False:
        dmarc_status = "unavailable"
    out["DMARC"] = [x for x in dmarc if x.lower().startswith("v=dmarc1")]
    out["DMARC_status"] = dmarc_status
    out["DMARC_analysis"] = _parse_dmarc(out["DMARC"])

    dkim_results = await asyncio.gather(*[_resolve(resolver, f"{selector}._domainkey.{domain}", "TXT") for selector in DKIM_SELECTORS])
    dkim = []
    dkim_statuses = []
    for selector, (values, status) in zip(DKIM_SELECTORS, dkim_results):
        if status is True:
            status = "ok"
        elif status is False:
            status = "unavailable"
        if values:
            dkim.extend([f"{selector}: {value}" for value in values if value.lower().startswith("v=dkim1")])
        dkim_statuses.append(status)
    out["DKIM"] = dkim
    out["DKIM_status"] = "ok" if dkim else ("unavailable" if "unavailable" in dkim_statuses or "error" in dkim_statuses else "no_result")
    out["DKIM_analysis"] = _parse_dkim(dkim)

    if statuses["DS"] == "ok" and out["DS"]:
        out["DNSSEC"] = True
        out["DNSSEC_status"] = "ok"
    elif statuses["DS"] in {"unavailable", "error"}:
        out["DNSSEC"] = None
        out["DNSSEC_status"] = statuses["DS"]
    else:
        out["DNSSEC"] = False
        out["DNSSEC_status"] = "no_result"

    observed_ips = list(dict.fromkeys(out["A"] + out["AAAA"]))[:MAX_INFRA_IPS]
    out["IP_CONTEXT"] = await asyncio.gather(*[_ip_context(address) for address in observed_ips]) if observed_ips else []
    out["MX_PROVIDER"] = _classify_mail_provider(out["MX"])
    out["NS_PROVIDER"] = _classify_dns_provider(out["NS"])
    return out

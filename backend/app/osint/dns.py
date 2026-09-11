import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver


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


async def resolve(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY"]
    results = await asyncio.gather(*[_resolve(resolver, domain, kind) for kind in record_types])
    out = {}
    statuses = {}
    for kind, (values, status) in zip(record_types, results):
        # Keep compatibility with existing tests/integrations that monkeypatch the
        # resolver helper with its former boolean status contract.
        if status is True:
            status = "ok"
        elif status is False:
            status = "unavailable"
        out[kind] = values
        statuses[kind] = status

    txt = out.get("TXT", [])
    out["SPF"] = [x for x in txt if x.lower().startswith("v=spf1")]
    out["SPF_status"] = statuses["TXT"]

    dmarc, dmarc_status = await _resolve(resolver, f"_dmarc.{domain}", "TXT")
    if dmarc_status is True:
        dmarc_status = "ok"
    elif dmarc_status is False:
        dmarc_status = "unavailable"
    out["DMARC"] = [x for x in dmarc if x.lower().startswith("v=dmarc1")]
    out["DMARC_status"] = dmarc_status

    # DKIM has no registry-wide selector discovery mechanism. Probe only a small,
    # deterministic set of common public selectors and report observations found.
    dkim_selectors = ("google", "selector1", "selector2", "default", "dkim", "mail")
    dkim_results = await asyncio.gather(
        *[_resolve(resolver, f"{selector}._domainkey.{domain}", "TXT") for selector in dkim_selectors]
    )
    dkim = []
    dkim_statuses = []
    for selector, (values, status) in zip(dkim_selectors, dkim_results):
        if status is True:
            status = "ok"
        elif status is False:
            status = "unavailable"
        if values:
            dkim.extend([f"{selector}: {value}" for value in values if value.lower().startswith("v=dkim1")])
        dkim_statuses.append(status)
    out["DKIM"] = dkim
    out["DKIM_status"] = "ok" if dkim else ("unavailable" if "unavailable" in dkim_statuses or "error" in dkim_statuses else "no_result")

    # A DS record is the authoritative DNS indication that the delegation is signed.
    # DNSKEY alone is insufficient to claim DNSSEC is enabled, and this resolver does
    # not perform DNSSEC validation. Therefore absence is an observation, not a failure.
    if statuses["DS"] == "ok" and out["DS"]:
        out["DNSSEC"] = True
        out["DNSSEC_status"] = "ok"
    elif statuses["DS"] in {"unavailable", "error"}:
        out["DNSSEC"] = None
        out["DNSSEC_status"] = statuses["DS"]
    else:
        out["DNSSEC"] = False
        out["DNSSEC_status"] = "no_result"
    return out

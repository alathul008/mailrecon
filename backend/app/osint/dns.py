import asyncio
import dns.asyncresolver


async def _resolve(resolver, name, rdtype):
    try:
        answer = await resolver.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answer], True
    except Exception:
        return [], False


async def resolve(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
    results = await asyncio.gather(*[_resolve(resolver, domain, kind) for kind in record_types])
    out = {}
    statuses = {}
    for kind, (values, ok) in zip(record_types, results):
        out[kind] = values
        statuses[kind] = "ok" if ok else "unavailable"

    txt = out.get("TXT", [])
    out["SPF"] = [x for x in txt if x.lower().startswith("v=spf1")]
    out["SPF_status"] = statuses["TXT"]

    dmarc, dmarc_ok = await _resolve(resolver, f"_dmarc.{domain}", "TXT")
    out["DMARC"] = [x for x in dmarc if x.lower().startswith("v=dmarc1")]
    out["DMARC_status"] = "ok" if dmarc_ok else "unavailable"

    # dnspython does not expose a portable boolean from this simple resolver call;
    # absence is therefore reported as unknown rather than a definitive failure.
    out["DNSSEC"] = []
    out["DNSSEC_status"] = "unknown"
    return out

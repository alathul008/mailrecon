import asyncio
import dns.asyncresolver
import dns.exception

async def _resolve(resolver, name, rdtype):
    try:
        answer = await resolver.resolve(name, rdtype)
        return [r.to_text().strip('"') for r in answer]
    except Exception:
        return []

async def resolve(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 4.0
    keys = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SPF", "DMARC", "DNSSEC"]
    results = await asyncio.gather(*[
        _resolve(resolver, domain, k) if k not in {"SPF", "DMARC", "DNSSEC"} else _resolve(resolver, f"_dmarc.{domain}" if k == "DMARC" else domain, "TXT") if k in {"SPF", "DMARC"} else _resolve(resolver, domain, "A")
        for k in keys
    ])
    out = dict(zip(keys, results))
    txt = out.get("TXT", [])
    out["SPF"] = [x for x in txt if x.lower().startswith("v=spf1")]
    out["DMARC"] = [x for x in out.get("DMARC", []) if x.lower().startswith("v=dmarc1")]
    # dnspython does not expose a portable boolean from this simple resolver call;
    # absence is therefore reported as not observed rather than definitive failure.
    out["DNSSEC"] = []
    return out

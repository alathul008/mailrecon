import httpx
from app.providers.base import ProviderResult, finding

class RDAPProvider:
    name="RDAP"
    async def run(self, domain: str) -> ProviderResult:
        url=f"https://rdap.org/domain/{domain}"
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client: r=await client.get(url)
            if r.status_code >= 400: return ProviderResult(self.name,"ok",message="RDAP data unavailable for this domain")
            d=r.json(); f=[]
            if d.get("ldhName"): f.append(finding(self.name,"domain","ldhName: "+d["ldhName"],0.98,"info",url))
            events=d.get("events",[])
            for e in events:
                if e.get("eventAction") in {"registration","expiration","last changed"}:
                    f.append(finding(self.name,"domain_event",f"{e['eventAction']}: {e.get('eventDate','')}",0.95,"info",url,raw_reference=e))
            return ProviderResult(self.name,"ok",findings=f,message="Public RDAP metadata collected")
        except Exception as exc: return ProviderResult(self.name,"error",message=f"RDAP request failed: {type(exc).__name__}")

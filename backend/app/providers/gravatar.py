import hashlib, httpx
from app.providers.base import ProviderResult, finding

class GravatarProvider:
    name="Gravatar"
    async def run(self, email: str) -> ProviderResult:
        h=hashlib.md5(email.strip().lower().encode()).hexdigest()
        url=f"https://www.gravatar.com/{h}.json"
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
                r=await client.get(url)
            if r.status_code == 404: return ProviderResult(self.name,"ok",message="No public Gravatar profile")
            r.raise_for_status(); data=r.json()
            entries=data.get("entry",[])
            if not entries: return ProviderResult(self.name,"ok",message="No public Gravatar profile")
            e=entries[0]; f=[]
            if e.get("displayName"): f.append(finding(self.name,"public_identity",e["displayName"],0.8,"info",url,notes="Returned by public Gravatar profile."))
            if e.get("profileUrl"): f.append(finding(self.name,"profile",e["profileUrl"],0.95,"info",url))
            if e.get("thumbnailUrl"): f.append(finding(self.name,"avatar",e["thumbnailUrl"],0.9,"info",url))
            return ProviderResult(self.name,"ok",findings=f,message="Public Gravatar profile found")
        except Exception as exc: return ProviderResult(self.name,"error",message=f"Gravatar request failed: {type(exc).__name__}")

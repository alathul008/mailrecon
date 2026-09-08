import httpx
from app.providers.base import ProviderResult, finding
from app.core.config import get_settings

class GitHubProvider:
    name="GitHub"
    async def run(self, candidates: list[str], email: str) -> ProviderResult:
        s=get_settings(); headers={"accept":"application/vnd.github+json","user-agent":"MailRecon"}
        if s.github_token: headers["authorization"]=f"Bearer {s.github_token}"
        findings=[]
        try:
            async with httpx.AsyncClient(timeout=8, headers=headers, follow_redirects=False) as client:
                for username in candidates[:8]:
                    r=await client.get(f"https://api.github.com/users/{username}")
                    if r.status_code != 200: continue
                    u=r.json()
                    # Existence is evidence of a username, not identity proof.
                    score=0.35
                    evidence=["public GitHub username matches a generated candidate"]
                    if u.get("email") and str(u.get("email")).lower()==email.lower(): score=0.95; evidence.append("public profile email exactly matches target")
                    if u.get("name") and any(p in str(u.get("name")).lower() for p in username.lower().replace("_"," ").replace("-"," ").split()): score=min(0.7,score+0.2)
                    findings.append(finding(self.name,"profile_candidate",u.get("html_url",username),score,"info",u.get("html_url"),notes="Possible match; username alone is not proof of identity.",raw_reference={"login":u.get("login"),"name":u.get("name"),"public_repos":u.get("public_repos"),"evidence":evidence}))
            return ProviderResult(self.name,"ok",findings=findings,message=f"{len(findings)} possible public profile matches")
        except Exception as exc: return ProviderResult(self.name,"error",message=f"GitHub request failed: {type(exc).__name__}")

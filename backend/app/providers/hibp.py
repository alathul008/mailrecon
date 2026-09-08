import httpx
from urllib.parse import quote
from app.core.config import get_settings
from app.providers.base import ProviderResult, finding
from datetime import datetime, timezone

class HIBPProvider:
    name = "Have I Been Pwned"
    async def run(self, email: str) -> ProviderResult:
        s = get_settings()
        if not s.hibp_api_key:
            return ProviderResult(self.name, "unconfigured", message="Provider unavailable — configure HIBP_API_KEY")
        headers = {"hibp-api-key": s.hibp_api_key, "user-agent": s.hibp_user_agent}
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(email, safe="")
        try:
            async with httpx.AsyncClient(timeout=s.request_timeout_seconds, headers=headers) as client:
                r = await client.get(url, params={"truncateResponse": "false"})
                if r.status_code == 404:
                    return ProviderResult(self.name, "ok", message="No known breaches returned by HIBP")
                if r.status_code in (401,403): return ProviderResult(self.name, "error", message="HIBP API key rejected")
                r.raise_for_status()
                data = r.json()
            findings=[]
            for breach in data:
                findings.append(finding(self.name, "breach", breach.get("Name", "Unknown"), 0.99, "high", "https://haveibeenpwned.com/", notes="Breach metadata only; no passwords are displayed.", raw_reference={"domain": breach.get("Domain"), "date": breach.get("BreachDate"), "data_classes": breach.get("DataClasses", [])}, first_seen=datetime.fromisoformat(breach["BreachDate"]).replace(tzinfo=timezone.utc) if breach.get("BreachDate") else None))
            return ProviderResult(self.name, "ok", findings=findings, message=f"{len(findings)} breach records returned")
        except Exception as exc:
            return ProviderResult(self.name, "error", message=f"HIBP request failed: {type(exc).__name__}")

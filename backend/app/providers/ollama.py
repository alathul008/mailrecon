import httpx
from app.core.config import get_settings

class OllamaProvider:
    name="Ollama"
    async def summarize(self, target:str, evidence:list[dict]) -> str | None:
        s=get_settings()
        if not s.enable_ollama: return None
        compact=[{"type":x.get("finding_type"),"value":x.get("value"),"confidence":x.get("confidence"),"severity":x.get("severity"),"source":x.get("source")} for x in evidence]
        prompt=("You are an OSINT analyst. Summarize ONLY the supplied evidence. "
                "Do not infer identity, invent facts, expose credentials, or claim an account exists from ambiguous evidence. "
                "State uncertainty. Target: "+target+"\nEvidence:\n"+str(compact))
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r=await client.post(f"{s.ollama_base_url.rstrip('/')}/api/generate",json={"model":s.ollama_model,"prompt":prompt,"stream":False})
                r.raise_for_status(); data=r.json(); return data.get("response")
        except Exception:
            return None

import csv, io, json, html
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse, HTMLResponse
from sqlalchemy import select, func, delete, text
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.schemas.schemas import InvestigationCreate
from app.services.orchestrator import MODULES
from app.reports.render import pdf_report
from app.core.auth import require_api_key
from app.core.config import get_settings
from app.core.rate_limit import allow_investigation_creation

router=APIRouter(prefix="/api")
TIMELINE_FINDING_TYPES={"email","domain","domain_event","a","aaaa","mx","ns","cname","spf","dmarc","dnssec","profile_candidate","public_identity","profile","avatar","breach"}

def evidence_state(f):
    if f.evidence_state: return f.evidence_state
    notes=f.notes or ""; marker="Evidence state: "
    if marker in notes: return notes.split(marker,1)[1].split(".",1)[0].strip()
    if isinstance(f.raw_reference,dict) and isinstance(f.raw_reference.get("evidence_state"),str): return f.raw_reference["evidence_state"]
    return None

def timeline_timestamp(f): return f.first_seen or f.collected_at

def csv_safe(value):
    if not isinstance(value,str): return value
    first=value.lstrip(" \t\r\n")[:1]
    return "'" + value if first in {"=","+","-","@"} else value

def module_projection(module,current_attempt_id):
    return {"module":module.module,"status":module.status,"message":module.message,"execution_id":module.execution_id,"execution_attempt_id":module.execution_attempt_id,"current":bool(current_attempt_id and module.execution_attempt_id==current_attempt_id),"started_at":module.started_at,"finished_at":module.finished_at}

def finding_projection(f,current_attempt_id):
    return {"id":f.id,"source":f.source,"source_url":f.source_url,"finding_type":f.finding_type,"value":f.value,"confidence":f.confidence,"evidence_state":evidence_state(f),"severity":f.severity,"execution_id":f.execution_id,"execution_attempt_id":f.execution_attempt_id,"current_attempt":bool(current_attempt_id and f.execution_attempt_id==current_attempt_id),"historical_attempt":bool(f.execution_attempt_id and current_attempt_id and f.execution_attempt_id!=current_attempt_id),"first_seen":f.first_seen,"last_seen":f.last_seen,"collected_at":f.collected_at,"notes":f.notes}

def attempt_status(db,inv):
    if not inv.execution_attempt_id: return None
    from app.models import ExecutionAttempt
    return db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id==inv.execution_attempt_id))

def report_provenance(db,inv,generated_at=None):
    attempt=attempt_status(db,inv)
    return {"investigation_id":inv.id,"execution_id":inv.execution_id,"execution_attempt_id":inv.execution_attempt_id,"attempt_status":attempt.status if attempt else None,"attempt_started_at":attempt.started_at if attempt else inv.execution_started_at,"attempt_finished_at":attempt.finished_at if attempt else inv.completed_at,"recovered_at":attempt.recovered_at if attempt else None,"recovery_reason":attempt.recovery_reason if attempt else None,"external_provider_disclosure":inv.external_provider_disclosure,"privacy_mode":inv.privacy_mode,"report_generated_at":generated_at or datetime.now(timezone.utc),"graph_semantics":"current_derived_view","graph_provenance":"producing_execution_attempt"}

@router.get("/health")
def health(): return {"status":"ok","service":"MailRecon"}

@router.get("/providers", dependencies=[Depends(require_api_key)])
def providers():
    s=get_settings()
    return [{"name":"DNS","status":"available","configuration":"none"},{"name":"RDAP","status":"available","configuration":"none"},{"name":"Gravatar","status":"available","configuration":"none"},{"name":"GitHub","status":"configured" if s.github_token else "available","configuration":"optional GITHUB_TOKEN"},{"name":"Have I Been Pwned","status":"configured" if s.hibp_api_key else "unconfigured","configuration":"optional HIBP_API_KEY"},{"name":"Ollama","status":"configured" if s.enable_ollama else "disabled","configuration":"optional local model"}]

@router.post("/investigations", dependencies=[Depends(require_api_key)])
async def create(payload: InvestigationCreate, db: Session=Depends(get_db)):
    settings=get_settings()
    if not allow_investigation_creation(): raise HTTPException(429,"Investigation creation rate limit exceeded; retry later")
    if db.bind.dialect.name == "sqlite": db.execute(text("BEGIN IMMEDIATE"))
    active_count=db.scalar(select(func.count()).select_from(Investigation).where(Investigation.status.in_(("queued","running")))) or 0
    if active_count >= settings.max_queue_depth: db.rollback(); raise HTTPException(429,"Investigation queue is full; retry later")
    inv=Investigation(target=str(payload.email),normalized_email=str(payload.email),username=str(payload.email).split("@",1)[0],domain=str(payload.email).split("@",1)[1].lower(),privacy_mode=payload.privacy_mode,external_provider_disclosure=payload.external_provider_disclosure,status="queued")
    db.add(inv); db.commit(); db.refresh(inv)
    for m in MODULES: db.add(ModuleRun(investigation_id=inv.id,execution_id=inv.execution_id,module=m,status="queued"))
    db.commit(); return {"id":inv.id,"status":"queued","external_provider_disclosure":inv.external_provider_disclosure}

@router.post("/demo", dependencies=[Depends(require_api_key)])
def demo(db:Session=Depends(get_db)):
    inv=Investigation(target="alex.morgan@fictional.test",normalized_email="alex.morgan@fictional.test",username="alex.morgan",domain="fictional.test",status="completed",risk_score=42,risk_level="MEDIUM",privacy_mode=False,external_provider_disclosure=False)
    db.add(inv); db.commit(); db.refresh(inv)
    demo_findings=[{"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"email","value":"alex.morgan@fictional.test","confidence":1.0,"severity":"info","notes":"Completely fictional demo evidence. Evidence state: observed."},{"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"classification","value":"provider=Custom; type=Personal/Business unknown","confidence":0.95,"severity":"info","notes":"Fictional classification. Evidence state: observed."},{"source":"Demo Dataset","source_url":"https://github.com/alex-morgan-demo","finding_type":"profile_candidate","value":"https://github.com/alex-morgan-demo","confidence":0.72,"severity":"info","notes":"Possible match only; intentionally fictional. Evidence state: possible_match."},{"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"breach","value":"ExampleForum-2024 (fictional)","confidence":1.0,"severity":"high","notes":"Historical breach exposure only; no real leaked data and no active-compromise assertion."},{"source":"MailRecon Risk Engine","source_url":None,"finding_type":"risk_factor","value":"Known historical breach exposure (fictional demo)","confidence":1.0,"severity":"high","notes":"Score delta: +30"}]
    for f in demo_findings: db.add(Finding(investigation_id=inv.id,**f))
    for m in MODULES: db.add(ModuleRun(investigation_id=inv.id,module=m,status="completed",message="Demo dataset"))
    e=GraphNode(investigation_id=inv.id,node_key="email:alex.morgan@fictional.test",node_type="EMAIL",label="alex.morgan@fictional.test"); d=GraphNode(investigation_id=inv.id,node_key="domain:fictional.test",node_type="DOMAIN",label="fictional.test"); p=GraphNode(investigation_id=inv.id,node_key="profile:https://github.com/alex-morgan-demo",node_type="PROFILE",label="github.com/alex-morgan-demo",node_metadata={"evidence_state":"possible_match","confidence":0.72}); db.add_all([e,d,p]); db.flush(); db.add_all([GraphEdge(investigation_id=inv.id,source=e.node_key,target=d.node_key,relation="uses",confidence=1),GraphEdge(investigation_id=inv.id,source=e.node_key,target=p.node_key,relation="possible_profile",confidence=.72)]); db.commit(); return {"id":inv.id,"status":"completed","demo":True}

@router.get("/investigations", dependencies=[Depends(require_api_key)])
def list_investigations(db:Session=Depends(get_db)):
    q=db.execute(select(Investigation).order_by(Investigation.created_at.desc()).limit(50)); return [{"id":x.id,"target":x.target,"status":x.status,"risk_score":x.risk_score,"risk_level":x.risk_level,"created_at":x.created_at,"external_provider_disclosure":x.external_provider_disclosure} for x in q.scalars()]

def load(inv_id,db):
    q=db.execute(select(Investigation).where(Investigation.id==inv_id)); inv=q.scalar_one_or_none()
    if not inv: raise HTTPException(404,"Investigation not found")
    fq=db.execute(select(Finding).where(Finding.investigation_id==inv_id).order_by(Finding.collected_at.desc(),Finding.id.desc())); findings=fq.scalars().all()
    mq=db.execute(select(ModuleRun).where(ModuleRun.investigation_id==inv_id)); mods=mq.scalars().all(); return inv,findings,mods

@router.get("/investigations/{inv_id}", dependencies=[Depends(require_api_key)])
def get_inv(inv_id:int,db:Session=Depends(get_db)):
    inv,findings,mods=load(inv_id,db); return {"id":inv.id,"target":inv.target,"username":inv.username,"domain":inv.domain,"status":inv.status,"risk_score":inv.risk_score,"risk_level":inv.risk_level,"privacy_mode":inv.privacy_mode,"external_provider_disclosure":inv.external_provider_disclosure,"created_at":inv.created_at,"completed_at":inv.completed_at,"execution_id":inv.execution_id,"execution_attempt_id":inv.execution_attempt_id,"modules":[module_projection(m,inv.execution_attempt_id) for m in mods],"findings":[finding_projection(f,inv.execution_attempt_id) for f in findings]}

@router.get("/investigations/{inv_id}/findings", dependencies=[Depends(require_api_key)])
def findings(inv_id:int,db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db); return [finding_projection(f,inv.execution_attempt_id) for f in fs]

@router.get("/investigations/{inv_id}/risk", dependencies=[Depends(require_api_key)])
def risk(inv_id:int,db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db); dimensions={}; factors=[]
    for f in fs:
        if f.finding_type == "risk_dimension" and "=" in f.value:
            key,value=f.value.split("=",1)
            try: dimensions[key]=int(value)
            except ValueError: pass
        elif f.finding_type == "risk_factor":
            delta=None
            if f.notes and "Score delta:" in f.notes:
                try: delta=int(f.notes.split("Score delta:",1)[1].split(";",1)[0].strip())
                except ValueError: pass
            factors.append({"reason":f.value,"delta":delta,"notes":f.notes})
    return {"score":inv.risk_score,"level":inv.risk_level,"dimensions":dimensions,"factors":factors}

@router.get("/investigations/{inv_id}/timeline", dependencies=[Depends(require_api_key)])
def timeline(inv_id:int,db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db); events=[]; seen=set()
    for f in fs:
        if f.finding_type not in TIMELINE_FINDING_TYPES: continue
        state=evidence_state(f); timestamp=timeline_timestamp(f); key=(f.source,f.finding_type,f.value,state,timestamp,f.collected_at)
        if key in seen: continue
        seen.add(key); events.append({"id":f.id,"timestamp":timestamp,"last_seen":f.last_seen,"collected_at":f.collected_at,"kind":"finding","label":f.finding_type,"source":f.source,"value":f.value,"severity":f.severity,"confidence":f.confidence,"evidence_state":state,"execution_attempt_id":f.execution_attempt_id,"current_attempt":bool(inv.execution_attempt_id and f.execution_attempt_id==inv.execution_attempt_id)})
    events.sort(key=lambda x:(x["timestamp"],x["id"]),reverse=True); return events[:500]

@router.get("/investigations/{inv_id}/graph", dependencies=[Depends(require_api_key)])
def graph(inv_id:int,db:Session=Depends(get_db)):
    inv,_,_=load(inv_id,db); nodes=list(db.scalars(select(GraphNode).where(GraphNode.investigation_id==inv_id).order_by(GraphNode.node_key.asc(),GraphNode.id.asc())).all()); edges=list(db.scalars(select(GraphEdge).where(GraphEdge.investigation_id==inv_id).order_by(GraphEdge.source.asc(),GraphEdge.target.asc(),GraphEdge.relation.asc(),GraphEdge.id.asc())).all()); return {"semantics":"current_derived_view","provenance":{"type":"producing_execution_attempt","execution_id":inv.execution_id,"execution_attempt_id":inv.execution_attempt_id,"attempt_status":attempt_status(db,inv).status if attempt_status(db,inv) else None},"nodes":[{"id":n.node_key,"type":n.node_type,"label":n.label,"metadata":n.node_metadata} for n in nodes],"edges":[{"source":e.source,"target":e.target,"relation":e.relation,"confidence":e.confidence} for e in edges]}

@router.get("/investigations/{inv_id}/report", dependencies=[Depends(require_api_key)])
def report(inv_id:int,format:str="json",db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db); generated_at=datetime.now(timezone.utc); provenance=report_provenance(db,inv,generated_at); fq=db.execute(select(Finding).where(Finding.investigation_id==inv_id,Finding.finding_type=="risk_factor")); factors=[{"delta":int((f.notes or "").replace("Score delta: ","").strip() or 0),"reason":f.value} for f in fq.scalars()]
    if format=="json": return {"provenance":provenance,"target":inv.target,"risk_score":inv.risk_score,"risk_level":inv.risk_level,"findings":[{**finding_projection(f,inv.execution_attempt_id)} for f in fs],"risk_factors":factors}
    if format=="csv":
        s=io.StringIO(); w=csv.writer(s); w.writerow(["report_generated_at","investigation_id","execution_id","execution_attempt_id","attempt_status","attempt_started_at","attempt_finished_at","recovered_at","recovery_reason","external_provider_disclosure","privacy_mode","source","type","value","confidence","evidence_state","severity","current_attempt","historical_attempt","source_url","notes"])
        for f in fs:
            p=finding_projection(f,inv.execution_attempt_id); w.writerow([provenance["report_generated_at"],provenance["investigation_id"],csv_safe(provenance["execution_id"]),csv_safe(provenance["execution_attempt_id"]),csv_safe(provenance["attempt_status"]),provenance["attempt_started_at"],provenance["attempt_finished_at"],provenance["recovered_at"],csv_safe(provenance["recovery_reason"]),provenance["external_provider_disclosure"],provenance["privacy_mode"],csv_safe(f.source),csv_safe(f.finding_type),csv_safe(f.value),f.confidence,csv_safe(evidence_state(f)),csv_safe(f.severity),p["current_attempt"],p["historical_attempt"],csv_safe(f.source_url),csv_safe(f.notes)])
        return Response(s.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="mailrecon-{inv_id}.csv"'})
    if format=="html":
        p=provenance; meta="".join(f"<li><b>{html.escape(str(k))}</b>: {html.escape(str(v))}</li>" for k,v in p.items()); body=f"<html><body><h1>MailRecon Report</h1><h2>Provenance</h2><ul>{meta}</ul><p>Target: {html.escape(inv.target)}</p><h2>Risk {inv.risk_score}/100 — {html.escape(str(inv.risk_level))}</h2><ul>"+"".join(f"<li><b>{html.escape(f.severity)}</b> {html.escape(f.finding_type)}: {html.escape(f.value)} ({f.confidence:.0%}; {html.escape(str(evidence_state(f)))}; {'current' if f.execution_attempt_id == inv.execution_attempt_id else 'historical'})</li>" for f in fs)+"</ul><p>OSINT findings are probabilistic and should be independently verified. Numeric confidence is not an identity probability; evidence state describes the strength/type of correlation. Provider status is distinct from a negative finding.</p></body></html>"; return HTMLResponse(body)
    if format=="pdf": return Response(pdf_report(inv,fs,factors,provenance).read(),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="mailrecon-{inv_id}.pdf"'})
    raise HTTPException(400,"Unsupported format")

@router.delete("/investigations/{inv_id}", dependencies=[Depends(require_api_key)])
def delete_inv(inv_id:int,db:Session=Depends(get_db)):
    result=db.execute(delete(Investigation).where(Investigation.id==inv_id)); db.commit()
    if result.rowcount != 1: raise HTTPException(404,"Investigation not found")
    return {"deleted":True}

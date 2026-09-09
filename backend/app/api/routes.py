import asyncio, csv, io, json, html
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse, HTMLResponse
from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.schemas.schemas import InvestigationCreate
from app.services.orchestrator import run_investigation, MODULES
from app.reports.render import pdf_report
from app.core.auth import require_api_key

router=APIRouter(prefix="/api")

TIMELINE_FINDING_TYPES={"email","domain","domain_event","a","aaaa","mx","ns","cname","spf","dmarc","dnssec","profile_candidate","public_identity","profile","avatar","breach"}

def evidence_state(f):
    notes=f.notes or ""
    marker="Evidence state: "
    if marker in notes:
        return notes.split(marker,1)[1].split(".",1)[0].strip()
    if isinstance(f.raw_reference,dict) and isinstance(f.raw_reference.get("evidence_state"),str):
        return f.raw_reference["evidence_state"]
    return None

def timeline_timestamp(f):
    """Use earliest known observation time; fall back to collection time when absent."""
    return f.first_seen or f.collected_at

@router.get("/health")
def health(): return {"status":"ok","service":"MailRecon"}

@router.get("/providers", dependencies=[Depends(require_api_key)])
def providers():
    from app.core.config import get_settings
    s=get_settings()
    return [
        {"name":"DNS","status":"available","configuration":"none"},
        {"name":"RDAP","status":"available","configuration":"none"},
        {"name":"Gravatar","status":"available","configuration":"none"},
        {"name":"GitHub","status":"configured" if s.github_token else "available","configuration":"optional GITHUB_TOKEN"},
        {"name":"Have I Been Pwned","status":"configured" if s.hibp_api_key else "unconfigured","configuration":"optional HIBP_API_KEY"},
        {"name":"Ollama","status":"configured" if s.enable_ollama else "disabled","configuration":"optional local model"},
    ]

@router.post("/investigations", dependencies=[Depends(require_api_key)])
async def create(payload: InvestigationCreate, db: Session=Depends(get_db)):
    inv=Investigation(target=str(payload.email),normalized_email=str(payload.email),username=str(payload.email).split("@",1)[0],domain=str(payload.email).split("@",1)[1].lower(),privacy_mode=payload.privacy_mode,status="queued")
    db.add(inv); db.commit(); db.refresh(inv)
    for m in MODULES: db.add(ModuleRun(investigation_id=inv.id,module=m,status="queued"))
    db.commit(); asyncio.create_task(run_investigation(inv.id)); return {"id":inv.id,"status":"queued"}

@router.post("/demo", dependencies=[Depends(require_api_key)])
def demo(db: Session=Depends(get_db)):
    inv=Investigation(target="alex.morgan@fictional.test",normalized_email="alex.morgan@fictional.test",username="alex.morgan",domain="fictional.test",status="completed",risk_score=42,risk_level="MEDIUM",privacy_mode=False)
    db.add(inv); db.commit(); db.refresh(inv)
    demo_findings=[
      {"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"email","value":"alex.morgan@fictional.test","confidence":1.0,"severity":"info","notes":"Completely fictional demo evidence. Evidence state: observed."},
      {"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"classification","value":"provider=Custom; type=Personal/Business unknown","confidence":0.95,"severity":"info","notes":"Fictional classification. Evidence state: observed."},
      {"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"profile_candidate","value":"https://github.com/alex-morgan-demo","confidence":0.72,"severity":"info","notes":"Possible match only; intentionally fictional. Evidence state: possible_match."},
      {"source":"Demo Dataset","source_url":"https://example.org/demo","finding_type":"breach","value":"ExampleForum-2024 (fictional)","confidence":1.0,"severity":"high","notes":"Historical breach exposure only; no real leaked data and no active-compromise assertion."},
      {"source":"MailRecon Risk Engine","source_url":None,"finding_type":"risk_factor","value":"Known historical breach exposure (fictional demo)","confidence":1.0,"severity":"high","notes":"Score delta: +30"},
    ]
    for f in demo_findings: db.add(Finding(investigation_id=inv.id,**f))
    for m in MODULES: db.add(ModuleRun(investigation_id=inv.id,module=m,status="completed",message="Demo dataset"))
    e=GraphNode(investigation_id=inv.id,node_key="email:alex.morgan@fictional.test",node_type="EMAIL",label="alex.morgan@fictional.test"); d=GraphNode(investigation_id=inv.id,node_key="domain:fictional.test",node_type="DOMAIN",label="fictional.test"); p=GraphNode(investigation_id=inv.id,node_key="profile:https://github.com/alex-morgan-demo",node_type="PROFILE",label="github.com/alex-morgan-demo",node_metadata={"evidence_state":"possible_match","confidence":0.72}); db.add_all([e,d,p]); db.flush(); db.add_all([GraphEdge(investigation_id=inv.id,source=e.node_key,target=d.node_key,relation="uses",confidence=1),GraphEdge(investigation_id=inv.id,source=e.node_key,target=p.node_key,relation="possible_profile",confidence=.72)]); db.commit(); return {"id":inv.id,"status":"completed","demo":True}

@router.get("/investigations", dependencies=[Depends(require_api_key)])
def list_investigations(db: Session=Depends(get_db)):
    q=db.execute(select(Investigation).order_by(Investigation.created_at.desc()).limit(50)); return [{"id":x.id,"target":x.target,"status":x.status,"risk_score":x.risk_score,"risk_level":x.risk_level,"created_at":x.created_at} for x in q.scalars()]

def load(inv_id,db):
    q=db.execute(select(Investigation).where(Investigation.id==inv_id)); inv=q.scalar_one_or_none()
    if not inv: raise HTTPException(404,"Investigation not found")
    fq=db.execute(select(Finding).where(Finding.investigation_id==inv_id).order_by(Finding.collected_at.desc(),Finding.id.desc())); findings=fq.scalars().all()
    mq=db.execute(select(ModuleRun).where(ModuleRun.investigation_id==inv_id)); mods=mq.scalars().all(); return inv,findings,mods

@router.get("/investigations/{inv_id}", dependencies=[Depends(require_api_key)])
def get_inv(inv_id:int,db:Session=Depends(get_db)):
    inv,findings,mods=load(inv_id,db); return {"id":inv.id,"target":inv.target,"username":inv.username,"domain":inv.domain,"status":inv.status,"risk_score":inv.risk_score,"risk_level":inv.risk_level,"created_at":inv.created_at,"completed_at":inv.completed_at,"modules":[{"module":m.module,"status":m.status,"message":m.message} for m in mods],"findings":[{"id":f.id,"source":f.source,"source_url":f.source_url,"finding_type":f.finding_type,"value":f.value,"confidence":f.confidence,"evidence_state":evidence_state(f),"severity":f.severity,"first_seen":f.first_seen,"last_seen":f.last_seen,"collected_at":f.collected_at,"notes":f.notes} for f in findings]}

@router.get("/investigations/{inv_id}/findings", dependencies=[Depends(require_api_key)])
def findings(inv_id:int,db:Session=Depends(get_db)):
    _,fs,_=load(inv_id,db); return [{"id":f.id,"source":f.source,"source_url":f.source_url,"finding_type":f.finding_type,"value":f.value,"confidence":f.confidence,"evidence_state":evidence_state(f),"severity":f.severity,"collected_at":f.collected_at,"notes":f.notes} for f in fs]

@router.get("/investigations/{inv_id}/risk", dependencies=[Depends(require_api_key)])
def risk(inv_id:int,db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db)
    dimensions={}
    factors=[]
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
    """Project approved evidence-bearing findings into a deterministic forensic timeline.

    timestamp is first_seen when available, otherwise collected_at. collected_at
    remains separate so collection time is never presented as fact occurrence time.
    Only explicitly classified evidence types are projected; processing and
    assessment findings remain available through their existing endpoints.
    """
    _,fs,_=load(inv_id,db)
    events=[]
    seen=set()
    for f in fs:
        if f.finding_type not in TIMELINE_FINDING_TYPES:
            continue
        state=evidence_state(f)
        timestamp=timeline_timestamp(f)
        key=(f.source,f.finding_type,f.value,state,timestamp,f.collected_at)
        if key in seen:
            continue
        seen.add(key)
        events.append({"id":f.id,"timestamp":timestamp,"last_seen":f.last_seen,"collected_at":f.collected_at,"kind":"finding","label":f.finding_type,"source":f.source,"value":f.value,"severity":f.severity,"confidence":f.confidence,"evidence_state":state})
    events.sort(key=lambda x:(x["timestamp"],x["id"]),reverse=True)
    return events[:500]

@router.get("/investigations/{inv_id}/graph", dependencies=[Depends(require_api_key)])
def graph(inv_id:int,db:Session=Depends(get_db)):
    load(inv_id,db); nq=db.execute(select(GraphNode).where(GraphNode.investigation_id==inv_id)); eq=db.execute(select(GraphEdge).where(GraphEdge.investigation_id==inv_id)); return {"nodes":[{"id":n.node_key,"type":n.node_type,"label":n.label,"metadata":n.node_metadata} for n in nq.scalars()],"edges":[{"source":e.source,"target":e.target,"relation":e.relation,"confidence":e.confidence} for e in eq.scalars()]}

@router.get("/investigations/{inv_id}/report", dependencies=[Depends(require_api_key)])
def report(inv_id:int,format:str="json",db:Session=Depends(get_db)):
    inv,fs,_=load(inv_id,db); fq=db.execute(select(Finding).where(Finding.investigation_id==inv_id,Finding.finding_type=="risk_factor")); factors=[{"delta":int((f.notes or "").replace("Score delta: ","").strip() or 0),"reason":f.value} for f in fq.scalars()]
    if format=="json": return {"target":inv.target,"risk_score":inv.risk_score,"risk_level":inv.risk_level,"findings":[{"source":f.source,"type":f.finding_type,"value":f.value,"confidence":f.confidence,"evidence_state":evidence_state(f),"severity":f.severity,"source_url":f.source_url,"notes":f.notes} for f in fs],"risk_factors":factors}
    if format=="csv":
        s=io.StringIO(); w=csv.writer(s); w.writerow(["source","type","value","confidence","evidence_state","severity","source_url","notes"]); [w.writerow([f.source,f.finding_type,f.value,f.confidence,evidence_state(f),f.severity,f.source_url,f.notes]) for f in fs]; return Response(s.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="mailrecon-{inv_id}.csv"'})
    if format=="html":
        body=f"<html><body><h1>MailRecon Report</h1><p>Target: {html.escape(inv.target)}</p><h2>Risk {inv.risk_score}/100 — {html.escape(str(inv.risk_level))}</h2><ul>"+"".join(f"<li><b>{html.escape(f.severity)}</b> {html.escape(f.finding_type)}: {html.escape(f.value)} ({f.confidence:.0%}; {html.escape(str(evidence_state(f)))})</li>" for f in fs)+"</ul><p>OSINT findings are probabilistic and should be independently verified. Numeric confidence is not an identity probability; evidence state describes the strength/type of correlation. Provider status is distinct from a negative finding.</p></body></html>"; return HTMLResponse(body)
    if format=="pdf":
        buf=pdf_report(inv,fs,factors); return Response(buf.read(),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="mailrecon-{inv_id}.pdf"'})
    raise HTTPException(400,"Unsupported format")

@router.delete("/investigations/{inv_id}", dependencies=[Depends(require_api_key)])
def delete_inv(inv_id:int,db:Session=Depends(get_db)):
    load(inv_id,db); db.execute(delete(Investigation).where(Investigation.id==inv_id)); db.commit(); return {"deleted":True}

import asyncio
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, update, or_

from app.db.session import SessionLocal
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.osint.email import analyze_email, username_candidates, EVIDENCE_DERIVED, EVIDENCE_POSSIBLE, EVIDENCE_CORROBORATED, EVIDENCE_SOURCE_ASSOCIATED, EVIDENCE_OBSERVED
from app.osint.dns import resolve, record_presence
from app.providers.ollama import OllamaProvider
from app.providers.base import ProviderContext, ProviderResult, finding
from app.providers.github import GitHubProvider
from app.providers.gitlab import GitLabProvider
from app.providers.gravatar import GravatarProvider
from app.providers.hibp import HIBPProvider
from app.providers.public_web import PublicWebProvider
from app.providers.rdap import RDAPProvider
from app.providers.registry import execute, provider_definitions
from app.risk.engine import calculate
from app.services.lifecycle import execution_is_owned, fence_execution, heartbeat_investigation, finish_execution_attempt

PROVIDER_DEFINITIONS = provider_definitions(orchestrated=True)
MODULES=["email_validation","domain_analysis","dns_analysis","gravatar","rdap","username_extraction","public_profile_discovery","gitlab","public_web","breach_sources","risk_calculation","graph_build"]
DERIVED_USERNAME_RELATION = "derived_username"
MODULE_TRANSITIONS = {"queued": {"queued", "running", "completed", "skipped", "abandoned"}, "running": {"running", "completed", "failed", "skipped", "abandoned"}, "completed": {"completed"}, "failed": {"failed"}, "skipped": {"skipped"}, "abandoned": {"abandoned"}}

# Explicit construction hooks keep existing monkeypatch-based tests possible without
# resolving provider classes through dynamic global symbol lookup.
PROVIDER_FACTORY_RESOLVERS = {
    "Gravatar": lambda: GravatarProvider(),
    "RDAP": lambda: RDAPProvider(),
    "GitHub": lambda: GitHubProvider(),
    "GitLab": lambda: GitLabProvider(),
    "Have I Been Pwned": lambda: HIBPProvider(),
    "Public Web": lambda: PublicWebProvider(),
}

def utcnow(): return datetime.now(timezone.utc)
def _require_ownership(db, inv_id, token):
    if not execution_is_owned(db,inv_id,token): raise RuntimeError("Investigation execution lease is no longer owned")
def _capture_owned_execution(db, inv_id, token): return fence_execution(db,inv_id,token)
def _persistence_key(f, execution_attempt_id):
    payload={"execution_attempt_id":execution_attempt_id,"source":f.get("source"),"source_url":f.get("source_url"),"finding_type":f.get("finding_type"),"value":f.get("value"),"first_seen":f.get("first_seen").isoformat() if f.get("first_seen") else None}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()

def set_module(db,inv_id,name,status,message=None,token=None):
    if status not in MODULE_TRANSITIONS: raise ValueError(f"Unknown ModuleRun status: {status}")
    if token is not None: execution_id,execution_attempt_id=_capture_owned_execution(db,inv_id,token)
    else: execution_id=execution_attempt_id=None
    inv=db.get(Investigation,inv_id)
    if not inv:return
    if token is None: execution_id=inv.execution_id;execution_attempt_id=inv.execution_attempt_id
    if not execution_id:raise RuntimeError("Investigation has no durable logical execution identity")
    if token is not None and not execution_attempt_id:raise RuntimeError("Investigation has no durable execution-attempt provenance")
    m=db.scalar(select(ModuleRun).where(ModuleRun.investigation_id==inv_id,ModuleRun.execution_attempt_id==execution_attempt_id,ModuleRun.module==name)) if execution_attempt_id else None
    if not m:
        m=ModuleRun(investigation_id=inv_id,execution_id=execution_id,execution_attempt_id=execution_attempt_id,module=name);db.add(m);db.flush()
    if status not in MODULE_TRANSITIONS.get(m.status,set()):raise RuntimeError(f"Invalid ModuleRun transition: {m.status} -> {status}")
    m.status=status;m.message=message
    if status=="running":m.started_at=m.started_at or utcnow()
    if status in {"completed","failed","skipped","abandoned"}:m.finished_at=m.finished_at or utcnow()
    db.commit()

def _structured_evidence_state(f):
    state=f.get("evidence_state")
    if isinstance(state,str) and state:return state
    raw=f.get("raw_reference")
    if isinstance(raw,dict) and isinstance(raw.get("evidence_state"),str):return raw["evidence_state"]
    notes=f.get("notes") or "";marker="Evidence state: "
    if marker in notes:return notes.split(marker,1)[1].split(".",1)[0].strip() or None
    return None

def add_findings(db,inv_id,fs,token=None):
    if not fs:return
    if token is not None:execution_id,execution_attempt_id=_capture_owned_execution(db,inv_id,token)
    else:execution_id=execution_attempt_id=None
    inv=db.get(Investigation,inv_id)
    if not inv:return
    if token is None:execution_id=inv.execution_id;execution_attempt_id=inv.execution_attempt_id
    if not execution_id:raise RuntimeError("Investigation has no durable logical execution identity")
    if token is not None and not execution_attempt_id:raise RuntimeError("Investigation has no durable execution-attempt provenance")
    inserted=set()
    for f in fs:
        f=dict(f);f["evidence_state"]=_structured_evidence_state(f)
        if inv.privacy_mode:
            f["raw_reference"]=None
            if f.get("finding_type")=="profile_candidate" and f.get("evidence_state")==EVIDENCE_POSSIBLE:continue
        key=_persistence_key(f,execution_attempt_id)
        if key in inserted:continue
        existing=db.scalar(select(Finding.id).where(Finding.investigation_id==inv_id,Finding.execution_attempt_id==execution_attempt_id,Finding.persistence_key==key))
        if existing:inserted.add(key);continue
        legacy=db.scalar(select(Finding.id).where(Finding.investigation_id==inv_id,Finding.execution_attempt_id==execution_attempt_id,Finding.persistence_key.is_(None),Finding.source==f.get("source"),Finding.source_url==f.get("source_url"),Finding.finding_type==f.get("finding_type"),Finding.value==f.get("value"),Finding.first_seen==f.get("first_seen")))
        if legacy:inserted.add(key);continue
        db.add(Finding(investigation_id=inv_id,execution_id=execution_id,execution_attempt_id=execution_attempt_id,persistence_key=key,**f));inserted.add(key)
    db.commit()

def provider_finding(result):
    severity="warning" if result.status in {"error","rate_limited","unavailable"} else "info"
    return finding(result.provider,"provider_status",result.status,1.0,severity,notes=result.message or "Provider execution completed.",raw_reference={"status":result.status,"checked_at":result.checked_at.isoformat()})

class ProviderOwnershipLost(RuntimeError):
    """Provider work was abandoned because the execution lease was lost."""

async def _cancel_provider_tasks(tasks):
    pending=[task for task in tasks if not task.done()]
    for task in pending:task.cancel()
    if pending:await asyncio.gather(*pending,return_exceptions=True)

async def _provider_tasks_owned(inv_id,token,tasks,*,poll_interval=0.25):
    while True:
        pending=[task for task in tasks if not task.done()]
        if not pending:return
        await asyncio.sleep(poll_interval)
        with SessionLocal() as db:
            if not execution_is_owned(db,inv_id,token): raise ProviderOwnershipLost("Provider work abandoned after execution ownership was lost")

def _provider_tasks_outcome(tasks):
    return [task.result() if not task.cancelled() else ProviderOwnershipLost("Provider work cancelled after execution ownership was lost") for task in tasks]

async def _run_provider_call(definition,email,domain,candidates):
    context=ProviderContext(email=email,domain=domain,candidates=tuple(candidates))
    factory=PROVIDER_FACTORY_RESOLVERS.get(definition.name)
    return await execute(definition,context=context,factory=factory)

async def run_providers(email: str,domain: str,candidates: list[str],*,inv_id:int|None=None,token:str|None=None,allow_external: bool=True):
    definitions=tuple(item for item in PROVIDER_DEFINITIONS if item.factory is not None)
    if not allow_external:
        message="External provider disclosure disabled for this investigation"
        return [ProviderResult(definition.name,"disabled",message=message) for definition in definitions]
    tasks=[asyncio.create_task(_run_provider_call(definition,email,domain,candidates)) for definition in definitions]
    if inv_id is None or token is None:return await asyncio.gather(*tasks,return_exceptions=True)
    monitor=asyncio.create_task(_provider_tasks_owned(inv_id,token,tasks));gathered=None
    try:
        while True:
            done,_=await asyncio.wait([*tasks,monitor],return_when=asyncio.FIRST_COMPLETED)
            if monitor in done:
                exc=monitor.exception()
                if exc is not None:raise exc
                break
            if all(task.done() for task in tasks):break
        gathered=_provider_tasks_outcome(tasks)
        try:
            with SessionLocal() as db:_require_ownership(db,inv_id,token)
        except RuntimeError as exc:raise ProviderOwnershipLost(str(exc)) from exc
        return gathered
    finally:
        if not monitor.done():
            monitor.cancel()
            try:await monitor
            except asyncio.CancelledError:pass
        await _cancel_provider_tasks(tasks)

def _finding_evidence_state(row):
    state=getattr(row,"evidence_state",None)
    if state:return state
    raw=getattr(row,"raw_reference",None)
    if isinstance(raw,dict) and isinstance(raw.get("evidence_state"),str):return raw["evidence_state"]
    notes=getattr(row,"notes",None) or "";marker="Evidence state: "
    if marker in notes:return notes.split(marker,1)[1].split(".",1)[0].strip()
    return None

def _rdap_domain_consistency(domain,result):
    if isinstance(result,Exception) or getattr(result,"status",None)!="ok":return None
    observed=[f.get("value","").split(": ",1)[1] for f in result.findings if f.get("finding_type")=="domain" and isinstance(f.get("value"),str) and f["value"].startswith("ldhName: ")]
    if not observed:return None
    if observed[0].lower().rstrip(".")==domain.lower().rstrip("."):return finding("MailRecon","domain_correlation","DNS/RDAP domain match",1.0,"info",notes="Explicit comparison of normalized investigation domain with RDAP ldhName.",evidence_state=EVIDENCE_OBSERVED)
    return finding("MailRecon","domain_correlation",f"DNS/RDAP domain mismatch: {observed[0]}",1.0,"warning",notes="RDAP returned a domain different from the normalized investigation domain; this is a consistency warning, not an identity assertion.",evidence_state=EVIDENCE_OBSERVED)
def _graph_relation(finding_type,evidence_state):
    if finding_type=="breach":return "historical_breach_exposure"
    if evidence_state==EVIDENCE_CORROBORATED:return "corroborated_profile"
    if evidence_state==EVIDENCE_SOURCE_ASSOCIATED:return "source_associated_identity"
    return "possible_profile"
async def _heartbeat_loop(inv_id,token,stop_event):
    from app.core.config import get_settings
    interval=max(1.0,min(20.0,get_settings().execution_lease_seconds/3))
    while not stop_event.is_set():
        try:await asyncio.wait_for(stop_event.wait(),timeout=interval)
        except asyncio.TimeoutError:
            with SessionLocal() as db:
                if not heartbeat_investigation(db,inv_id,token):return

def mark_investigation_failed(db,inv_id,token,exc):
    try:execution_id,execution_attempt_id=fence_execution(db,inv_id,token)
    except RuntimeError:return False
    inv=db.get(Investigation,inv_id)
    if not inv:return False
    inv.status="failed";inv.completed_at=None;inv.execution_token=None;inv.execution_heartbeat_at=None
    for m in db.scalars(select(ModuleRun).where(ModuleRun.investigation_id==inv_id,or_(ModuleRun.execution_attempt_id==execution_attempt_id,ModuleRun.execution_attempt_id.is_(None)))).all():
        if m.execution_attempt_id is None:m.execution_attempt_id=execution_attempt_id;m.execution_id=execution_id
        if m.status=="running":set_module(db,inv_id,m.module,"failed",f"Investigation failed: {type(exc).__name__}")
        elif m.status=="queued":set_module(db,inv_id,m.module,"skipped","Not executed after investigation failure")
    finish_execution_attempt(db,inv_id,execution_attempt_id,"failed",reason=f"{type(exc).__name__}: investigation execution failed");db.commit();return True

async def run_investigation(inv_id:int,token:str):
    heartbeat_stop=asyncio.Event();heartbeat_task=asyncio.create_task(_heartbeat_loop(inv_id,token,heartbeat_stop))
    with SessionLocal() as db:
        try:
            _require_ownership(db,inv_id,token);inv=db.get(Investigation,inv_id)
            if not inv:return
            set_module(db,inv_id,"email_validation","running",token=token);analysis=analyze_email(inv.target);execution_id,execution_attempt_id=_capture_owned_execution(db,inv_id,token);inv.normalized_email=analysis["email"];inv.username=analysis["username"];inv.domain=analysis["domain"];db.commit()
            add_findings(db,inv_id,[finding("MailRecon","email",analysis["email"],1.0,"info",notes=f"Normalized and syntax-validated target. Evidence state: {EVIDENCE_OBSERVED}.",evidence_state=EVIDENCE_OBSERVED),finding("MailRecon","classification",f"provider={analysis['provider']}; type={'Disposable' if analysis['disposable'] else 'Role-based' if analysis['role_based'] else 'Personal/Business unknown'}",.95,"info",notes=f"Classification, not an identity verdict. Evidence state: {EVIDENCE_OBSERVED}.",evidence_state=EVIDENCE_OBSERVED)],token);set_module(db,inv_id,"email_validation","completed","Validated and normalized",token)
            set_module(db,inv_id,"username_extraction","running",token=token);candidates=username_candidates(analysis["username"]);add_findings(db,inv_id,[finding("MailRecon","username_candidate",c,0.0,"info",notes=f"Evidence state: {EVIDENCE_DERIVED}. Generated from email local-part; hypothesis only, not proof of account ownership.",evidence_state=EVIDENCE_DERIVED) for c in candidates],token);set_module(db,inv_id,"username_extraction","completed",f"Generated {len(candidates)} candidates",token)
            set_module(db,inv_id,"dns_analysis","running",token=token);dns=await resolve(inv.domain);_require_ownership(db,inv_id,token);analysis["has_dmarc"]=record_presence(dns.get("DMARC",[]),dns.get("DMARC_status"));analysis["has_spf"]=record_presence(dns.get("SPF",[]),dns.get("SPF_status"));dnssec=dns.get("DNSSEC");analysis["dnssec"]=dnssec if isinstance(dnssec,bool) else None
            fs=[]
            for k in ["A","AAAA","MX","NS","CNAME","SPF","DMARC"]:
                if dns.get(k):fs.append(finding("DNS",k.lower(),"; ".join(dns[k]),.99,"info",notes=f"Public DNS response. Evidence state: {EVIDENCE_OBSERVED}.",evidence_state=EVIDENCE_OBSERVED))
            dnssec_value="enabled" if analysis["dnssec"] is True else "disabled" if analysis["dnssec"] is False else "unknown";fs.append(finding("DNS","dnssec",dnssec_value,1.0 if analysis["dnssec"] is not None else 0.0,"info",notes="DNSSEC state is unknown when the resolver cannot validate it; unknown is not a security failure.",evidence_state=EVIDENCE_OBSERVED));add_findings(db,inv_id,fs,token);set_module(db,inv_id,"dns_analysis","completed","DNS analysis complete",token);set_module(db,inv_id,"domain_analysis","completed","Domain metadata derived from DNS/RDAP",token)
            provider_modules=[definition.module for definition in PROVIDER_DEFINITIONS if definition.factory is not None and definition.module]
            for name in provider_modules:set_module(db,inv_id,name,"running",token=token)
            results=await run_providers(analysis["email"],analysis["domain"],candidates,inv_id=inv_id,token=token,allow_external=inv.external_provider_disclosure)
            executable_definitions=tuple(item for item in PROVIDER_DEFINITIONS if item.factory is not None)
            for definition,res in zip(executable_definitions,results):
                name=definition.module or definition.name.lower().replace(" ","_")
                if isinstance(res,Exception):set_module(db,inv_id,name,"failed",f"Provider exception: {type(res).__name__}",token);add_findings(db,inv_id,[finding(name,"provider_status","error",1.0,"warning",notes=f"Provider raised {type(res).__name__}",evidence_state=EVIDENCE_OBSERVED)],token)
                else:add_findings(db,inv_id,[provider_finding(res),*res.findings],token);set_module(db,inv_id,name,"completed" if res.status in {"ok","unconfigured","rate_limited","unavailable","disabled"} else "failed",res.message,token)
            rdap_index=next((index for index,item in enumerate(executable_definitions) if item.name=="RDAP"),None)
            consistency=_rdap_domain_consistency(analysis["domain"],results[rdap_index]) if rdap_index is not None else None
            if consistency:add_findings(db,inv_id,[consistency],token)
            set_module(db,inv_id,"risk_calculation","running",token=token);rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.execution_attempt_id==execution_attempt_id)).all();risk=calculate({**analysis},[{"finding_type":r.finding_type,"confidence":r.confidence,"value":r.value,"notes":r.notes,"evidence_state":r.evidence_state,"raw_reference":r.raw_reference} for r in rows]);_capture_owned_execution(db,inv_id,token);inv.risk_score=risk.score;inv.risk_level=risk.level;db.commit();add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_factor",f["reason"],1.0,"high" if f["delta"]>10 else "medium" if f["delta"]>0 else "info",notes=f"Score delta: {f['delta']:+d}; dimension={f['dimension']}",evidence_state=EVIDENCE_DERIVED) for f in risk.factors],token);add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_dimension",f"{k}={v}",1.0,"info",notes="Dimension score, not a probability of compromise.",evidence_state=EVIDENCE_DERIVED) for k,v in risk.dimensions.items()],token);set_module(db,inv_id,"risk_calculation","completed",f"Risk score {risk.score}/100 ({risk.level})",token)
            ai_summary=await OllamaProvider().summarize(inv.target,[{"finding_type":r.finding_type,"value":r.value,"confidence":r.confidence,"severity":r.severity,"source":r.source} for r in rows]);
            if ai_summary:add_findings(db,inv_id,[finding("Ollama","ai_summary",ai_summary,.6,"info",notes="Evidence-grounded local summary; review source findings before relying on it.",evidence_state=EVIDENCE_DERIVED)],token)
            set_module(db,inv_id,"graph_build","running",token=token);_capture_owned_execution(db,inv_id,token);db.query(GraphEdge).filter(GraphEdge.investigation_id==inv_id).delete(synchronize_session=False);db.query(GraphNode).filter(GraphNode.investigation_id==inv_id).delete(synchronize_session=False)
            email_node=GraphNode(investigation_id=inv_id,node_key=f"email:{analysis['email']}",node_type="EMAIL",label=analysis['email']);domain_node=GraphNode(investigation_id=inv_id,node_key=f"domain:{analysis['domain']}",node_type="DOMAIN",label=analysis['domain']);user_node=GraphNode(investigation_id=inv_id,node_key=f"username:{analysis['username']}",node_type="USERNAME",label=analysis['username']);db.add_all([email_node,domain_node,user_node]);db.flush();db.add_all([GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=domain_node.node_key,relation="uses",confidence=1),GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=user_node.node_key,relation=DERIVED_USERNAME_RELATION,confidence=1)])
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.execution_attempt_id==execution_attempt_id)).all();seen=set()
            for r in rows:
                state=_finding_evidence_state(r)
                if r.finding_type in {"breach","profile_candidate","public_identity","profile","public_web_reference"}:
                    typ={"breach":"BREACH","profile_candidate":"PROFILE","public_identity":"IDENTITY","profile":"PROFILE","public_web_reference":"WEB_REFERENCE"}[r.finding_type];key=f"{typ.lower()}:{r.value}"
                    if key in seen:continue
                    seen.add(key);db.add(GraphNode(investigation_id=inv_id,node_key=key,node_type=typ,label=r.value,node_metadata={"evidence_state":state,"confidence":r.confidence,"source_url":r.source_url}));db.add(GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=key,relation=_graph_relation(r.finding_type,state),confidence=r.confidence))
            _capture_owned_execution(db,inv_id,token);set_module(db,inv_id,"graph_build","completed","Relationship graph built with evidence-state-aware relationships",token);finish_execution_attempt(db,inv_id,execution_attempt_id,"completed");result=db.execute(update(Investigation).where(Investigation.id==inv_id,Investigation.status=="running",Investigation.execution_token==token).values(status="completed",completed_at=utcnow(),execution_heartbeat_at=None,execution_token=None));db.commit()
            if result.rowcount!=1:return
        except Exception as exc:
            try:mark_investigation_failed(db,inv_id,token,exc)
            except Exception:db.rollback()
        finally:
            heartbeat_stop.set();heartbeat_task.cancel()
            try:await heartbeat_task
            except asyncio.CancelledError:pass

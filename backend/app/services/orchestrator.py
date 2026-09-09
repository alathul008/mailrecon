import asyncio
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, update, or_

from app.db.session import SessionLocal
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.osint.email import analyze_email, username_candidates, EVIDENCE_DERIVED, EVIDENCE_POSSIBLE, EVIDENCE_CORROBORATED, EVIDENCE_SOURCE_ASSOCIATED, EVIDENCE_OBSERVED
from app.osint.dns import resolve
from app.providers import HIBPProvider, GravatarProvider, GitHubProvider, RDAPProvider
from app.providers.ollama import OllamaProvider
from app.providers.base import finding
from app.risk.engine import calculate
from app.services.lifecycle import execution_is_owned, fence_execution, heartbeat_investigation

MODULES=["email_validation","domain_analysis","dns_analysis","gravatar","rdap","username_extraction","public_profile_discovery","breach_sources","risk_calculation","graph_build"]
DERIVED_USERNAME_RELATION = "derived_username"


def utcnow(): return datetime.now(timezone.utc)


def _require_ownership(db, inv_id, token):
    if not execution_is_owned(db,inv_id,token):
        raise RuntimeError("Investigation execution lease is no longer owned")


def _capture_owned_execution(db, inv_id, token):
    """Fence the worker token before returning execution provenance for a mutation."""
    return fence_execution(db, inv_id, token)


def _persistence_key(f):
    """Stable semantic key for one finding within one durable execution/acquisition.

    Collection time is deliberately excluded: a recovery may collect the same
    evidence again at a different wall-clock time. Investigation/execution scope
    keeps legitimate separate acquisitions distinct without global deduplication.
    """
    payload={
        "source":f.get("source"),
        "source_url":f.get("source_url"),
        "finding_type":f.get("finding_type"),
        "value":f.get("value"),
        "first_seen":f.get("first_seen").isoformat() if f.get("first_seen") else None,
    }
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()


def set_module(db,inv_id,name,status,message=None,token=None):
    if token is not None:
        execution_id, execution_attempt_id=_capture_owned_execution(db,inv_id,token)
    else:
        execution_id=execution_attempt_id=None
    inv=db.get(Investigation,inv_id)
    if not inv: return
    if token is None:
        execution_id=inv.execution_id
        execution_attempt_id=inv.execution_attempt_id
    if not execution_id:
        raise RuntimeError("Investigation has no durable logical execution identity")
    if token is not None and not execution_attempt_id:
        raise RuntimeError("Investigation has no durable execution-attempt provenance")
    m=db.scalar(select(ModuleRun).where(
        ModuleRun.investigation_id==inv_id,
        ModuleRun.execution_attempt_id==execution_attempt_id,
        ModuleRun.module==name,
    )) if execution_attempt_id else None
    if not m:
        m=ModuleRun(
            investigation_id=inv_id,
            execution_id=execution_id,
            execution_attempt_id=execution_attempt_id,
            module=name,
        )
        db.add(m)
    m.status=status; m.message=message
    if status=="running": m.started_at=utcnow()
    if status in {"completed","failed","skipped"}: m.finished_at=utcnow()
    db.commit()


def add_findings(db,inv_id,fs,token=None):
    if not fs: return
    if token is not None:
        execution_id, execution_attempt_id=_capture_owned_execution(db,inv_id,token)
    else:
        execution_id=execution_attempt_id=None
    inv=db.get(Investigation,inv_id)
    if not inv: return
    if token is None:
        execution_id=inv.execution_id
        execution_attempt_id=inv.execution_attempt_id
    if not execution_id:
        raise RuntimeError("Investigation has no durable logical execution identity")
    if token is not None and not execution_attempt_id:
        raise RuntimeError("Investigation has no durable execution-attempt provenance")
    inserted=set()
    for f in fs:
        f=dict(f)
        if inv.privacy_mode:
            f["raw_reference"]=None
            if f.get("finding_type") == "profile_candidate" and EVIDENCE_POSSIBLE in (f.get("notes") or ""):
                continue
        key=_persistence_key(f)
        if key in inserted:
            continue
        existing=db.scalar(select(Finding.id).where(Finding.investigation_id==inv_id,Finding.execution_id==execution_id,Finding.persistence_key==key))
        if existing:
            inserted.add(key)
            continue
        legacy=db.scalar(select(Finding.id).where(
            Finding.investigation_id==inv_id,
            Finding.execution_id==execution_id,
            Finding.persistence_key.is_(None),
            Finding.source==f.get("source"),
            Finding.source_url==f.get("source_url"),
            Finding.finding_type==f.get("finding_type"),
            Finding.value==f.get("value"),
            Finding.first_seen==f.get("first_seen"),
        ))
        if legacy:
            inserted.add(key)
            continue
        db.add(Finding(
            investigation_id=inv_id,
            execution_id=execution_id,
            execution_attempt_id=execution_attempt_id,
            persistence_key=key,
            **f,
        ))
        inserted.add(key)
    db.commit()


def provider_finding(result):
    severity = "warning" if result.status in {"error","rate_limited","unavailable"} else "info"
    return finding(result.provider, "provider_status", result.status, 1.0, severity, notes=result.message or "Provider execution completed.", raw_reference={"status": result.status})


async def run_providers(email: str, domain: str, candidates: list[str]):
    providers=[GravatarProvider().run(email), RDAPProvider().run(domain), GitHubProvider().run(candidates,email), HIBPProvider().run(email)]
    return await asyncio.gather(*providers,return_exceptions=True)


def _finding_evidence_state(row):
    notes=row.notes or ""
    marker="Evidence state: "
    if marker in notes:
        return notes.split(marker,1)[1].split(".",1)[0].strip()
    return None


def _rdap_domain_consistency(domain, result):
    if isinstance(result,Exception) or getattr(result,"status",None) != "ok": return None
    observed=[f.get("value","").split(": ",1)[1] for f in result.findings if f.get("finding_type")=="domain" and isinstance(f.get("value"),str) and f["value"].startswith("ldhName: ")]
    if not observed: return None
    if observed[0].lower().rstrip(".") == domain.lower().rstrip("."):
        return finding("MailRecon","domain_correlation","DNS/RDAP domain match",1.0,"info",notes="Explicit comparison of normalized investigation domain with RDAP ldhName.")
    return finding("MailRecon","domain_correlation",f"DNS/RDAP domain mismatch: {observed[0]}",1.0,"warning",notes="RDAP returned a domain different from the normalized investigation domain; this is a consistency warning, not an identity assertion.")


def _graph_relation(finding_type, evidence_state):
    """Map evidence semantics to an explicit graph relation; never infer confirmation from confidence."""
    if finding_type == "breach": return "historical_breach_exposure"
    if evidence_state == EVIDENCE_CORROBORATED: return "corroborated_profile"
    if evidence_state == EVIDENCE_SOURCE_ASSOCIATED: return "source_associated_identity"
    return "possible_profile"


async def _heartbeat_loop(inv_id, token, stop_event):
    from app.core.config import get_settings
    interval=max(1.0, min(20.0, get_settings().execution_lease_seconds / 3))
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            with SessionLocal() as db:
                if not heartbeat_investigation(db, inv_id, token):
                    return


def mark_investigation_failed(db, inv_id, token, exc):
    try:
        execution_id, execution_attempt_id = fence_execution(db, inv_id, token)
    except RuntimeError:
        return False
    inv=db.get(Investigation,inv_id)
    if not inv: return False
    inv.status="failed"; inv.completed_at=None; inv.execution_token=None; inv.execution_heartbeat_at=None
    for m in db.scalars(select(ModuleRun).where(
        ModuleRun.investigation_id==inv_id,
        or_(
            ModuleRun.execution_attempt_id==execution_attempt_id,
            ModuleRun.execution_attempt_id.is_(None),
        ),
    )).all():
        if m.execution_attempt_id is None:
            m.execution_attempt_id=execution_attempt_id
            m.execution_id=execution_id
        if m.status == "running":
            m.status="failed"; m.message=f"Investigation failed: {type(exc).__name__}"; m.finished_at=utcnow()
        elif m.status == "queued":
            m.status="skipped"; m.message="Not executed after investigation failure"; m.finished_at=utcnow()
    db.commit()
    return True


async def run_investigation(inv_id:int, token:str):
    heartbeat_stop=asyncio.Event()
    heartbeat_task=asyncio.create_task(_heartbeat_loop(inv_id,token,heartbeat_stop))
    with SessionLocal() as db:
        try:
            _require_ownership(db,inv_id,token)
            inv=db.get(Investigation,inv_id)
            if not inv: return
            set_module(db,inv_id,"email_validation","running",token=token)
            analysis=analyze_email(inv.target)
            execution_id, execution_attempt_id = _capture_owned_execution(db,inv_id,token)
            inv.normalized_email=analysis["email"]; inv.username=analysis["username"]; inv.domain=analysis["domain"]; db.commit()
            add_findings(db,inv_id,[
                finding("MailRecon","email",analysis["email"],1.0,"info",notes=f"Normalized and syntax-validated target. Evidence state: {EVIDENCE_OBSERVED}."),
                finding("MailRecon","classification",f"provider={analysis['provider']}; type={'Disposable' if analysis['disposable'] else 'Role-based' if analysis['role_based'] else 'Personal/Business unknown'}",0.95,"info",notes=f"Classification, not an identity verdict. Evidence state: {EVIDENCE_OBSERVED}."),
            ],token)
            set_module(db,inv_id,"email_validation","completed","Validated and normalized",token)

            set_module(db,inv_id,"username_extraction","running",token=token)
            candidates=username_candidates(analysis["username"])
            add_findings(db,inv_id,[finding("MailRecon","username_candidate",c,0.0,"info",notes=f"Evidence state: {EVIDENCE_DERIVED}. Generated from email local-part; hypothesis only, not proof of account ownership.") for c in candidates],token)
            set_module(db,inv_id,"username_extraction","completed",f"Generated {len(candidates)} candidates",token)

            set_module(db,inv_id,"dns_analysis","running",token=token)
            dns=await resolve(inv.domain)
            _require_ownership(db,inv_id,token)
            analysis["has_dmarc"]=dns.get("has_dmarc")
            analysis["has_spf"]=dns.get("has_spf")
            dnssec=dns.get("DNSSEC")
            analysis["dnssec"]=dnssec if isinstance(dnssec,bool) else None
            fs=[]
            for k in ["A","AAAA","MX","NS","CNAME","SPF","DMARC"]:
                if dns.get(k): fs.append(finding("DNS",k.lower(),"; ".join(dns[k]),0.99,"info",notes=f"Public DNS response. Evidence state: {EVIDENCE_OBSERVED}."))
            dnssec_value="enabled" if analysis["dnssec"] is True else "disabled" if analysis["dnssec"] is False else "unknown"
            fs.append(finding("DNS","dnssec",dnssec_value,1.0 if analysis["dnssec"] is not None else 0.0,"info",notes="DNSSEC state is unknown when the resolver cannot validate it; unknown is not a security failure."))
            add_findings(db,inv_id,fs,token)
            set_module(db,inv_id,"dns_analysis","completed","DNS analysis complete",token)
            set_module(db,inv_id,"domain_analysis","completed","Domain metadata derived from DNS/RDAP",token)

            for n in ["gravatar","rdap","public_profile_discovery","breach_sources"]: set_module(db,inv_id,n,"running",token=token)
            results=await run_providers(analysis["email"],analysis["domain"],candidates)
            _require_ownership(db,inv_id,token)
            mapping=[("gravatar",results[0]),("rdap",results[1]),("public_profile_discovery",results[2]),("breach_sources",results[3])]
            for name,res in mapping:
                if isinstance(res,Exception):
                    set_module(db,inv_id,name,"failed",f"Provider exception: {type(res).__name__}",token)
                    add_findings(db,inv_id,[finding(name,"provider_status","error",1.0,"warning",notes=f"Provider raised {type(res).__name__}")],token)
                else:
                    add_findings(db,inv_id,[provider_finding(res), *res.findings],token)
                    module_status="completed" if res.status in {"ok","unconfigured","rate_limited","unavailable"} else "failed"
                    set_module(db,inv_id,name,module_status,res.message,token)

            consistency=_rdap_domain_consistency(analysis["domain"],results[1])
            if consistency: add_findings(db,inv_id,[consistency],token)

            set_module(db,inv_id,"risk_calculation","running",token=token)
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.execution_id==inv.execution_id)).all()
            risk=calculate({**analysis},[{"finding_type":r.finding_type,"confidence":r.confidence,"value":r.value,"notes":r.notes,"raw_reference":r.raw_reference} for r in rows])
            _capture_owned_execution(db,inv_id,token)
            inv.risk_score=risk.score; inv.risk_level=risk.level; db.commit()
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_factor",f["reason"],1.0,"high" if f["delta"]>10 else "medium" if f["delta"]>0 else "info",notes=f"Score delta: {f['delta']:+d}; dimension={f['dimension']}") for f in risk.factors],token)
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_dimension",f"{k}={v}",1.0,"info",notes="Dimension score, not a probability of compromise.") for k,v in risk.dimensions.items()],token)
            set_module(db,inv_id,"risk_calculation","completed",f"Risk score {risk.score}/100 ({risk.level})",token)

            ai_summary=await OllamaProvider().summarize(inv.target,[{"finding_type":r.finding_type,"value":r.value,"confidence":r.confidence,"severity":r.severity,"source":r.source} for r in rows])
            if ai_summary: add_findings(db,inv_id,[finding("Ollama","ai_summary",ai_summary,0.6,"info",notes="Evidence-grounded local summary; review source findings before relying on it.")],token)

            set_module(db,inv_id,"graph_build","running",token=token)
            _capture_owned_execution(db,inv_id,token)
            db.query(GraphEdge).filter(GraphEdge.investigation_id==inv_id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id==inv_id).delete(synchronize_session=False)
            email_node=GraphNode(investigation_id=inv_id,node_key=f"email:{analysis['email']}",node_type="EMAIL",label=analysis['email'])
            domain_node=GraphNode(investigation_id=inv_id,node_key=f"domain:{analysis['domain']}",node_type="DOMAIN",label=analysis['domain'])
            user_node=GraphNode(investigation_id=inv_id,node_key=f"username:{analysis['username']}",node_type="USERNAME",label=analysis['username'])
            db.add_all([email_node,domain_node,user_node]); db.flush()
            db.add_all([
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=domain_node.node_key,relation="uses",confidence=1),
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=user_node.node_key,relation=DERIVED_USERNAME_RELATION,confidence=1),
            ])
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.execution_id==inv.execution_id)).all()
            seen=set()
            for r in rows:
                state=_finding_evidence_state(r)
                if r.finding_type in {"breach","profile_candidate","public_identity","profile"}:
                    typ={"breach":"BREACH","profile_candidate":"PROFILE","public_identity":"IDENTITY","profile":"PROFILE"}[r.finding_type]
                    key=f"{typ.lower()}:{r.value}"
                    if key in seen: continue
                    seen.add(key)
                    db.add(GraphNode(investigation_id=inv_id,node_key=key,node_type=typ,label=r.value,node_metadata={"evidence_state":state,"confidence":r.confidence}))
                    db.add(GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=key,relation=_graph_relation(r.finding_type,state),confidence=r.confidence))
            _capture_owned_execution(db,inv_id,token)
            db.commit(); set_module(db,inv_id,"graph_build","completed","Relationship graph built with evidence-state-aware relationships",token)
            result=db.execute(update(Investigation).where(Investigation.id==inv_id,Investigation.status=="running",Investigation.execution_token==token).values(status="completed",completed_at=utcnow(),execution_heartbeat_at=None,execution_token=None))
            db.commit()
            if result.rowcount != 1: return
        except Exception as exc:
            try:
                mark_investigation_failed(db,inv_id,token,exc)
            except Exception:
                db.rollback()
        finally:
            heartbeat_stop.set()
            heartbeat_task.cancel()
            try: await heartbeat_task
            except asyncio.CancelledError: pass

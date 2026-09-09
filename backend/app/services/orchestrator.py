import asyncio
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.session import SessionLocal
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.osint.email import analyze_email, username_candidates, EVIDENCE_DERIVED, EVIDENCE_POSSIBLE, EVIDENCE_CORROBORATED, EVIDENCE_SOURCE_ASSOCIATED
from app.osint.dns import resolve
from app.providers import HIBPProvider, GravatarProvider, GitHubProvider, RDAPProvider
from app.providers.ollama import OllamaProvider
from app.providers.base import finding
from app.risk.engine import calculate

MODULES=["email_validation","domain_analysis","dns_analysis","gravatar","rdap","username_extraction","public_profile_discovery","breach_sources","risk_calculation","graph_build"]

def utcnow(): return datetime.now(timezone.utc)

def set_module(db,inv_id,name,status,message=None):
    m=db.scalar(select(ModuleRun).where(ModuleRun.investigation_id==inv_id,ModuleRun.module==name))
    if not m:
        m=ModuleRun(investigation_id=inv_id,module=name); db.add(m)
    m.status=status; m.message=message
    if status=="running": m.started_at=utcnow()
    if status in {"completed","failed","skipped"}: m.finished_at=utcnow()
    db.commit()

def add_findings(db,inv_id,fs):
    if not fs: return
    inv=db.get(Investigation,inv_id)
    for f in fs:
        if inv and inv.privacy_mode:
            f=dict(f)
            f["raw_reference"]=None
            if f.get("finding_type") == "profile_candidate" and EVIDENCE_POSSIBLE in (f.get("notes") or ""):
                continue
        db.add(Finding(investigation_id=inv_id,**f))
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

async def run_investigation(inv_id:int):
    with SessionLocal() as db:
        inv=db.get(Investigation,inv_id)
        if not inv: return
        try:
            set_module(db,inv_id,"email_validation","running")
            analysis=analyze_email(inv.target)
            inv.normalized_email=analysis["email"]; inv.username=analysis["username"]; inv.domain=analysis["domain"]; inv.status="running"; db.commit()
            add_findings(db,inv_id,[
                finding("MailRecon","email",analysis["email"],1.0,"info",notes="Normalized and syntax-validated target. Evidence state: observed."),
                finding("MailRecon","classification",f"provider={analysis['provider']}; type={'Disposable' if analysis['disposable'] else 'Role-based' if analysis['role_based'] else 'Personal/Business unknown'}",0.95,"info",notes="Classification, not an identity verdict. Evidence state: observed."),
            ])
            set_module(db,inv_id,"email_validation","completed","Validated and normalized")

            set_module(db,inv_id,"username_extraction","running")
            candidates=username_candidates(analysis["username"])
            add_findings(db,inv_id,[finding("MailRecon","username_candidate",c,0.0,"info",notes=f"Evidence state: {EVIDENCE_DERIVED}. Generated from email local-part; hypothesis only, not proof of account ownership.") for c in candidates])
            set_module(db,inv_id,"username_extraction","completed",f"Generated {len(candidates)} candidates")

            set_module(db,inv_id,"dns_analysis","running")
            dns=await resolve(inv.domain)
            analysis["has_dmarc"]=True if dns.get("DMARC") else False if dns.get("DMARC") is not None else None
            analysis["has_spf"]=True if dns.get("SPF") else False if dns.get("SPF") is not None else None
            dnssec=dns.get("DNSSEC")
            analysis["dnssec"]=dnssec if isinstance(dnssec,bool) else None
            fs=[]
            for k in ["A","AAAA","MX","NS","CNAME","SPF","DMARC"]:
                if dns.get(k): fs.append(finding("DNS",k.lower(),"; ".join(dns[k]),0.99,"info",notes="Public DNS response. Evidence state: observed."))
            dnssec_value="enabled" if analysis["dnssec"] is True else "disabled" if analysis["dnssec"] is False else "unknown"
            fs.append(finding("DNS","dnssec",dnssec_value,1.0 if analysis["dnssec"] is not None else 0.0,"info",notes="DNSSEC state is unknown when the resolver cannot validate it; unknown is not a security failure."))
            add_findings(db,inv_id,fs)
            set_module(db,inv_id,"dns_analysis","completed","DNS analysis complete")
            set_module(db,inv_id,"domain_analysis","completed","Domain metadata derived from DNS/RDAP")

            for n in ["gravatar","rdap","public_profile_discovery","breach_sources"]: set_module(db,inv_id,n,"running")
            results=await run_providers(analysis["email"],analysis["domain"],candidates)
            mapping=[("gravatar",results[0]),("rdap",results[1]),("public_profile_discovery",results[2]),("breach_sources",results[3])]
            for name,res in mapping:
                if isinstance(res,Exception):
                    set_module(db,inv_id,name,"failed",f"Provider exception: {type(res).__name__}")
                    add_findings(db,inv_id,[finding(name,"provider_status","error",1.0,"warning",notes=f"Provider raised {type(res).__name__}")])
                else:
                    add_findings(db,inv_id,[provider_finding(res), *res.findings])
                    module_status="completed" if res.status in {"ok","unconfigured","rate_limited","unavailable"} else "failed"
                    set_module(db,inv_id,name,module_status,res.message)

            consistency=_rdap_domain_consistency(analysis["domain"],results[1])
            if consistency: add_findings(db,inv_id,[consistency])

            set_module(db,inv_id,"risk_calculation","running")
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id)).all()
            risk=calculate({**analysis},[{"finding_type":r.finding_type,"confidence":r.confidence,"value":r.value,"notes":r.notes,"raw_reference":r.raw_reference} for r in rows])
            inv.risk_score=risk.score; inv.risk_level=risk.level; db.commit()
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_factor",f["reason"],1.0,"high" if f["delta"]>10 else "medium" if f["delta"]>0 else "info",notes=f"Score delta: {f['delta']:+d}; dimension={f['dimension']}") for f in risk.factors])
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_dimension",f"{k}={v}",1.0,"info",notes="Dimension score, not a probability of compromise.") for k,v in risk.dimensions.items()])
            set_module(db,inv_id,"risk_calculation","completed",f"Risk score {risk.score}/100 ({risk.level})")

            ai_summary=await OllamaProvider().summarize(inv.target,[{"finding_type":r.finding_type,"value":r.value,"confidence":r.confidence,"severity":r.severity,"source":r.source} for r in rows])
            if ai_summary: add_findings(db,inv_id,[finding("Ollama","ai_summary",ai_summary,0.6,"info",notes="Evidence-grounded local summary; review source findings before relying on it.")])

            set_module(db,inv_id,"graph_build","running")
            db.query(GraphEdge).filter(GraphEdge.investigation_id==inv_id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id==inv_id).delete(synchronize_session=False)
            email_node=GraphNode(investigation_id=inv_id,node_key=f"email:{analysis['email']}",node_type="EMAIL",label=analysis['email'])
            domain_node=GraphNode(investigation_id=inv_id,node_key=f"domain:{analysis['domain']}",node_type="DOMAIN",label=analysis['domain'])
            user_node=GraphNode(investigation_id=inv_id,node_key=f"username:{analysis['username']}",node_type="USERNAME",label=analysis['username'])
            db.add_all([email_node,domain_node,user_node]); db.flush()
            db.add_all([
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=domain_node.node_key,relation="uses",confidence=1),
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=user_node.node_key,relation="registered_as",confidence=1),
            ])
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id)).all()
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
            db.commit(); set_module(db,inv_id,"graph_build","completed","Relationship graph built with evidence-state-aware relationships")
            inv.status="completed"; inv.completed_at=utcnow(); db.commit()
        except Exception as exc:
            inv.status="failed"; db.commit()
            for m in MODULES:
                try: set_module(db,inv_id,m,"failed",f"Investigation failed: {type(exc).__name__}")
                except Exception: pass

import asyncio
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.session import SessionLocal
from app.models import Investigation, Finding, ModuleRun, GraphNode, GraphEdge
from app.osint.email import analyze_email, username_candidates
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
        db.add(Finding(investigation_id=inv_id,**f))
    db.commit()

def provider_finding(result):
    severity = "warning" if result.status in {"error","rate_limited","unavailable"} else "info"
    return finding(
        result.provider, "provider_status", result.status, 1.0, severity,
        notes=result.message or "Provider execution completed.",
        raw_reference={"status": result.status},
    )

async def run_investigation(inv_id:int):
    with SessionLocal() as db:
        inv=db.get(Investigation,inv_id)
        if not inv: return
        try:
            set_module(db,inv_id,"email_validation","running")
            analysis=analyze_email(inv.target)
            inv.normalized_email=analysis["email"]; inv.username=analysis["username"]; inv.domain=analysis["domain"]; inv.status="running"; db.commit()
            add_findings(db,inv_id,[
                finding("MailRecon","email",analysis["email"],1.0,"info",notes="Normalized and syntax-validated target."),
                finding("MailRecon","classification",f"provider={analysis['provider']}; type={'Disposable' if analysis['disposable'] else 'Role-based' if analysis['role_based'] else 'Personal/Business unknown'}",0.95,"info",notes="Classification, not an identity verdict."),
            ])
            set_module(db,inv_id,"email_validation","completed","Validated and normalized")

            set_module(db,inv_id,"username_extraction","running")
            candidates=username_candidates(analysis["username"])
            add_findings(db,inv_id,[finding("MailRecon","username_candidate",c,0.7,"info",notes="Generated from email local-part; not proof of account ownership.") for c in candidates])
            set_module(db,inv_id,"username_extraction","completed",f"Generated {len(candidates)} candidates")

            set_module(db,inv_id,"dns_analysis","running")
            dns=await resolve(inv.domain)
            analysis["has_dmarc"]=bool(dns.get("DMARC")); analysis["has_spf"]=bool(dns.get("SPF")); analysis["dnssec"]=bool(dns.get("DNSSEC"))
            fs=[]
            for k in ["A","AAAA","MX","NS","CNAME","SPF","DMARC"]:
                if dns.get(k): fs.append(finding("DNS",k.lower(),"; ".join(dns[k]),0.99,"info",notes="Public DNS response."))
            fs.append(finding("DNS","dnssec","enabled" if dns.get("DNSSEC") else "not observed",0.95,"info",notes="Absence is not proof of misconfiguration."))
            add_findings(db,inv_id,fs)
            set_module(db,inv_id,"dns_analysis","completed","DNS analysis complete")
            set_module(db,inv_id,"domain_analysis","completed","Domain metadata derived from DNS/RDAP")

            for n in ["gravatar","rdap","public_profile_discovery","breach_sources"]: set_module(db,inv_id,n,"running")
            providers=[GravatarProvider().run(analysis["email"]), RDAPProvider().run(analysis["domain"]), GitHubProvider().run(candidates,analysis["email"]), HIBPProvider().run(analysis["email"])]
            results=await asyncio.gather(*providers,return_exceptions=True)
            mapping=[("gravatar",results[0]),("rdap",results[1]),("public_profile_discovery",results[2]),("breach_sources",results[3])]
            for name,res in mapping:
                if isinstance(res,Exception):
                    set_module(db,inv_id,name,"failed",f"Provider exception: {type(res).__name__}")
                    add_findings(db,inv_id,[finding(name,"provider_status","error",1.0,"warning",notes=f"Provider raised {type(res).__name__}")])
                else:
                    add_findings(db,inv_id,[provider_finding(res), *res.findings])
                    module_status="completed" if res.status in {"ok","unconfigured","rate_limited","unavailable"} else "failed"
                    set_module(db,inv_id,name,module_status,res.message)

            set_module(db,inv_id,"risk_calculation","running")
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id)).all()
            risk=calculate({**analysis},[{"finding_type":r.finding_type,"confidence":r.confidence,"value":r.value} for r in rows])
            inv.risk_score=risk.score; inv.risk_level=risk.level; db.commit()
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_factor",f["reason"],1.0,"high" if f["delta"]>10 else "medium" if f["delta"]>0 else "info",notes=f"Score delta: {f['delta']:+d}; dimension={f['dimension']}") for f in risk.factors])
            add_findings(db,inv_id,[finding("MailRecon Risk Engine","risk_dimension",f"{k}={v}",1.0,"info",notes="Dimension score, not a probability of compromise.") for k,v in risk.dimensions.items()])
            set_module(db,inv_id,"risk_calculation","completed",f"Risk score {risk.score}/100 ({risk.level})")

            ai_summary=await OllamaProvider().summarize(inv.target,[{"finding_type":r.finding_type,"value":r.value,"confidence":r.confidence,"severity":r.severity,"source":r.source} for r in rows])
            if ai_summary: add_findings(db,inv_id,[finding("Ollama","ai_summary",ai_summary,0.6,"info",notes="Evidence-grounded local summary; review source findings before relying on it.")])

            set_module(db,inv_id,"graph_build","running")
            # Rebuild graph deterministically to avoid duplicate nodes on retries.
            db.query(GraphEdge).filter(GraphEdge.investigation_id==inv_id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id==inv_id).delete(synchronize_session=False)
            email_node=GraphNode(investigation_id=inv_id,node_key=f"email:{analysis['email']}",node_type="EMAIL",label=analysis['email'])
            domain_node=GraphNode(investigation_id=inv_id,node_key=f"domain:{analysis['domain']}",node_type="DOMAIN",label=analysis['domain'])
            user_node=GraphNode(investigation_id=inv_id,node_key=f"username:{analysis['username']}",node_type="USERNAME",label=analysis['username'])
            db.add_all([email_node,domain_node,user_node]); db.flush()
            db.add_all([
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=domain_node.node_key,relation="uses",confidence=1),
                GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=user_node.node_key,relation="registered_as",confidence=.95),
            ])
            rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id)).all()
            seen=set()
            for r in rows:
                if r.finding_type in {"breach","profile_candidate","public_identity","profile"}:
                    typ={"breach":"BREACH","profile_candidate":"PROFILE","public_identity":"IDENTITY","profile":"PROFILE"}[r.finding_type]
                    key=f"{typ.lower()}:{r.value}"
                    if key in seen: continue
                    seen.add(key)
                    db.add(GraphNode(investigation_id=inv_id,node_key=key,node_type=typ,label=r.value))
                    relation="appeared_in" if typ=="BREACH" else "possible_profile" if typ=="PROFILE" else "associated_identity"
                    db.add(GraphEdge(investigation_id=inv_id,source=email_node.node_key,target=key,relation=relation,confidence=r.confidence))
            db.commit(); set_module(db,inv_id,"graph_build","completed","Relationship graph built")
            inv.status="completed"; inv.completed_at=utcnow(); db.commit()
        except Exception as exc:
            inv.status="failed"; db.commit()
            for m in MODULES:
                try: set_module(db,inv_id,m,"failed",f"Investigation failed: {type(exc).__name__}")
                except Exception: pass

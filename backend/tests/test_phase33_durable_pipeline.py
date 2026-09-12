from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.account_discovery import account_discovery
from app.api.routes import report
from app.db.session import Base
from app.models import Finding, Investigation, ModuleRun, GraphEdge, GraphNode
from app.osint.correlation import correlate_email_findings
from app.providers.base import ProviderResult, finding
from app.providers.public_web import PublicWebProvider
from app.providers import public_web as public_web_module
from app.services import lifecycle, orchestrator

class _FakeProvider:
    def __init__(self,name,result): self.name=name; self.result=result
    async def run(self,context): return await self.result(context)

@pytest.mark.asyncio
async def test_durable_pipeline_persists_current_attempt_and_projects_public_web(monkeypatch):
    engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool); Base.metadata.create_all(engine); TestSessionLocal=sessionmaker(engine,expire_on_commit=False,class_=Session)
    monkeypatch.setattr(orchestrator,"SessionLocal",TestSessionLocal); monkeypatch.setattr(lifecycle,"SessionLocal",TestSessionLocal)
    async def fake_ollama(self,target,findings): return None
    monkeypatch.setattr(orchestrator.OllamaProvider,"summarize",fake_ollama)
    async def fake_resolve(domain): return {"A":["192.0.2.10"],"AAAA":[],"MX":["mx.example.com"],"NS":[],"CNAME":[],"SPF":["v=spf1 -all"],"DMARC":["v=DMARC1; p=reject"],"DMARC_status":"present","SPF_status":"present","DNSSEC":True}
    monkeypatch.setattr(orchestrator,"resolve",fake_resolve)
    settings=public_web_module.get_settings(); original_url=settings.public_web_search_url; original_token=settings.public_web_search_token; settings.public_web_search_url="https://search.example.test/search"; settings.public_web_search_token=None
    class FakeSearchClient:
        def __init__(self,*args,**kwargs): self.follow_redirects=kwargs["follow_redirects"]; self.trust_env=kwargs["trust_env"]
        async def __aenter__(self): return self
        async def __aexit__(self,exc_type,exc,tb): return False
        async def get(self,url,*args,**kwargs): return __import__("httpx").Response(200,json={"results":[{"title":"Local public reference","url":"https://example.org/public-reference","engine":"mock"}]})
    monkeypatch.setattr(public_web_module.httpx,"AsyncClient",FakeSearchClient); monkeypatch.setattr(public_web_module,"validate_provider_url",lambda url:url); monkeypatch.setattr(public_web_module,"pinned_transport",lambda url:object())
    def public_web_factory(): return PublicWebProvider()
    def fake_factory(name):
        async def run(context):
            if name=="RDAP": return ProviderResult(name,"ok",findings=[finding(name,"domain","ldhName: example.com",0.98,"info","https://rdap.example.test/domain/example.com")])
            if name=="GitHub": return ProviderResult(name,"ok",findings=[finding(name,"profile_candidate","https://github.com/example",0.45,"info","https://github.com/example",evidence_state="possible_match",raw_reference={"login":"example","evidence_state":"possible_match"})])
            if name=="GitLab": return ProviderResult(name,"ok")
            if name=="Have I Been Pwned": return ProviderResult(name,"unconfigured")
            if name=="Gravatar": return ProviderResult(name,"ok")
            raise AssertionError(name)
        return lambda:_FakeProvider(name,run)
    original_resolvers=orchestrator.PROVIDER_FACTORY_RESOLVERS.copy(); captured=[]; original_failure_handler=orchestrator.mark_investigation_failed
    def capture_failure(db,inv_id,token,exc): captured.append(exc); return original_failure_handler(db,inv_id,token,exc)
    monkeypatch.setattr(orchestrator,"mark_investigation_failed",capture_failure)
    orchestrator.PROVIDER_FACTORY_RESOLVERS.update({"Gravatar":fake_factory("Gravatar"),"RDAP":fake_factory("RDAP"),"GitHub":fake_factory("GitHub"),"GitLab":fake_factory("GitLab"),"Have I Been Pwned":fake_factory("Have I Been Pwned"),"Public Web":public_web_factory})
    try:
        with TestSessionLocal() as db:
            inv=Investigation(target="user@example.com",normalized_email="user@example.com",username="user",domain="example.com",status="queued",privacy_mode=False,external_provider_disclosure=True); db.add(inv); db.commit(); db.refresh(inv)
            for module in orchestrator.MODULES: db.add(ModuleRun(investigation_id=inv.id,execution_id=inv.execution_id,module=module,status="queued"))
            db.commit(); token=lifecycle.claim_investigation(db,inv.id); assert token; inv_id=inv.id
        await orchestrator.run_investigation(inv_id,token)
        with TestSessionLocal() as db:
            first=db.get(Investigation,inv_id); assert first.status=="completed", f"durable pipeline failed: {captured!r}"
            first_attempt=first.execution_attempt_id; first_execution=first.execution_id; public=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.source=="Public Web",Finding.finding_type=="public_web_reference")).all(); assert public; assert all(row.evidence_state=="possible_match" for row in public); assert all(row.execution_attempt_id==first_attempt for row in public)
            current_rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.execution_attempt_id==first_attempt)).all(); correlation=correlate_email_findings([{"id":row.id,"finding_type":row.finding_type,"value":row.value,"confidence":row.confidence,"evidence_state":row.evidence_state,"source":row.source,"source_url":row.source_url,"raw_reference":row.raw_reference,"notes":row.notes} for row in current_rows]); web_rel=next(item for item in correlation["relationships"] if item["relationship"]=="public_web_observation"); assert web_rel["evidence_state"]=="possible_match"; assert web_rel["confidence"]==0.55; assert "does not confirm account ownership" in web_rel["limitations"]
            graph_nodes=db.scalars(select(GraphNode).where(GraphNode.investigation_id==inv_id)).all(); graph_edges=db.scalars(select(GraphEdge).where(GraphEdge.investigation_id==inv_id)).all(); assert any(node.node_type=="WEB_REFERENCE" for node in graph_nodes); assert any(edge.relation=="possible_profile" for edge in graph_edges)
            discovery=account_discovery(inv_id,db); discovery_web=next(row for row in discovery["services"] if row["service"]=="Public Web"); evidence_id=discovery_web["evidence"][0]["finding_id"]; assert db.get(Finding,evidence_id).execution_attempt_id==first_attempt
            json_report=report(inv_id,format="json",db=db); assert json_report["provenance"]["execution_attempt_id"]==first_attempt; assert any(item["finding_type"]=="public_web_reference" and item["current_attempt"] for item in json_report["findings"])
            first.status="queued"; first.execution_token=None; first.execution_heartbeat_at=None; db.commit(); second_token=lifecycle.claim_investigation(db,inv_id); assert second_token; second_attempt=db.get(Investigation,inv_id).execution_attempt_id; assert second_attempt!=first_attempt; assert db.get(Investigation,inv_id).execution_id==first_execution
        await orchestrator.run_investigation(inv_id,second_token)
        with TestSessionLocal() as db:
            current=db.get(Investigation,inv_id); assert current.status=="completed", f"second durable attempt failed: {captured!r}"; assert current.execution_attempt_id==second_attempt; rows=db.scalars(select(Finding).where(Finding.investigation_id==inv_id,Finding.finding_type=="public_web_reference")).all(); assert {row.execution_attempt_id for row in rows}=={first_attempt,second_attempt}; discovery=account_discovery(inv_id,db); discovery_web=next(row for row in discovery["services"] if row["service"]=="Public Web"); evidence_ids={item["finding_id"] for item in discovery_web["evidence"]}; assert evidence_ids; assert all(db.get(Finding,finding_id).execution_attempt_id==second_attempt for finding_id in evidence_ids); json_report=report(inv_id,format="json",db=db); public_rows=[item for item in json_report["findings"] if item["finding_type"]=="public_web_reference"]; assert any(item["current_attempt"] for item in public_rows); assert any(item["historical_attempt"] for item in public_rows); assert all(item["evidence_state"]=="possible_match" for item in public_rows)
    finally:
        orchestrator.PROVIDER_FACTORY_RESOLVERS.clear(); orchestrator.PROVIDER_FACTORY_RESOLVERS.update(original_resolvers); settings.public_web_search_url=original_url; settings.public_web_search_token=original_token

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models import GraphEdge, GraphNode, Investigation
from app.providers.ollama import OllamaProvider
from app.services.lifecycle import claim_investigation, fence_execution, recover_stale_investigations


def make_db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'phase15.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


def add_inv(db):
    inv = Investigation(
        target="test@example.com",
        normalized_email="test@example.com",
        username="test",
        domain="example.com",
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def test_concurrent_claims_only_one_worker_owns_queued_investigation(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        inv_id = inv.id

    barrier = Barrier(2)

    def claim_from_separate_session():
        with Session(engine) as db:
            barrier.wait()
            return claim_investigation(db, inv_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.map(lambda _: claim_from_separate_session(), range(2))

    tokens = [token for token in (first, second) if token]
    assert len(tokens) == 1
    with Session(engine) as db:
        current = db.get(Investigation, inv_id)
        assert current.status == "running"
        assert current.execution_token == tokens[0]


def test_stale_takeover_fences_old_worker_token(tmp_path):
    from datetime import timedelta

    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        old_token = claim_investigation(db, inv.id)
        old = db.get(Investigation, inv.id)
        old_attempt = old.execution_attempt_id
        stale_at = old.execution_heartbeat_at
        assert old_token and old_attempt and stale_at
        assert recover_stale_investigations(db, now=stale_at + timedelta(seconds=61)) == 1
        new_token = claim_investigation(db, inv.id, now=stale_at + timedelta(seconds=62))
        current = db.get(Investigation, inv.id)
        assert new_token and new_token != old_token
        assert current.execution_attempt_id != old_attempt
        with pytest.raises(RuntimeError, match="lease is no longer owned"):
            fence_execution(db, inv.id, old_token)


def test_graph_rebuild_transaction_rolls_back_on_failure(tmp_path):
    engine = make_db(tmp_path)
    with Session(engine) as db:
        inv = add_inv(db)
        db.add(GraphNode(investigation_id=inv.id, node_key="email:test@example.com", node_type="EMAIL", label="test@example.com"))
        db.add(GraphEdge(investigation_id=inv.id, source="email:test@example.com", target="domain:example.com", relation="uses", confidence=1.0))
        db.commit()
        try:
            db.query(GraphEdge).filter(GraphEdge.investigation_id == inv.id).delete(synchronize_session=False)
            db.query(GraphNode).filter(GraphNode.investigation_id == inv.id).delete(synchronize_session=False)
            db.add(GraphNode(investigation_id=inv.id, node_key="email:new@example.com", node_type="EMAIL", label="new@example.com"))
            db.add(GraphNode(investigation_id=inv.id, node_key="email:new@example.com", node_type="EMAIL", label="duplicate"))
            db.flush()
            pytest.fail("graph rebuild should have failed on duplicate identity")
        except IntegrityError:
            db.rollback()

        nodes = db.scalars(select(GraphNode).where(GraphNode.investigation_id == inv.id)).all()
        edges = db.scalars(select(GraphEdge).where(GraphEdge.investigation_id == inv.id)).all()
        assert [(n.node_key, n.label) for n in nodes] == [("email:test@example.com", "test@example.com")]
        assert [(e.source, e.target, e.relation) for e in edges] == [("email:test@example.com", "domain:example.com", "uses")]


@pytest.mark.asyncio
async def test_ollama_client_disables_environment_proxy_routing(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"response": "ok"}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.providers.ollama.httpx.AsyncClient", FakeClient)
    monkeypatch.setattr("app.providers.ollama.get_settings", lambda: type("Settings", (), {
        "enable_ollama": True,
        "ollama_base_url": "http://127.0.0.1:11434",
        "ollama_allowed_hosts": "127.0.0.1",
        "ollama_model": "test-model",
    })())

    result = await OllamaProvider().summarize("test@example.com", [])
    assert result == "ok"
    assert captured["trust_env"] is False


def test_frontend_exposes_external_provider_disclosure_separately():
    api = Path("frontend/src/services/api.ts").read_text(encoding="utf-8")
    lookup = Path("frontend/src/pages/Lookup.tsx").read_text(encoding="utf-8")
    assert "external_provider_disclosure = true" in api
    assert "external_provider_disclosure" in api
    assert "setExternalDisclosure" in lookup
    assert "Privacy mode" in lookup
    assert "external providers" in lookup


def test_docker_and_ci_use_the_same_python_lockfile():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "requirements.lock" in dockerfile
    assert "pip install --no-cache-dir --requirement requirements.lock" in dockerfile
    assert "pip install -r backend/requirements.lock" in workflow
    assert "pip-audit -r backend/requirements.lock --strict" in workflow


def test_trivy_critical_policy_does_not_ignore_unfixed_findings():
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    critical_block = workflow.split("- name: Fail on critical container findings", 1)[1].split("workflow-security:", 1)[0]
    assert "--severity CRITICAL" in critical_block
    assert "--ignore-unfixed" not in critical_block


def test_lock_contains_all_direct_runtime_requirements():
    def package_name(line):
        return line.strip().split("==", 1)[0].split("[", 1)[0].lower()

    direct = {
        package_name(line)
        for line in Path("backend/requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    locked = {
        package_name(line)
        for line in Path("backend/requirements.lock").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "==" in line
    }
    assert direct <= locked

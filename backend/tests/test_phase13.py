from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.routes import graph, report_provenance
from app.models import ExecutionAttempt, GraphEdge, GraphNode, Investigation


def migration_config(db_path):
    from alembic.config import Config
    cfg=Config(); cfg.set_main_option("script_location","backend/alembic"); cfg.set_main_option("sqlalchemy.url",f"sqlite:///{db_path}"); return cfg


def test_graph_database_identity_constraints_reject_duplicates(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path / 'graph.db'}")
    from app.db.session import Base
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv=Investigation(target="test@example.com",normalized_email="test@example.com",username="test",domain="example.com")
        db.add(inv); db.commit()
        db.add(GraphNode(investigation_id=inv.id,node_key="email:test@example.com",node_type="EMAIL",label="test@example.com")); db.commit()
        db.add(GraphNode(investigation_id=inv.id,node_key="email:test@example.com",node_type="EMAIL",label="test@example.com"))
        with pytest.raises(Exception): db.commit()
        db.rollback()
        db.add(GraphEdge(investigation_id=inv.id,source="email:test@example.com",target="domain:example.com",relation="uses",confidence=1.0)); db.commit()
        db.add(GraphEdge(investigation_id=inv.id,source="email:test@example.com",target="domain:example.com",relation="uses",confidence=1.0))
        with pytest.raises(Exception): db.commit()


def test_graph_view_is_sorted_and_declares_current_derived_provenance(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path / 'graph-view.db'}")
    from app.db.session import Base
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv=Investigation(target="test@example.com",normalized_email="test@example.com",username="test",domain="example.com",status="completed",execution_id="exec-1",execution_attempt_id="attempt-1")
        db.add(inv); db.commit(); db.refresh(inv)
        db.add(ExecutionAttempt(investigation_id=inv.id,execution_id="exec-1",execution_attempt_id="attempt-1",status="completed",started_at=datetime(2026,9,9,8,tzinfo=timezone.utc),finished_at=datetime(2026,9,9,8,1,tzinfo=timezone.utc)))
        db.add_all([
            GraphNode(investigation_id=inv.id,node_key="z:last",node_type="PROFILE",label="z"),
            GraphNode(investigation_id=inv.id,node_key="a:first",node_type="EMAIL",label="a"),
            GraphEdge(investigation_id=inv.id,source="z:last",target="a:first",relation="z_relation",confidence=.5),
            GraphEdge(investigation_id=inv.id,source="a:first",target="z:last",relation="a_relation",confidence=.8),
        ]); db.commit()
        payload=graph(inv.id,db)
        assert payload["semantics"] == "current_derived_view"
        assert payload["provenance"]["type"] == "producing_execution_attempt"
        assert payload["provenance"]["execution_attempt_id"] == "attempt-1"
        assert [node["id"] for node in payload["nodes"]] == ["a:first","z:last"]
        assert [(edge["source"],edge["target"],edge["relation"]) for edge in payload["edges"]] == [("a:first","z:last","a_relation"),("z:last","a:first","z_relation")]


def test_report_provenance_contains_execution_and_privacy_metadata(tmp_path):
    engine=create_engine(f"sqlite:///{tmp_path / 'report.db'}")
    from app.db.session import Base
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv=Investigation(target="test@example.com",normalized_email="test@example.com",username="test",domain="example.com",status="completed",privacy_mode=True,external_provider_disclosure=False,execution_id="exec-1",execution_attempt_id="attempt-1",execution_started_at=datetime(2026,9,9,8,tzinfo=timezone.utc),completed_at=datetime(2026,9,9,8,1,tzinfo=timezone.utc))
        db.add(inv); db.commit(); db.refresh(inv)
        attempt=ExecutionAttempt(investigation_id=inv.id,execution_id="exec-1",execution_attempt_id="attempt-1",status="completed",started_at=inv.execution_started_at,finished_at=inv.completed_at)
        db.add(attempt); db.commit()
        generated=datetime(2026,9,9,9,tzinfo=timezone.utc)
        provenance=report_provenance(db,inv,generated)
        assert provenance["investigation_id"] == inv.id
        assert provenance["execution_id"] == "exec-1"
        assert provenance["execution_attempt_id"] == "attempt-1"
        assert provenance["attempt_status"] == "completed"
        assert provenance["external_provider_disclosure"] is False
        assert provenance["privacy_mode"] is True
        assert provenance["report_generated_at"] == generated
        assert provenance["graph_semantics"] == "current_derived_view"


def test_docker_build_uses_lockfile_enforced_npm_ci():
    dockerfile=Path(__file__).resolve().parents[2] / "Dockerfile"
    text=dockerfile.read_text(encoding="utf-8")
    assert "RUN npm ci --no-audit --no-fund" in text
    assert "RUN npm install --no-audit --no-fund" not in text


def test_ci_security_jobs_and_pinned_scanners_are_present():
    workflow=(Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for job in ("secret-scan:","sast:","container-scan:","workflow-security:"):
        assert job in workflow
    for action in ("gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e","github/codeql-action/init@977e6ceaea7361825998245d787fa3b4d6b9e5df","aquasecurity/trivy-action@b6643a29fecd7f34b3597bc6acb0a98b03d33ff8","zizmorcore/zizmor-action@3dc1ecc9bcb9e94e9b2c709687979e1298497054"):
        assert action in workflow

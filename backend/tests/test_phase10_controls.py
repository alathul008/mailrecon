import json

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
from starlette.requests import Request
from starlette.routing import Route

from app.db.session import Base
from app.main import MAX_REQUEST_BODY_SIZE, app
from app.models import Finding, Investigation
from app.osint.email import EVIDENCE_POSSIBLE
from app.osint.dns import record_presence
from app.providers.base import finding
from app.risk.engine import calculate
from app.services import lifecycle
from app.services.orchestrator import add_findings


def make_body_app():
    async def echo(request: Request):
        body = await request.body()
        return JSONResponse({"size": len(body)})

    test_app = FastAPI(routes=[Route("/echo", echo, methods=["POST"])])
    test_app.add_middleware(RequestBodyLimitMiddleware, max_body_size=MAX_REQUEST_BODY_SIZE)
    return test_app


def test_request_body_limit_is_configured_on_actual_api():
    middleware = next(item for item in app.user_middleware if item.cls is RequestBodyLimitMiddleware)
    assert middleware.kwargs["max_body_size"] == 1_048_576


def test_request_body_limit_allows_exact_boundary():
    client = TestClient(make_body_app())
    body = b"x" * 1_048_576
    response = client.post("/echo", content=body)
    assert response.status_code == 200
    assert response.json() == {"size": 1_048_576}


def test_request_body_limit_rejects_oversized_content_length():
    client = TestClient(make_body_app())
    body = b"x" * (1_048_576 + 1)
    response = client.post("/echo", content=body)
    assert response.status_code == 413


def test_request_body_limit_rejects_oversized_stream_without_content_length():
    client = TestClient(make_body_app())

    def chunks():
        yield b"x" * 700_000
        yield b"x" * 400_000

    response = client.post("/echo", content=chunks())
    assert response.status_code == 413


def test_normal_api_request_remains_unaffected():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dns_record_presence_preserves_true_false_none():
    assert record_presence(["v=spf1 -all"], "ok") is True
    assert record_presence([], "ok") is False
    assert record_presence(["v=spf1 -all"], "unavailable") is None
    assert record_presence(["v=dmarc1; p=none"], "ok") is True
    assert record_presence([], "ok") is False
    assert record_presence(["v=dmarc1; p=none"], "unavailable") is None


def test_risk_consumes_dns_three_state_without_false_penalty_on_unavailable():
    present = calculate({"has_spf": True, "has_dmarc": True}, [])
    absent = calculate({"has_spf": False, "has_dmarc": False}, [])
    unavailable = calculate({"has_spf": None, "has_dmarc": None}, [])

    assert present.dimensions["domain_security"] == 0
    assert absent.dimensions["domain_security"] == 18
    assert unavailable.dimensions["domain_security"] == 0
    assert unavailable.factors == []


def test_finding_factory_populates_structured_evidence_state():
    item = finding(
        "test",
        "profile_candidate",
        "https://example.test/alice",
        notes="Possible match only. Evidence state: possible_match.",
    )
    assert item["evidence_state"] == EVIDENCE_POSSIBLE


def test_privacy_mode_rejects_possible_profile_by_structured_state_without_note_marker(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'privacy.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(
            target="alice@example.com",
            normalized_email="alice@example.com",
            username="alice",
            domain="example.com",
            privacy_mode=True,
            status="queued",
        )
        db.add(inv)
        db.commit()
        token = lifecycle.claim_investigation(db, inv.id)

        add_findings(
            db,
            inv.id,
            [{
                "source": "test",
                "source_url": "https://example.test/source",
                "finding_type": "profile_candidate",
                "value": "https://example.test/alice",
                "confidence": 0.4,
                "severity": "info",
                "evidence_state": "possible_match",
                "notes": "Provider returned a candidate; state is structured.",
                "raw_reference": {"secret": "must-not-persist"},
            }],
            token,
        )

        rows = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        assert rows == []


def test_non_privacy_mode_preserves_structured_evidence_state_and_raw_reference(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'nonprivacy.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        inv = Investigation(
            target="alice@example.com",
            normalized_email="alice@example.com",
            username="alice",
            domain="example.com",
            privacy_mode=False,
            status="queued",
        )
        db.add(inv)
        db.commit()
        token = lifecycle.claim_investigation(db, inv.id)

        raw = {"provider": "test", "evidence_state": "possible_match"}
        add_findings(
            db,
            inv.id,
            [{
                "source": "test",
                "source_url": "https://example.test/source",
                "finding_type": "profile_candidate",
                "value": "https://example.test/alice",
                "confidence": 0.4,
                "severity": "info",
                "evidence_state": "possible_match",
                "notes": "No legacy evidence marker.",
                "raw_reference": raw,
            }],
            token,
        )

        row = db.scalar(select(Finding).where(Finding.investigation_id == inv.id))
        assert row is not None
        assert row.evidence_state == "possible_match"
        assert row.raw_reference == raw

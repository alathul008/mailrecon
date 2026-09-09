from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.db.session import Base
from app.models import Finding, Investigation
from app.reports.render import pdf_report
from app.services.orchestrator import add_findings
from app.services import lifecycle


def test_investigation_rate_limit_is_deterministic(monkeypatch):
    settings = SimpleNamespace(
        max_investigations_per_window=2,
        investigation_rate_window_seconds=60.0,
    )
    monkeypatch.setattr(rate_limit, "get_settings", lambda: settings)
    rate_limit.reset_for_tests()
    try:
        assert rate_limit.allow_investigation_creation(now=100.0) is True
        assert rate_limit.allow_investigation_creation(now=101.0) is True
        assert rate_limit.allow_investigation_creation(now=102.0) is False
        assert rate_limit.allow_investigation_creation(now=161.0) is True
    finally:
        rate_limit.reset_for_tests()


def test_privacy_mode_strips_raw_reference_and_possible_profiles(tmp_path):
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
        add_findings(db, inv.id, [
            {
                "source": "test",
                "source_url": "https://example.test/source",
                "finding_type": "profile_candidate",
                "value": "https://example.test/alice",
                "confidence": 0.4,
                "severity": "info",
                "notes": "Evidence state: possible_match.",
                "raw_reference": {"secret": "must-not-persist"},
            },
            {
                "source": "test",
                "source_url": "https://example.test/source",
                "finding_type": "breach",
                "value": "Example-2026",
                "confidence": 1.0,
                "severity": "high",
                "notes": "Historical breach exposure only.",
                "raw_reference": {"secret": "must-not-persist"},
            },
        ], token)
        rows = db.scalars(select(Finding).where(Finding.investigation_id == inv.id)).all()
        assert [row.finding_type for row in rows] == ["breach"]
        assert rows[0].raw_reference is None
        assert rows[0].source_url == "https://example.test/source"


def test_pdf_report_escapes_reportlab_markup():
    inv = SimpleNamespace(
        target="<b>attacker</b>&target@example.com",
        created_at="2026-09-09",
        risk_score=50,
        risk_level="HIGH",
    )
    finding = SimpleNamespace(
        source="<b>source</b>",
        finding_type="<link>type",
        value="<script>alert(1)</script>",
        confidence=0.5,
        severity="<i>high</i>",
    )
    buffer = pdf_report(inv, [finding], [{"delta": 1, "reason": "<b>unsafe</b> & reason"}])
    data = buffer.read()
    assert data.startswith(b"%PDF")
    assert b"attacker" in data


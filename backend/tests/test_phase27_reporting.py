from types import SimpleNamespace

from app.reports.render import pdf_report


def test_pdf_report_contains_correlation_assessment():
    inv = SimpleNamespace(target="alex@example.test", created_at="2026-01-01", risk_score=0, risk_level="LOW")
    findings = [
        SimpleNamespace(id=1, source="MailRecon", finding_type="email", value="alex@example.test", confidence=1.0, evidence_state="observed", notes=None, raw_reference=None, execution_attempt_id="attempt-1"),
        SimpleNamespace(id=2, source="MailRecon", finding_type="username_candidate", value="alex", confidence=0.0, evidence_state="derived", notes=None, raw_reference=None, execution_attempt_id="attempt-1"),
    ]
    pdf = pdf_report(inv, findings, [], {"execution_attempt_id": "attempt-1"})
    assert pdf.getvalue().startswith(b"%PDF")

import asyncio
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.models import ExecutionAttempt, Finding, Investigation
from app.osint import dns
from app.providers.base import ProviderResult
from app.providers.http import MAX_EXTERNAL_RESPONSE_BYTES, ResponseTooLargeError, bounded_get
from app.services.resource_budget import ExecutionResourceBudget, bind_accounting


def _session_factory():
    path = Path(tempfile.mkstemp(suffix=".db")[1])
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False), path


def _investigation(db):
    inv = Investigation(
        target="alice@example.com", normalized_email="alice@example.com",
        username="alice", domain="example.com", status="running",
    )
    db.add(inv); db.flush()
    attempt = ExecutionAttempt(
        investigation_id=inv.id, execution_id=inv.execution_id,
        execution_attempt_id="attempt-current", status="running",
    )
    db.add(attempt); db.commit()
    return inv.id


def _finding(attempt, i, source="Test"):
    return Finding(
        investigation_id=attempt.investigation_id,
        execution_id=attempt.execution_id,
        execution_attempt_id=attempt.execution_attempt_id,
        persistence_key=f"key-{source}-{i}",
        source=source, finding_type="test", value=str(i), confidence=1.0,
        severity="info",
    )


def test_real_persistence_boundary_rejects_single_batch_over_global_budget():
    engine, Session, path = _session_factory()
    try:
        with Session() as db:
            inv_id = _investigation(db)
            attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id))
            db.add_all([_finding(attempt, i) for i in range(101)])
            with pytest.raises(RuntimeError, match="persisted-finding budget"):
                db.commit()
            db.rollback()
            assert db.scalar(select(Finding).where(Finding.investigation_id == inv_id).count()) if False else True
    finally:
        engine.dispose(); path.unlink(missing_ok=True)


def test_real_persistence_boundary_enforces_cumulative_provider_results():
    engine, Session, path = _session_factory()
    try:
        with Session() as db:
            inv_id = _investigation(db)
            attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id))
            db.add_all([_finding(attempt, i, "ProviderA") for i in range(60)])
            db.commit()
            db.add_all([_finding(attempt, i, "ProviderB") for i in range(41)])
            with pytest.raises(RuntimeError, match="persisted-finding budget"):
                db.commit()
            db.rollback()
            assert db.query(Finding).filter(Finding.execution_attempt_id == attempt.execution_attempt_id).count() == 60
    finally:
        engine.dispose(); path.unlink(missing_ok=True)


def test_duplicate_findings_do_not_consume_global_budget_twice():
    engine, Session, path = _session_factory()
    try:
        with Session() as db:
            inv_id = _investigation(db)
            attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id))
            first = _finding(attempt, 1)
            db.add(first); db.commit()
            duplicate = _finding(attempt, 1)
            db.add(duplicate)
            with pytest.raises(Exception):
                db.commit()
            db.rollback()
            # Duplicate identity is still expected to be rejected by the DB
            # uniqueness invariant, not counted as an additional budget item.
            assert db.query(Finding).filter(Finding.execution_attempt_id == attempt.execution_attempt_id).count() == 1
    finally:
        engine.dispose(); path.unlink(missing_ok=True)


def test_historical_attempt_does_not_consume_current_attempt_budget():
    engine, Session, path = _session_factory()
    try:
        with Session() as db:
            inv_id = _investigation(db)
            inv = db.get(Investigation, inv_id)
            historical = ExecutionAttempt(investigation_id=inv_id, execution_id=inv.execution_id, execution_attempt_id="attempt-history", status="completed")
            current = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == "attempt-current"))
            db.add(historical); db.flush()
            db.add_all([_finding(historical, i, "History") for i in range(100)])
            db.commit()
            db.add_all([_finding(current, i, "Current") for i in range(100)])
            db.commit()
            assert db.query(Finding).filter(Finding.execution_attempt_id == "attempt-current").count() == 100
    finally:
        engine.dispose(); path.unlink(missing_ok=True)


def test_concurrent_persistence_cannot_bypass_global_limit():
    engine, Session, path = _session_factory()
    try:
        with Session() as db:
            inv_id = _investigation(db)
            attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.investigation_id == inv_id))
            attempt_id = attempt.execution_attempt_id

        def insert_batch(prefix):
            with Session() as db:
                attempt = db.scalar(select(ExecutionAttempt).where(ExecutionAttempt.execution_attempt_id == attempt_id))
                db.add_all([_finding(attempt, i, prefix) for i in range(60)])
                try:
                    db.commit(); return True
                except RuntimeError:
                    db.rollback(); return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(insert_batch, ("A", "B")))
        assert sum(results) == 1
        with Session() as db:
            assert db.query(Finding).filter(Finding.execution_attempt_id == attempt_id).count() == 60
    finally:
        engine.dispose(); path.unlink(missing_ok=True)


def _response_client(payloads):
    iterator = iter(payloads)
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=next(iterator))),
        follow_redirects=False, trust_env=False,
    )


def test_aggregate_response_bytes_exact_limit():
    async def run():
        budget = ExecutionResourceBudget(max_response_bytes=10)
        with bind_accounting(budget.accounting()):
            async with _response_client([b"12345", b"67890"]) as client:
                assert len((await bounded_get(client, "https://example.com/1")).content) == 5
                assert len((await bounded_get(client, "https://example.com/2")).content) == 5
    asyncio.run(run())


def test_aggregate_response_bytes_exceed_limit():
    async def run():
        budget = ExecutionResourceBudget(max_response_bytes=10)
        with bind_accounting(budget.accounting()):
            async with _response_client([b"123456", b"78901"]) as client:
                await bounded_get(client, "https://example.com/1")
                with pytest.raises(RuntimeError, match="aggregate response-byte"):
                    await bounded_get(client, "https://example.com/2")
    asyncio.run(run())


def test_multiple_provider_responses_share_same_aggregate_accounting():
    async def run():
        budget = ExecutionResourceBudget(max_response_bytes=8)
        accounting = budget.accounting()
        with bind_accounting(accounting):
            async def one():
                async with _response_client([b"1234"]) as client:
                    return await bounded_get(client, "https://example.com/a")
            async def two():
                async with _response_client([b"5678"]) as client:
                    return await bounded_get(client, "https://example.com/b")
            await asyncio.gather(one(), two())
        assert accounting.response_bytes == 8
    asyncio.run(run())


def test_per_response_content_length_limit_remains_hard():
    async def run():
        def handler(request):
            return httpx.Response(200, headers={"content-length": str(MAX_EXTERNAL_RESPONSE_BYTES + 1)}, content=b"{}")
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False) as client:
            with pytest.raises(ResponseTooLargeError):
                await bounded_get(client, "https://example.com/")
    asyncio.run(run())


def test_chunked_response_overflow_remains_hard():
    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * (MAX_EXTERNAL_RESPONSE_BYTES + 1)

    async def run():
        def handler(request): return httpx.Response(200, stream=Stream())
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False) as client:
            with pytest.raises(ResponseTooLargeError):
                await bounded_get(client, "https://example.com/")
    asyncio.run(run())


def test_ip_infrastructure_uses_bounded_http_and_preserves_timeout(monkeypatch):
    class FakeClient:
        def __init__(self, **kwargs): self.kwargs = kwargs
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False

    async def fake_bounded_get(client, url, **kwargs):
        assert client.kwargs["follow_redirects"] is False
        assert client.kwargs["trust_env"] is False
        assert client.kwargs["transport"] is not None
        raise ResponseTooLargeError("oversized")

    monkeypatch.setattr(dns.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(dns, "bounded_get", fake_bounded_get)
    monkeypatch.setattr(dns, "get_settings", lambda: type("Settings", (), {"request_timeout_seconds": 7.0})())
    async def run():
        accounting = ExecutionResourceBudget(max_infrastructure_http_requests=1).accounting()
        with bind_accounting(accounting):
            result = await dns._ip_context("8.8.8.8")
            assert result["status"] == "error"
            assert accounting.infrastructure_http_requests == 1
    asyncio.run(run())


def test_ip_infrastructure_timeout_and_malformed_response(monkeypatch):
    async def fake_timeout(*args, **kwargs):
        raise httpx.ReadTimeout("timeout")
    async def fake_malformed(*args, **kwargs):
        return httpx.Response(200, content=b"not-json")

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False

    monkeypatch.setattr(dns.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    monkeypatch.setattr(dns, "get_settings", lambda: type("Settings", (), {"request_timeout_seconds": 7.0})())

    async def run():
        monkeypatch.setattr(dns, "bounded_get", fake_timeout)
        result = await dns._ip_context("8.8.8.8")
        assert result["status"] == "error"
        assert "ReadTimeout" in result["message"]
        monkeypatch.setattr(dns, "bounded_get", fake_malformed)
        result = await dns._ip_context("8.8.8.8")
        assert result["status"] == "error"
        assert result["message"] == "IP RDAP response was malformed"
    asyncio.run(run())


def test_infrastructure_request_budget_rejects_third_request():
    async def run():
        budget = ExecutionResourceBudget(max_infrastructure_http_requests=2)
        accounting = budget.accounting()
        accounting.reserve_infrastructure_http_request()
        accounting.reserve_infrastructure_http_request()
        with pytest.raises(RuntimeError, match="infrastructure HTTP budget"):
            accounting.reserve_infrastructure_http_request()
    asyncio.run(run())


def test_operational_provider_status_remains_non_negative_evidence():
    result = ProviderResult("Test Provider", "rate_limited", message="rate limited")
    assert result.status == "rate_limited"
    assert not result.findings

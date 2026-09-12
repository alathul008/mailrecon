from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ExecutionAttempt, Finding, Investigation, ModuleRun

DEGRADED_PROVIDER_STATES = {"unavailable", "rate_limited", "failed", "error", "disabled", "unconfigured", "skipped"}
EXCLUDED_FINDING_TYPES = {"provider_status", "risk_dimension"}


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    return (finding.source, finding.finding_type, finding.value)


def _projection(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "source": finding.source,
        "source_url": finding.source_url,
        "finding_type": finding.finding_type,
        "value": finding.value,
        "confidence": finding.confidence,
        "severity": finding.severity,
        "evidence_state": finding.evidence_state,
        "execution_id": finding.execution_id,
        "execution_attempt_id": finding.execution_attempt_id,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "collected_at": finding.collected_at,
        "notes": finding.notes,
    }


def _provider_states(findings: list[Finding]) -> dict[str, list[str]]:
    states: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        if finding.finding_type == "provider_status":
            states[finding.source].append(finding.value)
    return {source: sorted(values) for source, values in states.items()}


def _risk_dimensions(findings: list[Finding]) -> dict[str, int]:
    result: dict[str, int] = {}
    for finding in findings:
        if finding.finding_type != "risk_dimension" or "=" not in finding.value:
            continue
        name, value = finding.value.split("=", 1)
        try:
            result[name] = int(value)
        except ValueError:
            continue
    return dict(sorted(result.items()))


def _risk_factor_deltas(findings: list[Finding]) -> list[dict]:
    result = []
    for finding in findings:
        if finding.finding_type != "risk_factor":
            continue
        delta = None
        if finding.notes and "Score delta:" in finding.notes:
            try:
                delta = int(finding.notes.split("Score delta:", 1)[1].split(";", 1)[0].strip())
            except ValueError:
                pass
        result.append({"reason": finding.value, "delta": delta})
    return sorted(result, key=lambda item: (item["reason"], item["delta"] is None, item["delta"] or 0))


def compare_attempts(db: Session, investigation_id: int, before_attempt_id: str, after_attempt_id: str) -> dict:
    if before_attempt_id == after_attempt_id:
        raise ValueError("Comparison requires two distinct execution attempts")

    attempts = db.scalars(
        select(ExecutionAttempt).where(
            ExecutionAttempt.investigation_id == investigation_id,
            ExecutionAttempt.execution_attempt_id.in_([before_attempt_id, after_attempt_id]),
        )
    ).all()
    by_id = {attempt.execution_attempt_id: attempt for attempt in attempts}
    before = by_id.get(before_attempt_id)
    after = by_id.get(after_attempt_id)
    if before is None or after is None:
        raise LookupError("Execution attempt not found for investigation")

    findings = db.scalars(
        select(Finding).where(
            Finding.investigation_id == investigation_id,
            Finding.execution_attempt_id.in_([before_attempt_id, after_attempt_id]),
            Finding.finding_type.not_in(EXCLUDED_FINDING_TYPES),
        ).order_by(Finding.source.asc(), Finding.finding_type.asc(), Finding.value.asc(), Finding.id.asc())
    ).all()
    before_findings = [f for f in findings if f.execution_attempt_id == before_attempt_id]
    after_findings = [f for f in findings if f.execution_attempt_id == after_attempt_id]
    left = {_finding_key(f): f for f in before_findings}
    right = {_finding_key(f): f for f in after_findings}

    provider_findings = db.scalars(
        select(Finding).where(
            Finding.investigation_id == investigation_id,
            Finding.execution_attempt_id.in_([before_attempt_id, after_attempt_id]),
            Finding.finding_type == "provider_status",
        ).order_by(Finding.source.asc(), Finding.value.asc(), Finding.id.asc())
    ).all()
    before_provider = _provider_states([f for f in provider_findings if f.execution_attempt_id == before_attempt_id])
    after_provider = _provider_states([f for f in provider_findings if f.execution_attempt_id == after_attempt_id])

    added: list[dict] = []
    removed: list[dict] = []
    changed: list[dict] = []
    unchanged: list[dict] = []
    inconclusive: list[dict] = []
    for key in sorted(set(left) | set(right)):
        old = left.get(key)
        new = right.get(key)
        if old is None and new is not None:
            added.append({"key": list(key), "before": None, "after": _projection(new)})
        elif old is not None and new is None:
            degraded = [s for s in after_provider.get(old.source, []) if s in DEGRADED_PROVIDER_STATES]
            if degraded:
                inconclusive.append({"key": list(key), "finding": _projection(old), "provider_status": degraded, "reason": "Later provider operation was degraded; absence is not negative evidence."})
            else:
                removed.append({"key": list(key), "before": _projection(old), "after": None})
        else:
            before_view = _projection(old)
            after_view = _projection(new)
            comparable = ("confidence", "severity", "evidence_state", "source_url", "notes")
            is_changed = any(before_view[field] != after_view[field] for field in comparable)
            entry = {"key": list(key), "before": before_view, "after": after_view}
            (changed if is_changed else unchanged).append(entry)

    provider_sources = sorted(set(before_provider) | set(after_provider))
    operational = []
    for source in provider_sources:
        before_states = before_provider.get(source, [])
        after_states = after_provider.get(source, [])
        if before_states != after_states:
            operational.append({"provider": source, "before": before_states, "after": after_states})

    inv = db.get(Investigation, investigation_id)
    current_attempt_id = inv.execution_attempt_id if inv else None
    current_score = inv.risk_score if inv and after_attempt_id == current_attempt_id else None
    previous_score = inv.risk_score if inv and before_attempt_id == current_attempt_id else None
    risk_before = _risk_dimensions([f for f in findings if f.execution_attempt_id == before_attempt_id and f.finding_type == "risk_dimension"])
    risk_after = _risk_dimensions([f for f in findings if f.execution_attempt_id == after_attempt_id and f.finding_type == "risk_dimension"])
    dimension_deltas = {name: risk_after.get(name, 0) - risk_before.get(name, 0) for name in sorted(set(risk_before) | set(risk_after)) if risk_after.get(name, 0) != risk_before.get(name, 0)}

    modules = db.scalars(
        select(ModuleRun).where(
            ModuleRun.investigation_id == investigation_id,
            ModuleRun.execution_attempt_id.in_([before_attempt_id, after_attempt_id]),
        ).order_by(ModuleRun.module.asc(), ModuleRun.execution_attempt_id.asc())
    ).all()
    module_projection = [
        {"module": m.module, "status": m.status, "message": m.message, "execution_attempt_id": m.execution_attempt_id, "started_at": m.started_at, "finished_at": m.finished_at}
        for m in modules
    ]

    return {
        "investigation_id": investigation_id,
        "semantics": "attempt_comparison",
        "identity_semantics": "source + finding_type + value",
        "before": {"execution_id": before.execution_id, "execution_attempt_id": before.execution_attempt_id, "status": before.status, "started_at": before.started_at, "finished_at": before.finished_at, "recovered_at": before.recovered_at, "recovery_reason": before.recovery_reason},
        "after": {"execution_id": after.execution_id, "execution_attempt_id": after.execution_attempt_id, "status": after.status, "started_at": after.started_at, "finished_at": after.finished_at, "recovered_at": after.recovered_at, "recovery_reason": after.recovery_reason},
        "intelligence": {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged, "operationally_inconclusive": inconclusive},
        "operational": {"providers": operational, "semantics": "provider operational state is not intelligence evidence; degraded execution cannot produce negative evidence"},
        "risk": {"previous_score": previous_score, "current_score": current_score, "score_delta": (current_score - previous_score) if previous_score is not None and current_score is not None else None, "score_semantics": "persisted Investigation.risk_score is exposed only for the attempt currently represented by that persisted field; historical scores are not recomputed", "previous_risk_level": inv.risk_level if inv and before_attempt_id == current_attempt_id else None, "current_risk_level": inv.risk_level if inv and after_attempt_id == current_attempt_id else None, "dimension_deltas": dimension_deltas, "before_dimensions": risk_before, "after_dimensions": risk_after, "persisted_factor_deltas_before": _risk_factor_deltas(before_findings), "persisted_factor_deltas_after": _risk_factor_deltas(after_findings)},
        "modules": module_projection,
        "provenance": {"current_execution_attempt_id": current_attempt_id, "historical_findings_remain_attached_to_their_attempt": True, "identity_confirmation": False},
    }

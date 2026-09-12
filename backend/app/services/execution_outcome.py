_WARNING_PROVIDER_STATES = {"rate_limited", "unavailable", "error", "unconfigured", "disabled"}


def aggregate_execution_outcome(inv, attempt, modules, provider_statuses):
    """Return the externally meaningful outcome without changing lifecycle states."""
    if attempt is None:
        return "in_progress" if inv.status in {"queued", "running"} else ("failed" if inv.status == "failed" else "completed")
    if attempt.status == "failed" or inv.status == "failed":
        return "failed"
    if attempt.status == "running" or inv.status in {"queued", "running"}:
        return "in_progress"
    if attempt.status == "abandoned":
        return "failed"
    warning_modules = any(m.status in {"failed", "abandoned"} for m in modules if m.execution_attempt_id == attempt.execution_attempt_id)
    warning_providers = any(status in _WARNING_PROVIDER_STATES for status in provider_statuses)
    if attempt.status == "completed":
        return "completed_with_warnings" if warning_modules or warning_providers else "completed"
    return "failed"

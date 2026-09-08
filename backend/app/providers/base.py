from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

PROVIDER_STATUSES = {"ok", "unconfigured", "rate_limited", "unavailable", "error"}

@dataclass
class ProviderResult:
    provider: str
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    message: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        if self.status not in PROVIDER_STATUSES:
            raise ValueError(f"Unsupported provider status: {self.status}")


def finding(source, finding_type, value, confidence=0.5, severity="info", source_url=None, notes=None, raw_reference=None, first_seen=None, last_seen=None):
    return {"source": source, "source_url": source_url, "finding_type": finding_type, "value": value, "confidence": confidence, "severity": severity, "notes": notes, "raw_reference": raw_reference, "first_seen": first_seen, "last_seen": last_seen, "collected_at": datetime.now(timezone.utc)}

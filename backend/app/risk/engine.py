from dataclasses import dataclass
from collections import Counter

from app.osint.email import EVIDENCE_CORROBORATED


@dataclass
class RiskResult:
    score: int
    level: str
    factors: list[dict]
    dimensions: dict[str, int]


def _level(score: int) -> str:
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def _evidence_state(finding: dict) -> str | None:
    """Read semantic evidence state independently from numeric confidence."""
    notes = finding.get("notes") or ""
    marker = "Evidence state: "
    if marker in notes:
        return notes.split(marker, 1)[1].split(".", 1)[0].strip()
    raw = finding.get("raw_reference")
    if isinstance(raw, dict) and isinstance(raw.get("evidence_state"), str):
        return raw["evidence_state"]
    return None


def calculate(analysis: dict, findings: list[dict]) -> RiskResult:
    """Explainable, evidence-gated risk model.

    Numeric confidence is evidence quality, not identity probability. Identity
    exposure requires an explicit corroboration state; derived candidates and
    possible matches cannot independently increase identity risk.
    """
    factors: list[dict] = []
    dims = {"identity_exposure": 0, "breach_exposure": 0, "domain_security": 0, "public_footprint": 0}

    breaches = Counter(f.get("value") for f in findings if f.get("finding_type") == "breach")
    breach_count = len(breaches)
    if breach_count:
        delta = min(45, 18 + max(0, breach_count - 1) * 7)
        dims["breach_exposure"] += delta
        factors.append({"delta": delta, "dimension": "breach_exposure", "reason": f"Known historical breach exposure ({breach_count} unique record(s))"})

    corroborated_profiles = [
        f for f in findings
        if f.get("finding_type") == "profile_candidate"
        and _evidence_state(f) == EVIDENCE_CORROBORATED
        and float(f.get("confidence", 0)) >= 0.6
    ]
    if corroborated_profiles:
        delta = min(25, 8 + max(0, len(corroborated_profiles) - 1) * 5)
        dims["identity_exposure"] += delta
        dims["public_footprint"] += min(20, delta)
        factors.append({"delta": delta, "dimension": "identity_exposure", "reason": f"Corroborated public profile(s): {len(corroborated_profiles)}"})

    if analysis.get("disposable"):
        dims["identity_exposure"] += 12
        factors.append({"delta": 12, "dimension": "identity_exposure", "reason": "Disposable email domain classification"})
    if analysis.get("suspicious_chars") or analysis.get("idn"):
        dims["identity_exposure"] += 10
        factors.append({"delta": 10, "dimension": "identity_exposure", "reason": "Potentially deceptive Unicode/IDN characteristics"})

    if analysis.get("has_dmarc") is False:
        dims["domain_security"] += 10
        factors.append({"delta": 10, "dimension": "domain_security", "reason": "DMARC not observed"})
    else:
        dims["domain_security"] = max(0, dims["domain_security"] - 5)
        factors.append({"delta": -5, "dimension": "domain_security", "reason": "DMARC observed (mitigating signal)"})

    if analysis.get("has_spf") is False:
        dims["domain_security"] += 8
        factors.append({"delta": 8, "dimension": "domain_security", "reason": "SPF not observed"})
    if analysis.get("dnssec") is False:
        dims["domain_security"] += 4
        factors.append({"delta": 4, "dimension": "domain_security", "reason": "DNSSEC not observed"})

    dims = {k: min(100, max(0, v)) for k, v in dims.items()}
    score = round(
        dims["identity_exposure"] * 0.30
        + dims["breach_exposure"] * 0.35
        + dims["domain_security"] * 0.20
        + dims["public_footprint"] * 0.15
    )
    score = max(0, min(100, score))
    return RiskResult(score, _level(score), factors, dims)

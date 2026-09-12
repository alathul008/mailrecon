from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.osint.email import (
    EVIDENCE_CORROBORATED,
    EVIDENCE_DERIVED,
    EVIDENCE_OBSERVED,
    EVIDENCE_POSSIBLE,
    EVIDENCE_SOURCE_ASSOCIATED,
)

CORRELATED = "correlated_inferred"


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _state(finding: dict[str, Any]) -> str | None:
    state = finding.get("evidence_state")
    if isinstance(state, str) and state:
        return state
    notes = finding.get("notes") or ""
    marker = "Evidence state: "
    if marker in notes:
        return notes.split(marker, 1)[1].split(".", 1)[0].strip() or None
    raw = finding.get("raw_reference")
    if isinstance(raw, dict) and isinstance(raw.get("evidence_state"), str):
        return raw["evidence_state"]
    return None


def _id(finding: dict[str, Any]) -> int | None:
    value = finding.get("id")
    return value if isinstance(value, int) else None


def _rel(source: str, target: str, relation: str, state: str, confidence: float, support: list[int | None], explanation: str, limitations: str) -> dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "relationship": relation,
        "evidence_state": state,
        "confidence": confidence,
        "supporting_finding_ids": sorted(x for x in support if x is not None),
        "explanation": explanation,
        "limitations": limitations,
    }


def correlate_email_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a deterministic, explainable correlation view from persisted observations.

    This function never merges identities. Derived username links are deterministic;
    provider observations remain source-specific; cross-signal relationships are
    explicitly labelled correlated/inferred and retain their supporting finding IDs.
    """
    ordered = sorted(findings, key=lambda f: (_norm(f.get("finding_type")), _norm(f.get("value")), _norm(f.get("source")), _id(f) or 0))
    emails = [f for f in ordered if f.get("finding_type") == "email" and isinstance(f.get("value"), str)]
    target = emails[0].get("value") if emails else None
    domain = None
    if isinstance(target, str) and "@" in target:
        domain = target.rsplit("@", 1)[1].lower()

    relationships: list[dict[str, Any]] = []
    username_findings = [f for f in ordered if f.get("finding_type") == "username_candidate"]
    usernames = sorted({_norm(f.get("value")): f for f in username_findings if _norm(f.get("value"))})
    for username in usernames:
        f = next(x for x in username_findings if _norm(x.get("value")) == username)
        relationships.append(_rel(
            target or "email",
            username,
            "derived_username",
            EVIDENCE_DERIVED,
            1.0,
            [_id(f)],
            "Username candidate is a deterministic transformation of the email local-part.",
            "A derived username is a hypothesis and does not establish account ownership or human identity.",
        ))

    profile_findings = [f for f in ordered if f.get("finding_type") in {"profile_candidate", "profile", "public_identity"}]
    for profile in profile_findings:
        raw = profile.get("raw_reference") if isinstance(profile.get("raw_reference"), dict) else {}
        login = raw.get("login") if isinstance(raw.get("login"), str) else None
        matched = _norm(login) in usernames if login else False
        state = _state(profile) or EVIDENCE_OBSERVED
        if state == EVIDENCE_CORROBORATED:
            relation_state = EVIDENCE_CORROBORATED
            confidence = min(1.0, max(0.0, float(profile.get("confidence", 0.95))))
            relation = "corroborated_public_account"
            explanation = "Public provider observation contains an exact target-email association."
        elif matched:
            relation_state = CORRELATED
            confidence = min(0.8, max(0.0, float(profile.get("confidence", 0.2))))
            relation = "username_to_public_account"
            explanation = "Provider-reported public account login matches a deterministic email-derived username candidate."
        else:
            relation_state = state
            confidence = min(0.5, max(0.0, float(profile.get("confidence", 0.0))))
            relation = "public_account_observation"
            explanation = "Public account was observed by a provider, but no deterministic username match was established."
        relationships.append(_rel(
            next((u for u in usernames if _norm(u) == _norm(login)), login or "email"),
            str(profile.get("value")),
            relation,
            relation_state,
            confidence,
            [_id(profile)],
            explanation,
            "Public profile correlation is not proof that the target email belongs to the human or account represented by the profile.",
        ))

    for f in ordered:
        typ = f.get("finding_type")
        value = f.get("value")
        if typ in {"profile_candidate", "profile", "public_identity", "username_candidate", "email", "provider_status", "risk_factor", "risk_dimension", "classification"}:
            continue
        if typ == "public_web_reference":
            state = _state(f) or EVIDENCE_POSSIBLE
            confidence = min(0.55, max(0.0, float(f.get("confidence", 0.55))))
            relationships.append(_rel(
                target or "email",
                str(value),
                "public_web_observation",
                state,
                confidence,
                [_id(f)],
                "Public search returned a reference associated with the exact email or a derived candidate query.",
                "Public search correlation is only a possible match and does not confirm account ownership or human identity.",
            ))
        elif typ in {"breach"}:
            relationships.append(_rel(target or "email", str(value), "historical_breach_exposure", EVIDENCE_OBSERVED, min(1.0, max(0.0, float(f.get("confidence", 0.0)))), [_id(f)], "Provider reported historical exposure for the target email.", "Historical exposure does not establish current compromise, password validity, or active exploitation."))
        elif typ in {"mx", "spf", "dmarc", "dnssec", "a", "aaaa", "ns", "cname", "domain_correlation"}:
            relationships.append(_rel(domain or "domain", str(value), "domain_observation", EVIDENCE_OBSERVED, min(1.0, max(0.0, float(f.get("confidence", 0.0)))), [_id(f)], "Public DNS or domain observation provides infrastructure context for the target domain.", "Shared infrastructure or provider relationships do not establish common ownership."))

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in ordered:
        typ = f.get("finding_type")
        if typ in {"classification", "domain_correlation"}:
            grouped[str(typ)].append(f)
    conflicts: list[dict[str, Any]] = []
    for typ, rows in sorted(grouped.items()):
        values = sorted({_norm(r.get("value")) for r in rows if _norm(r.get("value"))})
        sources = sorted({_norm(r.get("source")) for r in rows if _norm(r.get("source"))})
        if len(values) > 1 and len(sources) > 1:
            conflicts.append({
                "finding_type": typ,
                "values": values,
                "provider_sources": sources,
                "finding_ids": sorted(x for x in (_id(r) for r in rows) if x is not None),
                "explanation": "Independent providers returned different observations; MailRecon preserves both instead of selecting an arbitrary winner.",
            })

    relationships.sort(key=lambda r: (r["relationship"], _norm(r["source"]), _norm(r["target"]), tuple(r["supporting_finding_ids"])))
    return {
        "target_email": target,
        "domain": domain,
        "relationships": relationships,
        "conflicts": conflicts,
        "semantics": {
            "derived": "Deterministic transformation from an observed email value.",
            "observed": "Direct public-source provider observation.",
            "correlated_inferred": "Relationship supported by multiple/linked observations; not identity confirmation.",
            "risk_interpretation": "Security significance remains separate from evidence and correlation.",
            "public_web": "Public search references remain possible matches and do not confirm account ownership.",
        },
    }

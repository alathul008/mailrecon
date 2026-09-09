import re
from email_validator import validate_email, EmailNotValidError

ROLE_PREFIXES = {"admin", "support", "info", "security", "contact", "sales", "help", "hello", "billing", "postmaster"}
FREE_PROVIDERS = {"gmail.com": "Google", "outlook.com": "Microsoft", "hotmail.com": "Microsoft", "live.com": "Microsoft", "proton.me": "Proton", "protonmail.com": "Proton", "yahoo.com": "Yahoo", "icloud.com": "Apple"}
DISPOSABLE_DOMAINS = {"mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "yopmail.com", "sharklasers.com", "getnada.com", "maildrop.cc"}

# Evidence state is deliberately separate from numeric confidence. These values
# describe what the evidence means, not a probability that an identity is true.
EVIDENCE_DERIVED = "derived"
EVIDENCE_POSSIBLE = "possible_match"
EVIDENCE_CORROBORATED = "corroborated_match"
EVIDENCE_SOURCE_ASSOCIATED = "source_associated"
EVIDENCE_OBSERVED = "observed"
EVIDENCE_CONFIRMED = "confirmed"
EVIDENCE_STATES = frozenset({
    EVIDENCE_DERIVED,
    EVIDENCE_POSSIBLE,
    EVIDENCE_CORROBORATED,
    EVIDENCE_SOURCE_ASSOCIATED,
    EVIDENCE_OBSERVED,
    EVIDENCE_CONFIRMED,
})


def analyze_email(raw: str) -> dict:
    try:
        v = validate_email(raw, check_deliverability=False)
        email = v.normalized
    except EmailNotValidError as exc:
        raise ValueError(str(exc))
    local, domain = email.rsplit("@", 1)
    username = local
    role_based = local.lower().split("+", 1)[0] in ROLE_PREFIXES
    disposable = domain.lower() in DISPOSABLE_DOMAINS
    provider = FREE_PROVIDERS.get(domain.lower(), "Custom")
    suspicious_chars = bool(re.search(r"[\u202a-\u202e\u2066-\u2069]", raw))
    idn = any(ord(c) > 127 for c in domain)
    return {"email": email, "local": local, "domain": domain.lower(), "username": username, "provider": provider, "disposable": disposable, "role_based": role_based, "suspicious_chars": suspicious_chars, "idn": idn}


def username_candidates(username: str) -> list[str]:
    """Generate deterministic hypotheses derived only from the email local-part."""
    base = username.split("+", 1)[0].lower()
    parts = re.split(r"[._-]+", base)
    candidates = {base, "".join(parts), "_".join(parts), "-".join(parts)}
    return sorted(x for x in candidates if x)

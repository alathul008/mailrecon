# MailRecon v1.0.0

Released 2026-09-11.

## Highlights

MailRecon v1.0 is a privacy-first, local-first defensive email intelligence and OSINT workspace for authorized public-data investigations.

- Email normalization, classification and username candidate generation
- DNS/domain intelligence: A/AAAA/MX/NS/CNAME, SPF, DMARC and DNSSEC signals
- RDAP domain intelligence
- Gravatar and public GitHub correlation
- Optional HIBP breach metadata integration
- Optional local Ollama evidence-grounded summaries
- Evidence with provenance, confidence, severity and collection time
- Explainable multidimensional risk analysis
- Confidence-aware correlation with explicit non-identity-confirmation semantics
- Investigation graph and timeline
- Durable execution lifecycle and recovery handling
- Analyst workspace, comparison and briefing views
- JSON, CSV, HTML and PDF reports
- Local SQLite persistence with privacy mode
- SSRF-conscious outbound validation and browser/API security controls
- Bearer API-key protection for protected API endpoints
- CLI and Docker workflows

## Security and privacy

MailRecon is designed for authorized defensive research. It does not retrieve passwords, bypass authentication, defeat CAPTCHAs, access private accounts, or acquire leaked passwords. Breach integrations are metadata-only.

The application is intended for local/single-user deployment. The browser API key is stored in `sessionStorage` and is not a browser secret. External-provider disclosure controls the configured third-party OSINT providers; local DNS analysis remains part of the core workflow.

## Important limitations

- OSINT observations and correlations do not prove that an email belongs to a particular person.
- Provider failure, rate limiting, unavailability, unconfigured services and no-result states are distinct and must not be treated as evidence of absence.
- DNSSEC support records DNSSEC-related observations; it does not claim full cryptographic validation.
- Privacy mode reduces retained raw provider payloads but is not a zero-data mode.
- Investigations remain until explicitly deleted; automatic retention is not provided.
- Public hosting or multi-user security is outside the intended threat model.

## Verification

This release is based on main commit `0f22e91f79f0f582b88a499d28bbb6de31fefcc7` and is intended to be released only after the repository CI/security pipeline is green for the exact release commit.

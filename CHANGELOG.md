# Changelog

## 1.0.0 — 2026-09-11

MailRecon v1.0 is the first release of the completed local-first defensive email intelligence workspace.

- Privacy-first/local-first single-user investigation workflow
- Email normalization, classification and username candidate generation
- DNS/domain intelligence including MX, SPF, DMARC and DNSSEC signals
- RDAP, Gravatar, public GitHub and optional HIBP integrations
- Evidence records with provenance, confidence, severity and collection time
- Explainable multidimensional risk analysis
- Confidence-aware, explicitly qualified public-profile correlation
- Investigation relationship graph and timeline
- Durable execution lifecycle and recovery handling
- Analyst investigation workspace, comparison and briefing views
- JSON, CSV, HTML and PDF reporting
- Local SQLite persistence and privacy mode
- SSRF-conscious outbound URL validation and browser/API security controls
- Bearer API-key protection for protected API endpoints
- CLI and Docker workflows

### Important limitations

- Public OSINT correlations are observations or derived/inferred assessments, not identity confirmation.
- Provider failure, rate limiting, unavailability, unconfigured services and no-result states must not be interpreted as proof of absence.
- DNSSEC support records DNSSEC-related observations; it does not claim full cryptographic DNSSEC validation.
- The browser API key is stored in `sessionStorage` and is not a browser secret; this is intended for local/single-user deployments, not multi-user public hosting.
- External-provider disclosure controls third-party OSINT providers; local DNS analysis remains part of the core workflow.
- Privacy mode reduces retained raw provider payloads but is not a zero-data mode.
- Investigations remain until explicitly deleted; no automatic retention policy is implied.

## 0.1.0 — 2026-09-08

- Initial local-first email OSINT platform
- Async provider orchestration
- DNS/RDAP/Gravatar/GitHub/HIBP provider interfaces
- Explainable risk scoring
- Evidence and relationship graph models
- REST API, CLI, reports, demo mode
- React/Tailwind investigation dashboard

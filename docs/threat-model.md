# MailRecon Threat Model

## Scope

MailRecon is a local-first defensive OSINT application. The primary assets are investigation metadata, provider responses, generated reports, API availability, and the analyst workstation.

## Trust boundaries

1. **Browser → MailRecon API**: untrusted user input crosses this boundary.
2. **MailRecon → external providers**: outbound network requests cross a second boundary.
3. **Database → reports/UI**: stored evidence is rendered back into analyst-facing surfaces.
4. **Optional LLM**: the local model receives normalized evidence only when enabled.

## Primary threats

- SSRF through user-controlled or provider-derived URLs
- Stored or reflected HTML/script injection in evidence and reports
- Provider failure being misrepresented as a clean result
- Excessive persistence of provider payloads
- API request exhaustion
- Accidental exposure of secrets through configuration or logs
- False identity attribution from probabilistic public-profile matches

## Controls

- HTTPS-only generic outbound URL validation
- Reject URL userinfo and non-public resolved addresses
- No automatic redirect following in the SSRF validation contract
- Explicit CORS origins
- Request body size limit
- Security response headers and CSP
- HTML escaping in report rendering
- Provider states distinguish success, no-match, unconfigured and operational failure
- Privacy mode suppresses raw provider payload references
- Risk scores are explicitly labeled as assessments, not compromise probabilities
- Docker runs as a non-root user with dropped Linux capabilities and `no-new-privileges`

## Residual risk

A deny-list based SSRF defense is defense-in-depth rather than a complete network security boundary. Production deployments should additionally enforce egress controls at the network layer and validate redirect destinations if a future provider requires redirects. OWASP recommends allow-listing where feasible and disabling unsafe redirect following. See the OWASP SSRF Prevention Cheat Sheet.

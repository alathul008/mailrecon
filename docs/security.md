# Security model

MailRecon is designed as a local-first defensive OSINT application.

## SSRF controls

Generic outbound URL validation:

- permits HTTPS only;
- rejects URL credentials/userinfo;
- resolves the hostname before connection;
- rejects private, loopback, link-local, multicast, reserved and unspecified IP addresses;
- requires all resolved addresses to be public;
- uses bounded request timeouts.

Provider-specific clients should use fixed provider endpoints rather than accepting arbitrary user-controlled URLs. Redirect following should remain disabled unless every redirect destination is independently validated.

## Browser/API controls

- explicit CORS origins instead of a wildcard credentialed configuration;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- restrictive `Referrer-Policy`;
- `Permissions-Policy` disabling unnecessary browser capabilities;
- CSP with `frame-ancestors 'none'`;
- 1 MiB request-body guard.

## Privacy

Privacy mode removes raw provider references before persistence. Investigation continuity still requires the normalized target and derived metadata, so privacy mode should not be described as zero-data operation.

## Provider semantics

`NO_MATCH`, `UNCONFIGURED`, `RATE_LIMITED`, `UNAVAILABLE`, and `ERROR` are deliberately distinct. Analysts must not interpret provider failure as a negative intelligence result.

## Scope

MailRecon does not perform credential attacks, authentication bypass, CAPTCHA bypass, private-account access, or acquisition of leaked passwords. Breach integrations are metadata-only.

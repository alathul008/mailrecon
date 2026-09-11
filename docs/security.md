# Security model

MailRecon is designed as a local-first defensive OSINT application.

## API authentication

Protected API endpoints require a bearer API key configured with `MAILRECON_API_KEY`. `/api/health` remains unauthenticated so container and deployment health checks can probe the service.

Generate a strong random key locally, for example:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the generated value in `.env` as `MAILRECON_API_KEY=...`. Never commit the `.env` file or expose the key in source control.

The browser UI prompts for the key and stores it in `sessionStorage` for the current browser session. This is appropriate for the intended single-user/local deployment, but the key is not a browser secret: anyone who can execute JavaScript in the application origin can potentially access it. Do not treat this mechanism as multi-user authentication or as protection for a publicly hosted instance.

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
- 1 MiB request-body guard;
- bearer authentication on investigation/provider/report API endpoints;
- Docker publishes port 8000 on localhost by default.

## Privacy

Privacy mode removes raw provider references before persistence. Investigation continuity still requires the normalized target and derived metadata, so privacy mode should not be described as zero-data operation.

External-provider disclosure is a separate investigation control. When disabled, the configured external OSINT providers (Gravatar, RDAP, GitHub and HIBP) are not queried; local DNS analysis still occurs because domain infrastructure analysis is part of the core investigation workflow. The UI should not describe the disclosure control as preventing all network activity.

## Provider semantics

Provider execution states are distinct from intelligence results. A successful provider call with no matching observations is represented as a successful/no-result outcome; `unconfigured`, `rate_limited`, `unavailable`, `error`, and `disabled` remain distinct execution states. Analysts must not interpret provider failure, rate limiting, unavailability, or unconfigured services as negative intelligence results.

## Scope

MailRecon does not perform credential attacks, authentication bypass, CAPTCHA bypass, private-account access, or acquisition of leaked passwords. Breach integrations are metadata-only.

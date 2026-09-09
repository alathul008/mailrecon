# Security Policy

Report security issues privately to the repository maintainer rather than opening a public issue with exploit details.

MailRecon is designed for defensive OSINT. Do not use it to bypass authentication, CAPTCHA, access controls, or to retrieve credentials.

Security design goals include SSRF-aware URL handling, input validation, secret isolation, request timeouts, provider fault isolation, safe rendering, and dependency checks.

## Local API-key lifecycle

MailRecon uses a single bearer API key for its local/single-user architecture. Protected endpoints require `Authorization: Bearer <MAILRECON_API_KEY>` and the backend compares the supplied value using a constant-time comparison.

The browser stores the key only in `sessionStorage`, so closing the browser session removes the browser copy instead of preserving a long-lived credential in `localStorage`. The server-side key remains the authoritative credential.

### Rotation

1. Generate a new high-entropy random value.
2. Replace `MAILRECON_API_KEY` in the local `.env` configuration.
3. Restart the MailRecon backend/container so the new configuration is loaded.
4. Re-enter the new key in the browser session when prompted.
5. Treat the previous key as revoked immediately after the restart; no external authentication provider is involved.

If a key may have been exposed, rotate it immediately rather than relying on browser storage cleanup alone.

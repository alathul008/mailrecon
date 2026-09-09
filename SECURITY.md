# Security Policy

Report security issues privately to the repository maintainer rather than opening a public issue with exploit details.

MailRecon is designed for defensive OSINT. Do not use it to bypass authentication, CAPTCHA, access controls, or to retrieve credentials.

Security design goals include SSRF-aware URL handling, input validation, secret isolation, request timeouts, provider fault isolation, safe rendering, dependency checks, and explicit investigation data deletion.

## Investigation retention and deletion

MailRecon investigations persist in the local application database until they are explicitly deleted. Application-level deletion is permanent: deleting an investigation removes its stored investigation aggregate, including associated findings, execution attempts, module runs, graph nodes, and graph edges.

Deletion is authenticated and scoped to the requested investigation ID. The database transaction is atomic; a failed deletion is rolled back rather than leaving a partially deleted investigation.

Deleting local MailRecon data does not delete information held by external providers. If an investigation disclosed its target to an external provider, MailRecon cannot control that provider's retention or deletion policies. External-provider disclosure does not transfer deletion responsibility for MailRecon's local data: MailRecon remains responsible for deleting the local investigation data when the user requests it.

MailRecon does not implement automatic retention or automatic deletion of investigations. Users should explicitly delete investigations when they no longer need the locally stored reconnaissance data.

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

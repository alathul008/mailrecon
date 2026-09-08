# Providers

| Provider | Key | Purpose |
|---|---|---|
| DNS | No | A/AAAA/MX/NS/TXT/CNAME/SPF/DMARC/DNSSEC |
| RDAP | No | Public domain registration metadata |
| Gravatar | No | Public profile metadata |
| GitHub | Optional | Public username candidate correlation |
| Have I Been Pwned | Yes | Legitimate breach metadata |

Providers should never return or store passwords. Secrets are supplied through environment variables.

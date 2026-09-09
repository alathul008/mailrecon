# Ollama Endpoint Security Policy

MailRecon treats Ollama as a trusted local/private inference service, not as a public OSINT provider.

## Endpoint policy

- `OLLAMA_BASE_URL` defaults to `http://127.0.0.1:11434`.
- Only `http` and `https` schemes are accepted.
- URL credentials are rejected.
- The hostname in `OLLAMA_BASE_URL` must exactly match an entry in `OLLAMA_ALLOWED_HOSTS`.
- The default allowlist is `localhost,127.0.0.1,::1`.
- A trusted private Ollama deployment can be enabled by explicitly adding its hostname or IP address to `OLLAMA_ALLOWED_HOSTS`.
- Arbitrary public destinations are not allowed unless they are explicitly and intentionally added to the allowlist.
- MailRecon does not reuse the public-provider validator for Ollama because that validator intentionally requires public HTTPS destinations, which would reject legitimate local/private Ollama deployments.
- Redirect following remains disabled by policy for the Ollama client path; an Ollama endpoint is authorized by its configured base host rather than by a redirect target.

## Examples

Local default:

```text
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_ALLOWED_HOSTS=localhost,127.0.0.1,::1
```

Trusted private host:

```text
OLLAMA_BASE_URL=http://192.168.1.50:11434
OLLAMA_ALLOWED_HOSTS=localhost,127.0.0.1,::1,192.168.1.50
```

An endpoint such as `https://example.com:11434` is rejected unless `example.com` is explicitly added to the allowlist. An endpoint containing credentials or an unsupported scheme is always rejected.

When `ENABLE_OLLAMA=false`, no Ollama request is made and the existing disabled behavior is preserved.

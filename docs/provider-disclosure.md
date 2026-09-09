# External Provider Disclosure Policy

MailRecon separates **persistence privacy** from **external-provider disclosure**.

## Persistence privacy

`privacy_mode=true` retains the existing contract in `PRIVACY_MODE.md`: sensitive provider `raw_reference` payloads are not persisted and possible-match profile candidates are not persisted.

## External disclosure

Each investigation has an explicit `external_provider_disclosure` setting.

- `false` (default): public external providers are not queried. They return an explicit `disabled` provider status so the result is visible and is not mistaken for a negative finding.
- `true`: the approved public providers may receive the investigation target for their normal OSINT queries. This is an explicit per-investigation opt-in.

Existing persisted investigations retain their stored disclosure setting. Changing the default for new investigations does not rewrite historical records or silently revoke/enable provider disclosure for them.

This setting does not silently change `privacy_mode` and does not weaken provider failure classification.

## API clients

API clients should set `external_provider_disclosure` explicitly when creating an investigation. Omitting it uses the secure default of `false`. Clients that require public-provider queries must explicitly send `true` for that investigation.

## Ollama

Ollama remains governed by its Phase 11 endpoint policy. `external_provider_disclosure` does not weaken or bypass `OLLAMA_BASE_URL` validation. Local/private Ollama use remains an explicit provider configuration choice.

## Security property

The policy answers two different questions:

1. **May provider data be persisted locally?** — controlled by `privacy_mode`.
2. **May public external providers receive the target?** — controlled by `external_provider_disclosure`.

Both controls are explicit in the investigation API and returned by investigation metadata.

# External Provider Disclosure Policy

MailRecon separates **persistence privacy** from **external-provider disclosure**.

## Persistence privacy

`privacy_mode=true` retains the existing contract in `PRIVACY_MODE.md`: sensitive provider `raw_reference` payloads are not persisted and possible-match profile candidates are not persisted.

## External disclosure

Each investigation has an explicit `external_provider_disclosure` setting.

- `true` (default): the approved public providers may receive the investigation target for their normal OSINT queries.
- `false`: public external providers are not queried. They return an explicit `disabled` provider status so the result is visible and is not mistaken for a negative finding.

This setting does not silently change `privacy_mode` and does not weaken provider failure classification.

## Ollama

Ollama remains governed by its Phase 11 endpoint policy. `external_provider_disclosure` does not weaken or bypass `OLLAMA_BASE_URL` validation. Local/private Ollama use remains an explicit provider configuration choice.

## Security property

The policy answers two different questions:

1. **May provider data be persisted locally?** — controlled by `privacy_mode`.
2. **May public external providers receive the target?** — controlled by `external_provider_disclosure`.

Both controls are explicit in the investigation API and returned by investigation metadata.

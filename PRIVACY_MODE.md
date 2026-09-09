# Privacy mode contract

Privacy mode is a persistence-minimization mode for a single-user local investigation. It is not a multi-user access-control or cryptographic privacy boundary.

## Permitted persistence

When `privacy_mode=true`, MailRecon may persist:

- the investigation target and normal investigation lifecycle metadata required for continuity;
- normal finding metadata required for provenance, including source, source URL, finding type, value, confidence, severity, and observation/collection timestamps;
- evidence-state information needed to preserve the existing provenance semantics.

## Prohibited persistence

When `privacy_mode=true`, MailRecon must:

- never persist `Finding.raw_reference` payloads;
- never persist `profile_candidate` findings whose evidence state is `possible_match`;
- never expose a persisted `raw_reference` through JSON, CSV, HTML, or PDF exports.

Source URLs remain permitted because they are part of the existing evidence provenance model. The target remains stored intentionally for investigation continuity, as stated by the frontend.

This contract does not promise deletion from upstream providers, DNS resolvers, browser history, logs outside MailRecon, or third-party services.

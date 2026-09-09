# Graph Integrity and Provenance

MailRecon's relationship graph is a **current derived view**, not an attempt-scoped evidence ledger.

## Canonical identity

A graph node is unique within an investigation by `(investigation_id, node_key)`.
A graph edge is unique within an investigation by `(investigation_id, source, target, relation)`.

The database enforces both identities. Existing duplicate rows are handled by migration `0006` only when duplicates are semantically identical. If duplicate rows differ in node metadata, labels, node type, or edge confidence, migration stops and requires explicit operator review rather than guessing which record is authoritative.

## Deterministic reconstruction

Graph API responses are ordered canonically by node key and by edge source, target, relation, and row ID. Graph rebuilds therefore expose a stable current view for the same underlying investigation state.

## Provenance semantics

Graph provenance identifies the **producing execution attempt for the current derived view**. It does not claim that every graph artifact was independently collected by that attempt, and it does not convert graph rows into attempt-scoped evidence.

Finding-level current/historical semantics remain authoritative for evidence provenance. The graph is a derived visualization of those findings and the normalized investigation identity.

## Privacy

Graph provenance contains only investigation/execution metadata. It does not copy raw provider payloads into graph metadata and does not weaken `privacy_mode` or evidence-state handling.

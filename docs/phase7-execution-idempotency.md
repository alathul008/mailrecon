# Phase 7: Execution Idempotency

Phase 7 distinguishes two durable provenance concepts. `execution_id` is the stable logical investigation/acquisition identity and survives stale-worker recovery. `execution_attempt_id` identifies the actual worker attempt and changes on every successful claim. The short-lived `execution_token` remains the fencing credential for the currently owned attempt.

## Recovery invariant

For `Attempt A -> stale recovery -> Attempt B`, the investigation keeps the same `execution_id`, while Attempt B receives a new `execution_attempt_id` and lease token. Module runs record both identities, so work performed by A and B remains forensically distinguishable.

Finding persistence uses a deterministic semantic key scoped to `(investigation_id, execution_id)`. `execution_attempt_id` is deliberately excluded from that key. Collection time is also excluded. A provider/module replay after stale-worker recovery therefore cannot multiply the same logical evidence merely because it was collected again later, while any genuinely new finding is attributed to the attempt that produced it.

This is scoped replay protection, not global finding deduplication. Different investigations have different logical execution identities and remain separate acquisitions even when their target and evidence are identical.

Existing Phase 6/early Phase 7 rows are adopted lazily when an investigation is first claimed: child records without an execution identity receive both the logical identity and the first actual attempt identity. Recovery does not rewrite prior attempt provenance.

## Stale-worker fencing

The existing execution lease token remains the fencing mechanism. Recovery clears the stale token; the replacement worker receives a new token and a new `execution_attempt_id`. Ownership checks require the running state and current token, so an old worker cannot persist findings, heartbeat, or finalize the investigation after recovery.

## SQLite concurrency boundary

The worker's `max_concurrency` remains process-local. SQLite provides the atomic conditional claim used to prevent two workers from owning the same investigation, but the current architecture does not provide a clean global semaphore across multiple application processes.

Phase 7 deliberately does not add Redis, Celery, Kafka, or another coordination service. With the current single-process/local SQLite architecture, `max_concurrency` is therefore a per-process limit. Multi-process global concurrency should only be revisited if the deployment architecture requires it.

## Migration boundary

Phase 7 adds Alembic revision `0003_execution_idempotency`, including the separate attempt-provenance columns and attempt-scoped module uniqueness. The migration validates upgrading a legacy `0001` schema through `head` plus a downgrade to `0002`. Attempt IDs remain null until an actual worker claim, so migration does not fabricate an execution attempt that never ran.

The historical startup `create_all()`/compatibility path from Phase 6 remains unchanged rather than introducing a second Phase 7 schema-repair implementation. Existing persisted databases should use the Alembic migration path when upgrading to Phase 7; fresh databases created by the application's existing bootstrap path receive the model schema directly.

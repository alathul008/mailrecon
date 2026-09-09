# Phase 7: Execution Idempotency

Phase 7 gives each investigation a durable `execution_id`. Recovery rotates the short-lived execution lease token but preserves the `execution_id`, so all findings and module state remain attributable to the same logical acquisition.

## Recovery invariant

Finding persistence uses a deterministic semantic key scoped to `(investigation_id, execution_id)`. Collection time is intentionally excluded from that key. A provider/module replay after stale-worker recovery therefore cannot multiply the same evidence merely because it was collected again later.

This is scoped deduplication, not global finding deduplication. Different investigations have different execution identities and remain separate acquisitions even when their target and evidence are identical.

Existing Phase 6 rows are adopted lazily when an investigation is claimed: their child findings and module runs receive the investigation's durable execution identity. Existing findings without a persistence key are matched by their semantic identity before a replay inserts a new row.

## Stale-worker fencing

The existing execution lease token remains the fencing mechanism. Recovery preserves `execution_id` but clears the stale token; the replacement worker receives a new token. Ownership checks require both the running state and the current token, so an old worker cannot persist findings, heartbeat, or finalize the investigation after recovery.

## SQLite concurrency boundary

The worker's `max_concurrency` remains process-local. SQLite provides the atomic conditional claim used to prevent two workers from owning the same investigation, but the current architecture does not provide a clean global semaphore across multiple application processes.

Phase 7 deliberately does not add Redis, Celery, Kafka, or another coordination service. With the current single-process/local SQLite architecture, `max_concurrency` is therefore a per-process limit. Multi-process global concurrency should only be revisited if the deployment architecture requires it.

## Migration boundary

Phase 7 adds Alembic revision `0003_execution_idempotency` and validates upgrading a legacy `0001` schema through `head` plus a downgrade to `0002`.

The historical startup `create_all()`/compatibility path from Phase 6 remains unchanged rather than introducing a second Phase 7 schema-repair implementation. Existing persisted databases should use the Alembic migration path when upgrading to Phase 7; fresh databases created by the application's existing bootstrap path receive the model schema directly.

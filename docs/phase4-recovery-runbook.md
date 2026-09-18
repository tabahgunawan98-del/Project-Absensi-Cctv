# Phase 4 local backup and recovery runbook

Local drill only. Synthetic data only. No production deployment.

## Preconditions

- Quiescing is not required: `sqlite3.Connection.backup()` creates a consistent snapshot while writes continue.
- Run as a dedicated service account. Source DB, backup, manifest, and restored DB must not be world-readable.
- Store backups only on an owner-approved encrypted filesystem/backup target. No key belongs in config, source, logs, or comments.
- Restore requires two distinct authorized humans: operator and approver. Record reason/ticket outside the database before execution.
- Stop application writes before cutover. Restore always targets a fresh path; it never overwrites the active DB.

## Backup

Use `BackupService.create(source, destination)` from `attendance_backend.recovery`.

Verification performed before publication:
1. SQLite online snapshot completes.
2. `PRAGMA integrity_check` is `ok`.
3. `PRAGMA foreign_key_check` is empty.
4. `PRAGMA user_version` is allowed.
5. Required tables and immutable-audit triggers exist.
6. WAL content is checkpointed and the journal sealed to `DELETE` before hashing, so the checksum covers every committed byte and no `-wal`/`-shm`/`-journal` sidecar is left beside the artifact.
7. SHA-256 is stored in adjacent `*.manifest.json`.
8. The manifest is always signed with HMAC-SHA-256 using a signing key supplied at call time from an approved secret mechanism. The key is never stored in source, config, manifest, or logs. A service cannot be constructed without one.
9. Temporary partial files and journal sidecars are removed on both the success and the failure path.

Record artifact path, manifest path, checksum, creation time, schema version, operator, and approved encrypted destination. Never record payloads or secrets.

## Restore drill

1. Obtain human authorization: distinct operator and approver plus reason.
2. Select backup and adjacent manifest. Do not edit either.
3. Choose a fresh target path on isolated local storage.
4. Call `BackupService.restore(backup, manifest, fresh_target, authorization)`.
5. Restore verifies checksum before opening the DB; then integrity, foreign keys, schema compatibility, required tables/triggers, and restored-file checksum.
6. Start a local process against the fresh target only.
7. Verify:
   - readiness reports ready;
   - event replay returns `duplicate` with stable hash;
   - changed payload returns conflict;
   - queue depth/retry/failure metrics are aggregates only;
   - audit UPDATE/DELETE is rejected;
   - retained rows exist;
   - rows deleted before the selected backup do not exist.
8. Keep the original DB untouched until acceptance. Cutover is a separate human decision.

## Rejection conditions

Abort. Do not publish or start the restored DB when any condition occurs:
- manifest unsigned, or signature not verifiable with the approved key;
- checksum mismatch;
- missing/malformed manifest;
- truncated/corrupt DB;
- integrity/foreign-key failure;
- unsupported schema version;
- missing required table or immutable trigger;
- same operator and approver;
- target path already exists.

## Rollback

- Before cutover: delete only the failed fresh restore target; continue using the untouched original DB.
- After an authorized local cutover: stop writes, point the local process back to the untouched original DB, re-run readiness and idempotency probes. Preserve failed restore plus non-PII diagnostics for review according to approved retention.
- Never restore over the only known-good DB.

## Test command

```bash
uv run python -m unittest discover -v
```

The tests exercise online consistency, corruption/truncation rejection, fresh restore, restart/idempotency, immutable audit, post-retention backup, schema/trigger compatibility, RBAC separation, structured logs, and operational metrics.

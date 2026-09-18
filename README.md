# Project-Absensi-Cctv

Local backend MVP using Python, WSGI, SQLite, JSON Schema, and RFC 8785 canonicalization.

## Implemented

- Contract v2 ingest: single, batch partial-per-item, manual user-delegated.
- JWT boundary: signature/algorithm/issuer/audience/time/scope/event/site checks.
- Atomic event idempotency/conflict, limits, immutable audit, liveness/readiness.
- Attendance engine: explicit IANA timezone; separate entry/check-in and exit/check-out rules; cross-camera employee/time-window deduplication without mutating raw signals.
- `unknown`, `review_required`, or unknown direction create human-review cases, never attendance.
- Explicit human review and reasoned manual correction with immutable audit. No payroll, penalty, or disciplinary action exists.
- Durable local queue, idempotent retry, restart recovery.
- Configurable minimum retention policy for raw signals, completed queue, and audit.
- Non-biometric `badge`, `qr`, and `manual_review` paths. Attendance records contain no templates, embeddings, images, or media.

## Verify

```sh
uv sync
uv run python -m unittest discover -v
```

## Attendance API (internal Python)

```python
from attendance_backend.attendance import AttendanceConfig, AttendanceEngine

config = AttendanceConfig(
    timezone="Asia/Jakarta",
    dedupe_window_seconds=120,
    raw_event_retention_days=30,
    completed_queue_retention_days=7,
    audit_retention_days=90,
)
engine = AttendanceEngine("attendance.sqlite3", config)
engine.enqueue(signal)
engine.process_pending()
```

All policy values are supplied explicitly. The example is synthetic, not approved production policy. Shift schedules, grace periods, HR export, production IdP/JWKS, multi-instance queueing, CV integration, deployment, and real camera/biometric access remain out of scope. Biometric use still requires owner-reviewed lawful basis/consent, voluntary enrollment, access controls, minimum retention, and a non-biometric attendance route.

## Local recovery and observability

Phase 4 adds consistent SQLite online backup with mandatory HMAC-signed manifests, WAL sealing, checksum/compatibility verification, fresh-path human-authorized restore, aggregate non-PII health/queue/request metrics, and allowlist-only structured logs. The signing key is supplied at call time from an approved secret mechanism and never stored. Backups must use an owner-approved encrypted target. See `docs/phase4-recovery-runbook.md` and `docs/phase4-threat-model.md`.

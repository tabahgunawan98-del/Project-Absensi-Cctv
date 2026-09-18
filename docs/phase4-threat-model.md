# Phase 4 local threat model

Scope: local single-node SQLite runtime using synthetic data. This does not authorize staging or production.

| Threat | Impact | Control in this phase | Residual / owner action |
|---|---|---|---|
| Disk loss | Event, attendance, queue, audit, and policy unavailable | SQLite online backup; SHA-256 manifest; restore to fresh path; recovery drill | Configure approved encrypted backup target, media redundancy, RPO/RTO, and off-host copy |
| Corrupt/truncated backup | Silent partial restore or unavailable service | Checksum before opening; SQLite integrity, foreign-key, schema-version, required-table/trigger checks; fail closed | Periodic independent restore drills and alerting |
| Tampered backup with rewritten manifest checksum | Records silently dropped or altered with `integrity_check=ok` | Manifest signing is mandatory: no service without an approved key, unsigned or wrong-key manifests are rejected before the DB is opened | Own the key in an approved secret mechanism with rotation; consider storing checksums outside the backup directory as a second control |
| WAL/SHM residue beside an artifact | Committed data outside the hashed file; file-descriptor and cleanup hygiene | Connections closed explicitly; WAL checkpointed and journal sealed to `DELETE` before hashing; sidecars removed on success and failure paths and asserted absent | Confirm the same on the eventual production storage layout |
| Replay after restore | Duplicate attendance or changed event under reused ID | Restored event idempotency state is retained and tested; changed payload remains conflict | Keep event IDs stable across edge retries; monitor conflicts |
| Log leakage | Token, employee, biometric, or media exposure | Structured logging uses an explicit operational-field allowlist; metrics are aggregate only | Log destination access/retention and redaction review remain owner decisions |
| Unauthorized restore | Data disclosure, rollback, deleted-data revival | Restore requires distinct human operator and approver, reason, verified manifest, fresh target; no overwrite | Bind these roles to approved IdP/RBAC and record authorization externally before staging |
| Stale backup revives deleted records | Retention/privacy violation | Backup taken after retention is tested not to revive deleted raw data | Production needs an authenticated deletion ledger applied before readiness; not implemented here |

Secrets: no encryption key, token, camera credential, or password is stored by this implementation. Backup files contain application data and must reside only on an owner-approved encrypted filesystem or backup system.

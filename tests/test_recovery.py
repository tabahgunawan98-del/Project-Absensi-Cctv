import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from attendance_backend.app import App
from attendance_backend.attendance import AttendanceConfig, AttendanceEngine
from attendance_backend.observability import OperationalMetrics, SafeJsonLogger, health_snapshot
from attendance_backend.recovery import (
    BackupError,
    BackupService,
    RestoreAuthorization,
    RestoreError,
)
from tests.test_api import SITE, observation


def machine():
    return {
        "principal_type": "machine",
        "scopes": ["events:write"],
        "sites": [SITE],
        "event_types": ["observation.detected.v2"],
    }


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root / "app.sqlite3"
        self.config = AttendanceConfig(
            timezone="Asia/Jakarta",
            dedupe_window_seconds=120,
            raw_event_retention_days=30,
            completed_queue_retention_days=7,
            audit_retention_days=90,
        )
        self.app = App(self.database)
        self.engine = AttendanceEngine(self.database, self.config)
        event = observation()
        self.event = event
        accepted = self.app.handle(
            "POST", "/v2/events", json.dumps(event).encode(),
            {"HTTP_X_PRINCIPAL": json.dumps(machine()), "HTTP_IDEMPOTENCY_KEY": event["event_id"]},
        )
        self.assertEqual(accepted.status, 202)
        self.engine.enqueue({
            "signal_id": "synthetic-signal-1",
            "occurred_at": "2026-09-17T09:00:00Z",
            "site_id": event["site_id"],
            "camera_id": event["payload"]["camera_id"],
            "direction": "entry",
            "resolution": "matched",
            "employee_id": "80000000-0000-4000-8000-000000000001",
            "method": "badge",
        })
        self.engine.process_pending()
        self.service = BackupService(
            required_tables={
                "events", "audit_log", "raw_attendance_signals", "attendance_records",
                "durable_queue", "attendance_audit", "retention_policy",
            },
            required_triggers={
                "audit_immutable", "audit_no_delete", "attendance_audit_immutable",
                "attendance_audit_no_delete", "raw_signal_immutable",
            },
            allowed_schema_versions={0},
            manifest_signing_key=b"synthetic-test-key-not-for-production",
        )

    def tearDown(self):
        self.app.close()
        self.engine.close()
        self.tmp.cleanup()

    def backup(self):
        return self.service.create(self.database, self.root / "backup.sqlite3")

    def sidecars(self):
        """Journal residue of backup/restore artifacts only.

        The live application database legitimately keeps sidecars while the app
        holds connections; the defect under test is residue left behind by
        backup and restore artifacts.
        """
        live = self.database.name
        return sorted(
            path.name
            for path in self.root.rglob("*")
            if path.name.endswith(("-wal", "-shm", "-journal"))
            and not path.name.startswith(live)
        )

    def test_manifest_tamper_without_valid_signature_fails_closed(self):
        artifact = self.backup()
        with sqlite3.connect(artifact.database_path) as connection:
            connection.execute(
                "UPDATE maintenance_state SET allow_retention_delete=1 WHERE singleton=1"
            )
            connection.execute("DELETE FROM attendance_records")
        self.service._remove_sidecars(artifact.database_path)

        manifest = json.loads(artifact.manifest_path.read_text())
        manifest["sha256"] = self.service.sha256(artifact.database_path)
        artifact.manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        target = self.root / "tampered-record-restore.sqlite3"
        with self.assertRaises(BackupError):
            self.service.restore(
                artifact.database_path, artifact.manifest_path, target,
                RestoreAuthorization("operator-1", "approver-1", "tamper probe"),
            )
        self.assertFalse(target.exists())

        unsigned = dict(manifest)
        unsigned.pop("manifest_hmac_sha256")
        unsigned_path = self.root / "unsigned.manifest.json"
        unsigned_path.write_text(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with self.assertRaises(BackupError):
            self.service.restore(
                artifact.database_path, unsigned_path, self.root / "unsigned-restore.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "unsigned probe"),
            )
        self.assertFalse((self.root / "unsigned-restore.sqlite3").exists())

        foreign = BackupService(
            required_tables=self.service.required_tables,
            required_triggers=self.service.required_triggers,
            allowed_schema_versions=self.service.allowed_schema_versions,
            manifest_signing_key=b"a-different-synthetic-key",
        )
        with self.assertRaises(BackupError):
            foreign.restore(
                artifact.database_path, artifact.manifest_path,
                self.root / "foreign-restore.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "foreign key probe"),
            )
        self.assertFalse((self.root / "foreign-restore.sqlite3").exists())

    def test_service_requires_an_approved_signing_key(self):
        for bad_key in (None, b"", "not-bytes"):
            with self.assertRaises(BackupError):
                BackupService(
                    required_tables=self.service.required_tables,
                    required_triggers=self.service.required_triggers,
                    allowed_schema_versions=self.service.allowed_schema_versions,
                    manifest_signing_key=bad_key,
                )

    def test_no_orphan_sidecars_after_successful_or_failed_create_and_restore(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE sidecar_probe(id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO sidecar_probe VALUES (1)")

        artifact = self.backup()
        self.assertEqual(self.sidecars(), [])

        restored = self.root / "sidecar-restored.sqlite3"
        self.service.restore(
            artifact.database_path, artifact.manifest_path, restored,
            RestoreAuthorization("operator-1", "approver-1", "sidecar drill"),
        )
        self.assertEqual(self.sidecars(), [])

        with self.assertRaises(BackupError):
            self.service.create(self.database, artifact.database_path)
        self.assertEqual(self.sidecars(), [])

        broken = self.root / "broken.sqlite3"
        broken.write_bytes(artifact.database_path.read_bytes()[:256])
        with self.assertRaises(BackupError):
            self.service.restore(
                broken, artifact.manifest_path, self.root / "failed-restore.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "failed restore drill"),
            )
        self.assertFalse((self.root / "failed-restore.sqlite3").exists())
        self.assertEqual(self.sidecars(), [])

    def test_backup_seals_wal_so_manifest_covers_every_commit(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE late_commit(id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO late_commit VALUES (4242)")

        artifact = self.backup()
        self.assertEqual(artifact.sha256, self.service.sha256(artifact.database_path))
        with sqlite3.connect(f"file:{artifact.database_path}?mode=ro", uri=True) as connection:
            self.assertEqual(
                connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "delete"
            )
            self.assertEqual(
                connection.execute("SELECT id FROM late_commit").fetchone()[0], 4242
            )

    def test_online_backup_is_consistent_during_write_and_covers_storage_contract(self):
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                "CREATE TABLE pair_left(id INTEGER PRIMARY KEY);"
                "CREATE TABLE pair_right(id INTEGER PRIMARY KEY REFERENCES pair_left(id));"
            )

        started = threading.Event()

        def writer():
            with sqlite3.connect(self.database, timeout=30) as connection:
                for value in range(1, 51):
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("INSERT INTO pair_left VALUES (?)", (value,))
                    connection.execute("INSERT INTO pair_right VALUES (?)", (value,))
                    connection.commit()
                    started.set()

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertTrue(started.wait(2))
        artifact = self.backup()
        thread.join()

        self.assertEqual(artifact.sha256, self.service.sha256(artifact.database_path))
        with sqlite3.connect(artifact.database_path) as connection:
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            left = connection.execute("SELECT COUNT(*) FROM pair_left").fetchone()[0]
            right = connection.execute("SELECT COUNT(*) FROM pair_right").fetchone()[0]
            self.assertEqual(left, right)
            self.assertEqual(
                {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )} >= self.service.required_tables,
                True,
            )

    def test_corrupt_and_truncated_backups_are_rejected_before_restore(self):
        artifact = self.backup()
        manifest = json.loads(artifact.manifest_path.read_text())
        manifest["schema_version"] = 99
        tampered_manifest = self.root / "tampered.manifest.json"
        tampered_manifest.write_text(json.dumps(manifest))
        with self.assertRaises(BackupError):
            self.service.restore(
                artifact.database_path, tampered_manifest,
                self.root / "tampered-restored.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "synthetic drill"),
            )

        corrupt = self.root / "corrupt.sqlite3"
        corrupt.write_bytes(artifact.database_path.read_bytes() + b"tamper")
        with self.assertRaises(BackupError):
            self.service.restore(
                corrupt, artifact.manifest_path, self.root / "corrupt-restored.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "synthetic drill"),
            )

        truncated = self.root / "truncated.sqlite3"
        truncated.write_bytes(artifact.database_path.read_bytes()[:128])
        with self.assertRaises(BackupError):
            self.service.restore(
                truncated, artifact.manifest_path, self.root / "truncated-restored.sqlite3",
                RestoreAuthorization("operator-1", "approver-1", "synthetic drill"),
            )
        self.assertFalse((self.root / "corrupt-restored.sqlite3").exists())
        self.assertFalse((self.root / "truncated-restored.sqlite3").exists())

    def test_restore_requires_separate_human_approval_and_fresh_target(self):
        artifact = self.backup()
        for authorization in (
            None,
            RestoreAuthorization("same-person", "same-person", "self approval"),
            RestoreAuthorization("operator", "approver", ""),
        ):
            with self.assertRaises(RestoreError):
                self.service.restore(
                    artifact.database_path, artifact.manifest_path,
                    self.root / "unauthorized.sqlite3", authorization,
                )

        occupied = self.root / "occupied.sqlite3"
        occupied.write_bytes(b"do not overwrite")
        with self.assertRaises(RestoreError):
            self.service.restore(
                artifact.database_path, artifact.manifest_path, occupied,
                RestoreAuthorization("operator", "approver", "synthetic drill"),
            )
        self.assertEqual(occupied.read_bytes(), b"do not overwrite")

    def test_restore_to_fresh_database_preserves_audit_and_idempotency(self):
        artifact = self.backup()
        restored = self.root / "restored.sqlite3"
        report = self.service.restore(
            artifact.database_path, artifact.manifest_path, restored,
            RestoreAuthorization("restore-operator", "security-approver", "synthetic recovery drill"),
        )
        self.assertEqual(report.integrity_check, "ok")
        self.assertEqual(report.schema_version, 0)

        restored_app = App(restored)
        replay = restored_app.handle(
            "POST", "/v2/events", json.dumps(self.event).encode(),
            {"HTTP_X_PRINCIPAL": json.dumps(machine()), "HTTP_IDEMPOTENCY_KEY": self.event["event_id"]},
        )
        self.assertEqual((replay.status, replay.json["outcome"]), (200, "duplicate"))
        restored_app.close()

        with sqlite3.connect(restored) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE audit_log SET outcome='tampered'")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM attendance_audit")

    def test_deleted_data_does_not_reappear_when_backup_is_taken_after_retention(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE maintenance_state SET allow_retention_delete=1 WHERE singleton=1")
            connection.execute("DELETE FROM durable_queue WHERE signal_id='synthetic-signal-1'")
            connection.execute("DELETE FROM raw_attendance_signals WHERE signal_id='synthetic-signal-1'")
            connection.execute("UPDATE maintenance_state SET allow_retention_delete=0 WHERE singleton=1")
        artifact = self.backup()
        restored = self.root / "retention-restored.sqlite3"
        self.service.restore(
            artifact.database_path, artifact.manifest_path, restored,
            RestoreAuthorization("restore-operator", "security-approver", "post-retention drill"),
        )
        with sqlite3.connect(restored) as connection:
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM raw_attendance_signals WHERE signal_id='synthetic-signal-1'"
            ).fetchone()[0], 0)
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM attendance_records"
            ).fetchone()[0], 1)

    def test_schema_version_and_required_trigger_mismatch_fail_closed(self):
        artifact = self.backup()
        incompatible = BackupService(
            required_tables=self.service.required_tables,
            required_triggers=self.service.required_triggers | {"missing_security_trigger"},
            allowed_schema_versions={7},
            manifest_signing_key=b"synthetic-test-key-not-for-production",
        )
        with self.assertRaises(BackupError):
            incompatible.restore(
                artifact.database_path, artifact.manifest_path, self.root / "incompatible.sqlite3",
                RestoreAuthorization("operator", "approver", "compatibility probe"),
            )


class ObservabilityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "health.sqlite3"
        config = AttendanceConfig("Asia/Jakarta", 120, 30, 7, 90)
        self.engine = AttendanceEngine(self.database, config)

    def tearDown(self):
        self.engine.close()
        self.tmp.cleanup()

    def test_structured_logging_is_allowlist_only_and_contains_no_sensitive_payload(self):
        sink = []
        logger = SafeJsonLogger(sink.append)
        logger.emit(
            "request_completed", request_id="req-1", status=202,
            duration_ms=3.5, error_code=None,
        )
        record = json.loads(sink[0])
        self.assertEqual(record["event"], "request_completed")
        self.assertNotIn("payload", sink[0])
        for forbidden in ("payload", "token", "media_ref", "employee_id", "embedding"):
            with self.assertRaises(ValueError):
                logger.emit("unsafe", **{forbidden: "sensitive"})

    def test_health_and_metrics_expose_only_operational_aggregates(self):
        metrics = OperationalMetrics()
        metrics.observe_request(0.012, error=False)
        metrics.observe_request(0.040, error=True)
        snapshot = health_snapshot(self.database, metrics)
        self.assertEqual(snapshot["liveness"], "live")
        self.assertEqual(snapshot["readiness"], "ready")
        self.assertEqual(snapshot["queue_depth"], 0)
        self.assertEqual(snapshot["retry_count"], 0)
        self.assertEqual(snapshot["failure_count"], 1)
        self.assertEqual(snapshot["request_count"], 2)
        self.assertGreaterEqual(snapshot["latency_ms_max"], 40)
        serialized = json.dumps(snapshot)
        for forbidden in ("payload", "token", "media", "employee", "biometric"):
            self.assertNotIn(forbidden, serialized.lower())


if __name__ == "__main__":
    unittest.main()

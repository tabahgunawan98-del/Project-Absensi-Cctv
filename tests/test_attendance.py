import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from attendance_backend.attendance import AttendanceConfig, AttendanceEngine

EMPLOYEE = "80000000-0000-4000-8000-000000000001"
SITE = "40000000-0000-4000-8000-000000000001"


def signal(signal_id, occurred_at="2026-09-17T17:30:00Z", *, camera="cam-a", direction="entry",
           resolution="matched", employee_id=EMPLOYEE, method="face"):
    return {
        "signal_id": signal_id,
        "occurred_at": occurred_at,
        "site_id": SITE,
        "camera_id": camera,
        "direction": direction,
        "resolution": resolution,
        "employee_id": employee_id,
        "method": method,
    }


class AttendanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "attendance.sqlite3"
        self.now = datetime(2026, 9, 18, tzinfo=timezone.utc)
        self.config = AttendanceConfig(
            timezone="Asia/Jakarta",
            dedupe_window_seconds=120,
            raw_event_retention_days=30,
            completed_queue_retention_days=7,
            audit_retention_days=90,
        )
        self.engine = AttendanceEngine(self.database, self.config, clock=lambda: self.now)

    def tearDown(self):
        self.engine.close()
        self.tmp.cleanup()

    def rows(self, table, columns="*"):
        with sqlite3.connect(self.database) as connection:
            return connection.execute(f"SELECT {columns} FROM {table} ORDER BY rowid").fetchall()

    def test_timezone_boundary_and_entry_exit_rules_are_separate(self):
        # 17:30 UTC is 00:30 next day in Asia/Jakarta.
        self.engine.enqueue(signal("s-time-entry", direction="entry"))
        self.engine.enqueue(signal("s-time-exit", occurred_at="2026-09-17T17:35:00Z", direction="exit"))
        self.engine.process_pending()
        rows = self.rows("attendance_records", "kind, local_date, timezone")
        self.assertEqual(rows, [
            ("check_in", "2026-09-18", "Asia/Jakarta"),
            ("check_out", "2026-09-18", "Asia/Jakarta"),
        ])

    def test_cross_camera_duplicate_and_out_of_order_are_deduplicated(self):
        later = signal("s-later", "2026-09-17T09:01:00Z", camera="cam-b")
        earlier = signal("s-earlier", "2026-09-17T09:00:00Z", camera="cam-a")
        self.engine.enqueue(later)
        self.engine.process_pending()
        self.engine.enqueue(earlier)  # offline/out-of-order arrival
        self.engine.process_pending()
        self.assertEqual(len(self.rows("raw_attendance_signals")), 2)
        self.assertEqual(len(self.rows("attendance_records")), 1)
        outcomes = self.rows("processing_results", "signal_id, outcome")
        self.assertEqual(outcomes, [("s-later", "attendance_created"), ("s-earlier", "duplicate_window")])

    def test_replay_is_idempotent_without_mutating_raw_event(self):
        event = signal("s-replay")
        original = json.dumps(event, sort_keys=True, separators=(",", ":"))
        self.assertTrue(self.engine.enqueue(event))
        self.assertFalse(self.engine.enqueue(dict(event)))
        self.engine.process_pending()
        self.engine.process_pending()
        self.assertEqual(len(self.rows("attendance_records")), 1)
        stored = self.rows("raw_attendance_signals", "payload_json")[0][0]
        self.assertEqual(stored, original)
        with sqlite3.connect(self.database) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE raw_attendance_signals SET payload_json='tampered'")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM raw_attendance_signals")

    def test_unknown_low_confidence_and_unknown_direction_make_no_attendance(self):
        unknown = signal("s-unknown", resolution="unknown", employee_id=None)
        low = signal("s-low", resolution="review_required", employee_id=None)
        uncertain = signal("s-direction", direction="unknown")
        for item in (unknown, low, uncertain):
            self.engine.enqueue(item)
        self.engine.process_pending()
        self.assertEqual(self.rows("attendance_records"), [])
        self.assertEqual(len(self.rows("review_cases")), 3)
        self.assertEqual(
            [row[0] for row in self.rows("processing_results", "outcome")],
            ["review_required", "review_required", "review_required"],
        )

    def test_non_biometric_badge_and_qr_paths_create_attendance(self):
        self.engine.enqueue(signal("s-badge", method="badge"))
        self.engine.enqueue(signal("s-qr", "2026-09-17T09:10:00Z", method="qr", direction="exit"))
        self.engine.process_pending()
        self.assertEqual(self.rows("attendance_records", "method, kind"),
                         [("badge", "check_in"), ("qr", "check_out")])

    def test_manual_correction_requires_reason_and_has_immutable_audit(self):
        self.engine.enqueue(signal("s-correct"))
        self.engine.process_pending()
        attendance_id = self.rows("attendance_records", "attendance_id")[0][0]
        with self.assertRaises(ValueError):
            self.engine.correct(attendance_id, "check_out", "2026-09-17T10:00:00Z", "reviewer-1", "")
        self.engine.correct(attendance_id, "check_out", "2026-09-17T10:00:00Z",
                            "reviewer-1", "Synthetic correction")
        self.assertEqual(self.rows("attendance_records", "kind, corrected"), [("check_out", 1)])
        audit = self.rows("attendance_audit", "actor, action, reason")
        self.assertEqual(audit[-1], ("reviewer-1", "manual_correction", "Synthetic correction"))
        with sqlite3.connect(self.database) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE attendance_audit SET reason='tampered'")
        self.assertFalse(hasattr(self.engine, "apply_penalty"))

    def test_human_review_is_explicit_and_audited(self):
        self.engine.enqueue(signal("s-review", resolution="review_required", employee_id=None))
        self.engine.process_pending()
        review_id = self.rows("review_cases", "review_id")[0][0]
        self.engine.resolve_review(review_id, EMPLOYEE, "entry", "reviewer-2", "Badge verified")
        self.assertEqual(self.rows("attendance_records", "method, kind"),
                         [("manual_review", "check_in")])
        self.assertEqual(self.rows("review_cases", "status"), [("resolved",)])
        self.assertEqual(self.rows("attendance_audit", "action, actor")[-1],
                         ("human_review", "reviewer-2"))

    def test_queue_recovers_after_restart_and_retry_is_idempotent(self):
        self.engine.enqueue(signal("s-restart"))
        self.engine.close()
        self.engine = AttendanceEngine(self.database, self.config, clock=lambda: self.now)
        self.engine.process_pending()
        self.engine.close()
        self.engine = AttendanceEngine(self.database, self.config, clock=lambda: self.now)
        self.engine.process_pending()
        self.assertEqual(len(self.rows("attendance_records")), 1)
        self.assertEqual(self.rows("durable_queue", "status, attempts"), [("done", 1)])

    def test_failed_queue_item_retries_after_restart(self):
        self.engine.enqueue(signal("s-retry"))
        original = self.engine._process_signal
        self.engine._process_signal = lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic failure"))
        self.engine.process_pending()
        self.assertEqual(self.rows("durable_queue", "status, attempts"), [("pending", 1)])
        self.engine._process_signal = original
        self.engine.close()
        self.engine = AttendanceEngine(self.database, self.config, clock=lambda: self.now)
        self.engine.process_pending()
        self.assertEqual(len(self.rows("attendance_records")), 1)
        self.assertEqual(self.rows("durable_queue", "status, attempts"), [("done", 2)])

    def test_delayed_signal_retention_uses_immutable_received_at_across_restart(self):
        self.now = datetime(2026, 9, 1, tzinfo=timezone.utc)
        self.engine.enqueue(signal("s-delayed", "2026-01-01T09:00:00Z"))
        received_at = self.rows("raw_attendance_signals", "received_at")[0][0]
        self.engine.process_pending()
        self.engine.close()
        self.engine = AttendanceEngine(self.database, self.config, clock=lambda: self.now)
        self.assertEqual(self.rows("raw_attendance_signals", "received_at"), [(received_at,)])

        self.now += timedelta(days=8)
        deleted = self.engine.purge_retained()
        self.assertEqual(deleted["completed_queue"], 1)
        self.assertEqual(deleted["raw_events"], 0)

        self.now = datetime(2026, 9, 30, 23, 59, 59, 999999, tzinfo=timezone.utc)
        self.assertEqual(self.engine.purge_retained()["raw_events"], 0)
        self.now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.assertEqual(self.engine.purge_retained()["raw_events"], 0)
        self.now += timedelta(microseconds=1)
        self.assertEqual(self.engine.purge_retained()["raw_events"], 1)

    def test_retention_is_configurable_and_policy_audited(self):
        old = signal("s-old", "2026-07-01T09:00:00Z")
        self.engine.enqueue(old)
        self.engine.process_pending()
        self.now += timedelta(days=8)
        deleted = self.engine.purge_retained()
        self.assertEqual(deleted["raw_events"], 0)
        self.assertEqual(deleted["completed_queue"], 1)
        self.assertEqual(deleted["audit"], 0)
        self.assertEqual(len(self.rows("attendance_audit")), 1)
        self.now += timedelta(days=83)
        deleted = self.engine.purge_retained()
        self.assertEqual(deleted["raw_events"], 1)
        self.assertEqual(deleted["audit"], 1)
        policy = self.rows("retention_policy", "raw_event_days, queue_days, audit_days")
        self.assertEqual(policy, [(30, 7, 90)])


if __name__ == "__main__":
    unittest.main()

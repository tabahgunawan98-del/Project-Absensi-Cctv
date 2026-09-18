"""Durable attendance decisions, separate from recognition.

Input signals contain identity outcomes only, never biometric templates or media.
Attendance policy is explicit/configurable; no payroll or disciplinary action exists.
"""

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True)
class AttendanceConfig:
    timezone: str
    dedupe_window_seconds: int
    raw_event_retention_days: int
    completed_queue_retention_days: int
    audit_retention_days: int

    def __post_init__(self):
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("timezone must be a valid IANA name") from error
        for name in (
            "dedupe_window_seconds",
            "raw_event_retention_days",
            "completed_queue_retention_days",
            "audit_retention_days",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


def _utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("occurred_at must be UTC with Z suffix")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("occurred_at must include timezone")
    return parsed.astimezone(timezone.utc)


class AttendanceEngine:
    DIRECTIONS = {"entry": "check_in", "exit": "check_out"}
    METHODS = {"face", "badge", "qr", "manual_review"}
    RESOLUTIONS = {"matched", "unknown", "review_required"}

    def __init__(self, database_path, config, clock=None):
        self.database_path = str(database_path)
        self.config = config
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.timezone = ZoneInfo(config.timezone)
        self._closed = False
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS maintenance_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    allow_retention_delete INTEGER NOT NULL DEFAULT 0
                );
                INSERT OR IGNORE INTO maintenance_state VALUES (1, 0);
                CREATE TABLE IF NOT EXISTS raw_attendance_signals (
                    signal_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS raw_signal_immutable
                    BEFORE UPDATE ON raw_attendance_signals
                    BEGIN SELECT RAISE(ABORT, 'raw signal is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS raw_signal_no_delete
                    BEFORE DELETE ON raw_attendance_signals
                    WHEN (SELECT allow_retention_delete FROM maintenance_state WHERE singleton=1) = 0
                    BEGIN SELECT RAISE(ABORT, 'raw signal deletion requires retention job'); END;
                CREATE TABLE IF NOT EXISTS durable_queue (
                    signal_id TEXT PRIMARY KEY REFERENCES raw_attendance_signals(signal_id),
                    status TEXT NOT NULL CHECK(status IN ('pending','done')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS attendance_records (
                    attendance_id TEXT PRIMARY KEY,
                    employee_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    source_signal_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    local_date TEXT NOT NULL,
                    timezone TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('check_in','check_out')),
                    method TEXT NOT NULL,
                    corrected INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS attendance_dedupe
                    ON attendance_records(employee_id, kind, occurred_at);
                CREATE TABLE IF NOT EXISTS processing_results (
                    signal_id TEXT PRIMARY KEY,
                    outcome TEXT NOT NULL,
                    attendance_id TEXT,
                    processed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS review_cases (
                    review_id TEXT PRIMARY KEY,
                    signal_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('open','resolved')),
                    reason TEXT NOT NULL,
                    resolved_by TEXT,
                    resolved_at TEXT
                );
                CREATE TABLE IF NOT EXISTS attendance_audit (
                    audit_id TEXT PRIMARY KEY,
                    recorded_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    attendance_id TEXT,
                    signal_id TEXT,
                    reason TEXT
                );
                CREATE TRIGGER IF NOT EXISTS attendance_audit_immutable
                    BEFORE UPDATE ON attendance_audit
                    BEGIN SELECT RAISE(ABORT, 'attendance_audit is append-only'); END;
                DROP TRIGGER IF EXISTS attendance_audit_no_delete;
                CREATE TRIGGER attendance_audit_no_delete
                    BEFORE DELETE ON attendance_audit
                    WHEN (SELECT allow_retention_delete FROM maintenance_state WHERE singleton=1) = 0
                    BEGIN SELECT RAISE(ABORT, 'attendance_audit deletion requires retention job'); END;
                CREATE TABLE IF NOT EXISTS retention_policy (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    raw_event_days INTEGER NOT NULL,
                    queue_days INTEGER NOT NULL,
                    audit_days INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """INSERT INTO retention_policy VALUES (1, ?, ?, ?, ?)
                   ON CONFLICT(singleton) DO UPDATE SET
                     raw_event_days=excluded.raw_event_days,
                     queue_days=excluded.queue_days,
                     audit_days=excluded.audit_days,
                     updated_at=excluded.updated_at""",
                (
                    config.raw_event_retention_days,
                    config.completed_queue_retention_days,
                    config.audit_retention_days,
                    self._now_text(),
                ),
            )

    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _now(self):
        value = self.clock()
        if value.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _now_text(self):
        return self._now().isoformat().replace("+00:00", "Z")

    def close(self):
        self._closed = True

    def enqueue(self, signal):
        """Persist immutable raw input and queue atomically; exact replay is a no-op."""
        required = {
            "signal_id", "occurred_at", "site_id", "camera_id", "direction",
            "resolution", "employee_id", "method",
        }
        if set(signal) != required:
            raise ValueError("signal fields invalid")
        if signal["direction"] not in {"entry", "exit", "unknown"}:
            raise ValueError("direction invalid")
        if signal["resolution"] not in self.RESOLUTIONS:
            raise ValueError("resolution invalid")
        if signal["method"] not in self.METHODS:
            raise ValueError("method invalid")
        _utc(signal["occurred_at"])
        canonical = json.dumps(signal, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT payload_json FROM raw_attendance_signals WHERE signal_id=?",
                (signal["signal_id"],),
            ).fetchone()
            if existing:
                if existing[0] != canonical:
                    raise ValueError("signal_id conflict")
                return False
            connection.execute(
                "INSERT INTO raw_attendance_signals VALUES (?, ?, ?, ?)",
                (signal["signal_id"], canonical, signal["occurred_at"], self._now_text()),
            )
            connection.execute(
                "INSERT INTO durable_queue(signal_id,status) VALUES (?, 'pending')",
                (signal["signal_id"],),
            )
        return True

    def process_pending(self):
        """Retry durable items; each item commits independently and idempotently."""
        with self._connect() as connection:
            ids = [row[0] for row in connection.execute(
                "SELECT signal_id FROM durable_queue WHERE status='pending' ORDER BY rowid"
            )]
        for signal_id in ids:
            try:
                with self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT payload_json FROM raw_attendance_signals WHERE signal_id=?",
                        (signal_id,),
                    ).fetchone()
                    if row is None:
                        raise RuntimeError("raw signal missing")
                    self._process_signal(connection, json.loads(row[0]))
                    connection.execute(
                        "UPDATE durable_queue SET status='done', attempts=attempts+1, completed_at=? WHERE signal_id=?",
                        (self._now_text(), signal_id),
                    )
                    connection.commit()
            except Exception:
                with self._connect() as connection:
                    connection.execute(
                        "UPDATE durable_queue SET attempts=attempts+1 WHERE signal_id=?",
                        (signal_id,),
                    )
        return len(ids)

    def _process_signal(self, connection, signal):
        signal_id = signal["signal_id"]
        if connection.execute(
            "SELECT 1 FROM processing_results WHERE signal_id=?", (signal_id,)
        ).fetchone():
            return
        if (
            signal["resolution"] != "matched"
            or not signal["employee_id"]
            or signal["direction"] not in self.DIRECTIONS
        ):
            reason = (
                "direction_unknown" if signal["direction"] not in self.DIRECTIONS
                else signal["resolution"]
            )
            connection.execute(
                "INSERT OR IGNORE INTO review_cases VALUES (?, ?, 'open', ?, NULL, NULL)",
                (str(uuid.uuid4()), signal_id, reason),
            )
            self._result(connection, signal_id, "review_required", None)
            return

        occurred = _utc(signal["occurred_at"])
        kind = self.DIRECTIONS[signal["direction"]]
        window = timedelta(seconds=self.config.dedupe_window_seconds)
        rows = connection.execute(
            "SELECT occurred_at FROM attendance_records WHERE employee_id=? AND kind=?",
            (signal["employee_id"], kind),
        )
        if any(abs(_utc(row[0]) - occurred) <= window for row in rows):
            self._result(connection, signal_id, "duplicate_window", None)
            return

        attendance_id = str(uuid.uuid4())
        local_date = occurred.astimezone(self.timezone).date().isoformat()
        connection.execute(
            "INSERT INTO attendance_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                attendance_id,
                signal["employee_id"],
                signal["site_id"],
                signal_id,
                signal["occurred_at"],
                local_date,
                self.config.timezone,
                kind,
                signal["method"],
            ),
        )
        self._result(connection, signal_id, "attendance_created", attendance_id)
        self._audit(connection, "system", "attendance_created", attendance_id, signal_id, None)

    def _result(self, connection, signal_id, outcome, attendance_id):
        connection.execute(
            "INSERT INTO processing_results VALUES (?, ?, ?, ?)",
            (signal_id, outcome, attendance_id, self._now_text()),
        )

    def _audit(self, connection, actor, action, attendance_id, signal_id, reason):
        connection.execute(
            "INSERT INTO attendance_audit VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), self._now_text(), actor, action, attendance_id, signal_id, reason),
        )

    def correct(self, attendance_id, kind, occurred_at, actor, reason):
        """Human correction only; never applies payroll or disciplinary consequences."""
        if kind not in self.DIRECTIONS.values():
            raise ValueError("kind invalid")
        if not actor or not reason or not reason.strip():
            raise ValueError("actor and reason required")
        occurred = _utc(occurred_at)
        with self._connect() as connection:
            updated = connection.execute(
                """UPDATE attendance_records SET kind=?, occurred_at=?, local_date=?, corrected=1
                   WHERE attendance_id=?""",
                (kind, occurred_at, occurred.astimezone(self.timezone).date().isoformat(), attendance_id),
            ).rowcount
            if not updated:
                raise ValueError("attendance not found")
            self._audit(connection, actor, "manual_correction", attendance_id, None, reason.strip())

    def resolve_review(self, review_id, employee_id, direction, actor, reason):
        if direction not in self.DIRECTIONS or not employee_id or not actor or not reason.strip():
            raise ValueError("review resolution invalid")
        with self._connect() as connection:
            row = connection.execute(
                """SELECT r.signal_id, s.occurred_at,
                          json_extract(s.payload_json,'$.site_id')
                   FROM review_cases r JOIN raw_attendance_signals s USING(signal_id)
                   WHERE r.review_id=? AND r.status='open'""",
                (review_id,),
            ).fetchone()
            if row is None:
                raise ValueError("open review not found")
            signal_id, occurred_at, site_id = row
            occurred = _utc(occurred_at)
            attendance_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO attendance_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'manual_review', 0)",
                (
                    attendance_id, employee_id, site_id, signal_id, occurred_at,
                    occurred.astimezone(self.timezone).date().isoformat(),
                    self.config.timezone, self.DIRECTIONS[direction],
                ),
            )
            connection.execute(
                "UPDATE review_cases SET status='resolved', resolved_by=?, resolved_at=? WHERE review_id=?",
                (actor, self._now_text(), review_id),
            )
            self._audit(connection, actor, "human_review", attendance_id, signal_id, reason.strip())

    def purge_retained(self):
        """Delete expired raw/done queue data; immutable audit is retained at least its minimum."""
        now = self._now()
        raw_before = now - timedelta(days=self.config.raw_event_retention_days)
        queue_before = (now - timedelta(days=self.config.completed_queue_retention_days)).isoformat().replace("+00:00", "Z")
        audit_before = (now - timedelta(days=self.config.audit_retention_days)).isoformat().replace("+00:00", "Z")
        with self._connect() as connection:
            queue_deleted = connection.execute(
                "DELETE FROM durable_queue WHERE status='done' AND completed_at < ?", (queue_before,)
            ).rowcount
            connection.execute(
                "UPDATE maintenance_state SET allow_retention_delete=1 WHERE singleton=1"
            )
            expired_raw_ids = [
                signal_id
                for signal_id, received_at in connection.execute(
                    """SELECT signal_id, received_at FROM raw_attendance_signals
                       WHERE signal_id NOT IN (SELECT signal_id FROM durable_queue)"""
                )
                if _utc(received_at) < raw_before
            ]
            connection.executemany(
                "DELETE FROM raw_attendance_signals WHERE signal_id=?",
                ((signal_id,) for signal_id in expired_raw_ids),
            )
            raw_deleted = len(expired_raw_ids)
            audit_deleted = connection.execute(
                "DELETE FROM attendance_audit WHERE recorded_at < ?", (audit_before,)
            ).rowcount
            connection.execute(
                "UPDATE maintenance_state SET allow_retention_delete=0 WHERE singleton=1"
            )
        return {
            "raw_events": raw_deleted,
            "completed_queue": queue_deleted,
            "audit": audit_deleted,
        }

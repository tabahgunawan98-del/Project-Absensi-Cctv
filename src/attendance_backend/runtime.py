"""Composition root for the deployable single-node runtime."""

import json
import sqlite3
from datetime import datetime, timezone

from frontend.dashboard import DashboardClient, OperatorDashboard

from .app import App
from .auth import TokenError, verify_token
from .attendance import AttendanceConfig, AttendanceEngine
from .limits import Limits
from .recovery import BackupService


class RuntimeService:
    def __init__(self, database_path, *, auth_config, manifest_signing_key, clock, config=None):
        self.database_path = str(database_path)
        self.auth_config = auth_config
        self.clock = clock
        limits = None
        if config is not None:
            limits = Limits(max_requests_per_window=config.rate_limit_per_minute)
        self.app = App(database_path, auth_config=auth_config, clock=clock, limits=limits)
        self.attendance = AttendanceEngine(
            database_path,
            AttendanceConfig(
                timezone="Asia/Jakarta",
                dedupe_window_seconds=config.dedupe_window_seconds if config else 10,
                raw_event_retention_days=config.raw_retention_days if config else 30,
                completed_queue_retention_days=7,
                audit_retention_days=config.processed_retention_days if config else 90,
            ),
            clock=lambda: datetime.fromtimestamp(clock(), timezone.utc),
        )
        self.backups = BackupService(
            required_tables={
                "events",
                "audit_log",
                "raw_attendance_signals",
                "durable_queue",
                "attendance_records",
                "review_cases",
                "processing_results",
                "attendance_audit",
                "retention_policy",
            },
            required_triggers={
                "audit_immutable",
                "audit_no_delete",
                "raw_signal_immutable",
                "raw_signal_no_delete",
                "attendance_audit_immutable",
                "attendance_audit_no_delete",
            },
            allowed_schema_versions={0},
            manifest_signing_key=manifest_signing_key,
        )

    def ingest(self, event, token, *, idempotency_key):
        return self.app.handle(
            "POST",
            "/v2/events",
            json.dumps(event).encode(),
            {
                "HTTP_AUTHORIZATION": f"Bearer {token}",
                "HTTP_IDEMPOTENCY_KEY": idempotency_key,
            },
        )

    def record_synthetic_attendance(
        self, *, signal_id, occurred_at, employee_id, direction
    ):
        signal = {
            "signal_id": signal_id,
            "occurred_at": occurred_at,
            "site_id": "40000000-0000-4000-8000-000000000001",
            "camera_id": "synthetic-camera",
            "direction": direction,
            "resolution": "matched",
            "employee_id": employee_id,
            "method": "badge",
        }
        self.attendance.enqueue(signal)
        self.attendance.process_pending()
        with sqlite3.connect(self.database_path) as connection:
            return connection.execute(
                "SELECT outcome FROM processing_results WHERE signal_id=?", (signal_id,)
            ).fetchone()[0]

    def dashboard_with_token(self, token):
        try:
            principal = verify_token(token, self.auth_config, self.clock())
        except TokenError as error:
            raise PermissionError("OIDC login required") from error
        roles = principal.roles.intersection({"operator", "reviewer", "admin"})
        if principal.principal_type != "user" or "dashboard:read" not in principal.scopes or not roles:
            raise PermissionError("dashboard role required")
        return self.dashboard(actor=principal.subject, roles=roles)

    def dashboard(self, *, actor, roles):
        with sqlite3.connect(self.database_path) as connection:
            attendance = [
                {
                    "id": row[0],
                    "employee_id": row[1],
                    "site_id": row[2],
                    "occurred_at": row[3],
                    "status": "matched",
                    "kind": row[4],
                    "source": row[5],
                }
                for row in connection.execute(
                    "SELECT attendance_id, employee_id, site_id, occurred_at, kind, method FROM attendance_records"
                )
            ]
            reviews = [
                {
                    "id": row[0],
                    "status": "review_required",
                    "reason": row[1],
                }
                for row in connection.execute(
                    "SELECT review_id, reason FROM review_cases WHERE status='open'"
                )
            ]
            pending = connection.execute(
                "SELECT COUNT(*) FROM durable_queue WHERE status='pending'"
            ).fetchone()[0]
        client = DashboardClient(
            attendance=attendance,
            reviews=reviews,
            health={"status": "ready"},
            queue={"pending": pending},
            authorized_roles={"operator", "reviewer", "admin"},
        )
        return OperatorDashboard(client, actor=actor, roles=roles).render()

    def backup(self, destination):
        return self.backups.create(self.database_path, destination)

    def restore(self, artifact, target, authorization):
        return self.backups.restore(
            artifact.database_path, artifact.manifest_path, target, authorization
        )

    def close(self):
        self.attendance.close()
        self.app.close()

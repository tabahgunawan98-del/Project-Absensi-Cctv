"""Accessible operator dashboard renderer using the verified synthetic contract.

The module intentionally renders server-side HTML only. It does not expose media,
face embeddings, tokens, or biometric templates to the browser.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SENSITIVE_KEYS = {
    "embedding",
    "face_vector",
    "template",
    "image",
    "media",
    "media_ref_id",
    "payload",
    "raw_payload",
    "token",
    "authorization",
    "secret",
}


class DashboardApiError(Exception):
    """Raised when the dashboard contract cannot be loaded."""


@dataclass(init=False)
class DashboardClient:
    """In-memory client that mirrors the minimum dashboard API contract."""

    attendance: list[dict]
    reviews: list[dict]
    health: dict
    queue: dict
    authorized_roles: frozenset[str] | set[str]
    _audit: tuple[dict, ...]
    _next_error: str | None
    fetch_count: int

    def __init__(
        self,
        attendance=None,
        reviews=None,
        health=None,
        queue=None,
        audit=(),
        authorized_roles=frozenset({"operator"}),
    ):
        self.attendance = [self._redact(deepcopy(item)) for item in (attendance or [])]
        self.reviews = [self._redact(deepcopy(item)) for item in (reviews or [])]
        self.health = self._redact(deepcopy(health or {}))
        self.queue = self._redact(deepcopy(queue or {}))
        self._audit = tuple(self._redact(deepcopy(item)) for item in audit)
        self.authorized_roles = frozenset(authorized_roles)
        self._next_error = None
        self.fetch_count = 0

    @property
    def audit(self):
        return tuple(deepcopy(item) for item in self._audit)

    def fetch_dashboard(self, filters: dict | None = None):
        self.fetch_count += 1
        if self._next_error:
            message = self._next_error
            self._next_error = None
            raise DashboardApiError(message)
        filters = filters or {}
        attendance = [item for item in self.attendance if self._matches(item, filters)]
        reviews = [item for item in self.reviews if self._matches(item, filters)]
        return {
            "attendance": [self._redact(item) for item in attendance],
            "reviews": [self._redact(item) for item in reviews],
            "health": dict(self.health),
            "queue": dict(self.queue),
            "audit": [self._redact(item) for item in self._audit],
        }

    def fail_next(self, message):
        self._next_error = message

    def review(self, review_id, action, *, employee_id=None, actor=None, actor_roles=None, reason=None):
        self._authorize(actor_roles)
        if action not in {"approve", "reject", "correct"}:
            raise ValueError("review action invalid")
        if not reason or not reason.strip():
            raise ValueError("reason required")
        if action in {"approve", "correct"} and not self._valid_employee(employee_id):
            raise ValueError("employee_id required")
        row = self._find_review(review_id)
        if row is None:
            raise ValueError("open review not found")
        status = "resolved"
        audit_action = f"human_review {action}"
        row["status"] = status
        if self._valid_employee(employee_id):
            row["employee_id"] = employee_id.strip()
        self._append_audit({
            "actor": actor,
            "action": audit_action,
            "review_id": review_id,
            "reason": reason.strip(),
        })
        return {"status": status, "review_id": review_id}

    def correct_attendance(self, attendance_id, *, employee_id=None, actor=None, actor_roles=None, reason=None):
        self._authorize(actor_roles)
        if not reason or not reason.strip():
            raise ValueError("reason required")
        if not self._valid_employee(employee_id):
            raise ValueError("employee_id required")
        for row in self.attendance:
            if row.get("id") == attendance_id:
                row["employee_id"] = employee_id.strip()
                row["corrected"] = True
                self._append_audit({
                    "actor": actor,
                    "action": "manual_correction",
                    "attendance_id": attendance_id,
                    "reason": reason.strip(),
                })
                return {"status": "corrected", "attendance_id": attendance_id}
        raise ValueError("attendance not found")

    def _authorize(self, actor_roles):
        roles = frozenset(actor_roles or ())
        if not roles.intersection(self.authorized_roles):
            raise PermissionError("backend authorization required")

    @staticmethod
    def _valid_employee(employee_id):
        return isinstance(employee_id, str) and bool(employee_id.strip())

    def _append_audit(self, entry):
        self._audit = self._audit + (self._redact(deepcopy(entry)),)

    def _find_review(self, review_id):
        for row in self.reviews:
            if row.get("id") == review_id and row.get("status") in {"unknown", "review_required", "open"}:
                return row
        return None

    @classmethod
    def _matches(cls, item, filters):
        date = filters.get("date")
        if date and cls._local_date(item.get("occurred_at"), filters.get("timezone")) != date:
            return False
        for key in ("site_id", "status"):
            if filters.get(key) and item.get(key) != filters[key]:
                return False
        return True

    @staticmethod
    def _local_date(occurred_at, timezone_name):
        if not isinstance(occurred_at, str):
            return None
        try:
            zone = ZoneInfo(timezone_name or "UTC")
        except ZoneInfoNotFoundError:
            zone = ZoneInfo("UTC")
        try:
            instant = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        return instant.astimezone(zone).date().isoformat()

    @classmethod
    def _redact(cls, value):
        if isinstance(value, dict):
            redacted = {}
            for key, item in value.items():
                lowered = key.lower()
                if lowered in SENSITIVE_KEYS or any(token in lowered for token in SENSITIVE_KEYS):
                    continue
                redacted[key] = cls._redact(item)
            return redacted
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        return value


class SyntheticDashboardApi(DashboardClient):
    def __init__(self, empty=False):
        if empty:
            super().__init__(attendance=[], reviews=[], health={"status": "ready"}, queue={"pending": 0})
            return
        super().__init__(
            attendance=[
                {
                    "id": "att-1",
                    "employee_id": "EMP-001",
                    "site_id": "site-a",
                    "occurred_at": "2026-09-18T00:30:00Z",
                    "local_time": "2026-09-18 07:30",
                    "timezone": "Asia/Jakarta",
                    "status": "matched",
                    "kind": "check_in",
                    "source": "badge",
                    "dedupe": False,
                    "token": "secret-token",
                    "embedding": [0.1, 0.2],
                },
                {
                    "id": "att-2",
                    "employee_id": "EMP-001",
                    "site_id": "site-a",
                    "occurred_at": "2026-09-18T00:31:00Z",
                    "local_time": "2026-09-18 07:31",
                    "timezone": "Asia/Jakarta",
                    "status": "duplicate_window",
                    "kind": "check_in",
                    "source": "qr",
                    "dedupe": True,
                },
                {
                    "id": "att-3",
                    "employee_id": "EMP-004",
                    "site_id": "site-b",
                    "occurred_at": "2026-09-18T01:30:00Z",
                    "local_time": "2026-09-18 08:30",
                    "timezone": "Asia/Jakarta",
                    "status": "matched",
                    "kind": "check_out",
                    "source": "manual",
                },
            ],
            reviews=[
                {
                    "id": "unknown-1",
                    "site_id": "site-a",
                    "occurred_at": "2026-09-18T00:32:00Z",
                    "status": "unknown",
                    "resolution": "unknown",
                    "reason": "identity_unavailable",
                    "source": "face",
                    "employee_id": None,
                    "image": "redacted-by-contract",
                },
                {
                    "id": "review-1",
                    "site_id": "site-a",
                    "occurred_at": "2026-09-18T00:33:00Z",
                    "status": "review_required",
                    "resolution": "review_required",
                    "reason": "ambiguous_candidates",
                    "source": "face",
                    "employee_id": None,
                    "face_vector": [1, 1, 0],
                },
            ],
            health={"status": "ready"},
            queue={"pending": 2, "oldest_age_seconds": 40},
        )


class OperatorDashboard:
    def __init__(self, client, *, actor, roles):
        self.client = client
        self.actor = actor
        self.roles = set(roles)

    def render(self, filters: dict | None = None, *, loading=False):
        filters = filters or {}
        if loading:
            return '<section role="status" aria-busy="true">Loading dashboard...</section>'
        warning = ""
        try:
            data = self.client.fetch_dashboard(filters)
        except DashboardApiError as error:
            warning = f'<section role="alert">{escape(str(error))}</section><button type="button">Retry</button>'
            try:
                data = self.client.fetch_dashboard(filters)
            except DashboardApiError:
                return self._error(str(error))
        return warning + self._content(data, filters)

    def review(self, review_id, action, *, employee_id=None, reason=None):
        self._require_operator()
        return self.client.review(
            review_id,
            action,
            employee_id=employee_id,
            actor=self.actor,
            actor_roles=self.roles,
            reason=reason,
        )

    def correct_attendance(self, attendance_id, *, employee_id=None, reason=None):
        self._require_operator()
        return self.client.correct_attendance(
            attendance_id,
            employee_id=employee_id,
            actor=self.actor,
            actor_roles=self.roles,
            reason=reason,
        )

    def _require_operator(self):
        if "operator" not in self.roles:
            raise PermissionError("backend authorization required; UI action forbidden")

    def _content(self, data, filters):
        timezone = escape(filters.get("timezone") or "UTC")
        body = [
            '<main aria-labelledby="dashboard-title" aria-busy="false">',
            '<section role="status" aria-busy="false">Dashboard loaded</section>',
            '<h1 id="dashboard-title">Operator attendance dashboard</h1>',
            '<p>RBAC UI only adds a guard; backend authorization remains authoritative.</p>',
            '<p>No payroll or sanctions are automated.</p>',
            f'<p>Health: {escape(data["health"].get("status", "unknown"))}</p>',
            f'<p>Queue: {int(data["queue"].get("pending", 0))} pending</p>',
            self._filters(timezone),
            self._attendance(data["attendance"]),
            self._reviews(data["reviews"]),
            self._audit(data["audit"]),
            "</main>",
        ]
        return "".join(body)

    @staticmethod
    def _filters(timezone):
        return (
            '<form aria-label="Attendance filters">'
            '<label for="filter-date">Tanggal</label><input id="filter-date" name="date" type="date" />'
            '<label for="filter-site">Site</label><input id="filter-site" name="site_id" />'
            '<label for="filter-status">Status</label><select id="filter-status" name="status">'
            '<option value="">All</option><option>unknown</option><option>review_required</option><option>matched</option>'
            '</select>'
            f'<p>Timezone: {timezone}</p>'
            '</form>'
        )

    def _attendance(self, rows):
        if not rows:
            return '<section><h2>Attendance</h2><p>No attendance events match.</p></section>'
        items = ['<section><h2>Attendance</h2><ul>']
        for row in rows:
            source = self._source_label(row.get("source"))
            dedupe = "Duplicate window" if row.get("dedupe") or row.get("status") == "duplicate_window" else "Unique"
            items.append(
                '<li tabindex="0">'
                f'{escape(row.get("id", ""))} {escape(row.get("employee_id", ""))} '
                f'{escape(row.get("kind", ""))} {escape(row.get("site_id", ""))} '
                f'{source} <span>{dedupe}</span>'
                '</li>'
            )
        items.append("</ul></section>")
        return "".join(items)

    def _reviews(self, rows):
        if not rows:
            return '<section><h2>Human review</h2><p>No review cases open.</p></section>'
        controls = "" if "operator" in self.roles else "<p>Review controls unavailable</p>"
        items = ['<section><h2>Human review</h2>', controls, '<ul>']
        for row in rows:
            review_id = str(row.get("id", ""))
            safe_id = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in review_id)
            reason_id = f"review-{safe_id}-reason"
            error_id = f"review-{safe_id}-reason-error"
            employee_id = f"review-{safe_id}-employee"
            action_id = f"review-{safe_id}-action"
            employee = row.get("employee_id") or "No employee selected"
            items.append(
                '<li tabindex="0" role="group" aria-label="Human review case">'
                f'{escape(review_id)} {escape(row.get("status", ""))} '
                f'{escape(row.get("site_id", ""))} {escape(row.get("reason", ""))} {escape(employee)}'
                f'<label for="{employee_id}">Employee</label>'
                f'<select id="{employee_id}" name="employee_id">'
                '<option value="">Select employee</option><option value="EMP-001">EMP-001</option>'
                '<option value="EMP-002">EMP-002</option><option value="EMP-003">EMP-003</option>'
                '</select>'
                f'<label for="{reason_id}">Reason</label>'
                f'<input id="{reason_id}" aria-describedby="{error_id}" required />'
                f'<span id="{error_id}">Reason is required for approve, reject, or correct.</span>'
                f'<button id="{action_id}-approve" type="button" value="approve">Approve</button>'
                f'<button id="{action_id}-reject" type="button" value="reject">Reject</button>'
                f'<button id="{action_id}-correct" type="button" value="correct">Correct</button>'
                '</li>'
            )
        items.append("</ul></section>")
        return "".join(items)

    @staticmethod
    def _audit(rows):
        if not rows:
            return '<section><h2>Audit trail</h2><p>Audit trail empty.</p></section>'
        items = ['<section><h2>Audit trail</h2><ul>']
        for row in rows:
            items.append(
                '<li>'
                f'{escape(str(row.get("actor", "")))} {escape(str(row.get("action", "")))} '
                f'{escape(str(row.get("reason", "")))}'
                '</li>'
            )
        items.append("</ul></section>")
        return "".join(items)

    @staticmethod
    def _source_label(source):
        labels = {"badge": "Badge", "qr": "QR", "manual": "Manual", "manual_review": "Manual", "face": "Face signal"}
        return f'<span class="source-badge">{escape(labels.get(source, "Unknown source"))}</span>'

    @staticmethod
    def _error(message):
        return (
            '<main aria-busy="false">'
            f'<section role="alert">{escape(message)}</section>'
            '<button type="button">Retry</button>'
            '</main>'
        )

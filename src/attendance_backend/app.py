"""Minimal contract-v2 ingest core with SQLite persistence."""

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from http import HTTPStatus
from dataclasses import dataclass, field
from pathlib import Path

import rfc8785
from jsonschema import Draft202012Validator

from .invariants import InvariantError, check_invariants, parse_strict_json

MACHINE_PATHS = {"/v2/events", "/v2/machine-events"}
BATCH_PATHS = {"/v2/events/batch", "/v2/machine-event-batches"}
MANUAL_PATH = "/v2/manual-attendance-events"


@dataclass(frozen=True)
class Response:
    status: int
    json: dict
    headers: dict = field(default_factory=dict)


class RequestError(Exception):
    def __init__(self, status, code, title, event_id=None, retry_after=None):
        super().__init__(title)
        self.status = status
        self.code = code
        self.title = title
        self.event_id = event_id
        self.retry_after = retry_after


class App:
    def __init__(self, database_path, auth_config=None, limits=None, clock=None):
        self.database_path = str(database_path)
        self.auth_config = auth_config
        self.limits = limits or __import__('attendance_backend.limits', fromlist=['Limits']).Limits()
        self.clock = clock or __import__('time').time
        # Installed packages don't keep the repo layout, so allow an explicit
        # path; the repo-relative default still works for tests and dev.
        schema_path = Path(
            os.environ.get(
                "ABSENSI_CONTRACT_DIR", Path(__file__).parents[2] / "contract"
            )
        ) / "event.schema.json"
        self.schema = json.loads(schema_path.read_text())
        self.validator = Draft202012Validator(self.schema)
        self._closed = False
        self._schema_ready = True
        self._write_lock = threading.Lock()
        self._rate_limiter = None
        if auth_config:
            from .limits import RateLimiter
            self._rate_limiter = RateLimiter(self.limits, self.clock)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload_sha256 TEXT NOT NULL,
                    canonical_json BLOB NOT NULL,
                    event_type TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    actor_subject TEXT
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at REAL NOT NULL,
                    principal_type TEXT NOT NULL,
                    subject TEXT,
                    client_id TEXT,
                    path TEXT NOT NULL,
                    event_type TEXT,
                    event_id TEXT,
                    requested_site_id TEXT,
                    verified_site_ids TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    code TEXT
                )"""
            )
            audit_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(audit_log)")
            }
            if "site_id" in audit_columns and "requested_site_id" not in audit_columns:
                connection.execute("ALTER TABLE audit_log RENAME COLUMN site_id TO requested_site_id")
            if "verified_site_ids" not in audit_columns:
                connection.execute(
                    "ALTER TABLE audit_log ADD COLUMN verified_site_ids TEXT NOT NULL DEFAULT '[]'"
                )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS audit_immutable
                   BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"""
            )
            connection.execute(
                """CREATE TRIGGER IF NOT EXISTS audit_no_delete
                   BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"""
            )

    def __call__(self, environ, start_response):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length)
        headers = {key: value for key, value in environ.items() if key.startswith("HTTP_")}
        response = self.handle(environ["REQUEST_METHOD"], environ.get("PATH_INFO", ""), raw, headers)
        body = json.dumps(response.json, separators=(",", ":")).encode()
        status = f"{response.status} {HTTPStatus(response.status).phrase}"
        content_type = "application/problem+json" if response.status >= 400 else "application/json"
        response_headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            *response.headers.items(),
        ]
        start_response(status, response_headers)
        return [body]

    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def close(self):
        self._closed = True

    def event_count(self):
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def handle(self, method, path, raw=b"", headers=None):
        headers = headers or {}
        if method == "GET" and path == "/health/live":
            return Response(200, {"status": "live"})
        if method == "GET" and path == "/health/ready":
            return self._ready()
        if method != "POST" or path not in MACHINE_PATHS | BATCH_PATHS | {MANUAL_PATH}:
            return self._problem(RequestError(404, "resource_not_found", "Not found"))

        if self.limits and len(raw) > self.limits.max_request_bytes:
            return self._problem(RequestError(413, "request_too_large", "Request too large"))

        try:
            principal = self._authenticate(headers)

            if self._rate_limiter:
                key = f"{principal.principal_type}:{principal.client_id or principal.subject}"
                retry_after = self._rate_limiter.check(key)
                if retry_after:
                    raise RequestError(429, "rate_limited", "Rate limit exceeded", retry_after=retry_after)

            if path in BATCH_PATHS:
                envelope = self._parse(raw)
                if self.limits and isinstance(envelope.get("items"), list) and len(envelope["items"]) > self.limits.max_batch_items:
                    raise RequestError(413, "request_too_large", "Batch too large")
                self._require_base_authorization(principal, "machine", "events:write")
                return self._batch(raw, principal, path)

            event = self._parse(raw)
            required_type, scope = (
                ("user", "attendance:manual") if path == MANUAL_PATH else ("machine", "events:write")
            )
            self._authorize(principal, required_type, scope, event)
            key = headers.get("HTTP_IDEMPOTENCY_KEY")
            if key != event.get("event_id"):
                raise RequestError(400, "idempotency_mismatch", "Idempotency-Key must equal event_id", event.get("event_id"))
            self._validate(event)
            return self._store(event, principal, path)
        except RequestError as error:
            if error.status >= 400 and self.auth_config and 'principal' in locals():
                with self._connect() as connection:
                    event_id = getattr(error, 'event_id', None)
                    event_type = event.get("event_type") if 'event' in locals() and isinstance(event, dict) else None
                    site_id = event.get("site_id") if 'event' in locals() and isinstance(event, dict) else None
                    self._audit(connection, principal, path, event_type, event_id, site_id, "rejected", error.code)
                    connection.commit()
            if error.retry_after is not None:
                return self._throttled(error)
            return self._problem(error)

    def _parse(self, raw):
        try:
            value = parse_strict_json(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, InvariantError) as error:
            raise RequestError(400, "malformed_json", "Malformed JSON") from error
        if not isinstance(value, dict):
            raise RequestError(400, "schema_invalid", "JSON body must be an object")
        return value

    def _authenticate(self, headers):
        if self.auth_config is None:
            # Phase 1 fallback for existing tests
            return self._principal_legacy(headers)
        bearer = headers.get("HTTP_AUTHORIZATION", "")
        if not bearer or not bearer.startswith("Bearer "):
            raise RequestError(401, "authentication_required", "Authentication required")
        token = bearer[7:] if bearer.startswith("Bearer ") else ""
        if not token:
            raise RequestError(401, "authentication_required", "Authentication required")
        from .auth import TokenError, verify_token
        try:
            principal = verify_token(token, self.auth_config, self.clock())
        except TokenError as error:
            raise RequestError(401, error.code, error.title) from error
        return principal

    def _principal_legacy(self, headers):
        """Phase 1 X-Principal test stand-in; remove after phase 2 ships."""
        raw = headers.get("HTTP_X_PRINCIPAL")
        if not raw:
            raise RequestError(401, "authentication_required", "Authentication required")
        try:
            principal = json.loads(raw)
        except json.JSONDecodeError as error:
            raise RequestError(401, "token_invalid", "Verified principal context invalid") from error
        if not isinstance(principal, dict):
            raise RequestError(401, "token_invalid", "Verified principal context invalid")

        @dataclass(frozen=True)
        class LegacyPrincipal:
            principal_type: str
            subject: str | None
            client_id: str | None
            scopes: frozenset
            event_types: frozenset
            sites: frozenset
            roles: frozenset = frozenset()

        return LegacyPrincipal(
            principal_type=principal.get("principal_type"),
            subject=principal.get("subject"),
            client_id=None,
            scopes=frozenset(principal.get("scopes", [])),
            event_types=frozenset(principal.get("event_types", [])),
            sites=frozenset(principal.get("sites", [])),
            roles=frozenset(principal.get("roles", [])),
        )

    def _require_base_authorization(self, principal, principal_type, scope):
        if principal.principal_type != principal_type:
            raise RequestError(403, "principal_event_denied", "Principal type denied")
        if scope not in principal.scopes and scope not in principal.roles:
            raise RequestError(403, "scope_denied", "Scope denied")
        if principal_type == "user" and not principal.subject:
            raise RequestError(401, "token_invalid", "Human subject required")

    def _authorize(self, principal, principal_type, scope, event):
        event_id = event.get("event_id")
        event_type = event.get("event_type")
        self._require_base_authorization(principal, principal_type, scope)
        endpoint_types = {
            "machine": {"observation.detected.v2", "identity.resolved.v2"},
            "user": {"attendance.manual.v2"},
        }
        if event_type not in endpoint_types[principal_type] or event_type not in principal.event_types:
            raise RequestError(403, "principal_event_denied", "Event type denied", event_id)
        if event.get("site_id") not in principal.sites:
            raise RequestError(403, "site_denied", "Site denied", event_id)

    def _validate(self, event):
        errors = sorted(self.validator.iter_errors(event), key=lambda error: list(error.path))
        if errors:
            raise RequestError(400, "schema_invalid", "Event schema invalid", event.get("event_id"))
        try:
            check_invariants(event)
        except InvariantError as error:
            raise RequestError(400, error.code, "Event invariant violated", event.get("event_id")) from error

    @staticmethod
    def _canonical(event):
        return rfc8785.dumps(event)

    def _store(self, event, principal, path):
        canonical = self._canonical(event)
        digest = hashlib.sha256(canonical).hexdigest()
        event_id = event["event_id"]
        event_type = event["event_type"]
        site_id = event["site_id"]

        with self._write_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT payload_sha256 FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row:
                outcome = "duplicate"
                code = None
                if row[0] != digest:
                    outcome = "rejected"
                    code = "event_id_conflict"
                connection.rollback()
                self._audit(connection, principal, path, event_type, event_id, site_id, outcome, code)
                connection.commit()
                if code:
                    raise RequestError(409, "event_id_conflict", "event_id already has a different payload", event_id)
                return Response(200, self._result(event_id, "duplicate", digest))
            connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, digest, canonical, event_type, site_id, principal.subject),
            )
            self._audit(connection, principal, path, event_type, event_id, site_id, "accepted", None)
            connection.commit()
        return Response(202, self._result(event_id, "accepted", digest))

    def _audit(self, connection, principal, path, event_type, event_id, requested_site_id, outcome, code):
        verified_site_ids = json.dumps(sorted(principal.sites), separators=(",", ":"))
        connection.execute(
            "INSERT INTO audit_log (recorded_at, principal_type, subject, client_id, path, event_type, event_id, requested_site_id, verified_site_ids, outcome, code)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (self.clock(), principal.principal_type, principal.subject, principal.client_id,
             path, event_type, event_id, requested_site_id, verified_site_ids, outcome, code),
        )

    @staticmethod
    def _result(event_id, outcome, digest):
        return {
            "event_id": event_id,
            "outcome": outcome,
            "payload_sha256": digest,
            "canonicalization": "jcs-rfc8785-v1",
        }

    def _batch(self, raw, principal, path):
        envelope = self._parse(raw)
        if set(envelope) != {"batch_id", "items"} or not self._valid_event_id(envelope.get("batch_id")) or not isinstance(envelope.get("items"), list) or not envelope["items"] or any(not isinstance(item, dict) for item in envelope["items"]):
            raise RequestError(400, "schema_invalid", "Batch envelope invalid")
        results = []
        for index, event in enumerate(envelope["items"]):
            event_id = self._valid_event_id(event.get("event_id")) if isinstance(event, dict) else None
            event_type = event.get("event_type") if isinstance(event, dict) else None
            site_id = event.get("site_id") if isinstance(event, dict) else None
            outcome = "rejected"
            code = None
            try:
                if not isinstance(event, dict):
                    raise RequestError(400, "schema_invalid", "Batch item must be an object")
                self._authorize(principal, "machine", "events:write", event)
                self._validate(event)
                stored = self._store(event, principal, path)
                results.append({"index": index, **stored.json})
            except RequestError as error:
                code = error.code
                with self._connect() as connection:
                    self._audit(connection, principal, path, event_type, event_id, site_id, outcome, code)
                results.append({
                    "index": index,
                    "event_id": event_id,
                    "outcome": "rejected",
                    "error": self._problem_body(error),
                })
        return Response(200, {"batch_id": envelope["batch_id"], "results": results})

    @staticmethod
    def _valid_event_id(value):
        try:
            return value if str(uuid.UUID(value)) == value else None
        except (ValueError, TypeError, AttributeError):
            return None

    def _ready(self):
        if self._closed or not self._schema_ready:
            return Response(503, {"status": "not_ready"})
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("SELECT 1")
                connection.rollback()
        except sqlite3.Error:
            return Response(503, {"status": "not_ready"})
        return Response(200, {"status": "ready"})

    @staticmethod
    def _problem_body(error):
        return {
            "type": f"urn:absensi:error:{error.code}",
            "title": error.title,
            "status": error.status,
            "code": error.code,
            "request_id": str(uuid.uuid4()),
            "event_id": error.event_id,
            "retryable": False,
        }

    def _problem(self, error):
        return Response(error.status, self._problem_body(error))

    def _throttled(self, error):
        body = self._problem_body(error)
        body["retryable"] = True
        body["retry_after_seconds"] = error.retry_after
        return Response(error.status, body, headers={"Retry-After": str(error.retry_after)})

"""Phase 2 boundary tests: JWT auth, request limits, audit log.

All fixtures are synthetic; keys are generated per test run.
"""

import base64
import copy
import hashlib
import hmac
import json
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

from attendance_backend.app import App
from attendance_backend.auth import AuthConfig
from attendance_backend.limits import Limits

from tests.test_api import SITE, OTHER_SITE, manual, observation

ISSUER = "https://identity.test.invalid"
AUDIENCE = "absensi-ingress"
KID = "test-key-1"
NOW = 1_800_000_000.0


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def token(secret, *, kid=KID, alg="HS256", iss=ISSUER, aud=AUDIENCE, grant="client_credentials",
          sub=None, client_id="camera-adapter-1", scope="events:write",
          event_types=("observation.detected.v2",), sites=(SITE,), exp=NOW + 300, nbf=None,
          sign_with=None):
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    claims = {
        "iss": iss,
        "aud": aud,
        "grant_type": grant,
        "client_id": client_id,
        "scope": scope,
        "absensi.event_types": list(event_types),
        "absensi.sites": list(sites),
        "exp": exp,
    }
    if sub is not None:
        claims["sub"] = sub
    if nbf is not None:
        claims["nbf"] = nbf
    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    signature = hmac.new(sign_with or secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(signature)}"


class Phase2Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "events.sqlite3"
        self.secret = secrets.token_bytes(32)
        self.config = AuthConfig(issuer=ISSUER, audience=AUDIENCE, keys={KID: self.secret})
        self.limits = Limits(max_request_bytes=4096, max_batch_items=3,
                             max_requests_per_window=5, window_seconds=60)
        self.now = NOW
        self.app = App(self.database, auth_config=self.config, limits=self.limits,
                       clock=lambda: self.now)
        self.machine_token = token(self.secret)
        self.user_token = token(
            self.secret, grant="authorization_code", sub="operator-1", client_id="hr-console",
            scope="attendance:manual", event_types=("attendance.manual.v2",),
        )

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    def request(self, path, body=None, bearer=None, idem=None, raw=None, method=None):
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        headers = {}
        if bearer is not None:
            headers["HTTP_AUTHORIZATION"] = f"Bearer {bearer}"
        if idem:
            headers["HTTP_IDEMPOTENCY_KEY"] = idem
        method = method or ("POST" if payload else "GET")
        return self.app.handle(method, path, payload, headers)

    def audit(self):
        with sqlite3.connect(self.database) as connection:
            return connection.execute(
                "SELECT principal_type, subject, client_id, path, event_type, event_id,"
                " requested_site_id, verified_site_ids, outcome, code FROM audit_log ORDER BY seq"
            ).fetchall()

    # 1. surface parity / not-found code
    def test_declared_aliases_and_not_found_code(self):
        event = observation()
        for path in ("/v2/events", "/v2/machine-events"):
            fresh = copy.deepcopy(event)
            fresh["event_id"] = f"10000000-0000-4000-8000-00000000002{path.count('m')}"
            response = self.request(path, fresh, self.machine_token, fresh["event_id"])
            self.assertEqual(response.status, 202, path)
        missing = self.request("/v2/unknown", {}, self.machine_token, method="POST")
        self.assertEqual((missing.status, missing.json["code"]), (404, "resource_not_found"))

    # 2. real authentication
    def test_missing_and_malformed_authorization_header(self):
        event = observation()
        for bearer, code, status in (
            (None, "authentication_required", 401),
            ("", "authentication_required", 401),
            ("not-a-jwt", "token_invalid", 401),
            (token(self.secret, alg="none"), "token_invalid", 401),
            (token(self.secret, kid="unknown-kid"), "token_invalid", 401),
            (token(self.secret, sign_with=secrets.token_bytes(32)), "token_invalid", 401),
            (token(self.secret, iss="https://evil.invalid"), "token_invalid", 401),
            (token(self.secret, aud="other-api"), "token_invalid", 401),
            (token(self.secret, exp=NOW - 3600), "token_invalid", 401),
            (token(self.secret, nbf=NOW + 3600), "token_invalid", 401),
        ):
            response = self.request("/v2/events", event, bearer, event["event_id"])
            self.assertEqual((response.status, response.json["code"]), (status, code), bearer)
        self.assertEqual(self.app.event_count(), 0)

    def test_clock_skew_tolerated_within_configured_window(self):
        event = observation()
        just_expired = token(self.secret, exp=self.now - 30)
        response = self.request("/v2/events", event, just_expired, event["event_id"])
        self.assertEqual(response.status, 202)

    def test_scope_event_and_site_binding_from_claims(self):
        event = observation()
        for bearer, code in (
            (token(self.secret, scope="events:read"), "scope_denied"),
            (token(self.secret, event_types=("identity.resolved.v2",)), "principal_event_denied"),
            (token(self.secret, sites=(OTHER_SITE,)), "site_denied"),
        ):
            response = self.request("/v2/events", event, bearer, event["event_id"])
            self.assertEqual((response.status, response.json["code"]), (403, code))
        self.assertEqual(self.app.event_count(), 0)

    def test_body_actor_never_grants_authorization(self):
        forged = observation()
        forged["subject"] = "ceo"
        forged["site_id"] = OTHER_SITE
        response = self.request("/v2/events", forged, self.machine_token, forged["event_id"])
        self.assertEqual((response.status, response.json["code"]), (403, "site_denied"))

        accepted_manual = manual()
        accepted_manual["payload"]["reason"] = "Synthetic actor spoof attempt"
        stored = self.request("/v2/manual-attendance-events", accepted_manual, self.user_token,
                              accepted_manual["event_id"])
        self.assertEqual(stored.status, 202)
        self.assertEqual([row[1] for row in self.audit() if row[3] == "/v2/manual-attendance-events"],
                         ["operator-1"])

    def test_throttle_boundary_conditions(self):
        limit = self.limits.max_requests_per_window
        for index in range(limit + 2):
            event = observation(f"10000000-0000-4000-8000-00000000007{index}")
            response = self.request("/v2/events", event, self.machine_token, event["event_id"])
            if index < limit:
                self.assertEqual(response.status, 202, f"Request {index+1}/{limit} should be accepted")
            else:
                self.assertEqual(response.status, 429, f"Request {index+1}/{limit} should be throttled")
        self.assertEqual(self.app.event_count(), limit)

    def test_manual_rejects_client_credentials_token(self):
        event = manual()
        service = token(self.secret, scope="attendance:manual",
                        event_types=("attendance.manual.v2",))
        denied = self.request("/v2/manual-attendance-events", event, service, event["event_id"])
        self.assertEqual((denied.status, denied.json["code"]), (403, "principal_event_denied"))
        accepted = self.request("/v2/manual-attendance-events", event, self.user_token,
                                event["event_id"])
        self.assertEqual(accepted.status, 202)

    def test_user_token_without_subject_is_invalid(self):
        event = manual()
        anonymous = token(self.secret, grant="authorization_code", scope="attendance:manual",
                          event_types=("attendance.manual.v2",))
        response = self.request("/v2/manual-attendance-events", event, anonymous, event["event_id"])
        self.assertEqual((response.status, response.json["code"]), (401, "token_invalid"))

    # 3. request limits
    def test_oversized_request_and_batch_count_rejected_before_storage(self):
        event = observation()
        event["payload"]["track_id"] = "t" * 5000
        too_big = self.request("/v2/events", event, self.machine_token, event["event_id"])
        self.assertEqual((too_big.status, too_big.json["code"]), (413, "request_too_large"))

        items = [observation(f"10000000-0000-4000-8000-00000000003{index}") for index in range(4)]
        batch = self.request("/v2/events/batch",
                             {"batch_id": "a0000000-0000-4000-8000-000000000002", "items": items},
                             self.machine_token)
        self.assertEqual((batch.status, batch.json["code"]), (413, "request_too_large"))
        self.assertEqual(self.app.event_count(), 0)

    def test_throttle_returns_retry_after_and_throttled_problem(self):
        responses = []
        for index in range(7):
            event = observation(f"10000000-0000-4000-8000-00000000004{index}")
            responses.append(self.request("/v2/events", event, self.machine_token, event["event_id"]))
        accepted = [response for response in responses if response.status == 202]
        throttled = [response for response in responses if response.status == 429]
        self.assertEqual((len(accepted), len(throttled)), (5, 2))
        problem = throttled[0]
        self.assertEqual(problem.json["code"], "rate_limited")
        self.assertTrue(problem.json["retryable"])
        self.assertGreaterEqual(problem.json["retry_after_seconds"], 1)
        self.assertEqual(problem.headers["Retry-After"], str(problem.json["retry_after_seconds"]))
        self.assertEqual(self.app.event_count(), 5)

        self.now += self.limits.window_seconds
        event = observation("10000000-0000-4000-8000-000000000049")
        self.assertEqual(self.request("/v2/events", event, self.machine_token, event["event_id"]).status, 202)

    def test_wsgi_forwards_retry_after_header(self):
        for index in range(self.limits.max_requests_per_window):
            event = observation(f"10000000-0000-4000-8000-00000000008{index}")
            self.request("/v2/events", event, self.machine_token, event["event_id"])
        event = observation("10000000-0000-4000-8000-000000000089")
        raw = json.dumps(event).encode()
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v2/events",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": __import__("io").BytesIO(raw),
            "HTTP_AUTHORIZATION": f"Bearer {self.machine_token}",
            "HTTP_IDEMPOTENCY_KEY": event["event_id"],
        }
        metadata = {}
        body = b"".join(self.app(environ, lambda status, headers: metadata.update(
            status=status, headers=dict(headers))))
        problem = json.loads(body)
        self.assertEqual(metadata["status"], "429 Too Many Requests")
        self.assertEqual(metadata["headers"]["Retry-After"], str(problem["retry_after_seconds"]))

    def test_regular_problem_has_no_throttle_fields_or_header(self):
        event = observation()
        denied_token = token(self.secret, scope="events:read")
        response = self.request("/v2/events", event, denied_token, event["event_id"])
        self.assertEqual((response.status, response.json["code"]), (403, "scope_denied"))
        self.assertFalse(response.json["retryable"])
        self.assertNotIn("retry_after_seconds", response.json)
        self.assertNotIn("Retry-After", response.headers)

    # 4. audit log
    def test_audit_separates_requested_site_from_verified_claims(self):
        denied = observation("10000000-0000-4000-8000-000000000050")
        denied["site_id"] = OTHER_SITE
        response = self.request("/v2/events", denied, self.machine_token, denied["event_id"])
        self.assertEqual((response.status, response.json["code"]), (403, "site_denied"))
        row = self.audit()[0]
        self.assertEqual(row[6], OTHER_SITE)
        self.assertEqual(json.loads(row[7]), [SITE])
        self.assertNotEqual(row[6], json.loads(row[7])[0])

    def test_audit_log_records_verified_claims_and_is_append_only(self):
        event = observation()
        self.request("/v2/events", event, self.machine_token, event["event_id"])
        denied = observation("10000000-0000-4000-8000-000000000051")
        denied["site_id"] = OTHER_SITE
        self.request("/v2/events", denied, self.machine_token, denied["event_id"])
        rows = self.audit()
        verified_sites = json.dumps([SITE], separators=(",", ":"))
        self.assertEqual(rows[0], ("machine", None, "camera-adapter-1", "/v2/events",
                                   "observation.detected.v2", event["event_id"], SITE,
                                   verified_sites, "accepted", None))
        self.assertEqual(rows[1][6:], (OTHER_SITE, verified_sites, "rejected", "site_denied"))
        self.assertNotEqual(rows[1][6], json.loads(rows[1][7])[0])
        self.assertNotIn("payload", json.dumps(rows))

        with sqlite3.connect(self.database) as connection:
            for statement in ("UPDATE audit_log SET outcome = 'tampered'", "DELETE FROM audit_log"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)

    def test_audit_covers_each_batch_item(self):
        good = observation("10000000-0000-4000-8000-000000000061")
        invalid = copy.deepcopy(good)
        invalid["event_id"] = "10000000-0000-4000-8000-000000000062"
        invalid["payload"]["zone_transition"]["to_zone_id"] = "outside"
        self.request("/v2/events/batch",
                     {"batch_id": "a0000000-0000-4000-8000-000000000003", "items": [good, invalid]},
                     self.machine_token)
        rows = [row for row in self.audit() if row[3] == "/v2/events/batch"]
        self.assertEqual([(row[5], row[8]) for row in rows],
                         [(good["event_id"], "accepted"), (invalid["event_id"], "rejected")])


if __name__ == "__main__":
    unittest.main()

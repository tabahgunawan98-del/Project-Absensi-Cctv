import copy
import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from attendance_backend.app import App

SITE = "40000000-0000-4000-8000-000000000001"
OTHER_SITE = "40000000-0000-4000-8000-000000000002"


def observation(event_id="10000000-0000-4000-8000-000000000001"):
    return {
        "schema_version": "2.0",
        "canonicalization": "jcs-rfc8785-v1",
        "event_id": event_id,
        "event_type": "observation.detected.v2",
        "occurred_at": "2026-09-17T09:00:00Z",
        "source": {
            "instance_id": "20000000-0000-4000-8000-000000000001",
            "boot_id": "30000000-0000-4000-8000-000000000001",
            "version": "adapter-0.1.0",
        },
        "site_id": SITE,
        "payload": {
            "observation_id": "60000000-0000-4000-8000-000000000001",
            "camera_id": "70000000-0000-4000-8000-000000000001",
            "stream_id": "main",
            "sequence": 1,
            "track_id": "track-42",
            "pipeline": {
                "detector_version": "detector-1",
                "tracker_version": "tracker-1",
                "zone_config_version": "zones-1",
                "crossing_policy_version": "crossing-1",
            },
            "zone_transition": {
                "from_zone_id": "outside",
                "to_zone_id": "inside",
                "crossing_line_id": "door-a",
                "route_group_id": "lobby-main",
                "direction": "entry",
            },
            "quality_flags": [],
            "media_ref_id": None,
        },
    }


def manual(event_id="10000000-0000-4000-8000-000000000007"):
    return {
        "schema_version": "2.0",
        "canonicalization": "jcs-rfc8785-v1",
        "event_id": event_id,
        "event_type": "attendance.manual.v2",
        "occurred_at": "2026-09-17T09:05:00Z",
        "site_id": SITE,
        "payload": {
            "employee_id": "80000000-0000-4000-8000-000000000001",
            "kind": "check_in",
            "effective_at": "2026-09-17T09:00:00Z",
            "reason": "Synthetic test",
            "shift_instance_id": None,
        },
    }


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = App(Path(self.tmp.name) / "events.sqlite3")
        self.machine = {
            "principal_type": "machine",
            "scopes": ["events:write"],
            "sites": [SITE],
            "event_types": ["observation.detected.v2"],
        }
        self.user = {
            "principal_type": "user",
            "subject": "operator-1",
            "scopes": ["attendance:manual"],
            "sites": [SITE],
            "event_types": ["attendance.manual.v2"],
        }

    def tearDown(self):
        self.app.close()
        self.tmp.cleanup()

    def request(self, path, body=None, principal=None, idem=None, raw=None):
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        headers = {}
        if principal is not None:
            headers["HTTP_X_PRINCIPAL"] = json.dumps(principal)
        if idem:
            headers["HTTP_IDEMPOTENCY_KEY"] = idem
        return self.app.handle("POST" if body is not None or raw is not None else "GET", path, payload, headers)

    def test_single_accept_replay_and_changed_payload_conflict(self):
        event = observation()
        first = self.request("/v2/events", event, self.machine, event["event_id"])
        replay = self.request("/v2/events", event, self.machine, event["event_id"])
        changed = copy.deepcopy(event)
        changed["payload"]["sequence"] = 2
        conflict = self.request("/v2/events", changed, self.machine, event["event_id"])
        self.assertEqual((first.status, first.json["outcome"]), (202, "accepted"))
        self.assertEqual((replay.status, replay.json["outcome"]), (200, "duplicate"))
        self.assertEqual((conflict.status, conflict.json["code"]), (409, "event_id_conflict"))
        self.assertEqual(self.app.event_count(), 1)

    def test_rfc8785_numeric_equivalence_is_duplicate(self):
        event = observation()
        event["payload"]["sequence"] = 1
        equivalent = copy.deepcopy(event)
        equivalent["payload"]["sequence"] = 1.0
        first = self.request("/v2/events", event, self.machine, event["event_id"])
        replay = self.request("/v2/events", equivalent, self.machine, event["event_id"])
        self.assertEqual((first.status, replay.status, replay.json["outcome"]), (202, 200, "duplicate"))

    def test_replay_survives_restart(self):
        event = observation()
        first = self.request("/v2/events", event, self.machine, event["event_id"])
        self.app = App(Path(self.tmp.name) / "events.sqlite3")
        replay = self.request("/v2/events", event, self.machine, event["event_id"])
        self.assertEqual((first.status, replay.status, replay.json["outcome"]), (202, 200, "duplicate"))

    def test_concurrent_same_id_is_atomic(self):
        event = observation()
        barrier = threading.Barrier(8)
        def send():
            barrier.wait()
            return self.request("/v2/events", event, self.machine, event["event_id"])
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: send(), range(8)))
        self.assertEqual(sorted(response.status for response in responses), [200] * 7 + [202])
        self.assertEqual(self.app.event_count(), 1)

    def test_concurrent_same_id_different_payload_has_one_conflict(self):
        first = observation()
        second = copy.deepcopy(first)
        second["payload"]["sequence"] = 2
        barrier = threading.Barrier(2)
        def send(event):
            barrier.wait()
            return self.request("/v2/events", event, self.machine, event["event_id"])
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(send, [first, second]))
        self.assertEqual(sorted(response.status for response in responses), [202, 409])
        self.assertEqual(self.app.event_count(), 1)

    def test_duplicate_member_and_malformed_json_rejected(self):
        duplicate = b'{"event_id":"10000000-0000-4000-8000-000000000001","event_id":"10000000-0000-4000-8000-000000000001"}'
        huge_integer = json.dumps({**observation(), "payload": {**observation()["payload"], "sequence": 2**60}}).encode()
        for raw in (duplicate, b'{"broken":', huge_integer):
            response = self.request("/v2/events", principal=self.machine, idem="10000000-0000-4000-8000-000000000001", raw=raw)
            self.assertEqual((response.status, response.json["code"]), (400, "malformed_json"))
        self.assertEqual(self.app.event_count(), 0)

    def test_paired_surrogate_and_literal_unicode_have_same_hash(self):
        event = observation()
        event["payload"]["track_id"] = "track-😀"
        literal = json.dumps(event, ensure_ascii=False).encode()
        escaped = json.dumps(event, ensure_ascii=True).encode()
        first = self.request("/v2/events", principal=self.machine, idem=event["event_id"], raw=literal)
        replay = self.request("/v2/events", principal=self.machine, idem=event["event_id"], raw=escaped)
        self.assertEqual((first.status, replay.status, replay.json["outcome"]), (202, 200, "duplicate"))

    def test_scope_site_event_and_external_decision_denied_before_storage(self):
        event = observation()
        denied = []
        for principal in (
            {**self.machine, "scopes": []},
            {**self.machine, "sites": [OTHER_SITE]},
            {**self.machine, "event_types": ["identity.resolved.v2"]},
        ):
            denied.append(self.request("/v2/events", event, principal, event["event_id"]))
        decision = copy.deepcopy(event)
        decision["event_type"] = "attendance.decision.v2"
        forged_allowlist = {**self.machine, "event_types": ["attendance.decision.v2"]}
        denied.append(self.request("/v2/events", decision, forged_allowlist, decision["event_id"]))
        manual_on_machine = manual()
        forged_manual = {**self.machine, "event_types": ["attendance.manual.v2"]}
        denied.append(self.request("/v2/events", manual_on_machine, forged_manual, manual_on_machine["event_id"]))
        self.assertEqual([response.status for response in denied], [403, 403, 403, 403, 403])
        self.assertEqual([response.json["code"] for response in denied], ["scope_denied", "site_denied", "principal_event_denied", "principal_event_denied", "principal_event_denied"])
        self.assertEqual(self.app.event_count(), 0)

    def test_manual_requires_user_delegation(self):
        event = manual()
        denied = self.request("/v2/manual-attendance-events", event, self.machine, event["event_id"])
        accepted = self.request("/v2/manual-attendance-events", event, self.user, event["event_id"])
        self.assertEqual((denied.status, denied.json["code"]), (403, "principal_event_denied"))
        self.assertEqual((accepted.status, accepted.json["outcome"]), (202, "accepted"))

    def test_batch_partial_order_and_error_invariants(self):
        good = observation("10000000-0000-4000-8000-000000000011")
        invalid = copy.deepcopy(good)
        invalid["event_id"] = "10000000-0000-4000-8000-000000000012"
        invalid["payload"]["zone_transition"]["to_zone_id"] = "outside"
        malformed_object = {"event_id": "not-a-uuid"}
        response = self.request(
            "/v2/events/batch",
            {"batch_id": "a0000000-0000-4000-8000-000000000001", "items": [good, invalid, malformed_object, good]},
            self.machine,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual([item["index"] for item in response.json["results"]], [0, 1, 2, 3])
        self.assertEqual([item["outcome"] for item in response.json["results"]], ["accepted", "rejected", "rejected", "duplicate"])
        self.assertIn("payload_sha256", response.json["results"][0])
        self.assertNotIn("error", response.json["results"][0])
        self.assertIn("error", response.json["results"][1])
        self.assertNotIn("payload_sha256", response.json["results"][1])
        self.assertIsNone(response.json["results"][2]["event_id"])

        invalid_envelope = self.request(
            "/v2/events/batch",
            {"batch_id": "not-a-uuid", "items": [good]},
            self.machine,
        )
        self.assertEqual((invalid_envelope.status, invalid_envelope.json["code"]), (400, "schema_invalid"))

    def test_wsgi_http_adapter(self):
        event = observation()
        raw = json.dumps(event).encode()
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v2/events",
            "CONTENT_LENGTH": str(len(raw)),
            "wsgi.input": io.BytesIO(raw),
            "HTTP_X_PRINCIPAL": json.dumps(self.machine),
            "HTTP_IDEMPOTENCY_KEY": event["event_id"],
        }
        metadata = {}
        def start_response(status, headers):
            metadata.update(status=status, headers=dict(headers))
        body = b"".join(self.app(environ, start_response))
        self.assertEqual(metadata["status"], "202 Accepted")
        self.assertEqual(metadata["headers"]["Content-Type"], "application/json")
        self.assertEqual(json.loads(body)["outcome"], "accepted")

    def test_health(self):
        self.assertEqual(self.request("/health/live").status, 200)
        self.assertEqual(self.request("/health/ready").status, 200)
        self.app.close()
        self.assertEqual(self.request("/health/ready").status, 503)


if __name__ == "__main__":
    unittest.main()

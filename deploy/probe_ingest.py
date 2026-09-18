"""Probe helper: post one contract-valid observation event and exit non-zero on failure.

Kept as a file rather than an inline heredoc so the event matches the real 2.0
envelope (schema_version, canonicalization, source session, zone_transition)
instead of an invented shape that the schema would reject.
"""

import json
import sys
import urllib.error
import urllib.request

SITE = "40000000-0000-4000-8000-000000000001"


def observation(event_id):
    return {
        "schema_version": "2.0",
        "canonicalization": "jcs-rfc8785-v1",
        "event_id": event_id,
        "event_type": "observation.detected.v2",
        "occurred_at": "2026-09-18T12:00:00Z",
        "source": {
            "instance_id": "20000000-0000-4000-8000-000000000001",
            "boot_id": "30000000-0000-4000-8000-000000000001",
            "version": "probe-0.1.0",
        },
        "site_id": SITE,
        "payload": {
            "observation_id": "60000000-0000-4000-8000-000000000001",
            "camera_id": "70000000-0000-4000-8000-000000000001",
            "stream_id": "main",
            "sequence": 1,
            "track_id": "probe-track",
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


def main():
    event_id, token = sys.argv[1], sys.argv[2]
    body = json.dumps(observation(event_id)).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:8080/v2/events",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": event_id,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 202:
                print("unexpected status", response.status, file=sys.stderr)
                return 1
    except urllib.error.HTTPError as error:
        print("HTTP", error.code, error.read().decode()[:400], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

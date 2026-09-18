#!/usr/bin/env python3
"""Portable ingress invariants that JSON Schema cannot express.

Runtime MUST run parse_strict_json() then check_invariants() on every event, in that
order, before canonicalization and storage. Schema validity alone is not admissibility.
"""

import json
import math
from datetime import date, datetime, timezone


class InvariantError(ValueError):
    """Raised with a stable contract error code."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _reject_duplicate_members(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise InvariantError("malformed_json", f"duplicate object member {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_non_ijson(value, path="$"):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and not -(2**53) + 1 <= value <= 2**53 - 1:
        raise InvariantError("malformed_json", f"integer outside I-JSON exact range at {path}")
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise InvariantError("malformed_json", f"non-I-JSON numeric value at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_non_ijson(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_non_ijson(item, f"{path}.{key}")
    return value


def _reject_unpaired_surrogates(value, path="$"):
    if isinstance(value, str):
        index = 0
        while index < len(value):
            codepoint = ord(value[index])
            if 0xD800 <= codepoint <= 0xDBFF:
                if index + 1 >= len(value) or not 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                    raise InvariantError("malformed_json", f"unpaired high surrogate at {path}")
                index += 2
                continue
            if 0xDC00 <= codepoint <= 0xDFFF:
                raise InvariantError("malformed_json", f"unpaired low surrogate at {path}")
            index += 1
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unpaired_surrogates(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key, f"{path}.<key>")
            _reject_unpaired_surrogates(item, f"{path}.{key}")


def parse_strict_json(raw: str):
    """Parse I-JSON; reject duplicate members, non-finite numbers, and lone surrogates."""
    value = json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_members,
        parse_constant=lambda constant: _reject_non_ijson(float("nan")),
    )
    _reject_non_ijson(value)
    _reject_unpaired_surrogates(value)
    return value


def _check_calendar(value: str, field: str) -> None:
    try:
        date(int(value[0:4]), int(value[5:7]), int(value[8:10]))
    except ValueError as error:
        raise InvariantError("invariant_violated", f"{field} is not a real calendar date: {error}")


def parse_rfc3339_instant(value: str, field: str) -> datetime:
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise InvariantError("invariant_violated", f"{field} is not RFC3339: {error}")
    if instant.tzinfo is None:
        raise InvariantError("invariant_violated", f"{field} has no UTC offset")
    return instant.astimezone(timezone.utc)


def ensure_not_after(earlier: str, later: str) -> None:
    if parse_rfc3339_instant(earlier, "effective_at") > parse_rfc3339_instant(later, "occurred_at"):
        raise InvariantError("invariant_violated", "effective_at cannot follow occurred_at")


def check_invariants(event: dict) -> None:
    """Cross-field rules enforced identically by every producer and by ingest."""
    _check_calendar(event["occurred_at"], "occurred_at")
    payload = event["payload"]
    event_type = event["event_type"]

    if event_type == "observation.detected.v2":
        transition = payload["zone_transition"]
        if transition["from_zone_id"] == transition["to_zone_id"]:
            raise InvariantError("invariant_violated", "zone transition must change zone")

    elif event_type == "identity.resolved.v2":
        if payload["revision"] == 1 and payload["supersedes_resolution_id"] is not None:
            raise InvariantError("invariant_violated", "first revision cannot supersede")
        if payload["revision"] > 1 and payload["supersedes_resolution_id"] is None:
            raise InvariantError("invariant_violated", "later revision must supersede a resolution")
        if payload["supersedes_resolution_id"] == payload["resolution_id"]:
            raise InvariantError("invariant_violated", "resolution cannot supersede itself")
        metric = payload["score_metric"]
        score = payload["score"]
        if metric in {"cosine_similarity", "inner_product"} and not -1.0 <= score <= 1.0:
            raise InvariantError("invariant_violated", f"{metric} score out of range")
        if metric == "euclidean_distance" and score < 0:
            raise InvariantError("invariant_violated", "euclidean_distance must be non-negative")

    elif event_type == "attendance.manual.v2":
        _check_calendar(payload["effective_at"], "effective_at")
        ensure_not_after(payload["effective_at"], event["occurred_at"])

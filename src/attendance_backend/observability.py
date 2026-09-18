"""Minimal non-PII operational telemetry for local runtime."""

import json
import sqlite3
import threading
from pathlib import Path


class SafeJsonLogger:
    ALLOWED_FIELDS = frozenset({
        "request_id", "status", "duration_ms", "error_code", "path", "method",
        "queue_depth", "retry_count", "failure_count",
    })

    def __init__(self, sink):
        self.sink = sink

    def emit(self, event, **fields):
        unknown = set(fields) - self.ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"unsafe or unsupported log fields: {sorted(unknown)}")
        record = {"event": event, **fields}
        self.sink(json.dumps(record, sort_keys=True, separators=(",", ":")))


class OperationalMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._request_count = 0
        self._failure_count = 0
        self._latency_ms_sum = 0.0
        self._latency_ms_max = 0.0

    def observe_request(self, duration_seconds, *, error):
        latency_ms = max(0.0, float(duration_seconds) * 1000)
        with self._lock:
            self._request_count += 1
            self._failure_count += int(bool(error))
            self._latency_ms_sum += latency_ms
            self._latency_ms_max = max(self._latency_ms_max, latency_ms)

    def snapshot(self):
        with self._lock:
            average = (
                self._latency_ms_sum / self._request_count
                if self._request_count else 0.0
            )
            return {
                "request_count": self._request_count,
                "failure_count": self._failure_count,
                "latency_ms_avg": round(average, 3),
                "latency_ms_max": round(self._latency_ms_max, 3),
            }


def health_snapshot(database_path, metrics):
    result = {
        "liveness": "live",
        "readiness": "not_ready",
        "queue_depth": 0,
        "retry_count": 0,
        **metrics.snapshot(),
    }
    try:
        with sqlite3.connect(f"file:{Path(database_path)}?mode=ro", uri=True) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "durable_queue" in tables:
                row = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(attempts),0) "
                    "FROM durable_queue WHERE status='pending'"
                ).fetchone()
                result["queue_depth"], result["retry_count"] = row
            result["readiness"] = "ready"
    except sqlite3.Error:
        pass
    return result

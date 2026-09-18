"""Transport and at-rest encryption policy, enforced fail-closed at startup.

This module does not implement encryption. SQLite has no built-in at-rest
encryption in the stdlib driver, and terminating TLS belongs to the reverse
proxy or the WSGI server. What it does is refuse to run when the owner-approved
protections are not demonstrably in place, so "we forgot to enable it" cannot
silently become the running configuration.
"""

import json
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


class SecurityPolicyError(Exception):
    """A required transport or at-rest protection is absent or unproven."""


def _parse_timestamp(value, field):
    if not isinstance(value, str):
        raise SecurityPolicyError(f"attestation field is not a timestamp: {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SecurityPolicyError(f"attestation field is not ISO-8601: {field}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


@dataclass
class SecurityPolicy:
    """Startup gate for TLS and at-rest encryption.

    ponytail: at-rest encryption is *attested*, not measured — the runtime cannot
    verify LUKS/KMS from inside the process. The attestation file is signed off by
    the owner and expires, so it has to be re-confirmed. Replace with a real
    device/KMS probe when the deployment target is chosen.
    """

    require_tls: bool = True
    require_encryption_at_rest: bool = True
    attestation_path: Path | None = None
    clock: Callable[[], float] = time.time
    max_file_mode: int = 0o077

    def _attestation(self):
        if self.attestation_path is None:
            raise SecurityPolicyError(
                "encryption at rest is required but no attestation path is configured"
            )
        path = Path(self.attestation_path)
        if not path.is_file():
            raise SecurityPolicyError(f"at-rest encryption attestation is missing: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SecurityPolicyError("at-rest encryption attestation is malformed") from error
        if not isinstance(document, dict):
            raise SecurityPolicyError("at-rest encryption attestation must be an object")
        if document.get("encrypted_at_rest") is not True:
            raise SecurityPolicyError(
                "at-rest encryption attestation does not confirm encryption"
            )
        if not isinstance(document.get("mechanism"), str) or not document["mechanism"]:
            raise SecurityPolicyError("at-rest encryption attestation names no mechanism")
        if not isinstance(document.get("attested_by"), str) or not document["attested_by"]:
            raise SecurityPolicyError("at-rest encryption attestation names no attester")
        expires_at = _parse_timestamp(document.get("expires_at"), "expires_at")
        if self.clock() >= expires_at:
            raise SecurityPolicyError(
                "at-rest encryption attestation has expired; re-confirm with the owner"
            )
        return document

    def verify_storage(self, *paths):
        """Refuse to proceed unless every database/backup path is protected."""
        if not self.require_encryption_at_rest:
            # Explicit, reported opt-out (see describe()); used only where the
            # owner accepted the risk in writing.
            return True
        self._attestation()
        for path in paths:
            path = Path(path)
            if not path.exists():
                continue
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & self.max_file_mode:
                raise SecurityPolicyError(
                    f"{path} is readable beyond its owner (mode {mode:04o}); "
                    "tighten permissions before storing attendance data"
                )
        return True

    def describe(self):
        """Non-PII summary safe to log or expose on a health endpoint."""
        attested = False
        if self.require_encryption_at_rest:
            try:
                attested = bool(self._attestation())
            except SecurityPolicyError:
                attested = False
        return {
            "require_tls": self.require_tls,
            "require_encryption_at_rest": self.require_encryption_at_rest,
            "attested": attested,
        }


def require_tls_environ(policy, environ, *, trust_forwarded_proto=True):
    """Reject a plaintext request when the policy requires TLS.

    A terminating reverse proxy is accepted via X-Forwarded-Proto only when the
    deployment explicitly trusts it; an untrusted header must never be able to
    talk the service out of its own TLS requirement.
    """
    if not policy.require_tls:
        return True
    scheme = environ.get("wsgi.url_scheme")
    if scheme == "https":
        return True
    if trust_forwarded_proto and environ.get("HTTP_X_FORWARDED_PROTO") == "https":
        return True
    raise SecurityPolicyError("TLS is required for this endpoint")

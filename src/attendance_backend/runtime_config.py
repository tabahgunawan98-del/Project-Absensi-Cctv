"""Validated deployment configuration; no secret values are accepted here."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


# Upper bounds keep an operator typo from disabling a control: a huge clock skew
# would neutralise `exp`/`nbf`, and a huge rate limit would disable throttling.
MAXIMUMS = {
    "ABSENSI_DEDUPE_WINDOW_SECONDS": 3_600,
    "ABSENSI_RAW_RETENTION_DAYS": 3_650,
    "ABSENSI_PROCESSED_RETENTION_DAYS": 3_650,
    "ABSENSI_RATE_LIMIT_PER_MINUTE": 100_000,
    "ABSENSI_CLOCK_SKEW_SECONDS": 300,
    "ABSENSI_GRACE_PERIOD_MINUTES": 720,
}


def _required(environment, name):
    value = environment.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _bounded(environment, name, default, maximum):
    raw = environment.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise ConfigError(f"{name} must be an integer") from error
    if value <= 0:
        raise ConfigError(f"{name} must be positive")
    if value > maximum:
        raise ConfigError(f"{name} must not exceed {maximum}")
    return value


def _bool_flag(environment, name, default=True):
    """Parse an explicit boolean override. Anything but an exact true/false
    value is rejected so a typo cannot silently disable a control."""
    raw = environment.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean (true/false)")


@dataclass(frozen=True)
class RuntimeConfig:
    hostname: str
    database_path: Path
    backup_path: Path
    encryption_attestation: Path
    oidc_issuer: str
    oidc_audience: str
    jwks_uri: str
    rtsp_secret_path: str
    manifest_key_path: str
    dedupe_window_seconds: int = 10
    raw_retention_days: int = 30
    processed_retention_days: int = 90
    rate_limit_per_minute: int = 100
    clock_skew_seconds: int = 30
    grace_period_minutes: int = 15
    require_encryption_at_rest: bool = True

    @classmethod
    def from_environment(cls, environment):
        hostname = _required(environment, "ABSENSI_HOSTNAME")
        if "://" in hostname or hostname.endswith(".com") or hostname.endswith(".net") or hostname.endswith(".org"):
            raise ConfigError("ABSENSI_HOSTNAME must be an internal DNS hostname without scheme")
        issuer = _required(environment, "ABSENSI_OIDC_ISSUER")
        jwks_uri = _required(environment, "ABSENSI_JWKS_URI")
        if urlparse(issuer).scheme != "https" or urlparse(jwks_uri).scheme != "https":
            raise ConfigError("OIDC issuer and JWKS URI must use HTTPS")
        rtsp_secret_path = _required(environment, "ABSENSI_RTSP_SECRET_PATH")
        manifest_key_path = _required(environment, "ABSENSI_MANIFEST_KEY_PATH")
        if "://" in rtsp_secret_path or "://" in manifest_key_path:
            raise ConfigError("secret configuration must name a Vault path, not contain a secret")
        raw_days = _bounded(environment, "ABSENSI_RAW_RETENTION_DAYS", 30, MAXIMUMS["ABSENSI_RAW_RETENTION_DAYS"])
        processed_days = _bounded(
            environment, "ABSENSI_PROCESSED_RETENTION_DAYS", 90, MAXIMUMS["ABSENSI_PROCESSED_RETENTION_DAYS"]
        )
        if processed_days < raw_days:
            raise ConfigError("processed retention must not be shorter than raw retention")
        return cls(
            hostname=hostname,
            database_path=Path(_required(environment, "ABSENSI_DATABASE_PATH")),
            backup_path=Path(_required(environment, "ABSENSI_BACKUP_PATH")),
            encryption_attestation=Path(_required(environment, "ABSENSI_ENCRYPTION_ATTESTATION")),
            oidc_issuer=issuer,
            oidc_audience=_required(environment, "ABSENSI_OIDC_AUDIENCE"),
            jwks_uri=jwks_uri,
            rtsp_secret_path=rtsp_secret_path,
            manifest_key_path=manifest_key_path,
            dedupe_window_seconds=_bounded(
                environment, "ABSENSI_DEDUPE_WINDOW_SECONDS", 10, MAXIMUMS["ABSENSI_DEDUPE_WINDOW_SECONDS"]
            ),
            raw_retention_days=raw_days,
            processed_retention_days=processed_days,
            rate_limit_per_minute=_bounded(
                environment, "ABSENSI_RATE_LIMIT_PER_MINUTE", 100, MAXIMUMS["ABSENSI_RATE_LIMIT_PER_MINUTE"]
            ),
            clock_skew_seconds=_bounded(
                environment, "ABSENSI_CLOCK_SKEW_SECONDS", 30, MAXIMUMS["ABSENSI_CLOCK_SKEW_SECONDS"]
            ),
            grace_period_minutes=_bounded(
                environment, "ABSENSI_GRACE_PERIOD_MINUTES", 15, MAXIMUMS["ABSENSI_GRACE_PERIOD_MINUTES"]
            ),
            require_encryption_at_rest=_bool_flag(
                environment, "ABSENSI_REQUIRE_ENCRYPTION_AT_REST", True
            ),
        )

    def safe_summary(self):
        return {
            "hostname": self.hostname,
            "database_path": str(self.database_path),
            "backup_path": str(self.backup_path),
            "dedupe_window_seconds": self.dedupe_window_seconds,
            "raw_retention_days": self.raw_retention_days,
            "processed_retention_days": self.processed_retention_days,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "clock_skew_seconds": self.clock_skew_seconds,
            "grace_period_minutes": self.grace_period_minutes,
        }

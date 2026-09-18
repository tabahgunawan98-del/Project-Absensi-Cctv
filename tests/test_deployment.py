"""Deployment-package tests. All data, keys, and identities are synthetic."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from attendance_backend.auth import AuthConfig
from attendance_backend.jwks import JwksCache, jwk_from_public_key, sign_jwt
from attendance_backend.recovery import BackupService, RestoreAuthorization
from attendance_backend.runtime import RuntimeService
from attendance_backend.runtime_config import ConfigError, RuntimeConfig
from attendance_backend.runtime_server import RuntimeHttpApp
from attendance_backend.vault_client import VaultClient, VaultError
from tests.test_api import observation


ROOT = Path(__file__).parents[1]


class RuntimeConfigTest(unittest.TestCase):
    def valid_environment(self):
        return {
            "ABSENSI_HOSTNAME": "absensi.office.local",
            "ABSENSI_DATABASE_PATH": "/var/lib/absensi/attendance.sqlite3",
            "ABSENSI_BACKUP_PATH": "/var/backups/absensi",
            "ABSENSI_ENCRYPTION_ATTESTATION": "/run/absensi/at-rest.json",
            "ABSENSI_OIDC_ISSUER": "https://absensi.office.local/realms/absensi",
            "ABSENSI_OIDC_AUDIENCE": "absensi-api",
            "ABSENSI_JWKS_URI": "https://absensi.office.local/realms/absensi/protocol/openid-connect/certs",
            "ABSENSI_RTSP_SECRET_PATH": "secret/data/absensi/rtsp",
            "ABSENSI_MANIFEST_KEY_PATH": "secret/data/absensi/backup",
        }

    def test_owner_defaults_are_overridable(self):
        config = RuntimeConfig.from_environment(self.valid_environment())
        self.assertEqual(config.dedupe_window_seconds, 10)
        self.assertEqual(config.raw_retention_days, 30)
        self.assertEqual(config.processed_retention_days, 90)
        self.assertEqual(config.rate_limit_per_minute, 100)
        self.assertEqual(config.clock_skew_seconds, 30)
        self.assertEqual(config.grace_period_minutes, 15)

        values = self.valid_environment() | {
            "ABSENSI_DEDUPE_WINDOW_SECONDS": "20",
            "ABSENSI_RAW_RETENTION_DAYS": "14",
            "ABSENSI_PROCESSED_RETENTION_DAYS": "60",
            "ABSENSI_RATE_LIMIT_PER_MINUTE": "80",
            "ABSENSI_CLOCK_SKEW_SECONDS": "10",
            "ABSENSI_GRACE_PERIOD_MINUTES": "5",
        }
        overridden = RuntimeConfig.from_environment(values)
        self.assertEqual(
            (
                overridden.dedupe_window_seconds,
                overridden.raw_retention_days,
                overridden.processed_retention_days,
                overridden.rate_limit_per_minute,
                overridden.clock_skew_seconds,
                overridden.grace_period_minutes,
            ),
            (20, 14, 60, 80, 10, 5),
        )

    def test_missing_or_unsafe_configuration_fails_closed(self):
        required = self.valid_environment()
        for name in required:
            invalid = dict(required)
            invalid.pop(name)
            with self.subTest(name=name), self.assertRaises(ConfigError):
                RuntimeConfig.from_environment(invalid)

        invalid_values = [
            {"ABSENSI_HOSTNAME": "https://bad.example"},
            {"ABSENSI_HOSTNAME": "public.example.com"},
            {"ABSENSI_JWKS_URI": "http://keycloak:8080/certs"},
            {"ABSENSI_DEDUPE_WINDOW_SECONDS": "0"},
            {"ABSENSI_RAW_RETENTION_DAYS": "31", "ABSENSI_PROCESSED_RETENTION_DAYS": "30"},
            {"ABSENSI_RATE_LIMIT_PER_MINUTE": "many"},
            {"ABSENSI_RTSP_SECRET_PATH": "rtsp://camera.invalid/11"},
        ]
        for change in invalid_values:
            with self.subTest(change=change), self.assertRaises(ConfigError):
                RuntimeConfig.from_environment(required | change)

    def test_numeric_overrides_reject_values_above_the_sane_upper_bound(self):
        required = self.valid_environment()
        limits = {
            "ABSENSI_DEDUPE_WINDOW_SECONDS": 3_600,
            "ABSENSI_RAW_RETENTION_DAYS": 3_650,
            "ABSENSI_PROCESSED_RETENTION_DAYS": 3_650,
            "ABSENSI_RATE_LIMIT_PER_MINUTE": 100_000,
            "ABSENSI_CLOCK_SKEW_SECONDS": 300,
            "ABSENSI_GRACE_PERIOD_MINUTES": 720,
        }
        for name, maximum in limits.items():
            companion = {}
            if name == "ABSENSI_RAW_RETENTION_DAYS":
                companion = {"ABSENSI_PROCESSED_RETENTION_DAYS": str(maximum)}
            with self.subTest(name=name, bound="at maximum"):
                accepted = RuntimeConfig.from_environment(required | companion | {name: str(maximum)})
                self.assertEqual(getattr(accepted, name.removeprefix("ABSENSI_").lower()), maximum)
            for rejected in (maximum + 1, 10**20):
                with self.subTest(name=name, value=rejected), self.assertRaises(ConfigError):
                    RuntimeConfig.from_environment(required | companion | {name: str(rejected)})

    def test_config_repr_and_dict_do_not_contain_secret_values(self):
        config = RuntimeConfig.from_environment(self.valid_environment())
        text = repr(config) + json.dumps(config.safe_summary(), sort_keys=True)
        self.assertNotIn("rtsp://", text)
        self.assertNotIn("password", text.lower())
        self.assertNotIn("token", text.lower())


class ComposeSecurityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")

    def test_only_reverse_proxy_publishes_a_port_and_defaults_loopback(self):
        self.assertIn('${ABSENSI_BIND_ADDRESS:-127.0.0.1}:${ABSENSI_HTTPS_PORT:-443}:443', self.compose)
        for service in ("app", "keycloak", "vault", "keycloak-db"):
            block = self.compose.split(f"  {service}:", 1)[1].split("\n  ", 1)[0]
            self.assertNotIn("ports:", block)
        self.assertEqual(self.compose.count("ports:"), 1)

    def test_services_are_hardened_and_internal_networks_exist(self):
        for required in (
            "read_only: true",
            "no-new-privileges:true",
            "cap_drop:",
            "internal: true",
            "healthcheck:",
            "ABSENSI_RTSP_SECRET_PATH",
            "ABSENSI_MANIFEST_KEY_PATH",
        ):
            self.assertIn(required, self.compose)
        self.assertNotIn("VAULT_DEV_ROOT_TOKEN_ID", self.compose)
        self.assertNotIn("start-dev", self.compose)
        self.assertIn("_PASSWORD_FILE", self.compose)
        self.assertNotIn("rtsp://", self.compose.lower())

    def test_images_are_version_pinned_and_proxy_forces_tls(self):
        pinned = self.compose + (ROOT / "deploy" / "keycloak.Dockerfile").read_text(encoding="utf-8")
        for image in ("keycloak:26.3.3", "vault:1.20.3", "caddy:2.10.2", "postgres:17.6"):
            self.assertIn(image, pinned)
        caddy = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("tls /run/tls/tls.crt /run/tls/tls.key", caddy)
        self.assertIn("header_up X-Forwarded-Proto https", caddy)
        self.assertNotIn("http://{$ABSENSI_HOSTNAME}", caddy)

    def service_block(self, service):
        return self.compose.split(f"\n  {service}:", 1)[1].split("\n\n", 1)[0]

    def test_every_service_runs_as_an_explicit_non_root_uid(self):
        for service in ("proxy", "oauth2-proxy", "app", "keycloak", "keycloak-db", "vault"):
            block = self.service_block(service)
            with self.subTest(service=service):
                self.assertRegex(block, r"user: \"[1-9][0-9]*:[0-9]+\"")

    def test_vault_keeps_hardening_and_declares_its_mlock_posture(self):
        block = self.service_block("vault")
        self.assertIn("read_only: true", block)
        self.assertIn("cap_drop: [ALL]", block)
        self.assertIn("SKIP_SETCAP", block)
        self.assertIn("SKIP_CHOWN", block)
        vault_config = (ROOT / "deploy" / "vault.hcl").read_text(encoding="utf-8")
        self.assertIn("disable_mlock = true", vault_config)
        runbook = (ROOT / "docs" / "office-deployment-runbook.md").read_text(encoding="utf-8")
        self.assertIn("mlock", runbook)

    def test_keycloak_is_prebuilt_optimized_and_needs_no_writable_build_dir(self):
        block = self.service_block("keycloak")
        self.assertIn("keycloak.Dockerfile", block)
        self.assertIn("read_only: true", block)
        entrypoint = (ROOT / "deploy" / "keycloak-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("--optimized", entrypoint)
        dockerfile = (ROOT / "deploy" / "keycloak.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("kc.sh build", dockerfile)

    def test_healthchecks_validate_the_internal_certificate_chain(self):
        self.assertNotIn("--no-check-certificate", self.compose)
        self.assertNotIn("-k ", self.compose)
        self.assertNotIn("--insecure", self.compose)

    def test_runbook_documents_per_service_ownership_of_secret_files(self):
        runbook = (ROOT / "docs" / "office-deployment-runbook.md").read_text(encoding="utf-8")
        for marker in ("chown", "at-rest.json", "65532", "1000", "100:1000"):
            with self.subTest(marker=marker):
                self.assertIn(marker, runbook)

    def test_vault_keeps_hardening_and_declares_the_mlock_limit(self):
        vault = self.service_block("vault")
        self.assertIn("read_only: true", vault)
        self.assertIn("cap_drop: [ALL]", vault)
        # The image entrypoint appends its own -config; passing the file too
        # loads the listener twice and fails to bind.
        self.assertIn("command: [server]", vault)
        self.assertNotIn("-config=/vault/config/vault.hcl", vault)
        hcl = (ROOT / "deploy" / "vault.hcl").read_text(encoding="utf-8")
        self.assertIn("disable_mlock = true", hcl)
        self.assertIn("SECURITY LIMIT", hcl)
        runbook = (ROOT / "docs" / "office-deployment-runbook.md").read_text(encoding="utf-8")
        self.assertIn("mlock", runbook)

    def test_keycloak_image_is_built_optimized_ahead_of_start(self):
        dockerfile = (ROOT / "deploy" / "keycloak.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("kc.sh build", dockerfile)
        entrypoint = (ROOT / "deploy" / "keycloak-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("--optimized", entrypoint)
        # A secret file without a trailing newline makes `read` return non-zero;
        # under `set -e` that silently killed the entrypoint.
        self.assertIn("|| true", entrypoint)

    def test_proxy_keeps_the_capability_its_binary_requires(self):
        proxy = self.service_block("proxy")
        self.assertIn("cap_drop: [ALL]", proxy)
        self.assertIn("cap_add: [NET_BIND_SERVICE]", proxy)

    def test_no_healthcheck_skips_certificate_verification(self):
        for name in ("compose.yaml", "Caddyfile"):
            text = (ROOT / "deploy" / name).read_text(encoding="utf-8")
            for bypass in ("--no-check-certificate", "tls_skip_verify", "--insecure"):
                self.assertNotIn(bypass, text)

    def test_realm_bootstrap_is_provisioned_and_reads_secrets_from_files(self):
        script = (ROOT / "deploy" / "keycloak-realm-bootstrap.sh").read_text(encoding="utf-8")
        for path in ("/run/secrets/keycloak_admin_password", "/run/secrets/oidc_client_secret"):
            self.assertIn(path, script)
        self.assertIn("absensi-dashboard", script)
        self.assertIn("absensi.principal_type", script)
        compose_bootstrap = self.service_block("keycloak-bootstrap")
        self.assertIn("service_completed_successfully", self.compose)
        self.assertIn("read_only: true", compose_bootstrap)

    def test_vault_application_policy_is_read_only_and_narrow(self):
        policy = (ROOT / "deploy" / "vault-app-policy.hcl").read_text(encoding="utf-8")
        self.assertIn('path "secret/data/absensi/rtsp"', policy)
        self.assertIn('path "secret/data/absensi/backup"', policy)
        self.assertNotIn('path "secret/*"', policy)
        self.assertNotIn('"delete"', policy)
        self.assertNotIn('"sudo"', policy)


class VaultClientTest(unittest.TestCase):
    def test_reads_named_secret_without_exposing_token_or_value(self):
        calls = []

        def transport(url, token, ca_file):
            calls.append((url, token, ca_file))
            return {"data": {"data": {"url": "rtsp://synthetic.invalid/11"}}}

        client = VaultClient(
            "https://vault:8200",
            token="synthetic-vault-token",
            ca_file="/run/tls/ca.crt",
            transport=transport,
        )
        value = client.read("secret/data/absensi/rtsp", "url")
        self.assertEqual(value, "rtsp://synthetic.invalid/11")
        self.assertEqual(calls[0][0], "https://vault:8200/v1/secret/data/absensi/rtsp")
        self.assertNotIn("synthetic-vault-token", repr(client))
        self.assertNotIn(value, repr(client))

    def test_missing_token_http_or_malformed_response_fail_closed(self):
        with self.assertRaises(VaultError):
            VaultClient("https://vault:8200", token="", ca_file="/ca")
        with self.assertRaises(VaultError):
            VaultClient("http://vault:8200", token="token", ca_file="/ca")
        client = VaultClient(
            "https://vault:8200",
            token="token",
            ca_file="/ca",
            transport=lambda *_: {"data": {}},
        )
        with self.assertRaises(VaultError):
            client.read("secret/data/absensi/rtsp", "url")


class RuntimeHttpAppTest(unittest.TestCase):
    class Service:
        class App:
            def handle(self, method, path, raw=b"", headers=None):
                from attendance_backend.app import Response
                if path == "/health/live":
                    return Response(200, {"status": "live"})
                if path == "/health/ready":
                    return Response(200, {"status": "ready"})
                return Response(202, {"outcome": "accepted"})

        app = App()

        def dashboard_with_token(self, token):
            if token != "valid-synthetic-token":
                raise PermissionError("OIDC login required")
            return "<main>real backend row</main>"

    def request(self, application, path, *, token=None, forwarded_token=None):
        import io
        result = {}
        headers = {}
        if token:
            headers["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        if forwarded_token:
            headers["HTTP_X_FORWARDED_ACCESS_TOKEN"] = forwarded_token
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "CONTENT_LENGTH": "0",
            "wsgi.input": io.BytesIO(b""),
            **headers,
        }

        def start_response(status, response_headers):
            result["status"] = status
            result["headers"] = dict(response_headers)

        result["body"] = b"".join(application(environ, start_response))
        return result

    def test_health_and_oidc_dashboard_routes(self):
        application = RuntimeHttpApp(self.Service())
        self.assertEqual(self.request(application, "/health/live")["status"], "200 OK")
        denied = self.request(application, "/dashboard")
        self.assertEqual(denied["status"], "401 Unauthorized")
        self.assertNotIn(b"OIDC login required", denied["body"])
        allowed = self.request(application, "/dashboard", token="valid-synthetic-token")
        self.assertEqual(allowed["status"], "200 OK")
        forwarded = self.request(
            application, "/dashboard", forwarded_token="valid-synthetic-token"
        )
        self.assertEqual(forwarded["status"], "200 OK")
        self.assertEqual(allowed["headers"]["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"real backend row", allowed["body"])


class SyntheticEndToEndSmokeTest(unittest.TestCase):
    def test_oidc_ingest_attendance_dashboard_backup_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            jwks = {"keys": [jwk_from_public_key(private_key.public_key(), kid="smoke-key")]}
            auth = AuthConfig(
                issuer="https://absensi.office.local/realms/absensi",
                audience="absensi-api",
                keys={},
                algorithms=frozenset({"RS256"}),
                clock_skew_seconds=30,
                key_resolver=JwksCache(lambda: jwks, ttl_seconds=300, clock=lambda: 1_000),
            )
            service = RuntimeService(
                root / "attendance.sqlite3",
                auth_config=auth,
                manifest_signing_key=b"synthetic-manifest-key-for-test-only",
                clock=lambda: 1_000,
            )
            token = sign_jwt(
                {
                    "iss": auth.issuer,
                    "aud": auth.audience,
                    "exp": 2_000,
                    "nbf": 900,
                    "absensi.principal_type": "machine",
                    "client_id": "synthetic-camera",
                    "scope": "events:write",
                    "absensi.event_types": ["observation.detected.v2"],
                    "absensi.sites": ["40000000-0000-4000-8000-000000000001"],
                },
                private_key,
                kid="smoke-key",
                alg="RS256",
            )
            event = observation()
            response = service.ingest(
                event,
                token,
                idempotency_key=event["event_id"],
            )
            self.assertEqual(response.status, 202)
            attendance = service.record_synthetic_attendance(
                signal_id=event["event_id"],
                occurred_at=event["occurred_at"],
                employee_id="80000000-0000-4000-8000-000000000001",
                direction="entry",
            )
            self.assertEqual(attendance, "attendance_created")
            user_token = sign_jwt(
                {
                    "iss": auth.issuer,
                    "aud": auth.audience,
                    "exp": 2_000,
                    "nbf": 900,
                    "absensi.principal_type": "user",
                    "sub": "operator-test",
                    "scope": "dashboard:read",
                    "realm_access": {"roles": ["operator"]},
                    "absensi.event_types": [],
                    "absensi.sites": ["40000000-0000-4000-8000-000000000001"],
                },
                private_key,
                kid="smoke-key",
                alg="RS256",
            )
            html = service.dashboard_with_token(user_token)
            self.assertIn("80000000-0000-4000-8000-000000000001", html)
            self.assertNotIn("synthetic-manifest-key", html)
            with self.assertRaises(PermissionError):
                service.dashboard_with_token(token)
            artifact = service.backup(root / "backups" / "attendance.sqlite3")
            report = service.restore(
                artifact,
                root / "restored.sqlite3",
                RestoreAuthorization("operator-a", "approver-b", "synthetic smoke restore"),
            )
            self.assertEqual(report.integrity_check, "ok")
            with sqlite3.connect(report.target_path) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM attendance_records").fetchone()[0], 1)
            service.close()


if __name__ == "__main__":
    unittest.main()

"""Item 2 boundary tests: OIDC/JWKS verification, secret store, at-rest/TLS policy.

Every key and secret in this module is generated per test run. Nothing here is a
real credential and nothing is read from the developer environment.
"""

import base64
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from attendance_backend.auth import AuthConfig, TokenError, verify_token
from attendance_backend.jwks import (
    JwksCache,
    JwksUnavailable,
    UnsupportedKey,
    jwk_from_public_key,
    sign_jwt,
)
from attendance_backend.secret_store import (
    EncryptedFileSecretStore,
    SecretStoreError,
    SecretUnavailable,
)
from attendance_backend.security_policy import (
    SecurityPolicy,
    SecurityPolicyError,
    require_tls_environ,
)

ISSUER = "https://identity.test.invalid"
AUDIENCE = "absensi-ingress"
NOW = 1_800_000_000.0
SITE = "11111111-1111-4111-8111-111111111111"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def claims(**overrides):
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "grant_type": "client_credentials",
        "client_id": "camera-adapter-1",
        "scope": "events:write",
        "absensi.event_types": ["observation.detected.v2"],
        "absensi.sites": [SITE],
        "exp": NOW + 300,
    }
    base.update(overrides)
    return base


class JwksVerificationTest(unittest.TestCase):
    def setUp(self):
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.ed_key = ed25519.Ed25519PrivateKey.generate()
        self.documents = {
            "keys": [
                jwk_from_public_key(self.rsa_key.public_key(), kid="rsa-1"),
                jwk_from_public_key(self.ec_key.public_key(), kid="ec-1"),
                jwk_from_public_key(self.ed_key.public_key(), kid="ed-1"),
            ]
        }
        self.fetch_count = 0
        self.now = NOW
        self.cache = JwksCache(
            self._fetch, ttl_seconds=300, clock=lambda: self.now
        )
        self.config = AuthConfig(
            issuer=ISSUER, audience=AUDIENCE, keys={},
            algorithms=frozenset({"RS256", "ES256", "EdDSA"}),
            key_resolver=self.cache,
        )

    def _fetch(self):
        self.fetch_count += 1
        return self.documents

    def test_rs256_es256_and_eddsa_tokens_verify_from_jwks(self):
        for key, kid, alg in (
            (self.rsa_key, "rsa-1", "RS256"),
            (self.ec_key, "ec-1", "ES256"),
            (self.ed_key, "ed-1", "EdDSA"),
        ):
            token = sign_jwt(claims(), key, kid=kid, alg=alg)
            principal = verify_token(token, self.config, self.now)
            self.assertEqual(principal.principal_type, "machine")
            self.assertEqual(principal.client_id, "camera-adapter-1")
            self.assertEqual(principal.sites, frozenset({SITE}))

    def test_alg_none_and_symmetric_alg_are_rejected_in_asymmetric_mode(self):
        header = {"alg": "none", "kid": "rsa-1", "typ": "JWT"}
        unsigned = "{}.{}.".format(
            b64u(json.dumps(header).encode()), b64u(json.dumps(claims()).encode())
        )
        with self.assertRaises(TokenError):
            verify_token(unsigned, self.config, self.now)

        forged = sign_jwt(claims(), b"not-a-real-key", kid="rsa-1", alg="HS256")
        with self.assertRaises(TokenError):
            verify_token(forged, self.config, self.now)

    def test_signature_from_another_key_is_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = sign_jwt(claims(), other, kid="rsa-1", alg="RS256")
        with self.assertRaises(TokenError):
            verify_token(token, self.config, self.now)

    def test_unknown_kid_triggers_one_refresh_then_fails_closed(self):
        token = sign_jwt(claims(), self.rsa_key, kid="rotated-1", alg="RS256")
        before = self.fetch_count
        with self.assertRaises(TokenError):
            verify_token(token, self.config, self.now)
        self.assertEqual(self.fetch_count, before + 1)

    def test_key_rotation_is_picked_up_without_restart(self):
        rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = sign_jwt(claims(), rotated, kid="rsa-2", alg="RS256")
        with self.assertRaises(TokenError):
            verify_token(token, self.config, self.now)

        self.documents = {
            "keys": [
                jwk_from_public_key(self.rsa_key.public_key(), kid="rsa-1"),
                jwk_from_public_key(rotated.public_key(), kid="rsa-2"),
            ]
        }
        principal = verify_token(token, self.config, self.now)
        self.assertEqual(principal.client_id, "camera-adapter-1")

        old = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
        self.assertEqual(verify_token(old, self.config, self.now).principal_type, "machine")

    def test_jwks_is_cached_until_ttl_expires(self):
        token = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
        verify_token(token, self.config, self.now)
        first = self.fetch_count
        for _ in range(3):
            verify_token(token, self.config, self.now)
        self.assertEqual(self.fetch_count, first)

        self.now += 301
        verify_token(token, self.config, self.now)
        self.assertEqual(self.fetch_count, first + 1)

    def test_unreachable_jwks_fails_closed_without_stale_acceptance(self):
        token = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
        verify_token(token, self.config, self.now)

        def broken():
            raise JwksUnavailable("endpoint unreachable")

        self.cache.fetch = broken
        self.now += 301
        with self.assertRaises(TokenError):
            verify_token(token, self.config, self.now)

    def test_cold_start_without_jwks_never_accepts_a_token(self):
        def broken():
            raise JwksUnavailable("endpoint unreachable")

        cache = JwksCache(broken, ttl_seconds=300, clock=lambda: self.now)
        config = AuthConfig(
            issuer=ISSUER, audience=AUDIENCE, keys={},
            algorithms=frozenset({"RS256"}), key_resolver=cache,
        )
        token = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
        with self.assertRaises(TokenError):
            verify_token(token, config, self.now)

    def test_malformed_jwks_documents_are_rejected(self):
        for document in ({}, {"keys": "not-a-list"}, {"keys": [{"kty": "oct", "k": "x"}]}):
            cache = JwksCache(lambda d=document: d, ttl_seconds=300, clock=lambda: self.now)
            config = AuthConfig(
                issuer=ISSUER, audience=AUDIENCE, keys={},
                algorithms=frozenset({"RS256"}), key_resolver=cache,
            )
            token = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
            with self.assertRaises((TokenError, UnsupportedKey)):
                verify_token(token, config, self.now)

    def test_issuer_audience_exp_and_nbf_still_enforced_on_asymmetric_path(self):
        cases = (
            claims(iss="https://evil.test.invalid"),
            claims(aud="another-service"),
            claims(exp=self.now - 3600),
            claims(nbf=self.now + 3600),
        )
        for payload in cases:
            token = sign_jwt(payload, self.rsa_key, kid="rsa-1", alg="RS256")
            with self.assertRaises(TokenError):
                verify_token(token, self.config, self.now)

    def test_alg_outside_the_allowlist_is_rejected_even_with_a_known_kid(self):
        config = AuthConfig(
            issuer=ISSUER, audience=AUDIENCE, keys={},
            algorithms=frozenset({"ES256"}), key_resolver=self.cache,
        )
        token = sign_jwt(claims(), self.rsa_key, kid="rsa-1", alg="RS256")
        with self.assertRaises(TokenError):
            verify_token(token, config, self.now)


class SecretStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store_path = self.root / "secrets.enc"
        self.master = base64.b64encode(os.urandom(32)).decode()
        self.env = {"ABSENSI_SECRET_MASTER_KEY": self.master}

    def tearDown(self):
        self.tmp.cleanup()

    def store(self, env=None):
        return EncryptedFileSecretStore(
            self.store_path, environ=self.env if env is None else env
        )

    def test_put_and_get_roundtrip_without_plaintext_on_disk(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        self.assertEqual(store.get("backup.manifest_key"), b"synthetic-manifest-key")

        raw = self.store_path.read_bytes()
        self.assertNotIn(b"synthetic-manifest-key", raw)
        self.assertNotIn(self.master.encode(), raw)
        self.assertEqual(self.store_path.stat().st_mode & 0o077, 0)

    def test_missing_master_key_fails_closed(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        with self.assertRaises(SecretUnavailable):
            EncryptedFileSecretStore(self.store_path, environ={}).get("backup.manifest_key")

    def test_wrong_master_key_fails_closed_and_never_returns_a_value(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        other = {"ABSENSI_SECRET_MASTER_KEY": base64.b64encode(os.urandom(32)).decode()}
        with self.assertRaises(SecretStoreError):
            EncryptedFileSecretStore(self.store_path, environ=other).get("backup.manifest_key")

    def test_tampered_ciphertext_is_rejected(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        blob = bytearray(self.store_path.read_bytes())
        blob[-1] ^= 0xFF
        self.store_path.write_bytes(bytes(blob))
        with self.assertRaises(SecretStoreError):
            self.store().get("backup.manifest_key")

    def test_unknown_secret_name_fails_closed(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        with self.assertRaises(SecretUnavailable):
            store.get("does.not.exist")

    def test_rotation_keeps_the_new_value_and_records_a_version(self):
        store = self.store()
        store.put("backup.manifest_key", b"old-synthetic-key")
        first = store.version("backup.manifest_key")
        store.rotate("backup.manifest_key", b"new-synthetic-key")
        self.assertEqual(store.get("backup.manifest_key"), b"new-synthetic-key")
        self.assertGreater(store.version("backup.manifest_key"), first)
        self.assertNotIn(b"old-synthetic-key", self.store_path.read_bytes())

    def test_master_key_rotation_reencrypts_every_secret(self):
        store = self.store()
        store.put("a", b"value-a")
        store.put("b", b"value-b")
        new_master = base64.b64encode(os.urandom(32)).decode()
        store.rotate_master_key(new_master)

        with self.assertRaises(SecretStoreError):
            EncryptedFileSecretStore(self.store_path, environ=self.env).get("a")
        rotated = EncryptedFileSecretStore(
            self.store_path, environ={"ABSENSI_SECRET_MASTER_KEY": new_master}
        )
        self.assertEqual(rotated.get("a"), b"value-a")
        self.assertEqual(rotated.get("b"), b"value-b")

    def test_repr_and_str_never_leak_secret_material(self):
        store = self.store()
        store.put("backup.manifest_key", b"synthetic-manifest-key")
        rendered = f"{store!r} {store}"
        self.assertNotIn("synthetic-manifest-key", rendered)
        self.assertNotIn(self.master, rendered)


class SecurityPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root / "app.sqlite3"
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TABLE t(id INTEGER PRIMARY KEY)")
        self.attestation = self.root / "at-rest-encryption.json"

    def tearDown(self):
        self.tmp.cleanup()

    def attest(self, **overrides):
        document = {
            "encrypted_at_rest": True,
            "mechanism": "luks2",
            "attested_by": "owner-representative",
            "attested_at": "2026-09-18T00:00:00Z",
            "expires_at": "2027-09-18T00:00:00Z",
        }
        document.update(overrides)
        self.attestation.write_text(json.dumps(document), encoding="utf-8")
        return self.attestation

    def policy(self, **overrides):
        options = {
            "require_tls": True,
            "require_encryption_at_rest": True,
            "attestation_path": self.attest(),
            "clock": lambda: time.mktime(time.strptime("2026-09-18", "%Y-%m-%d")),
        }
        options.update(overrides)
        return SecurityPolicy(**options)

    def test_startup_fails_closed_when_at_rest_attestation_is_missing(self):
        policy = self.policy(attestation_path=self.root / "absent.json")
        with self.assertRaises(SecurityPolicyError):
            policy.verify_storage(self.database)

    def test_startup_fails_closed_when_attestation_denies_encryption(self):
        policy = self.policy(attestation_path=self.attest(encrypted_at_rest=False))
        with self.assertRaises(SecurityPolicyError):
            policy.verify_storage(self.database)

    def test_startup_fails_closed_when_attestation_has_expired(self):
        policy = self.policy(attestation_path=self.attest(expires_at="2026-01-01T00:00:00Z"))
        with self.assertRaises(SecurityPolicyError):
            policy.verify_storage(self.database)

    def test_world_readable_database_is_rejected(self):
        self.database.chmod(0o644)
        with self.assertRaises(SecurityPolicyError):
            self.policy().verify_storage(self.database)

    def test_valid_attestation_and_tight_permissions_pass(self):
        self.database.chmod(0o600)
        self.policy().verify_storage(self.database)

    def test_policy_can_be_disabled_only_explicitly_and_is_reported(self):
        policy = SecurityPolicy(
            require_tls=False, require_encryption_at_rest=False, attestation_path=None
        )
        policy.verify_storage(self.database)
        self.assertEqual(
            policy.describe(),
            {"require_tls": False, "require_encryption_at_rest": False, "attested": False},
        )

    def test_plaintext_http_request_is_refused_when_tls_is_required(self):
        policy = self.policy()
        for environ in (
            {"wsgi.url_scheme": "http"},
            {"wsgi.url_scheme": "http", "HTTP_X_FORWARDED_PROTO": "http"},
            {},
        ):
            with self.assertRaises(SecurityPolicyError):
                require_tls_environ(policy, environ)

    def test_tls_request_or_trusted_terminating_proxy_is_accepted(self):
        policy = self.policy()
        require_tls_environ(policy, {"wsgi.url_scheme": "https"})
        require_tls_environ(
            policy, {"wsgi.url_scheme": "http", "HTTP_X_FORWARDED_PROTO": "https"}
        )

    def test_backup_encryption_key_comes_from_the_secret_store(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            store_path = Path(tmp.name) / "secrets.enc"
            environ = {"ABSENSI_SECRET_MASTER_KEY": base64.b64encode(os.urandom(32)).decode()}
            store = EncryptedFileSecretStore(store_path, environ=environ)
            store.put("backup.manifest_key", os.urandom(32))

            from attendance_backend.recovery import BackupService

            service = BackupService(
                required_tables={"t"}, required_triggers=set(),
                allowed_schema_versions={0},
                manifest_signing_key=store.get("backup.manifest_key"),
            )
            artifact = service.create(self.database, Path(tmp.name) / "backup.sqlite3")
            self.assertTrue(artifact.manifest_path.exists())
            manifest = json.loads(artifact.manifest_path.read_text())
            self.assertIn("manifest_hmac_sha256", manifest)
        finally:
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()

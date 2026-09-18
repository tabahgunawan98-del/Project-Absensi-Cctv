"""Integration tests against a running Keycloak instance.
Requires VAULT_TOKEN_FILE and OIDC_CLIENT_SECRET_FILE for actual token acquisition.
"""

import base64
import json
import os
import ssl
import time
import unittest
import urllib.request
import urllib.parse
from pathlib import Path

from attendance_backend.auth import AuthConfig, Principal, verify_token
from attendance_backend.jwks import JwksCache


def _opener_context(ca_file):
    if ca_file and Path(ca_file).exists():
        return ssl.create_default_context(cafile=ca_file)
    return None


def _fetch_token(issuer, client_id, client_secret, grant_type, ca_file=None, **kwargs):
    url = f"{issuer}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret,
        **kwargs
    }).encode()
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=10, context=_opener_context(ca_file)) as response:
        return json.load(response)["access_token"]


@unittest.skipUnless(os.environ.get("ABSENSI_INTEGRATION_KEYCLOAK"), "Keycloak integration test disabled")
class KeycloakIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = os.environ["ABSENSI_OIDC_ISSUER"]
        cls.audience = os.environ["ABSENSI_OIDC_AUDIENCE"]
        cls.jwks_uri = os.environ["ABSENSI_JWKS_URI"]
        
        with open(os.environ["OIDC_CLIENT_SECRET_FILE"], "r") as f:
            cls.client_secret = f.read().strip()
            
        cls.ca_file = os.environ.get("VAULT_CACERT", "/run/tls/ca.crt")
        cls.cache = JwksCache(
            lambda: cls._fetch_jwks(),
            ttl_seconds=300,
            clock=time.time
        )
        cls.auth_config = AuthConfig(
            issuer=cls.issuer,
            audience=cls.audience,
            keys={},
            algorithms=frozenset({"RS256"}),
            key_resolver=cls.cache
        )

    @classmethod
    def _fetch_jwks(cls):
        ctx = ssl.create_default_context(cafile=cls.ca_file)
        with urllib.request.urlopen(cls.jwks_uri, context=ctx, timeout=10) as response:
            return json.load(response)

    def test_machine_token_ingest_claims(self):
        token = _fetch_token(
            self.issuer, "absensi-ingest", self.client_secret, "client_credentials",
            ca_file=self.ca_file,
        )
        principal = verify_token(token, self.auth_config)
        self.assertEqual(principal.principal_type, "machine")
        self.assertIn("events:write", principal.roles | principal.scopes)
        # Nested namespace claims must survive as strict typed sets.
        self.assertEqual(principal.event_types, frozenset({"observation.detected.v2", "identity.resolved.v2"}))
        self.assertEqual(principal.sites, frozenset({"40000000-0000-4000-8000-000000000001"}))

    def test_user_token_dashboard_claims(self):
        token = _fetch_token(
            self.issuer, "absensi-dashboard", self.client_secret, "password",
            ca_file=self.ca_file,
            username="smoke-operator", password="smoke-password"
        )
        principal = verify_token(token, self.auth_config)
        self.assertEqual(principal.principal_type, "user")
        self.assertIn("operator", principal.roles)
        self.assertIn("dashboard:read", principal.roles | principal.scopes)
        self.assertEqual(principal.event_types, frozenset({"attendance.manual.v2"}))
        self.assertEqual(principal.sites, frozenset({"40000000-0000-4000-8000-000000000001"}))

    def test_wrong_role_is_denied_at_the_backend_boundary(self):
        # A machine token must never satisfy a user-delegated dashboard route.
        token = _fetch_token(
            self.issuer, "absensi-ingest", self.client_secret, "client_credentials",
            ca_file=self.ca_file,
        )
        principal = verify_token(token, self.auth_config)
        self.assertNotIn("dashboard:read", principal.roles | principal.scopes)
        self.assertNotEqual(principal.principal_type, "user")


if __name__ == "__main__":
    unittest.main()

"""WSGI entry point for the internal-only deployment."""

import base64
import json
import os
import ssl
import time
import urllib.request
from http import HTTPStatus
from wsgiref.simple_server import make_server

from .auth import AuthConfig
from .jwks import JwksCache, JwksUnavailable
from .runtime import RuntimeService
from .runtime_config import RuntimeConfig
from .security_policy import SecurityPolicy
from .vault_client import VaultClient


class RuntimeHttpApp:
    def __init__(self, service):
        self.service = service

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "GET")
        if method == "GET" and path == "/dashboard":
            authorization = environ.get("HTTP_AUTHORIZATION", "")
            forwarded_token = environ.get("HTTP_X_FORWARDED_ACCESS_TOKEN", "")
            try:
                if authorization.startswith("Bearer "):
                    token = authorization[7:]
                elif forwarded_token:
                    token = forwarded_token
                else:
                    raise PermissionError
                body = self.service.dashboard_with_token(token).encode()
                return self._send(start_response, 200, body, "text/html; charset=utf-8")
            except PermissionError:
                return self._send(start_response, 401, b'{"code":"authentication_required"}', "application/problem+json")

        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length)
        headers = {key: value for key, value in environ.items() if key.startswith("HTTP_")}
        response = self.service.app.handle(method, path, raw, headers)
        body = json.dumps(response.json, separators=(",", ":")).encode()
        content_type = "application/problem+json" if response.status >= 400 else "application/json"
        return self._send(start_response, response.status, body, content_type, response.headers)

    @staticmethod
    def _send(start_response, status, body, content_type, headers=None):
        start_response(
            f"{status} {HTTPStatus(status).phrase}",
            [("Content-Type", content_type), ("Content-Length", str(len(body))), *((headers or {}).items())],
        )
        return [body]


def _fetch_json(url, ca_file):
    try:
        with urllib.request.urlopen(
            url, context=ssl.create_default_context(cafile=ca_file), timeout=5
        ) as response:
            return json.load(response)
    except (OSError, ValueError) as error:
        raise JwksUnavailable("JWKS endpoint is unreachable") from error


def build_service(environment=os.environ):
    config = RuntimeConfig.from_environment(environment)
    SecurityPolicy(attestation_path=config.encryption_attestation).verify_storage(
        config.database_path.parent, config.backup_path
    )
    vault_token_file = environment.get("VAULT_TOKEN_FILE", "/run/secrets/vault_app_token")
    with open(vault_token_file, encoding="utf-8") as source:
        vault_token = source.read().strip()
    vault = VaultClient(
        environment.get("VAULT_ADDR", "https://vault:8200"),
        token=vault_token,
        ca_file=environment.get("VAULT_CACERT", "/run/tls/ca.crt"),
    )
    # Read both at startup. The URL stays in memory only and is never logged;
    # CV ingestion consumes it in the next approved integration step.
    vault.read(config.rtsp_secret_path, "url")
    manifest_key = base64.b64decode(
        vault.read(config.manifest_key_path, "key_b64"), validate=True
    )
    ca_file = environment.get("VAULT_CACERT", "/run/tls/ca.crt")
    cache = JwksCache(
        lambda: _fetch_json(config.jwks_uri, ca_file),
        ttl_seconds=300,
        refresh_cooldown_seconds=30,
        clock=time.time,
    )
    auth = AuthConfig(
        issuer=config.oidc_issuer,
        audience=config.oidc_audience,
        keys={},
        algorithms=frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"}),
        clock_skew_seconds=config.clock_skew_seconds,
        key_resolver=cache,
    )
    return RuntimeService(
        config.database_path,
        auth_config=auth,
        manifest_signing_key=manifest_key,
        clock=time.time,
        config=config,
    )


def main():
    service = build_service()
    try:
        with make_server("0.0.0.0", 8080, RuntimeHttpApp(service)) as server:
            server.serve_forever()
    finally:
        service.close()


if __name__ == "__main__":
    main()

"""Minimal fail-closed HashiCorp Vault KV v2 reader."""

import json
import ssl
import urllib.error
import urllib.request


class VaultError(RuntimeError):
    pass


def _https_transport(url, token, ca_file):
    request = urllib.request.Request(url, headers={"X-Vault-Token": token})
    try:
        with urllib.request.urlopen(
            request, context=ssl.create_default_context(cafile=ca_file), timeout=5
        ) as response:
            return json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise VaultError("Vault request failed") from error


class VaultClient:
    def __init__(self, address, *, token, ca_file, transport=None):
        if not address.startswith("https://"):
            raise VaultError("Vault requires HTTPS")
        if not token:
            raise VaultError("Vault token is required")
        if not ca_file:
            raise VaultError("Vault CA is required")
        self.address = address.rstrip("/")
        self._token = token
        self.ca_file = ca_file
        self._transport = transport or _https_transport

    def __repr__(self):
        return f"VaultClient(address={self.address!r}, ca_file={self.ca_file!r})"

    def read(self, path, field):
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise VaultError("Vault path is invalid")
        try:
            document = self._transport(
                f"{self.address}/v1/{path}", self._token, self.ca_file
            )
            value = document["data"]["data"][field]
        except VaultError:
            raise
        except (KeyError, TypeError) as error:
            raise VaultError("Vault secret is missing or malformed") from error
        if not isinstance(value, str) or not value:
            raise VaultError("Vault secret field is empty or invalid")
        return value

"""Secret store abstraction with one local encrypted-file implementation.

No secret value is ever written in plaintext, logged, or rendered by repr/str.
The master key is supplied by the environment (or an injected mapping) and is
expected to come from an owner-approved mechanism: systemd-creds, a KMS-fed
environment, or an operator-entered value. This module deliberately does not
choose one — swapping in a KMS/Vault backend means implementing SecretStore.
"""

import base64
import binascii
import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_ENV = "ABSENSI_SECRET_MASTER_KEY"
_STORE_FORMAT = "absensi-secret-store-v1"


class SecretStoreError(Exception):
    """The store exists but could not be read, decrypted, or authenticated."""


class SecretUnavailable(SecretStoreError):
    """The requested secret, or the key needed to read it, is not configured."""


class SecretStore(ABC):
    """Minimal contract a KMS/Vault backend must satisfy to replace the local one."""

    @abstractmethod
    def get(self, name):
        """Return secret bytes, or raise SecretUnavailable/SecretStoreError."""

    @abstractmethod
    def put(self, name, value):
        """Store a new secret value."""

    @abstractmethod
    def rotate(self, name, value):
        """Replace a secret and bump its version."""

    @abstractmethod
    def version(self, name):
        """Return the monotonically increasing version of a secret."""

    def __repr__(self):  # never render secret material
        return f"<{type(self).__name__}>"

    __str__ = __repr__


class EncryptedFileSecretStore(SecretStore):
    """AES-256-GCM encrypted secret file, one AEAD box per secret.

    ponytail: single local file with a single master key — right for a
    single-node office server. Multi-node, per-secret access control, and audited
    retrieval need a real KMS/Vault backend implementing SecretStore.
    """

    def __init__(self, path, *, environ=None, master_key_env=MASTER_KEY_ENV):
        self.path = Path(path)
        self._environ = os.environ if environ is None else environ
        self._master_key_env = master_key_env

    def _master_key(self):
        encoded = self._environ.get(self._master_key_env)
        if not encoded:
            raise SecretUnavailable(
                f"{self._master_key_env} is not set; supply it from an approved "
                "secret mechanism before starting the service"
            )
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SecretUnavailable("master key is not valid base64") from error
        if len(key) not in (16, 24, 32):
            raise SecretUnavailable("master key must decode to 16, 24, or 32 bytes")
        return key

    def _read_document(self):
        if not self.path.exists():
            return {"format": _STORE_FORMAT, "secrets": {}}
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SecretStoreError("secret store file is missing or malformed") from error
        if not isinstance(document, dict) or document.get("format") != _STORE_FORMAT:
            raise SecretStoreError("secret store format is not recognised")
        if not isinstance(document.get("secrets"), dict):
            raise SecretStoreError("secret store contents are malformed")
        return document

    def _write_document(self, document):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name + ".")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise
        self.path.chmod(0o600)

    @staticmethod
    def _seal(key, name, value, version):
        nonce = os.urandom(12)
        box = AESGCM(key).encrypt(nonce, value, f"{name}:{version}".encode())
        return {
            "version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(box).decode(),
        }

    @staticmethod
    def _open(key, name, record):
        try:
            nonce = base64.b64decode(record["nonce"], validate=True)
            box = base64.b64decode(record["ciphertext"], validate=True)
            aad = f"{name}:{record['version']}".encode()
        except (KeyError, TypeError, ValueError, binascii.Error) as error:
            raise SecretStoreError("secret record is malformed") from error
        try:
            return AESGCM(key).decrypt(nonce, box, aad)
        except InvalidTag as error:
            raise SecretStoreError(
                "secret could not be authenticated: wrong master key or tampered store"
            ) from error

    def get(self, name):
        key = self._master_key()
        record = self._read_document()["secrets"].get(name)
        if record is None:
            raise SecretUnavailable(f"secret is not configured: {name}")
        return self._open(key, name, record)

    def put(self, name, value):
        self._store(name, value, bump=False)

    def rotate(self, name, value):
        self._store(name, value, bump=True)

    def _store(self, name, value, *, bump):
        if not isinstance(value, (bytes, bytearray)) or not value:
            raise SecretStoreError("secret value must be non-empty bytes")
        key = self._master_key()
        document = self._read_document()
        current = document["secrets"].get(name)
        version = (current["version"] + 1) if (current and bump) else (
            current["version"] if current else 1
        )
        document["secrets"][name] = self._seal(key, name, bytes(value), version)
        self._write_document(document)

    def version(self, name):
        record = self._read_document()["secrets"].get(name)
        if record is None:
            raise SecretUnavailable(f"secret is not configured: {name}")
        return record["version"]

    def names(self):
        return sorted(self._read_document()["secrets"])

    def rotate_master_key(self, new_encoded_key):
        """Re-encrypt every secret under a new master key.

        The caller is responsible for publishing the new key to the approved
        secret mechanism; this method never writes it anywhere.
        """
        old_key = self._master_key()
        try:
            new_key = base64.b64decode(new_encoded_key, validate=True)
        except (ValueError, binascii.Error) as error:
            raise SecretStoreError("new master key is not valid base64") from error
        if len(new_key) not in (16, 24, 32):
            raise SecretStoreError("new master key must decode to 16, 24, or 32 bytes")

        document = self._read_document()
        rotated = {}
        for name, record in document["secrets"].items():
            value = self._open(old_key, name, record)
            rotated[name] = self._seal(new_key, name, value, record["version"])
        document["secrets"] = rotated
        self._write_document(document)

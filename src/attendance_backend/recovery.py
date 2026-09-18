"""Local SQLite backup and human-authorized restore.

Backups contain application data and therefore inherit its access controls.
Encryption keys and credentials are deliberately not accepted or stored here;
operators must use an owner-approved encrypted filesystem or backup target.
"""

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


class BackupError(RuntimeError):
    pass


class RestoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class RestoreAuthorization:
    operator: str
    approver: str
    reason: str

    def validate(self):
        if not self.operator or not self.approver or not self.reason.strip():
            raise RestoreError("restore requires operator, separate approver, and reason")
        if self.operator == self.approver:
            raise RestoreError("restore operator and approver must be different humans")


@dataclass(frozen=True)
class BackupArtifact:
    database_path: Path
    manifest_path: Path
    sha256: str


@dataclass(frozen=True)
class RestoreReport:
    target_path: Path
    integrity_check: str
    schema_version: int


class BackupService:
    def __init__(
        self, *, required_tables, required_triggers, allowed_schema_versions,
        manifest_signing_key,
    ):
        if not isinstance(manifest_signing_key, (bytes, bytearray)) or not manifest_signing_key:
            raise BackupError(
                "manifest signing key is required; supply it from an approved secret "
                "mechanism at call time (it is never stored by this module)"
            )
        self.required_tables = frozenset(required_tables)
        self.required_triggers = frozenset(required_triggers)
        self.allowed_schema_versions = frozenset(allowed_schema_versions)
        self.manifest_signing_key = bytes(manifest_signing_key)

    @staticmethod
    def _manifest_bytes(manifest):
        return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    def _sign_manifest(self, manifest):
        return hmac.new(
            self.manifest_signing_key, self._manifest_bytes(manifest), hashlib.sha256
        ).hexdigest()

    def _verify_manifest_signature(self, manifest):
        signature = manifest.pop("manifest_hmac_sha256", None)
        if not isinstance(signature, str):
            raise BackupError("backup manifest is not signed")
        if not hmac.compare_digest(signature, self._sign_manifest(manifest)):
            raise BackupError("backup manifest signature mismatch")

    @staticmethod
    def sha256(path):
        digest = hashlib.sha256()
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _manifest_path(database_path):
        return Path(str(database_path) + ".manifest.json")

    @staticmethod
    def _sidecar_paths(database_path):
        base = str(database_path)
        return (Path(base + "-wal"), Path(base + "-shm"), Path(base + "-journal"))

    @classmethod
    def _remove_sidecars(cls, database_path):
        for sidecar in cls._sidecar_paths(database_path):
            sidecar.unlink(missing_ok=True)

    @classmethod
    def _seal_journal(cls, database_path):
        """Fold any WAL content into the main file so the checksum covers every commit."""
        try:
            with closing(sqlite3.connect(database_path)) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).lower() != "delete":
                raise BackupError(f"backup journal mode could not be sealed: {mode}")
        except sqlite3.Error as error:
            raise BackupError("backup journal could not be sealed") from error
        finally:
            cls._remove_sidecars(database_path)

    @classmethod
    def _assert_no_sidecars(cls, database_path):
        residue = [str(p.name) for p in cls._sidecar_paths(database_path) if p.exists()]
        if residue:
            raise BackupError(f"unexpected journal residue: {sorted(residue)}")

    @staticmethod
    def _objects(connection, kind):
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type=?", (kind,)
            )
        }

    def _verify_database(self, database_path):
        try:
            with closing(
                sqlite3.connect(f"file:{Path(database_path)}?mode=ro", uri=True)
            ) as connection:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
                if integrity != "ok":
                    raise BackupError(f"SQLite integrity check failed: {integrity}")
                schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
                if schema_version not in self.allowed_schema_versions:
                    raise BackupError(f"unsupported schema version: {schema_version}")
                missing_tables = self.required_tables - self._objects(connection, "table")
                missing_triggers = self.required_triggers - self._objects(connection, "trigger")
                if missing_tables:
                    raise BackupError(f"required tables missing: {sorted(missing_tables)}")
                if missing_triggers:
                    raise BackupError(f"required triggers missing: {sorted(missing_triggers)}")
                foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_keys:
                    raise BackupError("foreign key check failed")
        except sqlite3.Error as error:
            raise BackupError("backup is not a valid compatible SQLite database") from error
        return integrity, schema_version

    def create(self, source_path, destination_path):
        source_path = Path(source_path)
        destination_path = Path(destination_path)
        if not source_path.is_file():
            raise BackupError("source database does not exist")
        if destination_path.exists() or self._manifest_path(destination_path).exists():
            raise BackupError("backup destination must be fresh")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination_path.with_name(destination_path.name + ".partial")
        try:
            with closing(sqlite3.connect(source_path)) as source, \
                    closing(sqlite3.connect(temporary)) as target:
                source.backup(target)
            self._seal_journal(temporary)
            integrity, schema_version = self._verify_database(temporary)
            self._assert_no_sidecars(temporary)
            digest = self.sha256(temporary)
            os.replace(temporary, destination_path)
            manifest = {
                "format": "absensi-sqlite-backup-v1",
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "sha256": digest,
                "schema_version": schema_version,
                "integrity_check": integrity,
            }
            manifest["manifest_hmac_sha256"] = self._sign_manifest(manifest)
            manifest_path = self._manifest_path(destination_path)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            self._assert_no_sidecars(destination_path)
            return BackupArtifact(destination_path, manifest_path, digest)
        except Exception:
            temporary.unlink(missing_ok=True)
            destination_path.unlink(missing_ok=True)
            self._manifest_path(destination_path).unlink(missing_ok=True)
            raise
        finally:
            self._remove_sidecars(temporary)

    def restore(self, backup_path, manifest_path, target_path, authorization):
        if authorization is None:
            raise RestoreError("restore requires human authorization")
        authorization.validate()
        backup_path = Path(backup_path)
        manifest_path = Path(manifest_path)
        target_path = Path(target_path)
        if target_path.exists():
            raise RestoreError("restore target must be fresh; rollback keeps the old database")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise BackupError("backup manifest is missing or malformed") from error
        self._verify_manifest_signature(manifest)
        if manifest.get("format") != "absensi-sqlite-backup-v1":
            raise BackupError("unsupported backup format")
        actual = self.sha256(backup_path)
        if actual != manifest.get("sha256"):
            raise BackupError("backup checksum mismatch")
        integrity, schema_version = self._verify_database(backup_path)
        if schema_version != manifest.get("schema_version"):
            raise BackupError("manifest schema version mismatch")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=target_path.name + ".", suffix=".restore", dir=target_path.parent
        )
        os.close(fd)
        temporary = Path(temporary_name)
        temporary.unlink()
        try:
            shutil.copyfile(backup_path, temporary)
            self._seal_journal(temporary)
            restored_integrity, restored_schema = self._verify_database(temporary)
            self._assert_no_sidecars(temporary)
            if self.sha256(temporary) != actual:
                raise BackupError("restored database checksum differs from verified backup")
            os.replace(temporary, target_path)
            self._assert_no_sidecars(target_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            target_path.unlink(missing_ok=True)
            self._remove_sidecars(target_path)
            raise
        finally:
            self._remove_sidecars(temporary)
        return RestoreReport(target_path, restored_integrity, restored_schema)

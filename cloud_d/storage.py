from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StorageError(RuntimeError):
    """Base error for encrypted database operations."""


class StorageKeyError(StorageError):
    """Raised when the database encryption key cannot be loaded safely."""


class StorageIntegrityError(StorageError):
    """Raised when encrypted database content fails authentication."""


class DuplicateUploadError(StorageError):
    """Raised when an upload collides with a current filename and needs a user choice."""

    def __init__(self, duplicates: list[dict[str, Any]]):
        self.duplicates = duplicates
        super().__init__("One or more files already exist at this cloud node.")


class EncryptedSQLiteStore:
    """SQLite metadata store with AES-256-GCM encrypted uploaded-file payloads."""

    def __init__(self, data_dir: str | Path | None = None):
        configured_dir = data_dir or os.environ.get("CLOUD_D_DATA_DIR")
        self.data_dir = Path(configured_dir).expanduser() if configured_dir else Path.home() / ".cloud-d"
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.database_path = self.data_dir / "cloud-d.sqlite3"
        self.backup_path = self.data_dir / "cloud-d-backup.sqlite3"
        self.key_path = self.data_dir / "encryption.key"
        self._lock = RLock()
        self._key, self.key_source = self._load_key()
        self._cipher = AESGCM(self._key)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False, timeout=15)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("ATTACH DATABASE ? AS backup_db", (str(self.backup_path),))
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA secure_delete = ON")
        self._connection.execute("PRAGMA busy_timeout = 15000")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._create_schema()

    def _load_key(self) -> tuple[bytes, str]:
        configured = os.environ.get("CLOUD_D_ENCRYPTION_KEY", "").strip()
        if configured:
            try:
                key = base64.b64decode(
                    configured + "=" * (-len(configured) % 4), altchars=b"-_", validate=True
                )
            except (ValueError, TypeError) as exc:
                raise StorageKeyError("CLOUD_D_ENCRYPTION_KEY must be a URL-safe base64 encoded 32-byte key.") from exc
            if len(key) != 32:
                raise StorageKeyError("CLOUD_D_ENCRYPTION_KEY must decode to exactly 32 bytes.")
            return key, "environment variable"

        if self.key_path.exists():
            try:
                key = self.key_path.read_bytes()
            except OSError as exc:
                raise StorageKeyError("Cloud-D cannot read its encryption key. Check access to the Cloud-D data folder.") from exc
            if len(key) != 32:
                raise StorageKeyError("Cloud-D's encryption key file is invalid. Restore the original key before opening this database.")
            try:
                self.key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                # Windows uses the current user's profile ACL.
                pass
            return key, "local key file"

        has_encrypted_database = any(
            path.exists() and path.stat().st_size for path in (self.database_path, self.backup_path)
        )
        if has_encrypted_database:
            raise StorageKeyError(
                "A Cloud-D database exists but its encryption key is missing. Restore encryption.key or set "
                "CLOUD_D_ENCRYPTION_KEY; Cloud-D will not replace the key and lose access to encrypted data."
            )

        key = secrets.token_bytes(32)
        try:
            with self.key_path.open("xb") as key_file:
                key_file.write(key)
                key_file.flush()
                os.fsync(key_file.fileno())
            try:
                self.key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        except FileExistsError:
            # Another local process initialized the profile at the same time.
            key = self.key_path.read_bytes()
            if len(key) != 32:
                raise StorageKeyError("Cloud-D's encryption key file is invalid.")
        except OSError as exc:
            raise StorageKeyError("Cloud-D cannot create a private encryption key in its data folder.") from exc
        return key, "generated local key file"

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cloud_nodes (
                    node_id INTEGER PRIMARY KEY,
                    node_name TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cloud_users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('customer', 'staff')),
                    status TEXT NOT NULL CHECK(status IN ('active', 'pending')),
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    profile_nonce BLOB,
                    profile_ciphertext BLOB
                );
                CREATE TABLE IF NOT EXISTS cloud_sessions (
                    session_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES cloud_users(user_id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cloud_sessions_expiry_idx ON cloud_sessions(expires_at);
                CREATE TABLE IF NOT EXISTS cloud_folders (
                    folder_id TEXT PRIMARY KEY,
                    scope_key TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('customer', 'staff')),
                    owner_id TEXT,
                    node_id INTEGER NOT NULL,
                    name TEXT NOT NULL COLLATE NOCASE,
                    created_at TEXT NOT NULL,
                    UNIQUE(scope_key, name)
                );
                CREATE TABLE IF NOT EXISTS cloud_files (
                    file_id TEXT PRIMARY KEY,
                    node_id INTEGER NOT NULL REFERENCES cloud_nodes(node_id) ON DELETE CASCADE,
                    logical_id TEXT NOT NULL,
                    version_number INTEGER NOT NULL DEFAULT 1,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    owner_id TEXT,
                    access_role TEXT NOT NULL DEFAULT 'staff',
                    folder_id TEXT,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cloud_files_node_idx ON cloud_files(node_id, created_at);
                CREATE TABLE IF NOT EXISTS cloud_drive_entries (
                    owner_id TEXT NOT NULL,
                    logical_id TEXT NOT NULL,
                    starred INTEGER NOT NULL DEFAULT 0,
                    trashed_at TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(owner_id, logical_id)
                );
                CREATE TABLE IF NOT EXISTS cloud_simulation_reports (
                    report_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    node_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_db.nodes (
                    node_id INTEGER PRIMARY KEY,
                    node_name TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_db.users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    profile_nonce BLOB,
                    profile_ciphertext BLOB
                );
                CREATE TABLE IF NOT EXISTS backup_db.folders (
                    folder_id TEXT PRIMARY KEY,
                    scope_key TEXT NOT NULL,
                    role TEXT NOT NULL,
                    owner_id TEXT,
                    node_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_db.files (
                    file_id TEXT PRIMARY KEY,
                    node_id INTEGER NOT NULL,
                    logical_id TEXT NOT NULL,
                    version_number INTEGER NOT NULL,
                    is_current INTEGER NOT NULL,
                    owner_id TEXT,
                    access_role TEXT NOT NULL,
                    folder_id TEXT,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_db.drive_entries (
                    owner_id TEXT NOT NULL,
                    logical_id TEXT NOT NULL,
                    starred INTEGER NOT NULL DEFAULT 0,
                    trashed_at TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(owner_id, logical_id)
                );
                CREATE TABLE IF NOT EXISTS backup_db.simulation_reports (
                    report_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    node_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL
                );
                """
            )
        self._migrate_file_versions()
        self._migrate_identity_and_backup()
        self._expire_trash()

    def _migrate_file_versions(self) -> None:
        """Add version metadata and group older same-name uploads without changing their contents."""
        columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(cloud_files)")}
        with self._lock, self._connection:
            if "logical_id" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN logical_id TEXT")
            if "version_number" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN version_number INTEGER NOT NULL DEFAULT 1")
            if "is_current" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN is_current INTEGER NOT NULL DEFAULT 1")
            if "owner_id" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN owner_id TEXT")
            if "access_role" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN access_role TEXT NOT NULL DEFAULT 'staff'")
            if "folder_id" not in columns:
                self._connection.execute("ALTER TABLE cloud_files ADD COLUMN folder_id TEXT")

            rows = self._connection.execute(
                """SELECT file_id, node_id, nonce, ciphertext, created_at
                   FROM cloud_files WHERE logical_id IS NULL
                   ORDER BY node_id, created_at, file_id"""
            ).fetchall()
            groups: dict[tuple[int, str], list[sqlite3.Row]] = {}
            for row in rows:
                payload = self._open(int(row["node_id"]), row["file_id"], row["nonce"], row["ciphertext"])
                name = str(payload.get("filename", "uploaded-file"))[:120]
                groups.setdefault((int(row["node_id"]), name), []).append(row)

            for (node_id, _name), versions in groups.items():
                logical_id = uuid.uuid4().hex
                for version_number, row in enumerate(versions, start=1):
                    self._connection.execute(
                        """UPDATE cloud_files SET logical_id = ?, version_number = ?, is_current = ?
                           WHERE file_id = ?""",
                        (logical_id, version_number, int(version_number == len(versions)), row["file_id"]),
                    )
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS cloud_files_one_current_idx "
                "ON cloud_files(logical_id) WHERE is_current = 1"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS cloud_files_logical_idx ON cloud_files(logical_id, version_number)"
            )

    def _expire_trash(self) -> None:
        """Permanently remove trashed versions after 90 days; current files have no TTL."""
        cutoff = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - 90 * 86400, timezone.utc).isoformat()
        with self._lock, self._connection:
            expired = self._connection.execute(
                "SELECT owner_id, logical_id FROM cloud_drive_entries WHERE trashed_at IS NOT NULL AND trashed_at <= ?",
                (cutoff,),
            ).fetchall()
            for row in expired:
                self._connection.execute("DELETE FROM cloud_files WHERE logical_id = ?", (row["logical_id"],))
                self._connection.execute("DELETE FROM backup_db.files WHERE logical_id = ?", (row["logical_id"],))
                self._connection.execute(
                    "DELETE FROM cloud_drive_entries WHERE owner_id = ? AND logical_id = ?",
                    (row["owner_id"], row["logical_id"]),
                )
                self._connection.execute(
                    "DELETE FROM backup_db.drive_entries WHERE owner_id = ? AND logical_id = ?",
                    (row["owner_id"], row["logical_id"]),
                )

    def update_drive_entry(self, user: dict[str, Any], logical_id: str, action: str) -> dict[str, Any]:
        if action not in {"star", "unstar", "trash", "restore"}:
            raise ValueError("Choose a supported drive action.")
        self._expire_trash()
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT 1 FROM cloud_files WHERE logical_id = ? AND access_role = ? AND (? = 'staff' OR owner_id = ?)
                   UNION ALL SELECT 1 FROM backup_db.files WHERE logical_id = ? AND access_role = ? AND (? = 'staff' OR owner_id = ?) LIMIT 1""",
                (logical_id, user["role"], user["role"], user["id"], logical_id, user["role"], user["role"], user["id"]),
            ).fetchone()
            if row is None:
                raise ValueError("That file is not in your cloud area.")
            now = datetime.now(timezone.utc).isoformat()
            starred = int(action == "star")
            trashed_at = now if action == "trash" else None
            existing = self._connection.execute(
                "SELECT starred, trashed_at FROM cloud_drive_entries WHERE owner_id = ? AND logical_id = ?",
                (user["id"], logical_id),
            ).fetchone()
            if action == "unstar":
                starred = 0
                trashed_at = None if existing is None else existing["trashed_at"]
            elif action == "restore":
                starred = 0 if existing is None else int(existing["starred"])
                trashed_at = None
            elif action == "trash":
                starred = 0 if existing is None else int(existing["starred"])
            elif existing and existing["trashed_at"]:
                trashed_at = existing["trashed_at"]
            values = (user["id"], logical_id, starred, trashed_at, now)
            self._connection.execute(
                "INSERT INTO cloud_drive_entries(owner_id, logical_id, starred, trashed_at, updated_at) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(owner_id, logical_id) DO UPDATE SET starred=excluded.starred, trashed_at=excluded.trashed_at, updated_at=excluded.updated_at",
                values,
            )
            self._connection.execute(
                "INSERT INTO backup_db.drive_entries(owner_id, logical_id, starred, trashed_at, updated_at) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(owner_id, logical_id) DO UPDATE SET starred=excluded.starred, trashed_at=excluded.trashed_at, updated_at=excluded.updated_at",
                values,
            )
        return {"logical_id": logical_id, "starred": bool(starred), "trashed_at": trashed_at}

    def save_simulation_report(self, report_id: str, owner_id: str, payload: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        node_id = 2
        nonce, ciphertext = self._seal(node_id, report_id, payload)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT created_at FROM cloud_simulation_reports WHERE report_id = ? AND owner_id = ?",
                (report_id, owner_id),
            ).fetchone()
            created_at = row["created_at"] if row else now
            values = (report_id, owner_id, node_id, created_at, now, nonce, ciphertext)
            self._connection.execute(
                "INSERT INTO cloud_simulation_reports VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(report_id) DO UPDATE SET updated_at=excluded.updated_at, nonce=excluded.nonce, ciphertext=excluded.ciphertext",
                values,
            )
            self._connection.execute(
                "INSERT INTO backup_db.simulation_reports VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(report_id) DO UPDATE SET updated_at=excluded.updated_at, nonce=excluded.nonce, ciphertext=excluded.ciphertext",
                values,
            )

    def list_simulation_reports(self, owner_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connection:
            backup_rows = {row["report_id"]: row for row in self._connection.execute(
                "SELECT * FROM backup_db.simulation_reports WHERE owner_id = ?", (owner_id,)
            ).fetchall()}
            primary_rows = {row["report_id"]: row for row in self._connection.execute(
                "SELECT * FROM cloud_simulation_reports WHERE owner_id = ?", (owner_id,)
            ).fetchall()}
            for report_id, backup in backup_rows.items():
                if report_id not in primary_rows:
                    self._connection.execute(
                        "INSERT INTO cloud_simulation_reports VALUES(?, ?, ?, ?, ?, ?, ?)",
                        tuple(backup[key] for key in ("report_id", "owner_id", "node_id", "created_at", "updated_at", "nonce", "ciphertext")),
                    )
                    primary_rows[report_id] = backup
            rows = sorted(primary_rows.values(), key=lambda row: row["updated_at"], reverse=True)[:max(1, min(int(limit), 100))]
        reports = []
        for row in rows:
            try:
                payload = self._open(int(row["node_id"]), row["report_id"], row["nonce"], row["ciphertext"])
            except StorageIntegrityError:
                backup = backup_rows.get(row["report_id"])
                if backup is None:
                    continue
                payload = self._open(int(backup["node_id"]), backup["report_id"], backup["nonce"], backup["ciphertext"])
                with self._lock, self._connection:
                    self._connection.execute(
                        "UPDATE cloud_simulation_reports SET nonce=?, ciphertext=?, updated_at=? WHERE report_id=?",
                        (backup["nonce"], backup["ciphertext"], backup["updated_at"], backup["report_id"]),
                    )
            reports.append({"id": row["report_id"], "created_at": row["created_at"], "updated_at": row["updated_at"], "payload": payload})
        return reports

    def _migrate_identity_and_backup(self) -> None:
        """Recover missing primary rows and keep the separate backup database synchronized."""
        recovered_folder_id = "folder-recovered-staff"
        with self._lock, self._connection:
            # Older databases predate usernames. Add the column in both stores before
            # mirroring rows, then assign stable usernames to legacy accounts.
            for table in ("cloud_users", "backup_db.users"):
                if "." in table:
                    schema, table_name = table.split(".", 1)
                    pragma = f"PRAGMA {schema}.table_info({table_name})"
                else:
                    pragma = f"PRAGMA table_info({table})"
                columns = {row["name"] for row in self._connection.execute(pragma)}
                if "username" not in columns:
                    self._connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN username TEXT NOT NULL DEFAULT ''"
                    )
                if "profile_nonce" not in columns:
                    self._connection.execute(f"ALTER TABLE {table} ADD COLUMN profile_nonce BLOB")
                if "profile_ciphertext" not in columns:
                    self._connection.execute(f"ALTER TABLE {table} ADD COLUMN profile_ciphertext BLOB")
            self._connection.execute("INSERT OR IGNORE INTO cloud_nodes SELECT * FROM backup_db.nodes")
            self._connection.execute("INSERT OR IGNORE INTO cloud_users SELECT * FROM backup_db.users")
            rows = self._connection.execute(
                "SELECT user_id, email, username FROM cloud_users ORDER BY created_at, user_id"
            ).fetchall()
            used_usernames = {str(row["username"]).casefold() for row in rows if row["username"]}
            for row in rows:
                if row["username"]:
                    continue
                base = re.sub(r"[^a-z0-9._-]+", "-", str(row["email"]).split("@", 1)[0].casefold()).strip("._-")
                if len(base) < 3:
                    base = f"user-{base}".strip("._-")
                base = base[:30].rstrip("._-") or "cloud-user"
                username = base
                suffix = 2
                while username.casefold() in used_usernames:
                    tail = str(suffix)
                    username = f"{base[:30 - len(tail)].rstrip('._-')}{tail}"
                    suffix += 1
                self._connection.execute(
                    "UPDATE cloud_users SET username = ? WHERE user_id = ?", (username, row["user_id"])
                )
                used_usernames.add(username.casefold())
            self._connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS cloud_users_username_idx ON cloud_users(username COLLATE NOCASE)"
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO backup_db.users(user_id, email, display_name, role, status, password_salt,
                       password_hash, created_at, username, profile_nonce, profile_ciphertext)
                   SELECT user_id, email, display_name, role, status, password_salt, password_hash, created_at, username, profile_nonce, profile_ciphertext
                   FROM cloud_users"""
            )
            self._connection.execute("INSERT OR IGNORE INTO cloud_folders SELECT * FROM backup_db.folders")
            self._connection.execute(
                """INSERT OR IGNORE INTO cloud_files(file_id, node_id, logical_id, version_number, is_current,
                   owner_id, access_role, folder_id, nonce, ciphertext, created_at)
                   SELECT file_id, node_id, logical_id, version_number, is_current, owner_id, access_role,
                          folder_id, nonce, ciphertext, created_at FROM backup_db.files"""
            )
            primary_rows = self._connection.execute(
                "SELECT file_id, node_id, nonce, ciphertext FROM cloud_files"
            ).fetchall()
            for primary in primary_rows:
                try:
                    self._open(primary["node_id"], primary["file_id"], primary["nonce"], primary["ciphertext"])
                except StorageIntegrityError:
                    backup = self._connection.execute(
                        "SELECT * FROM backup_db.files WHERE file_id = ?", (primary["file_id"],)
                    ).fetchone()
                    if backup is None:
                        continue
                    self._open(backup["node_id"], backup["file_id"], backup["nonce"], backup["ciphertext"])
                    self._connection.execute(
                        """UPDATE cloud_files SET node_id=?, logical_id=?, version_number=?, is_current=?,
                           owner_id=?, access_role=?, folder_id=?, nonce=?, ciphertext=?, created_at=? WHERE file_id=?""",
                        (backup["node_id"], backup["logical_id"], backup["version_number"], backup["is_current"],
                         backup["owner_id"], backup["access_role"], backup["folder_id"], backup["nonce"],
                         backup["ciphertext"], backup["created_at"], backup["file_id"]),
                    )
            self._connection.execute(
                """INSERT OR IGNORE INTO cloud_folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                   VALUES(?, 'staff', 'staff', NULL, 2, 'Recovered files', ?)""",
                (recovered_folder_id, datetime.now(timezone.utc).isoformat()),
            )
            self._connection.execute(
                "UPDATE cloud_files SET folder_id = ? WHERE folder_id IS NULL",
                (recovered_folder_id,),
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO backup_db.nodes SELECT node_id, node_name, role FROM cloud_nodes"""
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO backup_db.users(user_id, email, display_name, role, status, password_salt,
                       password_hash, created_at, username)
                   SELECT user_id, email, display_name, role, status, password_salt, password_hash, created_at, username
                   FROM cloud_users"""
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO backup_db.folders
                   SELECT folder_id, scope_key, role, owner_id, node_id, name, created_at FROM cloud_folders"""
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO backup_db.files
                   SELECT file_id, node_id, logical_id, version_number, is_current, owner_id, access_role,
                          folder_id, nonce, ciphertext, created_at FROM cloud_files"""
            )

    def find_duplicates(
        self, node_id: int, folder_id: str, owner_id: str, access_role: str, filenames: list[str]
    ) -> list[dict[str, Any]]:
        requested = {name.casefold() for name in filenames}
        if not requested:
            return []
        with self._lock:
            rows = self._connection.execute(
                """SELECT f.file_id, f.logical_id, f.version_number, f.created_at, f.nonce, f.ciphertext
                   FROM cloud_files f WHERE f.node_id = ? AND f.folder_id = ? AND f.access_role = ?
                     AND f.is_current = 1 AND (? = 'staff' OR f.owner_id = ?)""",
                (node_id, folder_id, access_role, access_role, owner_id),
            ).fetchall()
            found = {}
            for row in rows:
                payload = self._open(node_id, row["file_id"], row["nonce"], row["ciphertext"])
                filename = str(payload.get("filename", "uploaded-file"))[:120]
                if filename.casefold() in requested:
                    try:
                        size_bytes = len(base64.b64decode(payload.get("content", ""), validate=True))
                    except (ValueError, TypeError):
                        size_bytes = 0
                    versions = self._connection.execute(
                        "SELECT COUNT(*) FROM cloud_files WHERE logical_id = ?", (row["logical_id"],)
                    ).fetchone()[0]
                    found[filename] = {"filename": filename, "version": int(row["version_number"]), "version_count": int(versions),
                                       "size_bytes": size_bytes, "created_at": row["created_at"]}
            return list(found.values())

    @staticmethod
    def _aad(node_id: int, file_id: str) -> bytes:
        return f"cloud-d|v1|{node_id}|{file_id}".encode("utf-8")

    def _seal(self, node_id: int, file_id: str, payload: dict[str, Any]) -> tuple[bytes, bytes]:
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        nonce = secrets.token_bytes(12)
        return nonce, self._cipher.encrypt(nonce, plaintext, self._aad(node_id, file_id))

    def _open(self, node_id: int, file_id: str, nonce: bytes, ciphertext: bytes) -> dict[str, Any]:
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, self._aad(node_id, file_id))
            result = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise StorageIntegrityError(
                f"Encrypted data for {file_id} failed authentication. Check that Cloud-D is using its original encryption key."
            ) from exc
        if not isinstance(result, dict):
            raise StorageIntegrityError(f"Encrypted data for {file_id} has an invalid format.")
        return result

    def sync_nodes(self, nodes: list[dict[str, Any]]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                """INSERT INTO cloud_nodes(node_id, node_name, role) VALUES(?, ?, ?)
                   ON CONFLICT(node_id) DO UPDATE SET node_name=excluded.node_name, role=excluded.role""",
                [(node["id"], node["name"], node["role"]) for node in nodes],
            )
            self._connection.executemany(
                """INSERT INTO backup_db.nodes(node_id, node_name, role) VALUES(?, ?, ?)
                   ON CONFLICT(node_id) DO UPDATE SET node_name=excluded.node_name, role=excluded.role""",
                [(node["id"], node["name"], node["role"]) for node in nodes],
            )

    def _public_user(self, row: sqlite3.Row | dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        user = {
            "id": row["user_id"],
            "email": row["email"],
            "username": row["username"],
            "name": row["display_name"],
            "role": row["role"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
        if "profile_nonce" in row.keys() and row["profile_nonce"] and row["profile_ciphertext"]:
            profile = self._open(0, f"profile-{row['user_id']}", row["profile_nonce"], row["profile_ciphertext"])
            user["profile_picture"] = profile.get("image_data_url", "")
        return user

    def create_user(
        self,
        user_id: str,
        email: str,
        username: str,
        display_name: str,
        role: str,
        status: str,
        password_salt: bytes,
        password_hash: bytes,
        profile_picture: str = "",
    ) -> dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        profile_nonce = profile_ciphertext = None
        if profile_picture:
            profile_nonce, profile_ciphertext = self._seal(0, f"profile-{user_id}", {"image_data_url": profile_picture})
        values = (user_id, email, display_name, role, status, password_salt, password_hash, created_at, username, profile_nonce, profile_ciphertext)
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO cloud_users(user_id, email, display_name, role, status, password_salt,
                   password_hash, created_at, username, profile_nonce, profile_ciphertext) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
            self._connection.execute(
                """INSERT INTO backup_db.users(user_id, email, display_name, role, status, password_salt,
                   password_hash, created_at, username, profile_nonce, profile_ciphertext) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )
        result = {"id": user_id, "email": email, "username": username, "name": display_name, "role": role, "status": status, "created_at": created_at}
        if profile_picture:
            result["profile_picture"] = profile_picture
        return result

    def get_user_credentials(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM cloud_users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        if row is None:
            return None
        return {key: row[key] for key in row.keys()}

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM cloud_users WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
        return {key: row[key] for key in row.keys()} if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM cloud_users WHERE user_id = ?", (user_id,)).fetchone()
        return self._public_user(row)

    def activate_pending_staff(self, user_id: str, username: str) -> dict[str, Any] | None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE cloud_users SET status = 'active', username = ? WHERE user_id = ? AND role = 'staff' AND status = 'pending'",
                (username, user_id),
            )
            self._connection.execute(
                "UPDATE backup_db.users SET status = 'active', username = ? WHERE user_id = ? AND role = 'staff' AND status = 'pending'",
                (username, user_id),
            )
        return self.get_user(user_id)

    def create_session(self, raw_token: str, user_id: str, expires_at: int) -> None:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM cloud_sessions WHERE expires_at <= ?", (int(datetime.now().timestamp()),))
            self._connection.execute(
                "INSERT INTO cloud_sessions(session_hash, user_id, expires_at, created_at) VALUES(?, ?, ?, ?)",
                (token_hash, user_id, expires_at, created_at),
            )

    def resolve_session(self, raw_token: str | None) -> dict[str, Any] | None:
        if not raw_token:
            return None
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            row = self._connection.execute(
                """SELECT u.user_id, u.email, u.username, u.display_name, u.role, u.status, u.created_at,
                          u.profile_nonce, u.profile_ciphertext
                   FROM cloud_sessions s JOIN cloud_users u ON u.user_id = s.user_id
                   WHERE s.session_hash = ? AND s.expires_at > ? AND u.status = 'active'""",
                (token_hash, int(datetime.now().timestamp())),
            ).fetchone()
            self._connection.execute("DELETE FROM cloud_sessions WHERE expires_at <= ?", (int(datetime.now().timestamp()),))
        return self._public_user(row)

    def revoke_session(self, raw_token: str | None) -> None:
        if not raw_token:
            return
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM cloud_sessions WHERE session_hash = ?", (token_hash,))

    @staticmethod
    def _folder_scope(user: dict[str, Any]) -> tuple[str, str, str | None, int]:
        role = user["role"]
        if role == "staff":
            return "staff", role, None, 2
        user_id = user["id"]
        return f"customer:{user_id}", role, user_id, 3

    def ensure_default_folder(self, user: dict[str, Any]) -> dict[str, Any]:
        scope_key, role, owner_id, node_id = self._folder_scope(user)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT folder_id, name, created_at FROM cloud_folders WHERE scope_key = ? AND name = 'My Files' COLLATE NOCASE",
                (scope_key,),
            ).fetchone()
            if row is None:
                folder_id = uuid.uuid4().hex
                created_at = datetime.now(timezone.utc).isoformat()
                values = (folder_id, scope_key, role, owner_id, node_id, "My Files", created_at)
                self._connection.execute(
                    """INSERT INTO cloud_folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                       VALUES(?, ?, ?, ?, ?, ?, ?)""", values,
                )
                self._connection.execute(
                    """INSERT INTO backup_db.folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                       VALUES(?, ?, ?, ?, ?, ?, ?)""", values,
                )
                return {"id": folder_id, "name": "My Files", "created_at": created_at, "node_id": node_id}
            return {"id": row["folder_id"], "name": row["name"], "created_at": row["created_at"], "node_id": node_id}

    def list_folders(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        scope_key, _role, _owner_id, _node_id = self._folder_scope(user)
        with self._lock:
            rows = self._connection.execute(
                "SELECT folder_id, name, created_at FROM cloud_folders WHERE scope_key = ? ORDER BY name COLLATE NOCASE",
                (scope_key,),
            ).fetchall()
        return [{"id": row["folder_id"], "name": row["name"], "created_at": row["created_at"]} for row in rows]

    def create_folder(self, user: dict[str, Any], name: str) -> dict[str, Any]:
        scope_key, role, owner_id, node_id = self._folder_scope(user)
        folder_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        values = (folder_id, scope_key, role, owner_id, node_id, name, created_at)
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO cloud_folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""", values,
            )
            self._connection.execute(
                """INSERT INTO backup_db.folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""", values,
            )
        return {"id": folder_id, "name": name, "created_at": created_at}

    def get_folder(self, folder_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
        scope_key, _role, _owner_id, _node_id = self._folder_scope(user)
        with self._lock:
            row = self._connection.execute(
                """SELECT folder_id, scope_key, role, owner_id, node_id, name, created_at
                   FROM cloud_folders WHERE folder_id = ? AND scope_key = ?""",
                (folder_id, scope_key),
            ).fetchone()
        return dict(row) if row else None

    def save_upload_batch(
        self,
        node_id: int,
        folder_id: str,
        owner_id: str,
        access_role: str,
        items: list[dict[str, Any]],
        duplicate_mode: str | None = None,
    ) -> list[dict[str, Any]]:
        names = [str(item["filename"])[:120] for item in items]
        duplicates = self.find_duplicates(node_id, folder_id, owner_id, access_role, names)
        if duplicates and duplicate_mode not in {"new_version", "replace"}:
            raise DuplicateUploadError(duplicates)

        stored: list[dict[str, Any]] = []
        with self._lock, self._connection:
            for item in items:
                filename = str(item["filename"])[:120]
                current_rows = self._connection.execute(
                    """SELECT file_id, logical_id, version_number, nonce, ciphertext
                       FROM cloud_files WHERE node_id = ? AND folder_id = ? AND access_role = ?
                         AND is_current = 1 AND (? = 'staff' OR owner_id = ?)""",
                    (node_id, folder_id, access_role, access_role, owner_id),
                ).fetchall()
                current_match = None
                all_group_rows = []
                replaced_ids = []
                matching_logical_id = None
                for row in current_rows:
                    payload = self._open(node_id, row["file_id"], row["nonce"], row["ciphertext"])
                    if str(payload.get("filename", "uploaded-file"))[:120].casefold() == filename.casefold():
                        current_match = row
                        matching_logical_id = row["logical_id"]
                        break

                if duplicate_mode == "replace" and current_match is not None:
                    replaced_ids = [row["file_id"] for row in self._connection.execute(
                        "SELECT file_id FROM cloud_files WHERE logical_id = ?", (matching_logical_id,)
                    ).fetchall()]
                    self._connection.execute(
                        "DELETE FROM cloud_files WHERE logical_id = ?", (matching_logical_id,)
                    )
                    self._connection.execute(
                        "DELETE FROM backup_db.files WHERE logical_id = ?", (matching_logical_id,)
                    )
                    matching_logical_id = None
                    current_match = None

                if matching_logical_id:
                    all_group_rows = self._connection.execute(
                        "SELECT file_id, version_number FROM cloud_files WHERE logical_id = ? ORDER BY version_number",
                        (matching_logical_id,),
                    ).fetchall()
                    version_number = max(int(row["version_number"]) for row in all_group_rows) + 1
                    superseded_ids = [row["file_id"] for row in all_group_rows if row["file_id"] == current_match["file_id"]]
                    self._connection.execute(
                        "UPDATE cloud_files SET is_current = 0 WHERE logical_id = ? AND is_current = 1",
                        (matching_logical_id,),
                    )
                    self._connection.execute(
                        "UPDATE backup_db.files SET is_current = 0 WHERE logical_id = ? AND is_current = 1",
                        (matching_logical_id,),
                    )
                else:
                    matching_logical_id = uuid.uuid4().hex
                    version_number = 1
                    superseded_ids = replaced_ids

                file_id = f"FILE-{node_id}-{uuid.uuid4().hex[:16].upper()}"
                payload = {
                    "filename": filename,
                    "kind": item["kind"],
                    "content": base64.b64encode(bytes(item.get("content", b""))).decode("ascii"),
                    "rows": item.get("rows", []),
                }
                nonce, ciphertext = self._seal(node_id, file_id, payload)
                created_at = datetime.now(timezone.utc).isoformat()
                self._connection.execute(
                    """INSERT INTO cloud_files(file_id, node_id, logical_id, version_number, is_current,
                       owner_id, access_role, folder_id, nonce, ciphertext, created_at)
                       VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
                    (file_id, node_id, matching_logical_id, version_number, owner_id, access_role, folder_id,
                     nonce, ciphertext, created_at),
                )
                self._connection.execute(
                    """INSERT INTO backup_db.files(file_id, node_id, logical_id, version_number, is_current,
                       owner_id, access_role, folder_id, nonce, ciphertext, created_at)
                       VALUES(?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
                    (file_id, node_id, matching_logical_id, version_number, owner_id, access_role, folder_id,
                     nonce, ciphertext, created_at),
                )
                stored.append({
                    "id": file_id,
                    "logical_id": matching_logical_id,
                    "filename": filename,
                    "version": version_number,
                    "version_count": version_number,
                    "created_at": created_at,
                    "superseded_ids": superseded_ids,
                    "owner_id": owner_id,
                    "access_role": access_role,
                    "folder_id": folder_id,
                })
        return stored

    def load_uploads(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT f.file_id, f.node_id, f.logical_id, f.version_number, f.created_at, f.nonce, f.ciphertext,
                          f.owner_id, f.access_role, f.folder_id,
                          (SELECT COUNT(*) FROM cloud_files v WHERE v.logical_id = f.logical_id) AS version_count
                   FROM cloud_files f JOIN cloud_nodes n ON n.node_id=f.node_id
                   WHERE f.is_current = 1 ORDER BY f.node_id, f.created_at, f.file_id"""
            ).fetchall()
        batches: dict[int, dict[str, Any]] = {}
        for row in rows:
            node_id = int(row["node_id"])
            payload = self._open(node_id, row["file_id"], row["nonce"], row["ciphertext"])
            batch = batches.setdefault(node_id, {
                "node_id": node_id,
                "items": [],
            })
            try:
                content = base64.b64decode(payload.get("content", ""), validate=True)
            except (ValueError, TypeError) as exc:
                raise StorageIntegrityError(f"Encrypted file {row['file_id']} has invalid content encoding.") from exc
            batch["items"].append({
                "file_id": row["file_id"],
                "logical_id": row["logical_id"],
                "version": int(row["version_number"]),
                "version_count": int(row["version_count"]),
                "created_at": row["created_at"],
                "owner_id": row["owner_id"],
                "access_role": row["access_role"],
                "folder_id": row["folder_id"],
                "filename": payload.get("filename", "uploaded-file"),
                "kind": payload.get("kind", "document"),
                "content": content,
                "rows": payload.get("rows", []),
            })
        return list(batches.values())

    @staticmethod
    def _can_access_file(row: sqlite3.Row | dict[str, Any], user: dict[str, Any]) -> bool:
        if row["access_role"] != user["role"]:
            return False
        return user["role"] == "staff" or row["owner_id"] == user["id"]

    def _decode_file_row(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        node_id = int(row["node_id"])
        file_id = str(row["file_id"])
        payload = self._open(node_id, file_id, row["nonce"], row["ciphertext"])
        try:
            content = base64.b64decode(payload.get("content", ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise StorageIntegrityError(f"Encrypted file {file_id} has invalid content encoding.") from exc
        return {
            "id": file_id,
            "logical_id": row["logical_id"],
            "version": int(row["version_number"]),
            "created_at": row["created_at"],
            "node_id": node_id,
            "owner_id": row["owner_id"],
            "access_role": row["access_role"],
            "folder_id": row["folder_id"],
            "filename": str(payload.get("filename", "uploaded-file"))[:120],
            "size_bytes": len(content),
            "kind": "data" if payload.get("kind") == "rows" else "document",
            "record_count": len(payload.get("rows", [])) if payload.get("kind") == "rows" else 1,
            "content": content,
            "rows": payload.get("rows", []),
        }

    def list_files(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        self._expire_trash()
        with self._lock:
            primary = self._connection.execute(
                """SELECT f.*, COALESCE(d.name, bd.name, 'Recovered files') AS folder_name, 1 AS primary_available,
                          (SELECT COUNT(*) FROM cloud_files v WHERE v.logical_id = f.logical_id) AS version_count,
                          EXISTS(SELECT 1 FROM backup_db.files b WHERE b.file_id = f.file_id) AS backup_available
                   FROM cloud_files f LEFT JOIN cloud_folders d ON d.folder_id = f.folder_id
                   LEFT JOIN backup_db.folders bd ON bd.folder_id = f.folder_id
                   WHERE f.is_current = 1 AND f.access_role = ? AND (? = 'staff' OR f.owner_id = ?)
                   ORDER BY f.created_at DESC""",
                (user["role"], user["role"], user["id"]),
            ).fetchall()
            recovered = self._connection.execute(
                """SELECT b.*, COALESCE(d.name, bd.name, 'Recovered files') AS folder_name,
                          (SELECT COUNT(*) FROM backup_db.files v WHERE v.logical_id = b.logical_id) AS version_count,
                          0 AS primary_available, 1 AS backup_available
                   FROM backup_db.files b LEFT JOIN cloud_folders d ON d.folder_id = b.folder_id
                   LEFT JOIN backup_db.folders bd ON bd.folder_id = b.folder_id
                   WHERE b.is_current = 1 AND b.access_role = ? AND (? = 'staff' OR b.owner_id = ?)
                     AND NOT EXISTS(SELECT 1 FROM cloud_files f WHERE f.file_id = b.file_id)
                   ORDER BY b.created_at DESC""",
                (user["role"], user["role"], user["id"]),
            ).fetchall()
            drive = self._connection.execute(
                "SELECT logical_id, starred, trashed_at FROM cloud_drive_entries WHERE owner_id = ?",
                (user["id"],),
            ).fetchall()
            drive_backup = self._connection.execute(
                "SELECT logical_id, starred, trashed_at FROM backup_db.drive_entries WHERE owner_id = ?",
                (user["id"],),
            ).fetchall()
        drive_state = {row["logical_id"]: {"starred": row["starred"], "trashed_at": row["trashed_at"]}
                       for row in [*drive_backup, *drive]}
        files = []
        for row in [*primary, *recovered]:
            decoded = self._decode_file_row(row)
            files.append({key: decoded[key] for key in (
                "id", "logical_id", "version", "created_at", "filename", "size_bytes", "kind", "record_count"
            )} | {
                "folder_id": row["folder_id"],
                "folder_name": row["folder_name"] or "Recovered files",
                "version_count": int(row["version_count"]),
                "primary_available": bool(row["primary_available"]),
                "backup_available": bool(row["backup_available"]),
                "starred": bool(drive_state.get(row["logical_id"], {}).get("starred", 0)),
                "trashed_at": drive_state.get(row["logical_id"], {}).get("trashed_at"),
            })
        return files

    def get_file(self, file_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM cloud_files WHERE file_id = ?", (file_id,)
            ).fetchone()
            if row is None:
                row = self._connection.execute(
                    "SELECT * FROM backup_db.files WHERE file_id = ?", (file_id,)
                ).fetchone()
        if row is None:
            return None
        if not self._can_access_file(row, user):
            return None
        try:
            return self._decode_file_row(row)
        except StorageIntegrityError:
            with self._lock:
                backup = self._connection.execute(
                    "SELECT * FROM backup_db.files WHERE file_id = ?", (file_id,)
                ).fetchone()
            if backup is None or not self._can_access_file(backup, user):
                raise
            repaired = self._decode_file_row(backup)
            with self._lock, self._connection:
                self._connection.execute(
                    """UPDATE cloud_files SET nonce=?, ciphertext=?, node_id=?, logical_id=?, version_number=?,
                       is_current=?, owner_id=?, access_role=?, folder_id=?, created_at=? WHERE file_id=?""",
                    (backup["nonce"], backup["ciphertext"], backup["node_id"], backup["logical_id"],
                     backup["version_number"], backup["is_current"], backup["owner_id"], backup["access_role"],
                     backup["folder_id"], backup["created_at"], file_id),
                )
            return repaired

    def get_file_versions(self, logical_id: str, user: dict[str, Any]) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM backup_db.files WHERE logical_id = ? ORDER BY version_number DESC""",
                (logical_id,),
            ).fetchall()
        versions = []
        for row in rows:
            if not self._can_access_file(row, user):
                return []
            decoded = self._decode_file_row(row)
            versions.append({
                "id": decoded["id"],
                "version": decoded["version"],
                "created_at": decoded["created_at"],
                "current": bool(row["is_current"]),
                "size_bytes": decoded["size_bytes"],
                "kind": decoded["kind"],
                "record_count": decoded["record_count"],
            })
        return versions

    def restore_backup_file(self, file_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock, self._connection:
            row = self._connection.execute("SELECT * FROM backup_db.files WHERE file_id = ?", (file_id,)).fetchone()
            if row is None or not self._can_access_file(row, user):
                return None
            current = self._connection.execute(
                "SELECT file_id FROM cloud_files WHERE logical_id = ? AND is_current = 1", (row["logical_id"],)
            ).fetchone()
            is_current = int(bool(row["is_current"]) and current is None)
            values = (
                row["file_id"], row["node_id"], row["logical_id"], row["version_number"], is_current,
                row["owner_id"], row["access_role"], row["folder_id"], row["nonce"], row["ciphertext"], row["created_at"],
            )
            self._connection.execute(
                """INSERT OR IGNORE INTO cloud_files(file_id, node_id, logical_id, version_number, is_current,
                   owner_id, access_role, folder_id, nonce, ciphertext, created_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", values,
            )
            if row["folder_id"]:
                folder = self._connection.execute(
                    "SELECT 1 FROM cloud_folders WHERE folder_id = ?", (row["folder_id"],)
                ).fetchone()
                if folder is None:
                    self._connection.execute(
                        """INSERT OR IGNORE INTO cloud_folders(folder_id, scope_key, role, owner_id, node_id, name, created_at)
                           SELECT folder_id, scope_key, role, owner_id, node_id, name, created_at
                           FROM backup_db.folders WHERE folder_id = ?""", (row["folder_id"],),
                    )
        restored = self.get_file(file_id, user)
        if restored is not None:
            restored["is_current"] = bool(is_current or row["is_current"])
            restored["superseded_ids"] = []
        return restored

    def verify_node_decryption(self, node_id: int) -> int:
        with self._lock:
            rows = self._connection.execute(
                "SELECT file_id, nonce, ciphertext FROM cloud_files WHERE node_id = ? ORDER BY file_id", (node_id,)
            ).fetchall()
        for row in rows:
            self._open(node_id, row["file_id"], row["nonce"], row["ciphertext"])
        return len(rows)

    def reencrypt_node(self, node_id: int) -> int:
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT file_id, nonce, ciphertext FROM cloud_files WHERE node_id = ? ORDER BY file_id", (node_id,)
            ).fetchall()
            updates = []
            for row in rows:
                payload = self._open(node_id, row["file_id"], row["nonce"], row["ciphertext"])
                nonce, ciphertext = self._seal(node_id, row["file_id"], payload)
                updates.append((nonce, ciphertext, row["file_id"]))
            self._connection.executemany(
                "UPDATE cloud_files SET nonce = ?, ciphertext = ? WHERE file_id = ?", updates
            )
            self._connection.executemany(
                "UPDATE backup_db.files SET nonce = ?, ciphertext = ? WHERE file_id = ?", updates
            )
        return len(rows)

    def snapshot(self, user: dict[str, Any] | None = None) -> dict[str, Any]:
        if user:
            file_scope = "f.access_role = ? AND (? = 'staff' OR f.owner_id = ?)"
            backup_scope = "b.access_role = ? AND (? = 'staff' OR b.owner_id = ?)"
            params = (user["role"], user["role"], user["id"])
        else:
            file_scope = "1 = 1"
            backup_scope = "1 = 1"
            params = ()
        with self._lock:
            rows = self._connection.execute(
                f"""SELECT n.node_id, n.node_name, COUNT(f.file_id) AS file_count,
                          COALESCE(SUM(length(f.ciphertext)), 0) AS encrypted_bytes
                   FROM cloud_nodes n LEFT JOIN cloud_files f ON f.node_id=n.node_id AND {file_scope}
                   GROUP BY n.node_id, n.node_name ORDER BY n.node_id"""
            , params).fetchall()
            backup = self._connection.execute(
                f"SELECT COUNT(*) AS file_count, COALESCE(SUM(length(ciphertext)), 0) AS encrypted_bytes "
                f"FROM backup_db.files b WHERE {backup_scope}", params
            ).fetchone()
            primary_count = self._connection.execute(
                f"SELECT COUNT(*) FROM cloud_files f WHERE {file_scope}", params
            ).fetchone()[0]
        hosted = bool(os.environ.get("RENDER") or os.environ.get("RENDER_EXTERNAL_HOSTNAME"))
        return {
            "engine": "SQLite",
            "encryption": "AES-256-GCM",
            "backup_database": "SQLite recovery replica with encrypted file payloads",
            "backup_file_count": int(backup["file_count"]),
            "backup_bytes": int(backup["encrypted_bytes"]),
            "backup_ready": self.backup_path.exists(),
            "key_source": self.key_source,
            "persistent": not hosted,
            "deployment": "hosted temporary filesystem" if hosted else "local persistent database",
            "storage_note": (
                "This Render service uses a temporary filesystem. Encrypted file contents can be lost when the instance is replaced. Account and folder metadata are not encrypted as a whole database."
                if hosted else
                "Encrypted file contents persist on this device across app restarts. Account and folder metadata are not encrypted as a whole database. Back up both SQLite files and the encryption key together."
            ),
            "nodes": [
                {"id": int(row["node_id"]), "name": row["node_name"], "file_count": int(row["file_count"]),
                 "encrypted_bytes": int(row["encrypted_bytes"])}
                for row in rows
            ],
            "encrypted_file_count": int(primary_count),
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()

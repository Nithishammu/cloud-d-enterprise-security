"""Cloud-D Expiring Encrypted Share Links Engine.

Task 6: Expiring Encrypted Share Links
Generates secure, temporary, password-protected public share links (/share/<token>)
with automatic TTL expiry, download quotas, cryptographic password hashing,
and one-click revocation.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cloud_d.share")


class ShareLinkManager:
    """Manages secure share links with TTL expiration, quotas, and PBKDF2 password checks."""

    def __init__(self, db_path: str = "cloud_d_production.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_share_links (
                    share_token TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    logical_id TEXT NOT NULL,
                    created_by_user TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    max_downloads INTEGER,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    password_hash TEXT,
                    salt TEXT,
                    is_revoked INTEGER NOT NULL DEFAULT 0,
                    label TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_share_access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    share_token TEXT NOT NULL,
                    accessed_at REAL NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    status TEXT NOT NULL
                )
                """
            )
            conn.commit()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Derive PBKDF2-HMAC-SHA256 password hash."""
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100_000,
        )
        return derived.hex()

    def create_share_link(
        self,
        file_id: str,
        logical_id: str,
        created_by_user: str,
        ttl_seconds: int = 86400,  # 24 hours default
        max_downloads: Optional[int] = None,
        password: Optional[str] = None,
        label: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a new expiring share token."""
        token = secrets.token_urlsafe(24)
        now = time.time()
        expires_at = now + ttl_seconds

        password_hash = None
        salt = None
        if password:
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(password, salt)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cloud_share_links
                (share_token, file_id, logical_id, created_by_user, created_at, expires_at, max_downloads, download_count, password_hash, salt, is_revoked, label)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, ?)
                """,
                (
                    token,
                    file_id,
                    logical_id,
                    created_by_user,
                    now,
                    expires_at,
                    max_downloads,
                    password_hash,
                    salt,
                    label or f"Share-{token[:8]}",
                ),
            )
            conn.commit()

        return {
            "share_token": token,
            "share_url": f"/share/{token}",
            "expires_at": expires_at,
            "ttl_seconds": ttl_seconds,
            "max_downloads": max_downloads,
            "has_password": bool(password),
            "label": label,
        }

    def get_share_metadata(self, token: str) -> dict[str, Any]:
        """Retrieve public metadata without revealing file content."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cloud_share_links WHERE share_token = ?", (token,)
            ).fetchone()

            if not row:
                raise ValueError("Share link not found or invalid.")

            now = time.time()
            if row["is_revoked"]:
                raise ValueError("This share link has been revoked by the owner.")
            if now > row["expires_at"]:
                raise ValueError("This share link has expired.")
            if row["max_downloads"] is not None and row["download_count"] >= row["max_downloads"]:
                raise ValueError("This share link has exceeded its maximum download quota.")

            return {
                "share_token": token,
                "file_id": row["file_id"],
                "logical_id": row["logical_id"],
                "created_by": row["created_by_user"],
                "expires_at": row["expires_at"],
                "remaining_seconds": max(0, int(row["expires_at"] - now)),
                "max_downloads": row["max_downloads"],
                "download_count": row["download_count"],
                "remaining_downloads": (row["max_downloads"] - row["download_count"]) if row["max_downloads"] else "unlimited",
                "requires_password": bool(row["password_hash"]),
                "label": row["label"],
            }

    def access_share_link(
        self,
        token: str,
        password: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        user_agent: str = "Unknown",
    ) -> dict[str, Any]:
        """Authorize access to the shared file, enforce quota/TTL, and increment count."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cloud_share_links WHERE share_token = ?", (token,)
            ).fetchone()

            def _log(status: str) -> None:
                conn.execute(
                    """
                    INSERT INTO cloud_share_access_logs (share_token, accessed_at, ip_address, user_agent, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (token, now, ip_address, user_agent, status),
                )
                conn.commit()

            if not row:
                _log("NOT_FOUND")
                raise ValueError("Share link not found.")

            if row["is_revoked"]:
                _log("REVOKED")
                raise ValueError("This share link has been revoked.")

            if now > row["expires_at"]:
                _log("EXPIRED")
                raise ValueError("This share link has expired.")

            if row["max_downloads"] is not None and row["download_count"] >= row["max_downloads"]:
                _log("QUOTA_EXCEEDED")
                raise ValueError("Download quota limit exceeded.")

            if row["password_hash"]:
                if not password:
                    _log("AUTH_REQUIRED")
                    raise PermissionError("Password required to access this file.")
                expected_hash = self._hash_password(password, row["salt"])
                if not hmac.compare_digest(expected_hash, row["password_hash"]):
                    _log("INVALID_PASSWORD")
                    raise PermissionError("Incorrect share link password.")

            # Increment count
            new_count = row["download_count"] + 1
            conn.execute(
                "UPDATE cloud_share_links SET download_count = ? WHERE share_token = ?",
                (new_count, token),
            )
            _log("AUTHORIZED")

            return {
                "authorized": True,
                "file_id": row["file_id"],
                "logical_id": row["logical_id"],
                "download_number": new_count,
            }

    def revoke_share_link(self, token: str, user_id: str) -> bool:
        """Revoke a share link by owner."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "UPDATE cloud_share_links SET is_revoked = 1 WHERE share_token = ? AND (created_by_user = ? OR ? = 'admin')",
                (token, user_id, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def list_user_shares(self, user_id: str) -> list[dict[str, Any]]:
        """List active share links created by the user."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM cloud_share_links
                WHERE created_by_user = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
            now = time.time()
            results = []
            for r in rows:
                item = dict(r)
                item["is_expired"] = now > r["expires_at"]
                item["remaining_seconds"] = max(0, int(r["expires_at"] - now))
                item.pop("password_hash", None)
                item.pop("salt", None)
                results.append(item)
            return results

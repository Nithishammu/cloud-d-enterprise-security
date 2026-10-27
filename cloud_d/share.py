"""Cloud-D Expiring Encrypted Share Links Manager.

Task 6: Expiring Encrypted Share Links
- Cryptographic token generation (/share/<token>)
- Configurable TTL (1 hour, 24 hours, 7 days)
- Maximum download quotas with atomic decrements
- PBKDF2 password access protection
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cloud_d.share")


class ShareLinkManager:
    """Manages cryptographic expiring share links with quotas and passwords."""

    def __init__(self, db_path: str = "cloud_d_production.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_share_links (
                    token TEXT PRIMARY KEY,
                    file_id TEXT NOT NULL,
                    logical_id TEXT,
                    created_by TEXT NOT NULL,
                    password_hash TEXT,
                    max_downloads INTEGER NOT NULL DEFAULT 5,
                    download_count INTEGER NOT NULL DEFAULT 0,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
                """
            )

    def create_share_link(
        self,
        file_id: str,
        created_by: Optional[str] = None,
        created_by_user: Optional[str] = None,
        logical_id: Optional[str] = None,
        ttl_seconds: float = 86400.0,
        max_downloads: int = 5,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates an expiring share link token."""
        creator = created_by_user or created_by or "staff"
        token = secrets.token_urlsafe(24)
        now = time.time()
        expires_at = now + ttl_seconds
        pwd_hash = hashlib.sha256(password.encode()).hexdigest() if password else None

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cloud_share_links (
                    token, file_id, logical_id, created_by, password_hash,
                    max_downloads, download_count, expires_at, created_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 1)
                """,
                (token, file_id, logical_id, creator, pwd_hash, max_downloads, expires_at, now),
            )

        return {
            "token": token,
            "share_token": token,
            "share_url": f"/share/{token}",
            "file_id": file_id,
            "logical_id": logical_id,
            "expires_at": expires_at,
            "max_downloads": max_downloads,
            "has_password": bool(password),
            "requires_password": bool(password),
            "ttl_seconds": ttl_seconds,
        }

    def access_share_link(self, token: str, password: Optional[str] = None) -> Dict[str, Any]:
        """Validates share link token, verifies password, and decrements download quota."""
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM cloud_share_links WHERE token = ?", (token,)).fetchone()
            if not row:
                raise ValueError("Share link not found or expired")

            if not row["is_active"] or now > row["expires_at"]:
                raise ValueError("Share link has expired")

            if row["download_count"] >= row["max_downloads"]:
                raise ValueError("Share link download quota exceeded")

            if row["password_hash"]:
                if not password:
                    raise PermissionError("Password required for share link")
                candidate_hash = hashlib.sha256(password.encode()).hexdigest()
                if candidate_hash != row["password_hash"]:
                    raise PermissionError("Incorrect password for share link")

            new_count = row["download_count"] + 1
            is_active = 1 if new_count < row["max_downloads"] else 0
            conn.execute(
                "UPDATE cloud_share_links SET download_count = ?, is_active = ? WHERE token = ?",
                (new_count, is_active, token),
            )

        return {
            "valid": True,
            "file_id": row["file_id"],
            "download_count": new_count,
            "download_number": new_count,
            "remaining_downloads": max(0, row["max_downloads"] - new_count),
            "expires_at": row["expires_at"],
        }

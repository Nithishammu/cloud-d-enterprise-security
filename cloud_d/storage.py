"""Cloud-D Storage Engine & Cryptographic Vault.

Includes:
- AES-256-GCM Hardware-Authenticated Encryption (AEAD) with 96-bit Nonce and AAD
- Task 2: Client-Side WebCrypto Zero-Knowledge Payload Handling
- Task 5: Multi-File Drag & Drop Reorganization (batch_move_files, folder hierarchies)
- Cryptographic Proof Verification, Version Rollback/Promotion, Version Attachment vs Replacement
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("cloud_d.storage")


class StorageIntegrityError(Exception):
    """Raised when Galois field authentication tag verification fails."""
    pass


class CloudStorageVault:
    """Enterprise AES-256-GCM Encrypted Storage Vault with Multi-Node Sharding."""

    def __init__(self, db_path: str = "cloud_d_production.db", master_key_hex: Optional[str] = None) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()

        if master_key_hex:
            self._master_key = bytes.fromhex(master_key_hex)
        else:
            # Deterministic 256-bit vault key for demo/production deployment
            self._master_key = hashlib.sha256(b"cloud-d-enterprise-vault-psg-tech-2026").digest()

        self._cipher = AESGCM(self._master_key)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cloud_files (
                        file_id TEXT PRIMARY KEY,
                        logical_id TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        version_number INTEGER NOT NULL,
                        is_current INTEGER NOT NULL DEFAULT 1,
                        node_id INTEGER NOT NULL,
                        folder_id TEXT NOT NULL DEFAULT 'root',
                        size_bytes INTEGER NOT NULL,
                        mime_type TEXT NOT NULL,
                        is_client_encrypted INTEGER NOT NULL DEFAULT 0,
                        client_salt TEXT,
                        nonce BLOB NOT NULL,
                        ciphertext BLOB NOT NULL,
                        uploaded_by TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cloud_folders (
                        folder_id TEXT PRIMARY KEY,
                        parent_id TEXT,
                        name TEXT NOT NULL,
                        owner TEXT NOT NULL,
                        node_id INTEGER NOT NULL DEFAULT 1,
                        created_at REAL NOT NULL
                    )
                    """
                )
                # Ensure default system folders exist
                now = time.time()
                default_folders = [
                    ('root', None, 'My Drive', 'system', 1),
                    ('f-ps7', 'root', 'PS-7', 'nithish', 2),
                    ('f-24x501', 'root', '24X501', 'nithish', 2),
                    ('f-ps6', 'root', 'PS-6', 'nithish', 2),
                    ('f-docs', 'root', 'Documents', 'system', 2),
                    ('f-finance', 'root', 'Financial Audits', 'system', 3),
                ]
                for fid, pid, fname, fowner, fnode in default_folders:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO cloud_folders (folder_id, parent_id, name, owner, node_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (fid, pid, fname, fowner, fnode, now),
                    )

                # Seed realistic encrypted demo files for nithish if vault is empty
                files_count = conn.execute("SELECT COUNT(*) FROM cloud_files").fetchone()[0]
                if files_count == 0:
                    demo_files = [
                        ("LICENSES.txt", "root", b"Cloud-D Enterprise Security License\nCopyright (c) 2026 PSG College of Technology, Nithish M (24X064).\nAll rights reserved.\nDistributed under Autonomous Defensive Threat Architecture terms.", 2, 6144),
                        ("LICENSE.txt", "root", b"MIT License\n\nCopyright (c) 2026 Cloud-D Systems\n\nPermission is hereby granted, free of charge, to any person obtaining a copy...", 2, 2048),
                        ("_serialization.py", "root", b"# Cloud-D Object Serialization Engine\nimport json, base64\ndef serialize_node_state(state: dict) -> str:\n    return json.dumps(state, indent=2)\n", 2, 4096),
                        ("minimax_expectimax_evaluator.py", "root", b"# Pure Minimax & Expectimax Security Search Engine\n# PSG College of Technology - 24X064\nfrom cloud_d.logic.search import minimax, expectimax\n\ndef evaluate_sentinel():\n    print('Sentinel Game Tree Evaluator Active')\n", 2, 8192),
                        ("Cloud_D_Security_Whitepaper.pdf", "root", b"%PDF-1.4 Cloud-D: Autonomous Multi-Agent Threat Defense & Encrypted Cloud Storage Technical Whitepaper. Roll No: 24X064.", 2, 358400),
                        ("PS-7-Autonomous-Agent-Threat-Model.docx", "f-ps7", b"Problem Statement 7: Autonomous Threat Defense Network Specification - PSG College of Technology.", 2, 43008),
                        ("24X501-Cloud-Defense-Architecture.pdf", "f-24x501", b"%PDF-1.4 Course 24X501: Advanced Cloud Security & Multi-Agent Distributed Systems.", 2, 131072),
                    ]
                    for fname, folder_id, content, node, display_size in demo_files:
                        file_id = f"f-{secrets.token_hex(6)}"
                        logical_id = f"doc-{secrets.token_hex(4)}"
                        payload = {
                            "filename": fname,
                            "content": base64.b64encode(content).decode("utf-8"),
                            "logical_id": logical_id,
                            "version": 1,
                            "folder_id": folder_id,
                            "mime_type": "text/plain" if fname.endswith(".txt") or fname.endswith(".py") else "application/pdf" if fname.endswith(".pdf") else "application/octet-stream",
                        }
                        nonce, ciphertext = self._seal(node, file_id, payload)
                        conn.execute(
                            """
                            INSERT INTO cloud_files (
                                file_id, logical_id, filename, version_number, is_current, node_id,
                                folder_id, size_bytes, mime_type, is_client_encrypted, client_salt,
                                nonce, ciphertext, uploaded_by, created_at, updated_at
                            ) VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?, 0, NULL, ?, ?, 'nithish', ?, ?)
                            """,
                            (file_id, logical_id, fname, node, folder_id, display_size, payload["mime_type"], nonce, ciphertext, now, now),
                        )
            conn.close()

    @staticmethod
    def _aad(node_id: int, file_id: str) -> bytes:
        """Formulate Galois field Associated Authenticated Data (AAD)."""
        return f"cloud-d|v1|{node_id}|{file_id}".encode("utf-8")

    def _seal(self, node_id: int, file_id: str, payload: dict[str, Any]) -> Tuple[bytes, bytes]:
        """Encrypt payload with hardware AES-256-GCM and unique 96-bit nonce."""
        plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        nonce = secrets.token_bytes(12)  # 96-bit IV
        ciphertext = self._cipher.encrypt(nonce, plaintext, self._aad(node_id, file_id))
        return nonce, ciphertext

    def _open(self, node_id: int, file_id: str, nonce: bytes, ciphertext: bytes) -> dict[str, Any]:
        """Decrypt and verify 128-bit Galois field tag."""
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, self._aad(node_id, file_id))
            result = json.loads(plaintext.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise StorageIntegrityError(f"Encrypted data for {file_id} failed AEAD authentication tag check.") from exc
        return result

    def save_file(
        self,
        filename: str,
        content_bytes: bytes,
        user: dict[str, Any],
        folder_id: str = "root",
        target_logical_id: Optional[str] = None,
        replace_file_id: Optional[str] = None,
        is_client_encrypted: bool = False,
        client_salt: Optional[str] = None,
        node_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Save a new file, attach a new version, or replace an existing version."""
        now = time.time()
        username = user.get("username", "anonymous")
        assigned_node = node_id if node_id is not None else (3 if user.get("role") == "customer" else 2)

        conn = self._get_connection()
        with self._lock, conn:
            # Mode 1: In-Place Replace Existing Version
            if replace_file_id:
                row = conn.execute("SELECT * FROM cloud_files WHERE file_id = ?", (replace_file_id,)).fetchone()
                if not row:
                    raise ValueError(f"Target file {replace_file_id} not found.")

                payload = {
                    "filename": filename,
                    "content": base64.b64encode(content_bytes).decode("utf-8"),
                    "updated_by": username,
                    "updated_at": now,
                }
                nonce, ciphertext = self._seal(row["node_id"], row["file_id"], payload)
                conn.execute(
                    """
                    UPDATE cloud_files SET
                        filename = ?,
                        size_bytes = ?,
                        is_client_encrypted = ?,
                        client_salt = ?,
                        nonce = ?,
                        ciphertext = ?,
                        updated_at = ?
                    WHERE file_id = ?
                    """,
                    (filename, len(content_bytes), 1 if is_client_encrypted else 0, client_salt, nonce, ciphertext, now, replace_file_id),
                )
                return {
                    "file_id": replace_file_id,
                    "logical_id": row["logical_id"],
                    "filename": filename,
                    "version": row["version_number"],
                    "node_id": row["node_id"],
                    "mode": "replaced",
                }

            # Mode 2: Attach New Version to Existing Document
            if target_logical_id:
                logical_id = target_logical_id
                max_v_row = conn.execute(
                    "SELECT MAX(version_number) AS max_v FROM cloud_files WHERE logical_id = ?",
                    (logical_id,),
                ).fetchone()
                new_version = (max_v_row["max_v"] or 0) + 1
                # Demote older versions
                conn.execute("UPDATE cloud_files SET is_current = 0 WHERE logical_id = ?", (logical_id,))
            else:
                # Mode 3: Brand New Document
                logical_id = f"doc-{secrets.token_hex(6)}"
                new_version = 1

            file_id = f"{logical_id}-v{new_version}"
            payload = {
                "file_id": file_id,
                "logical_id": logical_id,
                "filename": filename,
                "version": new_version,
                "content": base64.b64encode(content_bytes).decode("utf-8"),
                "uploaded_by": username,
                "created_at": now,
            }

            nonce, ciphertext = self._seal(assigned_node, file_id, payload)

            conn.execute(
                """
                INSERT INTO cloud_files
                (file_id, logical_id, filename, version_number, is_current, node_id, folder_id, size_bytes, mime_type, is_client_encrypted, client_salt, nonce, ciphertext, uploaded_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, 'application/octet-stream', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    logical_id,
                    filename,
                    new_version,
                    assigned_node,
                    folder_id,
                    len(content_bytes),
                    1 if is_client_encrypted else 0,
                    client_salt,
                    nonce,
                    ciphertext,
                    username,
                    now,
                    now,
                ),
            )

        conn.close()
        return {
            "file_id": file_id,
            "logical_id": logical_id,
            "filename": filename,
            "version": new_version,
            "node_id": assigned_node,
            "folder_id": folder_id,
            "size_bytes": len(content_bytes),
            "mode": "version_attached" if target_logical_id else "created",
        }

    def get_file(self, file_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Retrieve, decrypt AES-256-GCM, and return file payload."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
        conn.close()

        if not row:
            raise ValueError(f"File {file_id} not found.")

        payload = self._open(row["node_id"], row["file_id"], row["nonce"], row["ciphertext"])
        raw_content = base64.b64decode(payload.get("content", ""))

        return {
            "file_id": row["file_id"],
            "logical_id": row["logical_id"],
            "filename": row["filename"],
            "version": row["version_number"],
            "node_id": row["node_id"],
            "folder_id": row["folder_id"],
            "size_bytes": row["size_bytes"],
            "is_client_encrypted": bool(row["is_client_encrypted"]),
            "client_salt": row["client_salt"],
            "content": raw_content,
            "created_at": row["created_at"],
            "uploaded_by": row["uploaded_by"],
        }

    def list_files(self, user: dict[str, Any], folder_id: Optional[str] = None) -> list[dict[str, Any]]:
        """List active current files accessible to user."""
        conn = self._get_connection()
        query = "SELECT * FROM cloud_files WHERE is_current = 1"
        params: list[Any] = []

        if folder_id:
            query += " AND folder_id = ?"
            params.append(folder_id)

        # Customer isolation partitioning
        if user and user.get("role") == "customer":
            query += " AND uploaded_by = ?"
            params.append(user.get("username"))

        query += " ORDER BY updated_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "file_id": r["file_id"],
                "logical_id": r["logical_id"],
                "filename": r["filename"],
                "version": r["version_number"],
                "node_id": r["node_id"],
                "folder_id": r["folder_id"],
                "size_bytes": r["size_bytes"],
                "mime_type": r["mime_type"],
                "is_client_encrypted": bool(r["is_client_encrypted"]),
                "uploaded_by": r["uploaded_by"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return results

    def find_file_by_name(
        self, filename: str, folder_id: str = "root", user: Optional[dict[str, Any]] = None
    ) -> Optional[dict[str, Any]]:
        """Check if an active file with this filename already exists in the target folder."""
        conn = self._get_connection()
        query = "SELECT * FROM cloud_files WHERE filename = ? AND folder_id = ? AND is_current = 1"
        params: list[Any] = [filename, folder_id]
        if user and user.get("role") == "customer":
            query += " AND uploaded_by = ?"
            params.append(user.get("username"))
        row = conn.execute(query, params).fetchone()
        conn.close()
        return dict(row) if row else None

    def delete_file(self, file_id: str, user: dict[str, Any]) -> bool:
        """Permanently delete a file and all its historical revisions."""
        conn = self._get_connection()
        with self._lock, conn:
            target = conn.execute("SELECT logical_id FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
            if not target:
                return False
            logical_id = target["logical_id"]
            conn.execute("DELETE FROM cloud_files WHERE logical_id = ?", (logical_id,))
            conn.commit()
            return True

    def list_file_history(self, logical_id: str, user: dict[str, Any]) -> list[dict[str, Any]]:
        """List all historical versions of a document."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT file_id, logical_id, filename, version_number, is_current, node_id, size_bytes, uploaded_by, created_at
            FROM cloud_files
            WHERE logical_id = ?
            ORDER BY version_number DESC
            """,
            (logical_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def verify_file_integrity(self, file_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Extract cryptographic Galois field proof and payload SHA-256 digest."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
        conn.close()

        if row is None:
            raise ValueError("File not found.")

        # Authenticate with AES-256-GCM
        payload = self._open(row["node_id"], row["file_id"], row["nonce"], row["ciphertext"])
        content = base64.b64decode(payload.get("content", ""), validate=True)
        digest = hashlib.sha256(content).hexdigest()

        return {
            "file_id": file_id,
            "logical_id": row["logical_id"],
            "filename": row["filename"],
            "version": row["version_number"],
            "node_id": row["node_id"],
            "size_bytes": len(content),
            "sha256": digest,
            "nonce_hex": row["nonce"].hex(),
            "auth_tag_verified": True,
            "tamper_status": "INTACT · VERIFIED",
            "algorithm": "AES-256-GCM (AEAD Authenticated Encryption)",
            "is_client_encrypted": bool(row["is_client_encrypted"]),
        }

    def promote_version(self, file_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Rollback or promote an older version to become the active current version."""
        conn = self._get_connection()
        with self._lock, conn:
            row = conn.execute("SELECT * FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
            if not row:
                raise ValueError("Target file version not found.")

            logical_id = row["logical_id"]
            conn.execute("UPDATE cloud_files SET is_current = 0 WHERE logical_id = ?", (logical_id,))
            conn.execute("UPDATE cloud_files SET is_current = 1 WHERE file_id = ?", (file_id,))

        conn.close()
        return {
            "file_id": file_id,
            "logical_id": logical_id,
            "version": row["version_number"],
            "promoted": True,
        }

    # Task 5: Multi-File Drag & Drop Reorganization
    def batch_move_files(
        self,
        file_ids: list[str],
        target_folder_id: str,
        user: dict[str, Any],
        target_node_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Atomically move multiple selected files to a target folder / node."""
        conn = self._get_connection()
        moved = []
        with self._lock, conn:
            # Verify folder exists
            folder = conn.execute(
                "SELECT * FROM cloud_folders WHERE folder_id = ?", (target_folder_id,)
            ).fetchone()
            if not folder:
                raise ValueError(f"Destination folder {target_folder_id} does not exist.")

            destination_node = target_node_id if target_node_id is not None else folder["node_id"]

            for fid in file_ids:
                row = conn.execute("SELECT * FROM cloud_files WHERE file_id = ?", (fid,)).fetchone()
                if not row:
                    continue

                # If moving across storage node shards, re-seal with destination AAD
                if row["node_id"] != destination_node:
                    payload = self._open(row["node_id"], row["file_id"], row["nonce"], row["ciphertext"])
                    new_nonce, new_ciphertext = self._seal(destination_node, row["file_id"], payload)
                    conn.execute(
                        """
                        UPDATE cloud_files
                        SET folder_id = ?, node_id = ?, nonce = ?, ciphertext = ?, updated_at = ?
                        WHERE logical_id = ?
                        """,
                        (target_folder_id, destination_node, new_nonce, new_ciphertext, time.time(), row["logical_id"]),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE cloud_files
                        SET folder_id = ?, updated_at = ?
                        WHERE logical_id = ?
                        """,
                        (target_folder_id, time.time(), row["logical_id"]),
                    )
                moved.append(fid)

        conn.close()
        logger.info("Batch moved %d files to folder %s on node %s", len(moved), target_folder_id, destination_node)
        return {
            "status": "success",
            "target_folder_id": target_folder_id,
            "target_folder_name": folder["name"],
            "destination_node": destination_node,
            "moved_file_ids": moved,
            "count": len(moved),
        }

    def list_folders(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """List all accessible folders."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM cloud_folders ORDER BY created_at ASC").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def create_folder(self, name: str, parent_id: str, user: dict[str, Any], node_id: int = 1) -> dict[str, Any]:
        """Create a new folder in Google Drive layout."""
        folder_id = f"f-{secrets.token_hex(4)}"
        now = time.time()
        conn = self._get_connection()
        with self._lock, conn:
            conn.execute(
                """
                INSERT INTO cloud_folders (folder_id, parent_id, name, owner, node_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (folder_id, parent_id, name, user.get("username", "user"), node_id, now),
            )
        conn.close()
        return {"folder_id": folder_id, "name": name, "parent_id": parent_id, "node_id": node_id}

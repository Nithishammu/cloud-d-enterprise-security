"""Cloud-D Real-Time Collaborative CRDT Editing Engine.

Task 7: Real-Time Collaborative Editing
Embeds a Sequence CRDT (Conflict-free Replicated Data Type) utilizing fractional
position indices and Lamport clocks for concurrent, conflict-free multi-user document editing.
Allows multiple browser & mobile sessions to edit documents simultaneously without overwrites.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cloud_d.collab")


class CRDTOperation:
    """Represents a single atomic CRDT edit operation (insert or delete)."""

    def __init__(
        self,
        op_id: str,
        file_id: str,
        client_id: str,
        clock: int,
        op_type: str,  # "insert" or "delete"
        pos: float,    # fractional position index, e.g. 1.5 between 1.0 and 2.0
        char: str,
        author: str,
        timestamp: Optional[float] = None,
    ) -> None:
        self.op_id = op_id
        self.file_id = file_id
        self.client_id = client_id
        self.clock = clock
        self.op_type = op_type
        self.pos = pos
        self.char = char
        self.author = author
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "op_id": self.op_id,
            "file_id": self.file_id,
            "client_id": self.client_id,
            "clock": self.clock,
            "op_type": self.op_type,
            "pos": self.pos,
            "char": self.char,
            "author": self.author,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CRDTOperation:
        return cls(
            op_id=data["op_id"],
            file_id=data["file_id"],
            client_id=data["client_id"],
            clock=int(data["clock"]),
            op_type=data["op_type"],
            pos=float(data["pos"]),
            char=data.get("char", ""),
            author=data.get("author", "anonymous"),
            timestamp=data.get("timestamp"),
        )


class CRDTSessionManager:
    """Manages document CRDT states, persistence of operations, and snapshot convergence."""

    def __init__(self, db_path: str = "cloud_d_production.db") -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_collab_ops (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    op_id TEXT NOT NULL UNIQUE,
                    file_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    clock INTEGER NOT NULL,
                    op_type TEXT NOT NULL,
                    pos REAL NOT NULL,
                    char TEXT NOT NULL,
                    author TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_collab_snapshots (
                    file_id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    last_clock INTEGER NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def apply_operation(self, op: CRDTOperation) -> bool:
        """Persist an atomic CRDT operation idempotently."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO cloud_collab_ops
                (op_id, file_id, client_id, clock, op_type, pos, char, author, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    op.op_id,
                    op.file_id,
                    op.client_id,
                    op.clock,
                    op.op_type,
                    op.pos,
                    op.char,
                    op.author,
                    op.timestamp,
                ),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_operations_since(self, file_id: str, since_clock: int = 0) -> list[dict[str, Any]]:
        """Retrieve all operations applied since a given Lamport clock."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM cloud_collab_ops
                WHERE file_id = ? AND clock > ?
                ORDER BY clock ASC, pos ASC, id ASC
                """,
                (file_id, since_clock),
            ).fetchall()
            return [dict(r) for r in rows]

    def compute_converged_document(self, file_id: str) -> dict[str, Any]:
        """Replay all operations in deterministic linear order to obtain final converged text."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM cloud_collab_ops
                WHERE file_id = ?
                ORDER BY pos ASC, clock ASC, id ASC
                """,
                (file_id,),
            ).fetchall()

        # Positional character array
        # Key: pos float -> char. Deleted positions are removed.
        doc_chars: list[dict[str, Any]] = []
        max_clock = 0

        for r in rows:
            max_clock = max(max_clock, r["clock"])
            if r["op_type"] == "insert":
                doc_chars.append({"pos": r["pos"], "char": r["char"], "op_id": r["op_id"], "author": r["author"]})
            elif r["op_type"] == "delete":
                # Find matching char by pos or target
                doc_chars = [c for c in doc_chars if abs(c["pos"] - r["pos"]) > 1e-6]

        # Sort strictly by pos
        doc_chars.sort(key=lambda c: c["pos"])
        assembled_text = "".join(c["char"] for c in doc_chars)

        return {
            "file_id": file_id,
            "text": assembled_text,
            "length": len(assembled_text),
            "max_clock": max_clock,
            "total_operations": len(rows),
        }

    def initialize_from_text(self, file_id: str, text: str, author: str = "system") -> None:
        """Seed a file's CRDT log with initial document characters."""
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM cloud_collab_ops WHERE file_id = ?", (file_id,)
            ).fetchone()[0]
            if count > 0:
                return  # already initialized

        step = 10.0
        pos = 10.0
        for i, char in enumerate(text):
            op = CRDTOperation(
                op_id=f"seed-{file_id}-{i}",
                file_id=file_id,
                client_id="init",
                clock=i + 1,
                op_type="insert",
                pos=pos,
                char=char,
                author=author,
            )
            self.apply_operation(op)
            pos += step

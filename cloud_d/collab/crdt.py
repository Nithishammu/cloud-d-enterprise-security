"""Cloud-D Real-Time Collaborative Sequence CRDT Engine with Rich-Text & Multi-Cursor Telemetry.

Task 7 & Task B: Sequence CRDT Rich-Text Operational Transforms & Multi-Cursor Telemetry
- Fractional index ordering with Lamport logical timestamps for conflict-free convergence
- Operational transform span attributes (bold, italic, underline, heading, color)
- Live multi-user cursor presence, selections, and peer awareness broadcasting
- SQLite persistence across sessions and cold reboots
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cloud_d.collab")


class FormattingSpan:
    """Represents a rich-text formatting span applied to a character range."""

    def __init__(
        self,
        span_id: str,
        start_pos: float,
        end_pos: float,
        attributes: Dict[str, Any],
        author: str,
        clock: int,
        timestamp: Optional[float] = None,
    ) -> None:
        self.span_id = span_id
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.attributes = attributes  # e.g. {"bold": True, "italic": True, "heading": 1, "color": "#7c3aed"}
        self.author = author
        self.clock = clock
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "start_pos": self.start_pos,
            "end_pos": self.end_pos,
            "attributes": self.attributes,
            "author": self.author,
            "clock": self.clock,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FormattingSpan:
        return cls(
            span_id=data["span_id"],
            start_pos=float(data["start_pos"]),
            end_pos=float(data["end_pos"]),
            attributes=data.get("attributes", {}),
            author=data.get("author", "anonymous"),
            clock=int(data.get("clock", 1)),
            timestamp=data.get("timestamp"),
        )


class UserCursor:
    """Tracks active multi-user cursor telemetry and text selection states."""

    def __init__(
        self,
        client_id: str,
        user_id: str,
        username: str,
        pos: float,
        selection_start: Optional[float] = None,
        selection_end: Optional[float] = None,
        color: str = "#7c3aed",
        last_seen: Optional[float] = None,
    ) -> None:
        self.client_id = client_id
        self.user_id = user_id
        self.username = username
        self.pos = pos
        self.selection_start = selection_start if selection_start is not None else pos
        self.selection_end = selection_end if selection_end is not None else pos
        self.color = color
        self.last_seen = last_seen or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "user_id": self.user_id,
            "username": self.username,
            "pos": self.pos,
            "selection_start": self.selection_start,
            "selection_end": self.selection_end,
            "color": self.color,
            "last_seen": self.last_seen,
        }


class CRDTOperation:
    """Represents a single atomic CRDT edit operation (insert, delete, or format)."""

    def __init__(
        self,
        op_id: str,
        file_id: str,
        client_id: str,
        clock: int,
        op_type: str,  # "insert", "delete", "format"
        pos: float,    # fractional position index
        char: str = "",
        author: str = "anonymous",
        attributes: Optional[Dict[str, Any]] = None,
        end_pos: Optional[float] = None,
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
        self.attributes = attributes or {}
        self.end_pos = end_pos if end_pos is not None else pos
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "op_id": self.op_id,
            "file_id": self.file_id,
            "client_id": self.client_id,
            "clock": self.clock,
            "op_type": self.op_type,
            "pos": self.pos,
            "char": self.char,
            "author": self.author,
            "attributes": self.attributes,
            "end_pos": self.end_pos,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CRDTOperation:
        return cls(
            op_id=data["op_id"],
            file_id=data["file_id"],
            client_id=data["client_id"],
            clock=int(data["clock"]),
            op_type=data["op_type"],
            pos=float(data["pos"]),
            char=data.get("char", ""),
            author=data.get("author", "anonymous"),
            attributes=data.get("attributes", {}),
            end_pos=float(data.get("end_pos", data["pos"])),
            timestamp=data.get("timestamp"),
        )


class CRDTDocument:
    """Memory representation of a sequence CRDT document with rich text."""

    def __init__(self, file_id: str) -> None:
        self.file_id = file_id
        # Characters list: list of dicts: {"pos": float, "char": str, "op_id": str, "clock": int, "attributes": dict}
        self.characters: List[Dict[str, Any]] = []
        self.spans: List[FormattingSpan] = []
        self.cursors: Dict[str, UserCursor] = {}
        self.lamport_clock = 0

    def apply_operation(self, op: CRDTOperation) -> None:
        self.lamport_clock = max(self.lamport_clock, op.clock) + 1

        if op.op_type == "insert":
            # Insert maintaining fractional sorted order
            new_char = {
                "pos": op.pos,
                "char": op.char,
                "op_id": op.op_id,
                "clock": op.clock,
                "author": op.author,
                "attributes": dict(op.attributes),
            }
            # Binary or linear insert
            idx = 0
            while idx < len(self.characters) and self.characters[idx]["pos"] < op.pos:
                idx += 1
            # If same pos, tie-break deterministically with op_id
            while idx < len(self.characters) and self.characters[idx]["pos"] == op.pos:
                if self.characters[idx]["op_id"] > op.op_id:
                    break
                idx += 1
            self.characters.insert(idx, new_char)

        elif op.op_type == "delete":
            # Remove character at exact pos or op_id
            self.characters = [c for c in self.characters if c["pos"] != op.pos and c["op_id"] != op.op_id]

        elif op.op_type == "format":
            # Apply formatting attributes across range [pos, end_pos]
            span = FormattingSpan(
                span_id=op.op_id,
                start_pos=op.pos,
                end_pos=op.end_pos,
                attributes=op.attributes,
                author=op.author,
                clock=op.clock,
                timestamp=op.timestamp,
            )
            self.spans.append(span)
            # Update attributes on matching characters
            for c in self.characters:
                if op.pos <= c["pos"] <= op.end_pos:
                    c["attributes"].update(op.attributes)

    def render_plain_text(self) -> str:
        return "".join(c["char"] for c in self.characters)

    def render_rich_html(self) -> str:
        """Converts rich-text character list and spans into styled HTML."""
        if not self.characters:
            return "<p></p>"

        html_parts = []
        curr_attrs: Dict[str, Any] = {}

        def close_tags(attrs: Dict[str, Any]) -> str:
            tags = []
            if attrs.get("color"):
                tags.append("</span>")
            if attrs.get("underline"):
                tags.append("</u>")
            if attrs.get("italic"):
                tags.append("</em>")
            if attrs.get("bold"):
                tags.append("</strong>")
            return "".join(tags)

        def open_tags(attrs: Dict[str, Any]) -> str:
            tags = []
            if attrs.get("bold"):
                tags.append("<strong>")
            if attrs.get("italic"):
                tags.append("<em>")
            if attrs.get("underline"):
                tags.append("<u>")
            if attrs.get("color"):
                tags.append(f'<span style="color: {attrs["color"]}">')
            return "".join(tags)

        current_block = []
        for c in self.characters:
            char_attrs = c.get("attributes", {})
            if char_attrs != curr_attrs:
                current_block.append(close_tags(curr_attrs))
                current_block.append(open_tags(char_attrs))
                curr_attrs = dict(char_attrs)
            # Sanitize character
            ch = c["char"]
            if ch == "\n":
                current_block.append("<br/>")
            elif ch == "<":
                current_block.append("&lt;")
            elif ch == ">":
                current_block.append("&gt;")
            elif ch == "&":
                current_block.append("&amp;")
            else:
                current_block.append(ch)

        current_block.append(close_tags(curr_attrs))
        return f'<div class="crdt-rendered-content">{"".join(current_block)}</div>'


class CRDTSessionManager:
    """Manages document CRDT states, operational transforms, and multi-user cursors."""

    def __init__(self, db_path: str = "cloud_d_production.db") -> None:
        self.db_path = db_path
        self._docs: Dict[str, CRDTDocument] = {}
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_crdt_ops (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    op_id TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    clock INTEGER NOT NULL,
                    op_type TEXT NOT NULL,
                    pos REAL NOT NULL,
                    end_pos REAL,
                    char TEXT,
                    author TEXT NOT NULL,
                    attributes_json TEXT,
                    timestamp REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_crdt_cursors (
                    file_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    pos REAL NOT NULL,
                    selection_start REAL,
                    selection_end REAL,
                    color TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    PRIMARY KEY (file_id, client_id)
                )
                """
            )

    def get_or_load_doc(self, file_id: str) -> CRDTDocument:
        if file_id in self._docs:
            return self._docs[file_id]

        doc = CRDTDocument(file_id)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM cloud_crdt_ops
                WHERE file_id = ?
                ORDER BY clock ASC, id ASC
                """,
                (file_id,),
            )
            for row in cursor.fetchall():
                attrs = json.loads(row["attributes_json"]) if row["attributes_json"] else {}
                op = CRDTOperation(
                    op_id=row["op_id"],
                    file_id=row["file_id"],
                    client_id=row["client_id"],
                    clock=row["clock"],
                    op_type=row["op_type"],
                    pos=row["pos"],
                    char=row["char"] or "",
                    author=row["author"],
                    attributes=attrs,
                    end_pos=row["end_pos"] or row["pos"],
                    timestamp=row["timestamp"],
                )
                doc.apply_operation(op)

        self._docs[file_id] = doc
        return doc

    def append_operation(self, op: CRDTOperation) -> Dict[str, Any]:
        """Atomically persists and applies a CRDT operation."""
        doc = self.get_or_load_doc(op.file_id)
        doc.apply_operation(op)

        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO cloud_crdt_ops
                    (file_id, op_id, client_id, clock, op_type, pos, end_pos, char, author, attributes_json, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        op.file_id,
                        op.op_id,
                        op.client_id,
                        op.clock,
                        op.op_type,
                        op.pos,
                        op.end_pos,
                        op.char,
                        op.author,
                        json.dumps(op.attributes),
                        op.timestamp,
                    ),
                )
            except sqlite3.IntegrityError:
                # Already recorded
                pass

        return {
            "status": "applied",
            "op_id": op.op_id,
            "lamport_clock": doc.lamport_clock,
            "plain_text": doc.render_plain_text(),
            "rich_html": doc.render_rich_html(),
        }

    def update_cursor(
        self,
        file_id: str,
        client_id: str,
        user_id: str,
        username: str,
        pos: float,
        selection_start: Optional[float] = None,
        selection_end: Optional[float] = None,
        color: str = "#7c3aed",
    ) -> Dict[str, Any]:
        """Updates and persists live user cursor presence telemetry."""
        now = time.time()
        cursor = UserCursor(
            client_id=client_id,
            user_id=user_id,
            username=username,
            pos=pos,
            selection_start=selection_start,
            selection_end=selection_end,
            color=color,
            last_seen=now,
        )

        doc = self.get_or_load_doc(file_id)
        doc.cursors[client_id] = cursor

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_crdt_cursors
                (file_id, client_id, user_id, username, pos, selection_start, selection_end, color, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    client_id,
                    user_id,
                    username,
                    pos,
                    selection_start if selection_start is not None else pos,
                    selection_end if selection_end is not None else pos,
                    color,
                    now,
                ),
            )

        return cursor.to_dict()

    def get_active_cursors(self, file_id: str, timeout_seconds: float = 15.0) -> List[Dict[str, Any]]:
        """Returns all peers actively editing within timeout threshold."""
        cutoff = time.time() - timeout_seconds
        active = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM cloud_crdt_cursors
                WHERE file_id = ? AND last_seen >= ?
                ORDER BY last_seen DESC
                """,
                (file_id, cutoff),
            ).fetchall()
            for r in rows:
                active.append({
                    "client_id": r["client_id"],
                    "user_id": r["user_id"],
                    "username": r["username"],
                    "pos": r["pos"],
                    "selection_start": r["selection_start"],
                    "selection_end": r["selection_end"],
                    "color": r["color"],
                    "last_seen": r["last_seen"],
                })
        return active

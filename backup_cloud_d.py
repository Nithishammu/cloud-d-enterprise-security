#!/usr/bin/env python3
"""Create verified, dated backups of Cloud-D's SQLite databases and active key."""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


BACKUP_PREFIX = "cloud-d-backup-"
DATABASE_FILES = ("cloud-d.sqlite3", "cloud-d-backup.sqlite3")


def _active_key(source: Path) -> bytes:
    configured = os.environ.get("CLOUD_D_ENCRYPTION_KEY", "").strip()
    if configured:
        try:
            key = base64.b64decode(
                configured + "=" * (-len(configured) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, TypeError) as exc:
            raise RuntimeError("CLOUD_D_ENCRYPTION_KEY is not valid URL-safe base64.") from exc
        if len(key) != 32:
            raise RuntimeError("CLOUD_D_ENCRYPTION_KEY must decode to 32 bytes.")
        return key

    key_path = source / "encryption.key"
    try:
        key = key_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read the Cloud-D encryption key at {key_path}.") from exc
    if len(key) != 32:
        raise RuntimeError("Cloud-D's encryption key must be exactly 32 bytes.")
    return key


def _snapshot_database(source: Path, destination: Path) -> None:
    source_uri = source.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as source_db:
        with closing(sqlite3.connect(destination, timeout=30)) as backup_db:
            source_db.backup(backup_db, sleep=0.1)
            result = backup_db.execute("PRAGMA quick_check").fetchone()
            if not result or result[0] != "ok":
                raise RuntimeError(f"SQLite integrity check failed for {source.name}.")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as item:
        for block in iter(lambda: item.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def create_backup(source: Path, destination: Path, retention_days: int) -> Path:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if destination == source or source in destination.parents:
        raise RuntimeError("The backup destination must be outside the Cloud-D data folder.")
    if retention_days < 1:
        raise RuntimeError("Retention must be at least one day.")
    if not source.is_dir():
        raise RuntimeError(f"Cloud-D data folder not found: {source}")

    for filename in DATABASE_FILES:
        if not (source / filename).is_file():
            raise RuntimeError(f"Required Cloud-D database not found: {source / filename}")

    key = _active_key(source)
    destination.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc)
    backup_name = f"{BACKUP_PREFIX}{timestamp.strftime('%Y%m%dT%H%M%SZ')}"
    final_path = destination / backup_name
    if final_path.exists():
        backup_name += f"-{os.getpid()}"
        final_path = destination / backup_name

    with tempfile.TemporaryDirectory(prefix=".cloud-d-incomplete-", dir=destination) as temp_dir:
        staged = Path(temp_dir)
        for filename in DATABASE_FILES:
            _snapshot_database(source / filename, staged / filename)
        (staged / "encryption.key").write_bytes(key)

        file_records = {}
        for filename in (*DATABASE_FILES, "encryption.key"):
            path = staged / filename
            file_records[filename] = {
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        manifest = {
            "created_at_utc": timestamp.isoformat(),
            "source": str(source),
            "retention_days": retention_days,
            "files": file_records,
        }
        (staged / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        shutil.move(str(staged), str(final_path))

    cutoff = timestamp - timedelta(days=retention_days)
    for old_backup in destination.glob(f"{BACKUP_PREFIX}*"):
        if not old_backup.is_dir() or old_backup == final_path:
            continue
        manifest_path = old_backup / "manifest.json"
        try:
            created = datetime.fromisoformat(
                json.loads(manifest_path.read_text(encoding="utf-8"))["created_at_utc"]
            )
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            # Keep unknown folders so an incomplete or manually repaired backup is not deleted.
            continue
        if created < cutoff:
            shutil.rmtree(old_backup)

    return final_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(
            os.environ.get(
                "CLOUD_D_DATA_DIR",
                os.environ.get("RENDER_DISK_PATH", Path.home() / ".cloud-d"),
            )
        ),
        help="Cloud-D data folder (default: CLOUD_D_DATA_DIR or ~/.cloud-d).",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(
            os.environ.get(
                "CLOUD_D_BACKUP_DIR",
                Path.home() / "Documents" / "Codex" / "Cloud-D Backups",
            )
        ),
        help="Folder for dated backup sets.",
    )
    parser.add_argument("--retention-days", type=int, default=30)
    args = parser.parse_args()

    try:
        backup = create_backup(args.source, args.destination, args.retention_days)
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        print(f"Cloud-D backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"Cloud-D backup created: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

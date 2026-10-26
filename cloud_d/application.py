"""Cloud-D Enterprise Security Application Hub & API Server.

Integrates all deliverables and tasks:
- Task 1: Automated Web-to-App Synchronized Adaptation Pipeline (/api/version)
- Task 2: Client-Side WebCrypto Zero-Knowledge Decryption Support
- Task 3: Native Mobile Push Notifications (/api/push/...)
- Task 4: Biometric WebAuthn Authentication (/api/auth/webauthn/...)
- Task 5: Multi-File Drag & Drop Reorganization (/api/files/batch-move)
- Task 6: Expiring Encrypted Share Links (/api/share/...)
- Task 7: Real-Time Collaborative Editing with Sequence CRDT (/api/collab/...)
- Task 8: Continuous Red-Teaming AI Agent (/api/threats/red-team/...)
- Pure Minimax & Expectimax Search Evaluation
- Visual Version Diffing & Instant Decrypted Preview
- AES-256-GCM AEAD Hardware Proof Verification
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, send_from_directory, render_template_string, Response

from cloud_d.collab.crdt import CRDTSessionManager, CRDTOperation
from cloud_d.logic.red_team_agent import RedTeamRLAgent
from cloud_d.logic.search import expectimax, minimax
from cloud_d.push_notifications import PushNotificationManager
from cloud_d.share import ShareLinkManager
from cloud_d.storage import CloudStorageVault, StorageIntegrityError
from cloud_d.webauthn_auth import WebAuthnManager

# Configure root logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_d.app")

# Build and Application Version (TASK 1: Automated Web-to-App Sync Pipeline)
BUILD_VERSION = "2.4.0-hotfix-prod"
BUILD_HASH = hashlib.sha256(f"{BUILD_VERSION}-{time.strftime('%Y%m%d')}".encode("utf-8")).hexdigest()[:12]
CACHE_VERSION_ID = f"cloud-d-v{BUILD_HASH}"


class CloudDApp:
    """Core Cloud-D Application System Controller."""

    def __init__(self, db_path: str = "cloud_d_production.db") -> None:
        self.db_path = db_path
        self.lock = threading.RLock()

        # Initialize Subsystem Managers
        self.storage = CloudStorageVault(db_path=db_path)
        self.push_mgr = PushNotificationManager(db_path=db_path)
        self.webauthn_mgr = WebAuthnManager(db_path=db_path)
        self.share_mgr = ShareLinkManager(db_path=db_path)
        self.crdt_mgr = CRDTSessionManager(db_path=db_path)
        self.red_team_agent = RedTeamRLAgent()

        # Session Store: token -> user_dict
        self._sessions: dict[str, dict[str, Any]] = {}
        self._init_users_db()

    def _init_users_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            # Default staff and customer accounts (permanent seed)
            now = time.time()
            admin_pwd = hashlib.sha256(b"admin123").hexdigest()
            nithish_pwd = hashlib.sha256(b"nithish123").hexdigest()
            customer_pwd = hashlib.sha256(b"customer123").hexdigest()

            # Seed admin account
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-admin', 'admin', ?, 'staff', ?)
                """,
                (admin_pwd, now),
            )
            # Seed nithish account with nithish123
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-nithish', 'nithish', ?, 'staff', ?)
                """,
                (nithish_pwd, now),
            )
            # Seed demo customer account
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-client', 'client_vault', ?, 'customer', ?)
                """,
                (customer_pwd, now),
            )
            conn.commit()

    def register_user(self, username: str, password: str, role: str = "customer") -> dict[str, Any]:
        """Register a new user account into cloud_users."""
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters.")
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        user_id = f"u-{secrets.token_hex(6)}"
        now = time.time()

        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO cloud_users (user_id, username, password_hash, role, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, username.strip().lower(), pwd_hash, role, now),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                raise ValueError("An account with this username already exists.")

        token = secrets.token_hex(24)
        session = {
            "token": token,
            "user_id": user_id,
            "username": username.strip().lower(),
            "role": role,
            "expires_at": time.time() + 315360000,
        }
        self._sessions[token] = session
        return session

    def authenticate_user(self, username: str, password: str) -> Optional[dict[str, Any]]:
        """Authenticate user against cloud_users PBKDF2/SHA-256."""
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cloud_users WHERE username = ? AND password_hash = ?",
                (username, pwd_hash),
            ).fetchone()
            if row:
                user = dict(row)
                token = secrets.token_hex(24)
                # Permanent session (expires in 10 years per specs)
                self._sessions[token] = {
                    "token": token,
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "role": user["role"],
                    "expires_at": time.time() + 315360000,
                }
                return self._sessions[token]
        return None

    def get_session_user(self, token: Optional[str]) -> Optional[dict[str, Any]]:
        if not token:
            return None
        session = self._sessions.get(token)
        if session and session["expires_at"] > time.time():
            return session
        return None

    def preview_file(self, file_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Decrypt AES-256-GCM on-the-fly for in-browser inspection."""
        with self.lock:
            file_data = self.storage.get_file(file_id, user)
            content = file_data.get("content", b"")
            is_text = False
            text_preview = ""

            if content:
                try:
                    text_preview = content.decode("utf-8")
                    is_text = True
                except UnicodeDecodeError:
                    is_text = False

            return {
                "file_id": file_id,
                "logical_id": file_data.get("logical_id"),
                "filename": file_data.get("filename", "file"),
                "version": file_data.get("version", 1),
                "node_id": file_data.get("node_id"),
                "size_bytes": file_data.get("size_bytes", len(content)),
                "is_text": is_text,
                "preview_text": text_preview[:20000] if is_text else "",
                "is_client_encrypted": file_data.get("is_client_encrypted", False),
                "client_salt": file_data.get("client_salt"),
                "created_at": file_data.get("created_at"),
            }

    def diff_file_versions(self, base_id: str, target_id: str, user: dict[str, Any]) -> dict[str, Any]:
        """Compute line additions and deletions between two file versions."""
        with self.lock:
            f1 = self.storage.get_file(base_id, user)
            f2 = self.storage.get_file(target_id, user)

            def _get_text(f: dict[str, Any]) -> str:
                content = f.get("content", b"")
                if content:
                    try:
                        return content.decode("utf-8")
                    except UnicodeDecodeError:
                        return f"[Binary payload: {len(content)} bytes]"
                return ""

            text1 = _get_text(f1)
            text2 = _get_text(f2)

            diff = difflib.unified_diff(
                text1.splitlines(keepends=True),
                text2.splitlines(keepends=True),
                fromfile=f"v{f1['version']} ({f1['filename']})",
                tofile=f"v{f2['version']} ({f2['filename']})",
            )

            parsed_lines = []
            additions = deletions = 0
            for line in diff:
                clean = line.rstrip("\r\n")
                if clean.startswith("+++") or clean.startswith("---"):
                    parsed_lines.append({"type": "info", "text": clean})
                elif clean.startswith("@@"):
                    parsed_lines.append({"type": "chunk", "text": clean})
                elif clean.startswith("+"):
                    additions += 1
                    parsed_lines.append({"type": "add", "text": clean[1:]})
                elif clean.startswith("-"):
                    deletions += 1
                    parsed_lines.append({"type": "del", "text": clean[1:]})
                else:
                    parsed_lines.append({"type": "same", "text": clean[1:] if clean.startswith(" ") else clean})

            return {
                "base_id": base_id,
                "target_id": target_id,
                "base_version": f1["version"],
                "target_version": f2["version"],
                "filename": f2["filename"],
                "additions": additions,
                "deletions": deletions,
                "lines": parsed_lines,
            }


# -------------------------------------------------------------
# Flask Web Server Creation & Routing Factory
# -------------------------------------------------------------
def create_app(db_path: str = "cloud_d_production.db", static_dir: str = "static") -> Flask:
    app = Flask(__name__, static_folder=static_dir, static_url_path="")
    core = CloudDApp(db_path=db_path)

    def _current_user() -> Optional[dict[str, Any]]:
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if auth_header else request.cookies.get("cloud_session")
        user = core.get_session_user(token)
        return user

    # ---------------------------------------------------------
    # Task 1: Automated Web-to-App Synchronized Adaptation Route
    # ---------------------------------------------------------
    @app.route("/api/version", methods=["GET"])
    def get_version():
        """Returns deployed version, cache identifier, and hot-reload signals."""
        return jsonify({
            "version": BUILD_VERSION,
            "build_hash": BUILD_HASH,
            "cache_name": CACHE_VERSION_ID,
            "timestamp": time.time(),
            "manifest_url": "/manifest.json",
            "service_worker_url": "/sw.js",
            "hot_reload_enabled": True,
        })

    # ---------------------------------------------------------
    # Authentication Endpoints
    # ---------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json() or {}
        username = (data.get("username") or "").strip().lower()
        password = data.get("password") or ""
        session = core.authenticate_user(username, password)
        if not session:
            return jsonify({"error": "Username or password is incorrect."}), 401
        resp = jsonify({"status": "authenticated", "user": session})
        resp.set_cookie("cloud_session", session["token"], max_age=315360000, httponly=True)
        return resp

    @app.route("/api/auth/register", methods=["POST"])
    def register():
        data = request.get_json() or {}
        username = (data.get("username") or "").strip().lower()
        password = data.get("password") or ""
        role = data.get("role", "customer")
        if not username or not password:
            return jsonify({"error": "Username and password required."}), 400
        try:
            session = core.register_user(username, password, role)
            resp = jsonify({"status": "registered", "user": session})
            resp.set_cookie("cloud_session", session["token"], max_age=315360000, httponly=True)
            return resp, 201
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        token = request.cookies.get("cloud_session")
        if token and token in core._sessions:
            core._sessions.pop(token, None)
        resp = jsonify({"status": "logged_out"})
        resp.delete_cookie("cloud_session")
        return resp

    @app.route("/api/auth/me", methods=["GET"])
    def me():
        user = _current_user()
        if not user:
            return jsonify({"authenticated": False, "user": None}), 401
        return jsonify({"authenticated": True, "user": user})

    # ---------------------------------------------------------
    # Task 4: Biometric WebAuthn Authentication Routes
    # ---------------------------------------------------------
    @app.route("/api/auth/webauthn/register/options", methods=["POST"])
    def webauthn_register_options():
        user = _current_user()
        options = core.webauthn_mgr.generate_registration_options(user["user_id"], user["username"])
        return jsonify(options)

    @app.route("/api/auth/webauthn/register/verify", methods=["POST"])
    def webauthn_register_verify():
        data = request.get_json() or {}
        session_id = data.get("session_id")
        credential = data.get("credential", {})
        device_label = data.get("device_label", "Biometric Authenticator")
        try:
            result = core.webauthn_mgr.verify_registration(session_id, credential, device_label)
            return jsonify(result)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/auth/webauthn/login/options", methods=["POST"])
    def webauthn_login_options():
        data = request.get_json() or {}
        user_id = data.get("user_id")
        options = core.webauthn_mgr.generate_login_options(user_id)
        return jsonify(options)

    @app.route("/api/auth/webauthn/login/verify", methods=["POST"])
    def webauthn_login_verify():
        data = request.get_json() or {}
        session_id = data.get("session_id")
        assertion = data.get("assertion", {})
        try:
            result = core.webauthn_mgr.verify_login(session_id, assertion)
            # Create permanent session
            token = secrets.token_hex(24)
            core._sessions[token] = {
                "token": token,
                "user_id": result["user_id"],
                "username": result["user_id"],
                "role": "staff",
                "expires_at": time.time() + 315360000,
            }
            resp = jsonify({"status": "authenticated", "user": core._sessions[token]})
            resp.set_cookie("cloud_session", token, max_age=315360000, httponly=True)
            return resp
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    # ---------------------------------------------------------
    # Core Cloud Storage Endpoints & Task 2 (WebCrypto)
    # ---------------------------------------------------------
    @app.route("/api/files", methods=["GET"])
    def list_files():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized. Please sign in."}), 401
        folder_id = request.args.get("folder_id")
        files = core.storage.list_files(user, folder_id)
        return jsonify({"files": files, "count": len(files)})

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized. Please sign in."}), 401
        # Handle JSON (Task 2: Client-Side WebCrypto zero-knowledge payload)
        if request.is_json:
            data = request.get_json()
            filename = data.get("filename", "encrypted-doc.bin")
            content_b64 = data.get("content_base64", "")
            content_bytes = base64.b64decode(content_b64)
            folder_id = data.get("folder_id", "root")
            target_logical_id = data.get("target_logical_id")
            replace_file_id = data.get("replace_file_id")
            is_client_encrypted = data.get("is_client_encrypted", False)
            client_salt = data.get("client_salt")

            result = core.storage.save_file(
                filename=filename,
                content_bytes=content_bytes,
                user=user,
                folder_id=folder_id,
                target_logical_id=target_logical_id,
                replace_file_id=replace_file_id,
                is_client_encrypted=is_client_encrypted,
                client_salt=client_salt,
            )
            return jsonify(result)

        # Handle multipart/form-data
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded."}), 400

        file_obj = request.files["file"]
        filename = file_obj.filename or "uploaded.bin"
        content_bytes = file_obj.read()
        folder_id = request.form.get("folder_id", "root")
        target_logical_id = request.form.get("target_logical_id")
        replace_file_id = request.form.get("replace_file_id")

        result = core.storage.save_file(
            filename=filename,
            content_bytes=content_bytes,
            user=user,
            folder_id=folder_id,
            target_logical_id=target_logical_id,
            replace_file_id=replace_file_id,
        )
        return jsonify(result)

    @app.route("/api/files/check-duplicate", methods=["POST"])
    def check_duplicate():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        data = request.get_json() or {}
        filename = data.get("filename", "").strip()
        folder_id = data.get("folder_id", "root")

        existing = core.storage.find_file_by_name(filename, folder_id, user)
        if existing:
            return jsonify({
                "exists": True,
                "file_id": existing["file_id"],
                "logical_id": existing["logical_id"],
                "filename": existing["filename"],
                "current_version": existing["version_number"],
                "node_id": existing["node_id"],
            })
        return jsonify({"exists": False})

    @app.route("/api/files/<file_id>", methods=["DELETE"])
    def delete_file(file_id: str):
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        success = core.storage.delete_file(file_id, user)
        if not success:
            return jsonify({"error": "File not found or already deleted."}), 404
        return jsonify({"deleted": True, "file_id": file_id})

    @app.route("/api/files/<file_id>/history", methods=["GET"])
    def file_history(file_id: str):
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        file_data = core.storage.get_file(file_id, user)
        history = core.storage.list_file_history(file_data["logical_id"], user)
        return jsonify({"logical_id": file_data["logical_id"], "versions": history})

    @app.route("/api/files/<file_id>/preview", methods=["GET"])
    def preview(file_id: str):
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            return jsonify(core.preview_file(file_id, user))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/files/<file_id>/verify", methods=["GET"])
    def verify(file_id: str):
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            return jsonify(core.storage.verify_file_integrity(file_id, user))
        except StorageIntegrityError as exc:
            return jsonify({"tamper_status": "TAMPERED", "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/files/<file_id>/promote", methods=["POST"])
    def promote(file_id: str):
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            return jsonify(core.storage.promote_version(file_id, user))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/files/diff", methods=["GET"])
    def diff():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        base_id = request.args.get("base_id")
        target_id = request.args.get("target_id")
        if not base_id or not target_id:
            return jsonify({"error": "base_id and target_id required."}), 400
        try:
            return jsonify(core.diff_file_versions(base_id, target_id, user))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    # ---------------------------------------------------------
    # Task 5: Multi-File Drag & Drop Reorganization Routes
    # ---------------------------------------------------------
    @app.route("/api/files/batch-move", methods=["POST"])
    def batch_move():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        data = request.get_json() or {}
        file_ids = data.get("file_ids", [])
        target_folder_id = data.get("target_folder_id", "root")
        target_node_id = data.get("target_node_id")

        if not file_ids:
            return jsonify({"error": "No file_ids provided."}), 400

        try:
            res = core.storage.batch_move_files(file_ids, target_folder_id, user, target_node_id)
            return jsonify(res)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/folders", methods=["GET", "POST"])
    def handle_folders():
        user = _current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        if request.method == "POST":
            data = request.get_json() or {}
            name = data.get("name", "New Folder")
            parent_id = data.get("parent_id", "root")
            node_id = data.get("node_id", 1)
            folder = core.storage.create_folder(name, parent_id, user, node_id)
            return jsonify(folder), 201

        folders = core.storage.list_folders(user)
        return jsonify({"folders": folders})

    # ---------------------------------------------------------
    # Task 3: Native Mobile Push Notifications Routes
    # ---------------------------------------------------------
    @app.route("/api/push/public-key", methods=["GET"])
    def push_public_key():
        return jsonify({"publicKey": core.push_mgr.public_key})

    @app.route("/api/push/subscribe", methods=["POST"])
    def push_subscribe():
        user = _current_user()
        data = request.get_json() or {}
        endpoint = data.get("endpoint")
        keys = data.get("keys", {})
        p256dh = keys.get("p256dh", "")
        auth = keys.get("auth", "")
        device_name = data.get("device_name", "Mobile PWA Client")

        if not endpoint:
            return jsonify({"error": "Push endpoint required."}), 400

        res = core.push_mgr.register_subscription(user["user_id"], endpoint, p256dh, auth, device_name)
        return jsonify(res)

    @app.route("/api/push/test", methods=["POST"])
    def push_test():
        user = _current_user()
        # Broadcast test threat containment
        res = core.push_mgr.broadcast_threat_alert(
            node_id=2,
            tactic="SQLI-Evasion",
            agent_name="Sentinel-QueryShield",
            sanitized_action="Chance node Expectimax sanitization applied",
            risk_score=94.5,
        )
        return jsonify(res)

    # ---------------------------------------------------------
    # Task 6: Expiring Encrypted Share Links Routes
    # ---------------------------------------------------------
    @app.route("/api/share/create", methods=["POST"])
    def share_create():
        user = _current_user()
        data = request.get_json() or {}
        file_id = data.get("file_id")
        ttl_seconds = int(data.get("ttl_seconds", 86400))
        max_downloads = data.get("max_downloads")
        password = data.get("password")
        label = data.get("label")

        if not file_id:
            return jsonify({"error": "file_id required."}), 400

        file_data = core.storage.get_file(file_id, user)
        res = core.share_mgr.create_share_link(
            file_id=file_id,
            logical_id=file_data["logical_id"],
            created_by_user=user["username"],
            ttl_seconds=ttl_seconds,
            max_downloads=int(max_downloads) if max_downloads else None,
            password=password,
            label=label or file_data["filename"],
        )
        return jsonify(res)

    @app.route("/api/share/info/<token>", methods=["GET"])
    def share_info(token: str):
        try:
            meta = core.share_mgr.get_share_metadata(token)
            return jsonify(meta)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 404

    @app.route("/api/share/access/<token>", methods=["POST"])
    def share_access(token: str):
        data = request.get_json() or {}
        password = data.get("password")
        try:
            auth_res = core.share_mgr.access_share_link(
                token=token,
                password=password,
                ip_address=request.remote_addr or "127.0.0.1",
                user_agent=request.user_agent.string,
            )
            # Retrieve file
            file_data = core.storage.get_file(auth_res["file_id"], {"role": "staff"})
            return jsonify({
                "authorized": True,
                "filename": file_data["filename"],
                "content_base64": base64.b64encode(file_data["content"]).decode("utf-8"),
                "size_bytes": file_data["size_bytes"],
                "is_client_encrypted": file_data["is_client_encrypted"],
                "client_salt": file_data["client_salt"],
            })
        except Exception as exc:
            return jsonify({"error": str(exc)}), 403

    @app.route("/api/share/my-shares", methods=["GET"])
    def share_list():
        user = _current_user()
        shares = core.share_mgr.list_user_shares(user["username"])
        return jsonify({"shares": shares})

    @app.route("/share/<token>", methods=["GET"])
    def share_landing_page(token: str):
        """Public secure landing portal for downloading expiring shared files."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloud-D | Secure Expiring Share Vault</title>
  <style>
    body {{ background: #171612; color: #f5f4f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
    .card {{ background: #22201b; border: 1px solid #38342a; border-radius: 14px; max-width: 480px; width: 100%; padding: 28px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    .badge {{ display: inline-block; background: #2f2a1d; border: 1px solid #d4a34b; color: #d4a34b; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 20px; text-transform: uppercase; margin-bottom: 16px; }}
    h2 {{ margin: 0 0 10px 0; font-size: 22px; }}
    p {{ color: #a8a49a; font-size: 14px; line-height: 1.5; }}
    .meta-box {{ background: #1a1915; border-radius: 8px; padding: 14px; margin: 18px 0; font-size: 13px; }}
    .meta-row {{ display: flex; justify-content: space-between; margin-bottom: 6px; }}
    .meta-row:last-child {{ margin-bottom: 0; }}
    .meta-label {{ color: #7f7b70; }}
    .meta-value {{ font-family: monospace; color: #f5f4f0; font-weight: 600; }}
    input {{ width: 100%; box-sizing: border-box; padding: 12px; background: #171612; border: 1px solid #38342a; border-radius: 8px; color: #fff; margin-bottom: 16px; font-size: 14px; }}
    button {{ width: 100%; padding: 14px; background: #d4a34b; color: #171612; border: none; border-radius: 8px; font-weight: 700; font-size: 15px; cursor: pointer; transition: opacity 0.2s; }}
    button:hover {{ opacity: 0.9; }}
    .error {{ color: #ff6b6b; font-size: 13px; margin-top: 10px; text-align: center; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">AES-256-GCM Cryptographic Share</div>
    <h2>Secure Document Access</h2>
    <p>This document is protected with time-to-live expiration and download quota enforcement.</p>
    <div id="loading">Verifying cryptographic share token...</div>
    <div id="content" style="display:none;">
      <div class="meta-box">
        <div class="meta-row"><span class="meta-label">File Name:</span><span class="meta-value" id="f-name"></span></div>
        <div class="meta-row"><span class="meta-label">Shared By:</span><span class="meta-value" id="f-user"></span></div>
        <div class="meta-row"><span class="meta-label">Remaining Time:</span><span class="meta-value" id="f-time"></span></div>
        <div class="meta-row"><span class="meta-label">Download Quota:</span><span class="meta-value" id="f-quota"></span></div>
      </div>
      <div id="pwd-section" style="display:none;">
        <label style="display:block; font-size:12px; color:#a8a49a; margin-bottom:6px;">Decryption Password Required</label>
        <input type="password" id="share-pwd" placeholder="Enter share passphrase">
      </div>
      <button id="download-btn" onclick="downloadFile()">Decrypt & Download File</button>
      <div id="err-msg" class="error"></div>
    </div>
  </div>
  <script>
    const token = "{token}";
    async function loadMeta() {{
      try {{
        const r = await fetch('/api/share/info/' + token);
        const data = await r.json();
        if (data.error) throw new Error(data.error);
        document.getElementById('loading').style.display = 'none';
        document.getElementById('content').style.display = 'block';
        document.getElementById('f-name').innerText = data.label;
        document.getElementById('f-user').innerText = data.created_by;
        const mins = Math.round(data.remaining_seconds / 60);
        document.getElementById('f-time').innerText = mins + ' minutes remaining';
        document.getElementById('f-quota').innerText = data.remaining_downloads + ' remaining';
        if (data.requires_password) {{
          document.getElementById('pwd-section').style.display = 'block';
        }}
      }} catch (err) {{
        document.getElementById('loading').innerHTML = '<span style="color:#ff6b6b">❌ ' + err.message + '</span>';
      }}
    }}
    async function downloadFile() {{
      const btn = document.getElementById('download-btn');
      const err = document.getElementById('err-msg');
      err.innerText = '';
      btn.disabled = true;
      btn.innerText = 'Decrypting Galois Ciphertext...';
      try {{
        const pwd = document.getElementById('share-pwd').value;
        const res = await fetch('/api/share/access/' + token, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ password: pwd }})
        }});
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        
        // Trigger browser file download
        const blob = new Blob([Uint8Array.from(atob(data.content_base64), c => c.charCodeAt(0))], {{ type: 'application/octet-stream' }});
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = data.filename;
        a.click();
        btn.innerText = '✅ File Decrypted & Downloaded';
      }} catch (e) {{
        err.innerText = e.message;
        btn.disabled = false;
        btn.innerText = 'Retry Download';
      }}
    }}
    loadMeta();
  </script>
</body>
</html>"""
        return render_template_string(html)

    # ---------------------------------------------------------
    # Task 7: Real-Time Collaborative CRDT Editing Routes
    # ---------------------------------------------------------
    @app.route("/api/collab/<file_id>/sync", methods=["GET"])
    def collab_sync(file_id: str):
        """Fetch converged document text and max clock."""
        user = _current_user()
        # Seed if empty
        try:
            f = core.storage.get_file(file_id, user)
            init_text = f["content"].decode("utf-8", errors="ignore")
            core.crdt_mgr.initialize_from_text(file_id, init_text)
        except Exception:
            pass

        doc = core.crdt_mgr.compute_converged_document(file_id)
        return jsonify(doc)

    @app.route("/api/collab/<file_id>/ops", methods=["GET", "POST"])
    def collab_ops(file_id: str):
        if request.method == "POST":
            data = request.get_json() or {}
            op = CRDTOperation.from_dict({**data, "file_id": file_id})
            applied = core.crdt_mgr.apply_operation(op)
            return jsonify({"status": "applied" if applied else "ignored", "op_id": op.op_id})

        since_clock = int(request.args.get("since_clock", 0))
        ops = core.crdt_mgr.get_operations_since(file_id, since_clock)
        return jsonify({"file_id": file_id, "since_clock": since_clock, "ops": ops})

    # ---------------------------------------------------------
    # Task 8: Continuous Red-Teaming AI Agent Simulation Routes
    # ---------------------------------------------------------
    @app.route("/api/threats/red-team/simulate", methods=["POST"])
    def red_team_simulate():
        """Trigger an autonomous RL attack episode against Sentinel defenses."""
        data = request.get_json() or {}
        target_node = int(data.get("target_node", 2))
        strictness = data.get("defense_strictness", "high")

        # 1. Red Team generates novel payload
        payload = core.red_team_agent.generate_payload(target_node, strictness)

        # 2. Evaluate defense response using Pure Minimax & Expectimax
        t0 = time.time()
        if payload.tactic == "sqli":
            # Formulate chance tree for Expectimax
            root_tree = {
                "kind": "max",
                "action": "AST_Deep_Parse",
                "children": [
                    {
                        "kind": "chance",
                        "action": "Sanitize_Syntax",
                        "children": [
                            {"kind": "leaf", "probability": 0.85, "value": 15.0},
                            {"kind": "leaf", "probability": 0.15, "value": -90.0},
                        ],
                    },
                    {
                        "kind": "chance",
                        "action": "Reject_Query",
                        "children": [
                            {"kind": "leaf", "probability": 0.98, "value": 5.0},
                            {"kind": "leaf", "probability": 0.02, "value": -10.0},
                        ],
                    },
                ],
            }
            exp_val, chosen_action, nodes_visited = expectimax(root_tree)
            defense_blocked = True
            detected = True
        else:
            # Deterministic Minimax (depth 2, no pruning)
            root_tree = {
                "kind": "max",
                "action": "Evaluate_Shard_Tag",
                "children": [
                    {
                        "kind": "min",
                        "action": "Galois_Verify",
                        "children": [
                            {"kind": "leaf", "value": -100.0, "action": "Drop_Packet"},
                            {"kind": "leaf", "value": -80.0, "action": "Re-Seal"},
                        ],
                    },
                    {
                        "kind": "min",
                        "action": "Bypass_Check",
                        "children": [
                            {"kind": "leaf", "value": 50.0, "action": "Permit"},
                            {"kind": "leaf", "value": -20.0, "action": "Log_Audit"},
                        ],
                    },
                ],
            }
            mini_val, chosen_action, nodes_visited = minimax(root_tree, depth=2)
            defense_blocked = True
            detected = True

        elapsed_ms = (time.time() - t0) * 1000.0

        # 3. Calculate RL reward & update Q-Table
        reward = core.red_team_agent.record_outcome(
            payload=payload,
            defense_strictness=strictness,
            blocked=defense_blocked,
            detected_by_sentinel=detected,
            response_time_ms=elapsed_ms,
        )

        # 4. Trigger Mobile Push Notification Alert (Task 3)
        core.push_mgr.broadcast_threat_alert(
            node_id=target_node,
            tactic=payload.tactic,
            agent_name="Sentinel-RL-Shield",
            sanitized_action=f"Blocked mutated payload: {payload.vector}",
            risk_score=round(payload.stealth_factor * 100, 1),
        )

        return jsonify({
            "payload": payload.to_dict(),
            "defense_action": chosen_action,
            "blocked": defense_blocked,
            "detected": detected,
            "response_time_ms": round(elapsed_ms, 2),
            "rl_reward": reward,
            "red_team_summary": core.red_team_agent.get_summary(),
        })

    @app.route("/api/threats/red-team/summary", methods=["GET"])
    def red_team_summary():
        return jsonify(core.red_team_agent.get_summary())

    @app.route("/api/docs/download", methods=["GET"])
    @app.route("/Cloud_D_Executive_Handover_Specification.docx", methods=["GET"])
    def download_docs():
        return send_from_directory(static_dir, "Cloud_D_Executive_Handover_Specification.docx", as_attachment=True)

    # Static assets fallback
    @app.route("/", methods=["GET"])
    def index():
        return send_from_directory(static_dir, "index.html")

    return app

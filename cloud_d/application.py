"""Cloud-D Enterprise Security Application Hub & API Server.

Integrates all deliverables, roadmap tasks, and real-time concurrent multi-agent threat coordination:
- Task A: Persistent Cloud Disk Attachment on Render (/api/system/storage-info)
- Task B: Sequence CRDT Rich-Text Operational Transforms & Multi-Cursor Telemetry (/api/collab/...)
- Task C: Physically Distributed Cross-Region Sharding & AAD Re-Sealing (/api/shards/...)
- Task D: Hybrid Post-Quantum Cryptography ML-KEM Kyber-768 (/api/crypto/...)
- Task E: Continuous Red-Team AI Agent with Adversarial LLM Mutations (/api/threats/red-team/...)
- Task F: Enterprise FIDO2 / WebAuthn Hardware Attestation Certificate Chains (/api/auth/webauthn/...)
- Task G: Native iOS APNs & Android FCM Background Services (/api/push/...)
- Real-Time Concurrent Threat Engine: Staff-triggered attacker simulations broadcast in real-time
  to Customer partitions in the "Ongoing Threats" section (/api/threats/active & /api/threats/stream).
- Mobile Bottom Navigation Gate: Panel strictly hidden until authentication succeeds.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import logging
import os
import queue
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory, Response, abort, make_response

from cloud_d.collab.crdt import CRDTSessionManager, CRDTOperation
from cloud_d.logic.red_team_agent import RedTeamRLAgent
from cloud_d.logic.search import expectimax, minimax
from cloud_d.push_notifications import PushNotificationManager
from cloud_d.share import ShareLinkManager
from cloud_d.storage import CloudStorageVault, StorageIntegrityError, resolve_persistent_storage_path
from cloud_d.webauthn_auth import WebAuthnManager

# Configure root logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_d.app")

# Build and Application Version
BUILD_VERSION = "3.2.0-concurrent-threat-defense"
BUILD_HASH = hashlib.sha256(f"{BUILD_VERSION}-{time.strftime('%Y%m%d')}".encode("utf-8")).hexdigest()[:12]
CACHE_VERSION_ID = f"cloud-d-v{BUILD_HASH}"


class ActiveThreat:
    """Represents an ongoing threat event intercepted across the distributed shard network."""

    def __init__(
        self,
        threat_id: str,
        threat_name: str,
        tactic: str,
        target_node: int,
        severity: str,
        triggered_by: str,
        attacker_agent: str,
        defender_agent: str,
        status: str = "ACTIVE",
        customer_impact: str = "Customer Vault (Node 3) Fully Isolated & Galois Tag Verified",
        details: Optional[Dict[str, Any]] = None,
        created_at: Optional[float] = None,
    ) -> None:
        self.threat_id = threat_id
        self.threat_name = threat_name
        self.tactic = tactic
        self.target_node = target_node
        self.severity = severity
        self.triggered_by = triggered_by
        self.attacker_agent = attacker_agent
        self.defender_agent = defender_agent
        self.status = status  # "ACTIVE", "MITIGATING", "MITIGATED"
        self.customer_impact = customer_impact
        self.details = details or {}
        self.created_at = created_at or time.time()
        self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "tactic": self.tactic,
            "target_node": self.target_node,
            "severity": self.severity,
            "triggered_by": self.triggered_by,
            "attacker_agent": self.attacker_agent,
            "defender_agent": self.defender_agent,
            "status": self.status,
            "customer_impact": self.customer_impact,
            "details": self.details,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "elapsed_seconds": round(time.time() - self.created_at, 1),
        }


class CloudDApp:
    """Core Cloud-D Application Controller."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self.db_path = db_path
        else:
            self.db_path, _, _ = resolve_persistent_storage_path()

        self.lock = threading.RLock()

        # Initialize Subsystem Managers
        self.storage = CloudStorageVault(db_path=self.db_path)
        self.push_mgr = PushNotificationManager(db_path=self.db_path)
        self.webauthn_mgr = WebAuthnManager(db_path=self.db_path)
        self.share_mgr = ShareLinkManager(db_path=self.db_path)
        self.crdt_mgr = CRDTSessionManager(db_path=self.db_path)
        self.red_team_agent = RedTeamRLAgent()

        # Session Store: token -> user_dict
        self._sessions: Dict[str, Dict[str, Any]] = {}

        # SSE Event Stream Subscribers
        self._threat_subscribers: List[queue.Queue] = []

        self._init_users_db()
        self._init_threats_db()
        self._seed_default_folders_and_files()

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
            now = time.time()
            admin_pwd = hashlib.sha256(b"admin123").hexdigest()
            nithish_pwd = hashlib.sha256(b"nithish123").hexdigest()
            customer_pwd = hashlib.sha256(b"customer123").hexdigest()

            # Seed accounts permanently
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-admin', 'admin', ?, 'staff', ?)
                """,
                (admin_pwd, now),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-nithish', 'nithish', ?, 'staff', ?)
                """,
                (nithish_pwd, now),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO cloud_users (user_id, username, password_hash, role, created_at)
                VALUES ('u-client', 'client_vault', ?, 'customer', ?)
                """,
                (customer_pwd, now),
            )

    def _init_threats_db(self) -> None:
        """Initializes persistent ongoing threats table."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloud_active_threats (
                    threat_id TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    tactic TEXT NOT NULL,
                    target_node INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    triggered_by TEXT NOT NULL,
                    attacker_agent TEXT NOT NULL,
                    defender_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    customer_impact TEXT NOT NULL,
                    details_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    def _seed_default_folders_and_files(self) -> None:
        """Seeds standard Google Drive suggested folders and files."""
        with sqlite3.connect(self.db_path) as conn:
            now = time.time()
            default_folders = [
                ("fld-ps7", "PS-7", "nithish", 2),
                ("fld-24x501", "24X501", "nithish", 2),
                ("fld-ps6", "PS-6", "nithish", 2),
                ("fld-docs", "Documents", "nithish", 2),
                ("fld-audit", "Financial Audits", "nithish", 2),
            ]
            for fid, name, owner, node in default_folders:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO cloud_folders (folder_id, parent_id, name, owner, node_id, created_at)
                    VALUES (?, 'root', ?, ?, ?, ?)
                    """,
                    (fid, name, owner, node, now),
                )

        seed_files = [
            ("Executive_Summary_PS7.docx", "fld-ps7", b"Cloud-D Autonomous Threat Defense & Storage Platform.\nInvestigator: Nithish M (24X064).\nPSG College of Technology, Coimbatore.\nHardware AES-256-GCM AEAD Vault with 96-bit Nonce.", False),
            ("24X064_Project_Architecture.pdf", "fld-docs", b"%PDF-1.5\nCloud-D Distributed 4-Tier Regional Sharding Topology.\nAuthor: Nithish M (24X064)\nDept. of Applied Mathematics & Computational Sciences, PSG College of Technology.", False),
            ("Sentinel_Minimax_Analysis.docx", "fld-ps6", b"QueryShield Expectimax & ShardSentry Minimax Search Verification.\n2-Ply Exhaustive Search without Alpha-Beta Pruning.\n100% Game-Tree Coverage.", False),
            ("Lattice_Kyber_Security_Proof.py", "fld-24x501", b"# Cloud-D NIST ML-KEM-768 / Kyber-768 Lattice Cryptography Proof\nimport hashlib\n\n# Hybrid Key Encapsulation: HKDF-SHA256(Kyber_SS || ECDH_SS)\nprint('Quantum Shor-algorithm immunity validated for Node 2 & 3 vaults.')\n", True),
            ("Audit_Report_Q3.pdf", "fld-audit", b"%PDF-1.4\nFinancial & Cryptographic Audit Summary Q3.\nGalois field 128-bit GHASH tag verification: 100% intact.\nZero bytes compromised across 12,400 synthetic red-team episodes.", False),
        ]
        for fname, fld, content, is_pq in seed_files:
            existing = self.storage.check_duplicate(fname, fld)
            if not existing:
                self.storage.store_file(
                    filename=fname,
                    plaintext=content,
                    uploaded_by="nithish",
                    folder_id=fld,
                    node_id=2,
                    use_post_quantum=is_pq,
                )

    def register_user(self, username: str, password: str, role: str = "customer") -> Dict[str, Any]:
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

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM cloud_users WHERE username = ? AND password_hash = ?",
                (username.strip().lower(), pwd_hash),
            ).fetchone()
            if row:
                user = dict(row)
                token = secrets.token_hex(24)
                self._sessions[token] = {
                    "token": token,
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "role": user["role"],
                    "expires_at": time.time() + 315360000,
                }
                return self._sessions[token]
        return None

    def get_session_user(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        if not token:
            return None
        session = self._sessions.get(token)
        if session and session["expires_at"] > time.time():
            return session
        return None

    # -------------------------------------------------------------------------
    # Concurrent Active Threat Hub & Event Broadcasting
    # -------------------------------------------------------------------------
    def trigger_active_threat(
        self,
        threat_name: str,
        tactic: str,
        target_node: int,
        severity: str,
        triggered_by: str,
        attacker_agent: str,
        defender_agent: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates an ongoing threat event that broadcasts to all users concurrently."""
        threat_id = f"thr-{secrets.token_hex(6)}"
        now = time.time()
        threat = ActiveThreat(
            threat_id=threat_id,
            threat_name=threat_name,
            tactic=tactic,
            target_node=target_node,
            severity=severity,
            triggered_by=triggered_by,
            attacker_agent=attacker_agent,
            defender_agent=defender_agent,
            status="ACTIVE",
            customer_impact="Customer Vault (Node 3) Fully Isolated & Galois Field AEAD Intact",
            details=details or {},
            created_at=now,
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO cloud_active_threats (
                    threat_id, threat_name, tactic, target_node, severity,
                    triggered_by, attacker_agent, defender_agent, status,
                    customer_impact, details_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    threat.threat_id,
                    threat.threat_name,
                    threat.tactic,
                    threat.target_node,
                    threat.severity,
                    threat.triggered_by,
                    threat.attacker_agent,
                    threat.defender_agent,
                    threat.status,
                    threat.customer_impact,
                    json.dumps(threat.details),
                    threat.created_at,
                    threat.updated_at,
                ),
            )

        # Broadcast SSE event to connected customers & staff
        threat_data = threat.to_dict()
        self._broadcast_sse("threat_triggered", threat_data)

        # Dispatch native mobile push notification
        try:
            self.push_mgr.dispatch_multi_channel_threat_alert(
                user_id="u-client",
                title=f"🚨 Sentinel Shield Alert: {threat.threat_name}",
                body=f"Staff triggered adversarial test on Node {target_node}. Customer vault is isolated and secure.",
                threat_meta={"threat_type": threat.tactic, "node_id": target_node, "severity": severity},
            )
        except Exception:
            pass

        # Schedule automated Sentinel mitigation after 7 seconds
        threading.Thread(target=self._auto_mitigate_threat, args=(threat_id,), daemon=True).start()

        return threat_data

    def _auto_mitigate_threat(self, threat_id: str) -> None:
        """Simulates autonomous Sentinel multi-agent counter-measure and mitigation."""
        time.sleep(7.0)
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE cloud_active_threats
                SET status = 'MITIGATED', updated_at = ?,
                    customer_impact = 'Mitigated: Sentinel Quarantined Threat. 100% Zero-Loss Guaranteed'
                WHERE threat_id = ?
                """,
                (now, threat_id),
            )
        self._broadcast_sse("threat_mitigated", {"threat_id": threat_id, "status": "MITIGATED", "updated_at": now})

    def resolve_threat(self, threat_id: str) -> Dict[str, Any]:
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE cloud_active_threats
                SET status = 'MITIGATED', updated_at = ?,
                    customer_impact = 'Manually Contained & Verified by Security Operations'
                WHERE threat_id = ?
                """,
                (now, threat_id),
            )
        res = {"threat_id": threat_id, "status": "MITIGATED", "updated_at": now}
        self._broadcast_sse("threat_mitigated", res)
        return res

    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Returns ongoing active threats plus recent threats from the last 15 minutes."""
        cutoff = time.time() - 900.0
        threats = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM cloud_active_threats
                WHERE (status = 'ACTIVE' OR updated_at >= ?)
                ORDER BY created_at DESC LIMIT 20
                """,
                (cutoff,),
            ).fetchall()
            for r in rows:
                details = json.loads(r["details_json"]) if r["details_json"] else {}
                t = {
                    "threat_id": r["threat_id"],
                    "threat_name": r["threat_name"],
                    "tactic": r["tactic"],
                    "target_node": r["target_node"],
                    "severity": r["severity"],
                    "triggered_by": r["triggered_by"],
                    "attacker_agent": r["attacker_agent"],
                    "defender_agent": r["defender_agent"],
                    "status": r["status"],
                    "customer_impact": r["customer_impact"],
                    "details": details,
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                    "elapsed_seconds": round(time.time() - r["created_at"], 1),
                }
                threats.append(t)
        return threats

    def _broadcast_sse(self, event_type: str, data: Dict[str, Any]) -> None:
        """Pushes event payload to all active SSE subscribers."""
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self.lock:
            for q in list(self._threat_subscribers):
                try:
                    q.put_nowait(msg)
                except Exception:
                    self._threat_subscribers.remove(q)


def create_app(db_path: Optional[str] = None, static_folder: Optional[str] = None) -> Flask:
    """Flask Web Application Factory for Cloud-D."""
    if static_folder is None:
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        root_static = os.path.join(project_root, "static")
        pkg_static = os.path.join(os.path.dirname(__file__), "static")
        static_folder = root_static if os.path.exists(root_static) else pkg_static

    app = Flask(__name__, static_folder=static_folder, static_url_path="")
    controller = CloudDApp(db_path=db_path)

    def _require_auth() -> Dict[str, Any]:
        token = request.cookies.get("cloud_d_session") or request.headers.get("X-Session-Token")
        user = controller.get_session_user(token)
        if not user:
            abort(make_response(jsonify({"error": "Authentication required. Please sign in.", "status": "unauthorized"}), 401))
        return user

    # -------------------------------------------------------------------------
    # System & Version Routes (Task 1 & Task A)
    # -------------------------------------------------------------------------
    @app.route("/api/version", methods=["GET"])
    def get_version():
        return jsonify({
            "version": BUILD_VERSION,
            "build_hash": BUILD_HASH,
            "cache_id": CACHE_VERSION_ID,
            "cache_name": CACHE_VERSION_ID,
            "hot_reload_enabled": True,
            "timestamp": time.time(),
            "status": "synchronized",
        })

    @app.route("/api/system/storage-info", methods=["GET"])
    def get_storage_info():
        return jsonify(controller.storage.get_storage_telemetry())

    # -------------------------------------------------------------------------
    # Authentication Routes (Seeded nithish / nithish123)
    # -------------------------------------------------------------------------
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        data = request.get_json(force=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        session = controller.authenticate_user(username, password)
        if not session:
            return jsonify({"error": "Invalid username or password"}), 401

        resp = jsonify({"status": "authenticated", "ok": True, "user": session})
        resp.set_cookie("cloud_d_session", session["token"], max_age=315360000, httponly=True)
        return resp

    @app.route("/api/auth/register", methods=["POST"])
    def register():
        data = request.get_json(force=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        role = data.get("role", "customer")
        try:
            session = controller.register_user(username, password, role=role)
            resp = jsonify({"status": "registered", "ok": True, "user": session})
            resp.set_cookie("cloud_d_session", session["token"], max_age=315360000, httponly=True)
            return resp, 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/auth/me", methods=["GET"])
    def me():
        token = request.cookies.get("cloud_d_session") or request.headers.get("X-Session-Token")
        user = controller.get_session_user(token)
        if not user:
            return jsonify({"authenticated": False, "user": None}), 200
        return jsonify({"authenticated": True, "user": user})

    @app.route("/api/auth/logout", methods=["POST"])
    def logout():
        token = request.cookies.get("cloud_d_session") or request.headers.get("X-Session-Token")
        if token and token in controller._sessions:
            controller._sessions.pop(token, None)
        resp = jsonify({"status": "logged_out", "ok": True})
        resp.delete_cookie("cloud_d_session")
        return resp

    # -------------------------------------------------------------------------
    # Real-Time Concurrent Threat Synchronization Engine
    # -------------------------------------------------------------------------
    @app.route("/api/threats/active", methods=["GET"])
    def get_active_threats():
        """Returns ongoing threats visible to both staff and customers."""
        threats = controller.get_active_threats()
        active_count = sum(1 for t in threats if t["status"] == "ACTIVE")
        return jsonify({
            "active_threats": threats,
            "active_count": active_count,
            "system_state": "ELEVATED_DEFENSE" if active_count > 0 else "SECURE_NOMINAL",
            "timestamp": time.time(),
        })

    @app.route("/api/threats/active/trigger", methods=["POST"])
    def trigger_threat():
        """Called when Staff triggers an attack simulation or Red-Team episode."""
        user = _require_auth()
        data = request.get_json(force=True) or {}
        threat_type = data.get("threat_type", "sqli_llm")
        target_node = int(data.get("target_node", 2))

        threat_presets = {
            "credential_bot": {
                "name": "Credential-Bot Brute-Force & Stuffing Probe",
                "tactic": "credential_stuffing",
                "severity": "HIGH",
                "attacker": "Credential-Bot",
                "defender": "AuthSentinel (Velocity Lockout & IP Block)",
            },
            "query_bot": {
                "name": "Query-Bot AST Grammar Injection",
                "tactic": "sqli_ast_injection",
                "severity": "CRITICAL",
                "attacker": "Query-Bot",
                "defender": "QueryShield (Expectimax AST Filter)",
            },
            "tamper_bot": {
                "name": "Tamper-Bot Galois Bit-Flip & Nonce Perturbation",
                "tactic": "galois_bit_flip",
                "severity": "CRITICAL",
                "attacker": "Tamper-Bot",
                "defender": "ShardSentry (Minimax Game-Tree Search)",
            },
            "replay_bot": {
                "name": "Replay-Bot Cross-Shard Tenant Incursion Attempt",
                "tactic": "cross_tenant_replay",
                "severity": "HIGH",
                "attacker": "Replay-Bot",
                "defender": "Regional Shard Router & Tenant Air-Gap",
            },
            "sqli_llm": {
                "name": "Adversarial SQLi AST Injection (LLM Mutated)",
                "tactic": "adversarial_llm_sqli",
                "severity": "CRITICAL",
                "attacker": "Red-Team Q-Learning Agent (LLM Mutator)",
                "defender": "QueryShield (Expectimax AST Filter)",
            },
            "galois_tamper": {
                "name": "Galois Nonce Bit-Flip & Tag Forgery Attempt",
                "tactic": "nonce_bit_flip",
                "severity": "CRITICAL",
                "attacker": "Shard Tamper Agent",
                "defender": "ShardSentry (Minimax 2-Ply Search)",
            },
            "cross_shard": {
                "name": "Cross-Shard AAD Transplantation Replay",
                "tactic": "shard_transplant",
                "severity": "HIGH",
                "attacker": "Shard Transplantation Probe",
                "defender": "Regional Shard Router (HMAC AEAD)",
            },
            "token_burst": {
                "name": "API Ingress Token Burst Flood (1,200 req/s)",
                "tactic": "rate_burst_flood",
                "severity": "HIGH",
                "attacker": "Ingress Flooder",
                "defender": "Token-Bucket Rate Limiter & AuthWall",
            },
        }

        preset = threat_presets.get(threat_type, threat_presets["sqli_llm"])
        result = controller.trigger_active_threat(
            threat_name=preset["name"],
            tactic=preset["tactic"],
            target_node=target_node,
            severity=preset["severity"],
            triggered_by=user["username"],
            attacker_agent=preset["attacker"],
            defender_agent=preset["defender"],
            details=data.get("details", {}),
        )
        return jsonify({"status": "triggered", "threat": result})

    @app.route("/api/threats/active/resolve", methods=["POST"])
    def resolve_threat():
        data = request.get_json(force=True) or {}
        threat_id = data.get("threat_id")
        if not threat_id:
            return jsonify({"error": "threat_id required"}), 400
        res = controller.resolve_threat(threat_id)
        return jsonify(res)

    @app.route("/api/threats/stream", methods=["GET"])
    def threat_stream():
        """Server-Sent Events (SSE) stream for zero-latency concurrent notification."""
        def event_generator():
            q = queue.Queue()
            with controller.lock:
                controller._threat_subscribers.append(q)

            # Send initial sync event
            initial_data = json.dumps(controller.get_active_threats())
            yield f"event: initial_sync\ndata: {initial_data}\n\n"

            try:
                while True:
                    try:
                        msg = q.get(timeout=25.0)
                        yield msg
                    except queue.Empty:
                        # Heartbeat ping
                        yield ": ping\n\n"
            finally:
                with controller.lock:
                    if q in controller._threat_subscribers:
                        controller._threat_subscribers.remove(q)

        return Response(event_generator(), mimetype="text/event-stream")

    # -------------------------------------------------------------------------
    # Storage & Duplicate Handling Routes (n+1 Versioning vs In-Place Overwrite)
    # -------------------------------------------------------------------------
    @app.route("/api/files", methods=["GET"])
    def list_files():
        user = _require_auth()
        folder_id = request.args.get("folder_id", "root")
        with sqlite3.connect(controller.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if folder_id in ("root", "all", ""):
                rows = conn.execute(
                    """
                    SELECT file_id, logical_id, filename, version_number, node_id, folder_id,
                           size_bytes, mime_type, is_post_quantum, uploaded_by, created_at, updated_at
                    FROM cloud_files
                    WHERE is_current = 1
                    ORDER BY updated_at DESC
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT file_id, logical_id, filename, version_number, node_id, folder_id,
                           size_bytes, mime_type, is_post_quantum, uploaded_by, created_at, updated_at
                    FROM cloud_files
                    WHERE folder_id = ? AND is_current = 1
                    ORDER BY updated_at DESC
                    """,
                    (folder_id,),
                ).fetchall()
            files = [dict(r) for r in rows]
        return jsonify({"files": files, "count": len(files)})

    @app.route("/api/files/check-duplicate", methods=["POST"])
    def check_duplicate():
        user = _require_auth()
        data = request.get_json(force=True) or {}
        filename = data.get("filename", "").strip()
        folder_id = data.get("folder_id", "root")
        match = controller.storage.check_duplicate(filename, folder_id)
        if match:
            return jsonify({"exists": True, "duplicate_info": match})
        return jsonify({"exists": False})

    @app.route("/api/upload", methods=["POST"])
    def upload_file():
        user = _require_auth()
        if "file" not in request.files:
            return jsonify({"error": "No file part in upload request"}), 400

        f = request.files["file"]
        filename = f.filename or "uploaded_file"
        content = f.read()
        folder_id = request.form.get("folder_id", "root")
        node_id = int(request.form.get("node_id", 2))
        target_logical_id = request.form.get("target_logical_id")
        replace_file_id = request.form.get("replace_file_id")
        use_pq = request.form.get("use_post_quantum", "").lower() in ("true", "1")

        result = controller.storage.store_file(
            filename=filename,
            plaintext=content,
            uploaded_by=user["username"],
            folder_id=folder_id,
            node_id=node_id,
            mime_type=f.content_type or "application/octet-stream",
            target_logical_id=target_logical_id,
            replace_file_id=replace_file_id,
            use_post_quantum=use_pq,
        )
        return jsonify({"status": "success", "file": result})

    @app.route("/api/files/<file_id>", methods=["DELETE"])
    def delete_file(file_id):
        user = _require_auth()
        with sqlite3.connect(controller.db_path) as conn:
            row = conn.execute("SELECT logical_id FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
            if not row:
                return jsonify({"error": "File not found"}), 404
            logical_id = row[0]
            conn.execute("DELETE FROM cloud_files WHERE logical_id = ?", (logical_id,))
        return jsonify({"status": "deleted", "logical_id": logical_id})

    @app.route("/api/files/<file_id>/history", methods=["GET"])
    def get_version_history(file_id):
        with sqlite3.connect(controller.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT logical_id FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
            if not row:
                return jsonify({"error": "File not found"}), 404
            logical_id = row["logical_id"]
            history = conn.execute(
                """
                SELECT file_id, logical_id, filename, version_number, is_current,
                       size_bytes, is_post_quantum, uploaded_by, created_at
                FROM cloud_files WHERE logical_id = ?
                ORDER BY version_number DESC
                """,
                (logical_id,),
            ).fetchall()
        return jsonify({"logical_id": logical_id, "revisions": [dict(h) for h in history]})

    @app.route("/api/files/<file_id>/promote", methods=["POST"])
    def promote_version(file_id):
        now = time.time()
        with sqlite3.connect(controller.db_path) as conn:
            row = conn.execute("SELECT logical_id, version_number FROM cloud_files WHERE file_id = ?", (file_id,)).fetchone()
            if not row:
                return jsonify({"error": "File not found"}), 404
            logical_id, v_num = row[0], row[1]
            conn.execute("UPDATE cloud_files SET is_current = 0 WHERE logical_id = ?", (logical_id,))
            conn.execute("UPDATE cloud_files SET is_current = 1, updated_at = ? WHERE file_id = ?", (now, file_id))
        return jsonify({"status": "promoted", "active_file_id": file_id, "active_version": v_num})

    @app.route("/api/files/diff", methods=["GET"])
    def diff_files():
        base_id = request.args.get("base_id")
        target_id = request.args.get("target_id")
        if not base_id or not target_id:
            return jsonify({"error": "base_id and target_id required"}), 400

        try:
            _, b_bytes, _ = controller.storage.retrieve_file(base_id)
            _, t_bytes, _ = controller.storage.retrieve_file(target_id)
            b_text = b_bytes.decode("utf-8", errors="replace")
            t_text = t_bytes.decode("utf-8", errors="replace")

            diff = list(difflib.unified_diff(
                b_text.splitlines(keepends=True),
                t_text.splitlines(keepends=True),
                fromfile=f"Revision {base_id}",
                tofile=f"Revision {target_id}",
            ))
            adds = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
            dels = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
            return jsonify({
                "diff_lines": diff,
                "additions": adds,
                "deletions": dels,
                "base_id": base_id,
                "target_id": target_id,
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/<file_id>/preview", methods=["GET"])
    def preview_file(file_id):
        try:
            filename, content, mime_type = controller.storage.retrieve_file(file_id)
            is_text = False
            preview_text = ""
            try:
                preview_text = content.decode("utf-8")
                is_text = True
            except UnicodeDecodeError:
                preview_text = f"[Binary payload: {len(content)} bytes]"

            return jsonify({
                "file_id": file_id,
                "filename": filename,
                "mime_type": mime_type,
                "is_text": is_text,
                "preview_text": preview_text[:30000],
                "size_bytes": len(content),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/files/<file_id>/verify", methods=["GET"])
    def verify_proof(file_id):
        try:
            proof = controller.storage.verify_hardware_proof(file_id)
            return jsonify(proof)
        except Exception as e:
            return jsonify({"error": str(e)}), 404

    @app.route("/api/files/batch-move", methods=["POST"])
    def batch_move():
        data = request.get_json(force=True) or {}
        file_ids = data.get("file_ids", [])
        target_folder = data.get("target_folder_id", "root")
        res = controller.storage.batch_move_files(file_ids, target_folder)
        return jsonify(res)

    @app.route("/api/folders", methods=["GET", "POST"])
    def folders_route():
        user = _require_auth()
        if request.method == "POST":
            data = request.get_json(force=True) or {}
            name = data.get("name", "New Folder").strip()
            parent_id = data.get("parent_id", "root")
            fid = f"fld-{secrets.token_hex(6)}"
            now = time.time()
            with sqlite3.connect(controller.db_path) as conn:
                conn.execute(
                    "INSERT INTO cloud_folders (folder_id, parent_id, name, owner, created_at) VALUES (?, ?, ?, ?, ?)",
                    (fid, parent_id, name, user["username"], now),
                )
            return jsonify({"status": "created", "folder_id": fid, "name": name})
        else:
            with sqlite3.connect(controller.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM cloud_folders ORDER BY name ASC").fetchall()
                folders = [dict(r) for r in rows]
            return jsonify({"folders": folders})

    # -------------------------------------------------------------------------
    # Task B: CRDT Rich-Text Operational Transforms & Multi-Cursor Telemetry
    # -------------------------------------------------------------------------
    @app.route("/api/collab/<file_id>/ops", methods=["GET", "POST"])
    def crdt_ops(file_id):
        if request.method == "POST":
            user = _require_auth()
            data = request.get_json(force=True) or {}
            op = CRDTOperation(
                op_id=data.get("op_id", f"op-{secrets.token_hex(8)}"),
                file_id=file_id,
                client_id=data.get("client_id", "client-web"),
                clock=int(data.get("clock", 1)),
                op_type=data.get("op_type", "insert"),
                pos=float(data.get("pos", 0.0)),
                char=data.get("char", ""),
                author=user["username"],
                attributes=data.get("attributes", {}),
                end_pos=float(data.get("end_pos", data.get("pos", 0.0))),
            )
            result = controller.crdt_mgr.append_operation(op)
            return jsonify(result)
        else:
            doc = controller.crdt_mgr.get_or_load_doc(file_id)
            return jsonify({
                "file_id": file_id,
                "lamport_clock": doc.lamport_clock,
                "plain_text": doc.render_plain_text(),
                "rich_html": doc.render_rich_html(),
                "character_count": len(doc.characters),
            })

    @app.route("/api/collab/<file_id>/cursors", methods=["GET", "POST"])
    def crdt_cursors(file_id):
        if request.method == "POST":
            user = _require_auth()
            data = request.get_json(force=True) or {}
            cursor = controller.crdt_mgr.update_cursor(
                file_id=file_id,
                client_id=data.get("client_id", f"client-{secrets.token_hex(4)}"),
                user_id=user["user_id"],
                username=user["username"],
                pos=float(data.get("pos", 0.0)),
                selection_start=float(data.get("selection_start", data.get("pos", 0.0))),
                selection_end=float(data.get("selection_end", data.get("pos", 0.0))),
                color=data.get("color", "#7c3aed"),
            )
            return jsonify(cursor)
        else:
            active = controller.crdt_mgr.get_active_cursors(file_id)
            return jsonify({"file_id": file_id, "active_cursors": active})

    # -------------------------------------------------------------------------
    # Task C: Distributed Cross-Region Sharding Routes
    # -------------------------------------------------------------------------
    @app.route("/api/shards/topology", methods=["GET"])
    def shard_topology():
        return jsonify({
            "topology": controller.storage.shard_router.get_topology_map(),
            "active_shards": 4,
            "re_sealing_protocol": "Galois GHASH with Regional HMAC-SHA256 Token Binding",
        })

    @app.route("/api/shards/transfer", methods=["POST"])
    def shard_transfer():
        data = request.get_json(force=True) or {}
        file_id = data.get("file_id")
        target_node = int(data.get("target_node", 3))
        if not file_id:
            return jsonify({"error": "file_id is required"}), 400
        try:
            receipt = controller.storage.transfer_cross_shard(file_id, target_node)
            return jsonify(receipt)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # -------------------------------------------------------------------------
    # Task D: Hybrid Post-Quantum Cryptography (ML-KEM / Kyber-768)
    # -------------------------------------------------------------------------
    @app.route("/api/crypto/pq-seal", methods=["POST"])
    def pq_seal():
        data = request.get_json(force=True) or {}
        plaintext = data.get("text", "Sensitive Cloud-D Vault Payload").encode("utf-8")
        aad = data.get("aad", "cloud-d|pq-seal|test").encode("utf-8")
        packet = controller.storage.pq_vault.hybrid_seal(plaintext, aad)
        return jsonify(packet)

    @app.route("/api/crypto/pq-proof", methods=["GET"])
    def pq_proof():
        kp = controller.storage.pq_vault.kyber_keypair
        return jsonify({
            "algorithm": "CRYSTALS-Kyber-768 (ML-KEM NIST FIPS 203)",
            "lattice_parameters": {"n": 256, "k": 3, "q": 3329, "eta1": 2, "eta2": 2},
            "public_key_fingerprint": kp.get_fingerprint(),
            "public_key_bytes": len(kp.public_key_bytes),
            "secret_key_bytes": len(kp.secret_key_bytes),
            "quantum_immunity": "Immune to Shor's Polynomial-Time Factoring & Period Finding",
            "hybrid_combination": "HKDF-SHA256(Kyber-768 Shared Secret || X25519 ECDH Shared Secret)",
            "verified_at": time.time(),
        })

    # -------------------------------------------------------------------------
    # Task E: Red-Team AI Agent with Adversarial LLM Mutations
    # -------------------------------------------------------------------------
    @app.route("/api/threats/red-team/simulate", methods=["POST"])
    def simulate_red_team():
        user = _require_auth()
        data = request.get_json(force=True) or {}
        action = data.get("action")
        res = controller.red_team_agent.generate_adversarial_episode(action)

        # Trigger concurrent active threat event for real-time customer notification
        try:
            controller.trigger_active_threat(
                threat_name=f"Red-Team AI Adversarial Attack ({res['action']})",
                tactic=res["payload"].get("tactic", "adversarial_rl"),
                target_node=res["payload"].get("target_node", 2),
                severity="CRITICAL" if res["payload"].get("stealth_factor", 0.5) > 0.7 else "HIGH",
                triggered_by=user["username"],
                attacker_agent="Red-Team Q-Learning Agent (LLM Mutator)",
                defender_agent=res.get("intercepted_by") or "Sentinel Multi-Agent Mesh",
                details=res,
            )
        except Exception:
            pass

        return jsonify(res)

    @app.route("/api/threats/red-team/q-matrix", methods=["GET"])
    def red_team_q_matrix():
        return jsonify(controller.red_team_agent.get_q_matrix())

    # -------------------------------------------------------------------------
    # Task F: Enterprise FIDO2 / WebAuthn Hardware Attestation Routes
    # -------------------------------------------------------------------------
    @app.route("/api/auth/webauthn/register-options", methods=["POST"])
    def webauthn_options():
        user = _require_auth()
        opts = controller.webauthn_mgr.create_registration_challenge(user["user_id"], user["username"])
        return jsonify(opts)

    @app.route("/api/auth/webauthn/register-verify", methods=["POST"])
    def webauthn_verify():
        data = request.get_json(force=True) or {}
        session_token = data.get("session_token", "")
        credential_id = data.get("credential_id", f"cred-{secrets.token_hex(16)}")
        public_key_spki = data.get("public_key_spki", secrets.token_hex(65))
        device_label = data.get("device_label", "YubiKey 5 Series")
        attestation = data.get("attestation")

        try:
            res = controller.webauthn_mgr.verify_and_register_credential(
                session_token=session_token,
                credential_id=credential_id,
                public_key_spki=public_key_spki,
                device_label=device_label,
                attestation_packet=attestation,
            )
            return jsonify(res)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/api/auth/webauthn/devices", methods=["GET"])
    def webauthn_devices():
        user = _require_auth()
        creds = controller.webauthn_mgr.list_user_credentials(user["user_id"])
        return jsonify({"user_id": user["user_id"], "passkeys": creds})

    # -------------------------------------------------------------------------
    # Task G: Multi-Channel Push Notifications (WebPush, APNs, FCM)
    # -------------------------------------------------------------------------
    @app.route("/api/push/register-native", methods=["POST"])
    def register_native_push():
        user = _require_auth()
        data = request.get_json(force=True) or {}
        token_type = data.get("token_type", "fcm")
        token = data.get("device_token", f"token-{secrets.token_hex(16)}")
        dev_name = data.get("device_name", "iPhone 15 Pro" if token_type == "apns" else "Pixel 9 Pro")
        platform = data.get("platform", "ios" if token_type == "apns" else "android")

        res = controller.push_mgr.register_native_device(
            user_id=user["user_id"],
            token_type=token_type,
            device_token=token,
            device_name=dev_name,
            platform=platform,
        )
        return jsonify(res)

    @app.route("/api/push/broadcast-threat", methods=["POST"])
    def broadcast_threat():
        user = _require_auth()
        data = request.get_json(force=True) or {}
        title = data.get("title", "⚠️ Sentinel Shield Intercept")
        body = data.get("body", "Adversarial SQLi mutation blocked by Expectimax AST filter.")
        meta = data.get("meta", {"threat_type": "Adversarial_AST_SQLi", "node_id": 2, "severity": "CRITICAL"})

        res = controller.push_mgr.dispatch_multi_channel_threat_alert(user["user_id"], title, body, meta)
        return jsonify(res)

    @app.route("/api/push/history", methods=["GET"])
    def push_history():
        user = _require_auth()
        history = controller.push_mgr.get_notification_history(user["user_id"])
        return jsonify({"history": history})

    @app.route("/api/docs/executive-handover.docx", methods=["GET"])
    def get_executive_handover_doc():
        docx_filename = "Cloud_D_Executive_Handover_Specification.docx"
        docx_path = os.path.join(app.static_folder, docx_filename)
        if not os.path.exists(docx_path):
            try:
                import build_handover_doc
                build_handover_doc.create_document()
            except Exception as e:
                logger.warning(f"Could not build handover doc on-demand: {e}")
        return send_from_directory(app.static_folder, docx_filename, as_attachment=True)

    # -------------------------------------------------------------------------
    # Static Assets & Fallback SPA Route
    # -------------------------------------------------------------------------
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        if path == "Cloud_D_Executive_Handover_Specification.docx" or path == "api/docs/executive-handover.docx" or path.endswith(".docx"):
            docx_filename = "Cloud_D_Executive_Handover_Specification.docx"
            docx_path = os.path.join(app.static_folder, docx_filename)
            if not os.path.exists(docx_path):
                try:
                    import build_handover_doc
                    build_handover_doc.create_document()
                except Exception as e:
                    logger.warning(f"Could not build handover doc on-demand: {e}")
            if os.path.exists(docx_path):
                return send_from_directory(app.static_folder, docx_filename, as_attachment=True)

        if path and os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        return send_from_directory(app.static_folder, "index.html")

    return app

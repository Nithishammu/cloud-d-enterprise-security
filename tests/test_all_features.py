"""Comprehensive Test Suite for Cloud-D (Tasks 1 through 8 Deliverables).

Verifies:
1. Pure Minimax without pruning (depth 2) & Expectimax
2. Task 1: /api/version & Hot-Reload sync signals
3. Task 2: Client-Side WebCrypto zero-knowledge storage handling
4. Task 3: Native Mobile Push Notifications subscription & broadcast
5. Task 4: WebAuthn Biometric passkey registration & assertion
6. Task 5: Multi-File batch move & folder drag-and-drop
7. Task 6: Expiring encrypted share links with TTL & quotas
8. Task 7: Sequence CRDT collaborative editing & convergence
9. Task 8: Continuous Red-Teaming AI Agent RL mutations & Q-learning updates
10. AES-256-GCM AEAD hardware proof verification and rollback
"""

from __future__ import annotations

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloud_d.application import create_app
from cloud_d.collab.crdt import CRDTSessionManager, CRDTOperation
from cloud_d.logic.red_team_agent import RedTeamRLAgent
from cloud_d.logic.search import expectimax, minimax
from cloud_d.push_notifications import PushNotificationManager
from cloud_d.share import ShareLinkManager
from cloud_d.storage import CloudStorageVault, StorageIntegrityError
from cloud_d.webauthn_auth import WebAuthnManager


import uuid

class CloudDComprehensiveTestCase(unittest.TestCase):
    def setUp(self):
        self.test_db = f"test_cloud_d_{uuid.uuid4().hex[:8]}.db"

        self.storage = CloudStorageVault(db_path=self.test_db)
        self.push_mgr = PushNotificationManager(db_path=self.test_db)
        self.webauthn_mgr = WebAuthnManager(db_path=self.test_db)
        self.share_mgr = ShareLinkManager(db_path=self.test_db)
        self.crdt_mgr = CRDTSessionManager(db_path=self.test_db)
        self.red_team = RedTeamRLAgent()

        self.app = create_app(db_path=self.test_db)
        self.client = self.app.test_client()

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass
                pass

    # 1. Algorithmic Verifications: Pure Minimax & Expectimax
    def test_pure_minimax_no_pruning(self):
        tree = {
            "kind": "max",
            "children": [
                {
                    "kind": "min",
                    "action": "Tactic_A",
                    "children": [
                        {"kind": "leaf", "value": 10.0},
                        {"kind": "leaf", "value": 30.0},
                    ],
                },
                {
                    "kind": "min",
                    "action": "Tactic_B",
                    "children": [
                        {"kind": "leaf", "value": 5.0},
                        {"kind": "leaf", "value": 50.0},
                    ],
                },
            ],
        }
        val, action, nodes = minimax(tree, depth=2)
        # Min of Tactic_A is 10, Min of Tactic_B is 5. Max selects Tactic_A (10.0).
        self.assertEqual(val, 10.0)
        self.assertEqual(action, "Tactic_A")
        # Pure minimax visits all 7 nodes without pruning
        self.assertEqual(nodes, 7)

    def test_expectimax_chance_nodes(self):
        tree = {
            "kind": "max",
            "children": [
                {
                    "kind": "chance",
                    "action": "Sanitize_AST",
                    "children": [
                        {"kind": "leaf", "probability": 0.8, "value": 20.0},
                        {"kind": "leaf", "probability": 0.2, "value": -10.0},
                    ],
                },
                {
                    "kind": "chance",
                    "action": "Drop_Query",
                    "children": [
                        {"kind": "leaf", "probability": 1.0, "value": 5.0},
                    ],
                },
            ],
        }
        val, action, nodes = expectimax(tree)
        # E(Sanitize_AST) = 0.8*20 + 0.2*(-10) = 16 - 2 = 14.0. E(Drop_Query) = 5.0.
        self.assertEqual(val, 14.0)
        self.assertEqual(action, "Sanitize_AST")

    # 2. Task 1: Automated Web-to-App Sync Endpoint
    def test_task1_version_sync_api(self):
        resp = self.client.get("/api/version")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("version", data)
        self.assertIn("cache_name", data)
        self.assertTrue(data.get("hot_reload_enabled"))

    # Permanent Seeded Account & Registration Verification
    def test_seeded_accounts_and_registration(self):
        # 1. Test seeded account nithish / nithish123
        login_res = self.client.post("/api/auth/login", json={"username": "nithish", "password": "nithish123"})
        self.assertEqual(login_res.status_code, 200)
        data = login_res.get_json()
        self.assertEqual(data["status"], "authenticated")
        self.assertEqual(data["user"]["username"], "nithish")

        # 2. Test registration
        reg_res = self.client.post("/api/auth/register", json={"username": "newuser", "password": "securepassword10"})
        self.assertEqual(reg_res.status_code, 201)

        # 3. Test newly registered login
        new_login = self.client.post("/api/auth/login", json={"username": "newuser", "password": "securepassword10"})
        self.assertEqual(new_login.status_code, 200)

    # 3. Task 2: Client-Side WebCrypto Zero-Knowledge Storage
    def test_task2_webcrypto_zero_knowledge(self):
        payload_b64 = base64.b64encode(b"CLIENT_CIPHERTEXT_AES_GCM_ENCRYPTED").decode("utf-8")
        save_res = self.storage.save_file(
            filename="classified-vault.bin",
            content_bytes=base64.b64decode(payload_b64),
            user={"username": "nithish", "role": "staff"},
            is_client_encrypted=True,
            client_salt="deadbeef12345678",
        )
        self.assertTrue(save_res["file_id"].endswith("-v1"))

        # Verify integrity proof
        proof = self.storage.verify_file_integrity(save_res["file_id"], {"username": "nithish"})
        self.assertTrue(proof["is_client_encrypted"])
        self.assertTrue(proof["auth_tag_verified"])
        self.assertEqual(proof["tamper_status"], "INTACT · VERIFIED")

    # 4. Task 3: Native Mobile Push Notifications
    def test_task3_push_notifications(self):
        sub_res = self.push_mgr.register_subscription(
            user_id="u-nithish",
            endpoint="https://fcm.googleapis.com/fcm/send/test-token-12345",
            p256dh="mock_p256dh_key",
            auth="mock_auth_secret",
            device_name="iPhone 15 Pro",
        )
        self.assertEqual(sub_res["status"], "subscribed")

        alert = self.push_mgr.broadcast_threat_alert(
            node_id=2,
            tactic="SQLI",
            agent_name="Sentinel-QueryShield",
            sanitized_action="Chance Node Expectimax Filter",
            risk_score=95.0,
        )
        self.assertTrue(alert["dispatched"])
        self.assertEqual(alert["recipient_count"], 1)

    # 5. Task 4: Biometric WebAuthn Authentication
    def test_task4_webauthn_enrollment(self):
        options = self.webauthn_mgr.generate_registration_options("u-nithish", "nithish")
        self.assertIn("challenge", options)
        self.assertIn("session_id", options)

        cred_mock = {
            "id": "cred-touchid-test-id",
            "rawId": "raw-id-mock",
            "response": {"publicKey": "spki-key-data"},
        }
        res = self.webauthn_mgr.verify_registration(options["session_id"], cred_mock, "TouchID Authenticator")
        self.assertEqual(res["status"], "registered")

        # Login options
        login_opts = self.webauthn_mgr.generate_login_options("u-nithish")
        self.assertIn("challenge", login_opts)

        # Verify assertion
        auth_res = self.webauthn_mgr.verify_login(login_opts["session_id"], {"id": "cred-touchid-test-id"})
        self.assertTrue(auth_res["authenticated"])
        self.assertEqual(auth_res["user_id"], "u-nithish")

    # 6. Task 5: Multi-File Batch Move Reorganization
    def test_task5_batch_move(self):
        f1 = self.storage.save_file("doc1.txt", b"Hello 1", {"username": "admin", "role": "staff"})
        f2 = self.storage.save_file("doc2.txt", b"Hello 2", {"username": "admin", "role": "staff"})

        move_res = self.storage.batch_move_files(
            file_ids=[f1["file_id"], f2["file_id"]],
            target_folder_id="f-docs",
            user={"username": "admin"},
        )
        self.assertEqual(move_res["count"], 2)
        self.assertEqual(move_res["target_folder_id"], "f-docs")

        # Verify folder file listing
        docs = self.storage.list_files({"username": "admin", "role": "staff"}, folder_id="f-docs")
        self.assertEqual(len(docs), 2)

    # 7. Task 6: Expiring Encrypted Share Links
    def test_task6_share_links(self):
        f = self.storage.save_file("report.txt", b"Confidential Financials", {"username": "admin", "role": "staff"})
        share = self.share_mgr.create_share_link(
            file_id=f["file_id"],
            logical_id=f["logical_id"],
            created_by_user="admin",
            ttl_seconds=3600,
            max_downloads=2,
            password="secure-passphrase",
        )
        self.assertTrue(share["has_password"])
        token = share["share_token"]

        # Access with incorrect password -> should fail
        with self.assertRaises(PermissionError):
            self.share_mgr.access_share_link(token, password="wrong")

        # Access with valid password
        access1 = self.share_mgr.access_share_link(token, password="secure-passphrase")
        self.assertEqual(access1["download_number"], 1)

        access2 = self.share_mgr.access_share_link(token, password="secure-passphrase")
        self.assertEqual(access2["download_number"], 2)

        # Quota exceeded on 3rd access
        with self.assertRaises(ValueError):
            self.share_mgr.access_share_link(token, password="secure-passphrase")

    # 8. Task 7: Collaborative CRDT Editing
    def test_task7_crdt_convergence(self):
        file_id = "doc-collab-101"
        self.crdt_mgr.initialize_from_text(file_id, "Cloud", author="Alice")

        # Concurrent insert operations from two clients
        op_bob = CRDTOperation(
            op_id="op-1", file_id=file_id, client_id="bob", clock=10,
            op_type="insert", pos=55.0, char="-", author="Bob"
        )
        op_charlie = CRDTOperation(
            op_id="op-2", file_id=file_id, client_id="charlie", clock=11,
            op_type="insert", pos=60.0, char="D", author="Charlie"
        )

        self.crdt_mgr.apply_operation(op_bob)
        self.crdt_mgr.apply_operation(op_charlie)

        doc = self.crdt_mgr.compute_converged_document(file_id)
        self.assertEqual(doc["text"], "Cloud-D")

    # 9. Task 8: Continuous Red-Teaming AI Agent RL Loop
    def test_task8_red_team_rl_agent(self):
        payload = self.red_team.generate_payload(target_node=2, defense_strictness="high")
        self.assertIn(payload.tactic, RedTeamRLAgent.TACTICS)
        self.assertGreater(len(payload.raw_payload), 0)

        reward = self.red_team.record_outcome(
            payload=payload,
            defense_strictness="high",
            blocked=True,
            detected_by_sentinel=True,
            response_time_ms=45.0,
        )
        self.assertEqual(reward, -50.0)

        summary = self.red_team.get_summary()
        self.assertEqual(summary["total_episodes"], 1)
        self.assertIn("node_2:high", summary["q_table"])

    # 10. Version Rollback, Promotion, and Duplicate Handling
    def test_version_promotion(self):
        f_v1 = self.storage.save_file("draft.txt", b"Version 1 content", {"username": "admin", "role": "staff"})
        f_v2 = self.storage.save_file("draft.txt", b"Version 2 content", {"username": "admin", "role": "staff"}, target_logical_id=f_v1["logical_id"])

        # Check that version incremented to n+1 (v2)
        self.assertEqual(f_v2["version"], 2)

        # Promote v1 back to current
        prom = self.storage.promote_version(f_v1["file_id"], {"username": "admin"})
        self.assertTrue(prom["promoted"])
        self.assertEqual(prom["version"], 1)

    def test_duplicate_check_and_delete(self):
        # 1. Save initial file
        f_init = self.storage.save_file("duplicate_test.txt", b"Initial v1 payload", {"username": "admin", "role": "staff"})
        
        # 2. Check duplicate exists
        existing = self.storage.find_file_by_name("duplicate_test.txt", "root", {"username": "admin", "role": "staff"})
        self.assertIsNotNone(existing)
        self.assertEqual(existing["version_number"], 1)

        # 3. Save as n+1 version
        f_v2 = self.storage.save_file(
            "duplicate_test.txt",
            b"Updated v2 payload",
            {"username": "admin", "role": "staff"},
            target_logical_id=existing["logical_id"]
        )
        self.assertEqual(f_v2["version"], 2)

        # 4. In-place replace
        f_rep = self.storage.save_file(
            "duplicate_test.txt",
            b"In-place replaced v2 payload",
            {"username": "admin", "role": "staff"},
            replace_file_id=f_v2["file_id"]
        )
        self.assertEqual(f_rep["mode"], "replaced")

        # 5. Delete file
        deleted = self.storage.delete_file(f_v2["file_id"], {"username": "admin"})
        self.assertTrue(deleted)
        after_del = self.storage.find_file_by_name("duplicate_test.txt", "root")
        self.assertIsNone(after_del)


if __name__ == "__main__":
    unittest.main()

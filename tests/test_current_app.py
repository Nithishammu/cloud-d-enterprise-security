"""Regression checks for Cloud-D's current application and simulation API."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloud_d.application import CloudDApplication


class CloudDApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="cloud-d-test-")
        self.env = patch.dict(
            os.environ,
            {
                "CLOUD_D_DATA_DIR": self.temp_dir.name,
                "CLOUD_D_STAFF_REGISTRATION_CODE": "test-staff-code-123",
            },
        )
        self.env.start()
        self.app = CloudDApplication()

    def tearDown(self) -> None:
        self.app.close()
        self.env.stop()
        self.temp_dir.cleanup()

    def test_signup_login_and_account_persist_in_sqlite(self) -> None:
        created = self.app.register_user(
            {
                "username": "customer-one",
                "email": "customer@example.com",
                "password": "correct horse battery staple",
                "role": "customer",
            }
        )
        self.assertEqual(created["user"]["role"], "customer")
        self.assertTrue(self.app.resolve_session(created["session"]))

        self.app.close()
        reopened = CloudDApplication()
        try:
            logged_in = reopened.login_user(
                {"username": "customer-one", "password": "correct horse battery staple"}
            )
            self.assertEqual(logged_in["user"]["email"], "customer@example.com")
            self.assertTrue(reopened.resolve_session(logged_in["session"]))
        finally:
            reopened.close()

    def test_staff_signup_requires_the_configured_code(self) -> None:
        details = {
            "username": "staff-one",
            "email": "staff@example.com",
            "password": "correct horse battery staple",
            "role": "staff",
            "staff_registration_code": "wrong-code",
        }
        with self.assertRaisesRegex(ValueError, "incorrect"):
            self.app.register_user(details)

        details["staff_registration_code"] = "test-staff-code-123"
        created = self.app.register_user(details)
        self.assertEqual(created["user"]["role"], "staff")

    def test_simulation_round_creates_visible_agent_results(self) -> None:
        account = self.app.register_user(
            {
                "username": "staff-two",
                "email": "staff2@example.com",
                "password": "correct horse battery staple",
                "role": "staff",
                "staff_registration_code": "test-staff-code-123",
            }
        )["user"]

        self.app.begin_new_run(
            {"active_vectors": ["auth", "flow", "query", "behavior"]}, account
        )
        state = self.app.simulate_round(user=account)

        self.assertEqual(state["round"], 1)
        self.assertGreater(state["metrics"]["total_attacks"], 0)
        self.assertTrue(state["attack_log"])
        for event in state["attack_log"]:
            self.assertIn("assigned_defender", event)
            self.assertIn("utility", event)
            self.assertIn("blocked", event)
            self.assertIn("damage", event)

    def test_install_manifest_and_icon_are_public_before_login(self) -> None:
        root = Path(__file__).resolve().parents[1]
        page = (root / "index.html").read_text(encoding="utf-8")
        server = (root / "cloud_d" / "server.py").read_text(encoding="utf-8")
        manifest = (root / "manifest.json").read_text(encoding="utf-8")
        icon = (root / "cloud-d-icon.svg").read_text(encoding="utf-8")

        self.assertIn('<link rel="manifest" href="/manifest.json">', page)
        self.assertIn('if path == "/manifest.json":', server)
        self.assertIn('if path == "/cloud-d-icon.svg":', server)
        self.assertEqual(manifest.count('"src": "/cloud-d-icon.svg"'), 2)
        self.assertIn('<svg', icon)


if __name__ == "__main__":
    unittest.main()

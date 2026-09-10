import json
import tempfile
import unittest
from pathlib import Path

from src.loader import load_requests
from src.models import AccessRequest
from src.policy_engine import evaluate
from src.reporting import markdown, metrics


class ZeroTrustPolicyTests(unittest.TestCase):
    def good(self):
        return AccessRequest("R1", "user", "d1", "managed", "workforce", "restricted", "app", "critical", True, 10, True, True, frozenset({"HTTPS"}), "HTTPS")

    def test_good_request_allowed(self):
        self.assertEqual(evaluate(self.good()).action, "allow")

    def test_missing_mfa_on_critical_resource_denied(self):
        r = self.good().__class__(**{**self.good().__dict__, "mfa": False})
        self.assertEqual(evaluate(r).action, "deny")

    def test_high_identity_risk_creates_finding(self):
        r = self.good().__class__(**{**self.good().__dict__, "identity_risk": 80})
        self.assertTrue(any(f.control == "identity.risk" for f in evaluate(r).findings))

    def test_untrusted_device_creates_finding(self):
        r = self.good().__class__(**{**self.good().__dict__, "device_trust": "untrusted"})
        self.assertTrue(any(f.control == "device.trust" for f in evaluate(r).findings))

    def test_plain_transport_denied(self):
        r = self.good().__class__(**{**self.good().__dict__, "encrypted_channel": False})
        self.assertEqual(evaluate(r).action, "deny")

    def test_unapproved_protocol_detected(self):
        r = self.good().__class__(**{**self.good().__dict__, "protocol": "SSH"})
        self.assertTrue(any(f.control == "protocol.allowlist" for f in evaluate(r).findings))

    def test_finding_ids_are_deterministic(self):
        r = self.good().__class__(**{**self.good().__dict__, "mfa": False})
        self.assertEqual(evaluate(r).findings[0].finding_id, evaluate(r).findings[0].finding_id)

    def test_invalid_identity_risk_fails_closed(self):
        r = self.good().__class__(**{**self.good().__dict__, "identity_risk": 101})
        with self.assertRaises(ValueError):
            evaluate(r)

    def test_loader_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text(json.dumps([{"request_id": "x"}]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_requests(str(p))

    def test_reporting_contains_validation_workflow(self):
        decisions = [evaluate(self.good())]
        self.assertIn("Validation Workflow", markdown(decisions))
        self.assertEqual(metrics(decisions)["requests"], 1)


if __name__ == "__main__":
    unittest.main()

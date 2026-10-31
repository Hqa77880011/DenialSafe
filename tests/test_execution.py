import copy
import unittest

from denialsafe import core, execution


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.public = {
            "epoch": 1,
            "grammar_version": 1,
            "policies": [{"equals": {"mfa": True}}],
            "actions": {"mfa": {"set": {"mfa": True}, "user_executable": True}},
            "max_depth": 1,
        }
        self.request = {"principal": "u", "mfa": False}
        self.key = b"functional-test-key-only"
        self.result = core.synthesize(self.public, self.request)
        self.certificate = execution.certify(
            self.public, self.request, self.result, self.key
        )

    def test_current_pdp_remains_authoritative(self):
        accepted = execution.authorize(
            self.certificate, self.public, self.request,
            self.public["policies"][0], self.key,
        )
        self.assertEqual(accepted["type"], "EXECUTE")
        self.assertTrue(accepted["request"]["mfa"])
        denied = execution.authorize(
            self.certificate, self.public, self.request,
            {"denies": [{}]}, self.key,
        )
        self.assertEqual(denied["type"], "ACCESS_DENIED")

    def test_tampered_request_and_epoch_are_rejected(self):
        changed = copy.deepcopy(self.certificate)
        changed["payload"]["request"]["principal"] = "other"
        self.assertEqual(execution.authorize(
            changed, self.public, self.request, {}, self.key
        )["type"], "INVALID_CERTIFICATE")
        self.assertEqual(execution.authorize(
            self.certificate, dict(self.public, epoch=2), self.request, {}, self.key
        )["type"], "STALE_BINDING")

    def test_process_guidance_cannot_be_access(self):
        with self.assertRaises(ValueError):
            execution.certify(self.public, self.request,
                              {"type": "PROCESS_RECOURSE", "sequence": []}, self.key)

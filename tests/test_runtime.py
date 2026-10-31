import copy
import os
import secrets
import tempfile
import time
import unittest
from pathlib import Path
from denialsafe import core, execution, native
from denialsafe.runtime import Executor


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "public.txt").write_bytes(b"real public bytes")
        (self.root / "private.txt").write_bytes(b"secret protected bytes")
        self.public = dict(
            epoch=1,
            grammar_version=1,
            policies=[dict(equals={"mfa": True}, members={"scope": ["public"]})],
            actions={
                "mfa": dict(handler="mfa", set={"mfa": True}, user_executable=True),
                "narrow": dict(set={"scope": "public"}, user_executable=True),
            },
            max_depth=2,
            process_actions={
                "approval": dict(
                    kind="process", set={"workflow": "pending"}, user_executable=True
                )
            },
        )
        self.request = dict(
            principal="alice", mfa=False, scope="private", objects=["p", "q"]
        )
        self.key = secrets.token_bytes(32)
        self.objects = {
            "p": dict(path="public.txt", scope="public"),
            "q": dict(path="private.txt", scope="private"),
        }
        self.executor = Executor(
            self.root / "ledger.sqlite", self.root, self.key, self.objects
        )
        self.executor.set_identity("alice", {})
        self.executor.install(self.public, self.public["policies"][0])
        self.certificate = execution.certify(
            self.public,
            self.request,
            core.synthesize(self.public, self.request),
            self.key,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_actual_factor_narrowing_file_effect_and_persistent_receipt(self):
        with self.assertRaises(PermissionError):
            self.executor.execute(self.certificate, self.request, "alice")
        self.assertFalse((self.root / "effects").exists())
        self.executor.grant_mfa("alice", "one-time-factor", time.time() + 60)
        result = self.executor.execute(
            self.certificate, self.request, "alice", {"mfa": "one-time-factor"}
        )
        self.assertEqual(result["objects"], ["p"])
        self.assertEqual(
            (self.root / "effects/p.bin").read_bytes(), b"real public bytes"
        )
        self.assertFalse((self.root / "effects/q.bin").exists())
        reopened = Executor(
            self.root / "ledger.sqlite", self.root, self.key, self.objects
        )
        with reopened.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM effects").fetchone()[0], 1
            )
        with self.assertRaises(PermissionError):
            reopened.execute(
                self.certificate, self.request, "alice", {"mfa": "one-time-factor"}
            )

    def test_epoch_current_pdp_and_actual_pending_process(self):
        self.executor.grant_mfa("alice", "factor", time.time() + 60)
        updated = copy.deepcopy(self.public)
        updated["epoch"] = 2
        self.executor.install(updated, {"denies": [{}]})
        with self.assertRaises(PermissionError):
            self.executor.execute(
                self.certificate, self.request, "alice", {"mfa": "factor"}
            )
        result = self.executor.process("alice", self.request, "approval")
        self.assertEqual(result["status"], "PENDING")
        with self.executor.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM effects").fetchone()[0], 0
            )
            self.assertEqual(
                db.execute("SELECT status FROM workflow").fetchone()[0], "PENDING"
            )

    def test_private_identity_context_and_forged_context_rejection(self):
        self.public["hidden_request_fields"] = {"level": [3, 4]}
        self.public["policies"][0]["minimum"] = {"level": 3}
        self.public["epoch"] = 2
        self.executor.install(self.public, self.public["policies"][0])
        self.executor.set_identity("alice", {"level": 4})
        certificate = execution.certify(
            self.public,
            self.request,
            core.synthesize(self.public, self.request),
            self.key,
        )
        self.executor.grant_mfa("alice", "private-factor", time.time() + 60)
        self.assertEqual(
            self.executor.execute(
                certificate, self.request, "alice", {"mfa": "private-factor"}
            )["objects"],
            ["p"],
        )
        forged = {**self.request, "level": 10}
        with self.assertRaises(PermissionError):
            self.executor.execute(certificate, forged, "alice", {"mfa": "unused"})

    @unittest.skipUnless(
        os.getenv("DENIALSAFE_CEDAR"), "optional actual Cedar CLI not configured"
    )
    def test_actual_cedar_protected_execution(self):
        callback = lambda policy, request: native.cedar(
            policy, request, os.environ["DENIALSAFE_CEDAR"], self.root / "cedar"
        )["decision"]
        self.executor.pdp = callback
        self.executor.grant_mfa("alice", "native-factor", time.time() + 60)
        self.assertEqual(
            self.executor.execute(
                self.certificate, self.request, "alice", {"mfa": "native-factor"}
            )["objects"],
            ["p"],
        )


class NativeTests(unittest.TestCase):
    def cases(self):
        policy = dict(
            equals={"mfa": True},
            minimum={"level": 2},
            members={"scope": ["public"]},
            denies=[{"blocked": True}],
        )
        for mfa, blocked in ((True, False), (False, False), (True, True)):
            yield (
                policy,
                dict(
                    principal="alice", mfa=mfa, level=3, scope="public", blocked=blocked
                ),
                "Permit" if mfa and not blocked else "Deny",
            )

    @unittest.skipUnless(
        os.getenv("DENIALSAFE_CEDAR"), "optional actual Cedar CLI not configured"
    )
    def test_actual_cedar_common_fragment(self):
        with tempfile.TemporaryDirectory() as root:
            for policy, request, expected in self.cases():
                self.assertEqual(
                    native.cedar(policy, request, os.environ["DENIALSAFE_CEDAR"], root)[
                        "decision"
                    ],
                    expected,
                )

    @unittest.skipUnless(
        os.getenv("DENIALSAFE_BALANA_CLASSPATH"),
        "optional actual Balana classpath not configured",
    )
    def test_actual_balana_common_fragment_and_raw_categories(self):
        with tempfile.TemporaryDirectory() as root:
            rows = [
                native.balana(
                    policy,
                    request,
                    os.getenv("DENIALSAFE_JAVA", "java"),
                    os.environ["DENIALSAFE_BALANA_CLASSPATH"],
                    root,
                )
                for policy, request, expected in self.cases()
            ]
            self.assertEqual(
                [row["decision"] for row in rows], ["Permit", "Deny", "Deny"]
            )
            self.assertEqual(rows[1]["native_decision"], "NotApplicable")


if __name__ == "__main__":
    unittest.main()

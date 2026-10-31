import copy
import itertools
import unittest
from denialsafe import core, oracle, policy, symbolic
from denialsafe.channel import Service, update_history


class SymbolicTests(unittest.TestCase):
    def public(self):
        return dict(
            epoch=1,
            grammar_version=1,
            holes={"minimum": [1, 3], "blocked": [False, True]},
            skeleton=dict(
                required=["level", "mfa"],
                equals={"mfa": True},
                minimum={"level": {"hole": "minimum"}},
                denies=[{"blocked": {"hole": "blocked"}}],
            ),
            actions={
                "mfa": dict(set={"mfa": True}, user_executable=True, cost=1),
                "narrow": dict(set={"blocked": False}, user_executable=True, cost=2),
            },
            max_depth=2,
        )

    def test_both_symbolic_encodings_match_concrete_all_holes_and_categories(self):
        public = self.public()
        for independent in (False, True):
            family = symbolic.Family(public, independent=independent)
            for assignment, concrete in policy.enumerate_family(public):
                for request in (
                    {},
                    dict(level=1, mfa=False),
                    dict(level="bad", mfa=True),
                    dict(level=4, mfa=True, blocked=False),
                    dict(level=4, mfa=True, blocked=True),
                ):
                    import z3

                    solver = z3.Solver()
                    solver.add(family.bounds, family.fix(assignment))
                    expression = family.category(family.request(request))
                    self.assertEqual(solver.check(), z3.sat)
                    actual = policy.DECISIONS[solver.model().eval(expression).as_long()]
                    self.assertEqual(actual, oracle.decision(concrete, request))
                    self.assertEqual(actual, policy.decision(concrete, request))

    def test_symbolic_cegis_matches_exhaustive_reference_and_rejects_sampling(self):
        public = dict(
            holes={"scope": ["public", "private"]},
            skeleton={
                "members": {"scope": [{"hole": "scope"}, "both"]},
                "equals": {"mfa": True},
            },
            actions={
                "mfa": dict(set={"mfa": True}, user_executable=True, cost=1),
                "both": dict(set={"scope": "both"}, user_executable=True, cost=2),
            },
            max_depth=2,
        )
        request = dict(mfa=False, scope="public")
        complete = core.synthesize(public, request)
        exact = core.synthesize(public, request, "exact_robust")
        self.assertEqual(complete["sequence"], exact["sequence"])
        self.assertEqual(set(complete["sequence"]), {"both", "mfa"})
        self.assertTrue(oracle.check(public, request, complete["sequence"]))
        sampled = core.synthesize(public, request, "sampled_policies")
        self.assertEqual(sampled["type"], "ACCESS_RECOURSE")
        self.assertFalse(oracle.check(public, request, sampled["sequence"]))

    def test_full_published_history_categories_hidden_attributes_and_conflict(self):
        public = dict(
            holes={"threshold": [1, 3], "hidden_level": [1, 4]},
            skeleton={"minimum": {"level": {"hole": "threshold"}}},
            actions={},
            max_depth=0,
            history=[
                dict(request={"level": {"hole": "hidden_level"}}, decision="Permit")
            ],
        )
        family = symbolic.Family(public)
        self.assertEqual(family.query()["status"], "SAT")
        self.assertEqual(len(policy.possible(public)), 3)
        public["history"].append(dict(request={}, decision="Permit"))
        self.assertEqual(core.synthesize(public, {})["type"], "PUBLIC_CONFLICT")
        rules = {
            "allow_rules": [{"compare": ["$x", "ge", 1]}],
            "deny_rules": [{"blocked": True}],
        }
        self.assertEqual(
            core.evaluate(rules, dict(x=0, blocked=False)), "NotApplicable"
        )
        self.assertEqual(core.evaluate(rules, dict(x=2, blocked=True)), "Deny")
        self.assertEqual(
            core.evaluate(rules, dict(x="bad", blocked=False)), "Indeterminate"
        )

    def test_public_cache_epoch_history_and_fixed_length_channel(self):
        public = dict(
            epoch=1,
            policies=[{"equals": {"mfa": True}}],
            actions={"mfa": dict(set={"mfa": True}, user_executable=True)},
            max_depth=1,
            channel=dict(
                response_bytes=512, bucket_seconds=0.001, release_budget_seconds=0.01
            ),
        )
        service = Service()
        request = dict(mfa=False)
        a = service.explain(public, request, controlled_channel=True)
        b = service.explain(public, request, controlled_channel=True)
        self.assertFalse(a["cache_hit"])
        self.assertTrue(b["cache_hit"])
        self.assertEqual(a["output"], b["output"])
        self.assertEqual(len(a["output"].encode()), 512)
        changed = update_history(public, request, "Deny", epoch=2)
        self.assertNotEqual(
            service.explain(changed, request)["cache_key"], a["cache_key"]
        )
        with self.assertRaises(ValueError):
            service.explain(public, request, "true_policy")

    def test_optimized_template_and_process_are_distinct_from_access(self):
        public = dict(
            policies=[{"equals": {"x": True}}],
            actions={
                "a": dict(set={"x": True}, user_executable=True, cost=1),
                "b": dict(set={"x": True}, user_executable=True, cost=3),
            },
            templates=[dict(id="ready", goals={"x": True})],
            max_depth=1,
        )
        self.assertEqual(
            core.synthesize(public, {"x": False}, "public_templates")["sequence"], ["a"]
        )
        public["actions"] = {}
        public["process_actions"] = {
            "apply": dict(
                kind="process", set={"ticket": "pending"}, user_executable=True
            )
        }
        self.assertEqual(
            core.synthesize(public, {"x": False})["type"], "PROCESS_RECOURSE"
        )

    def test_secret_tie_redaction_and_causal_adaptation_are_real_distinct_controls(
        self,
    ):
        import hashlib

        choices = [
            dict(equals={"mfa": True}, minimum={"level": value}) for value in range(10)
        ]
        by_parity = {}
        for item in choices:
            by_parity.setdefault(
                hashlib.sha256(policy.encode(item).encode()).digest()[0] % 2, item
            )
        public = dict(
            policies=list(by_parity.values()),
            actions={
                name: dict(set={"mfa": True}, user_executable=True, cost=1)
                for name in ("a", "b")
            },
            max_depth=1,
        )
        request = dict(mfa=False, level=20)
        outcomes = [
            core.synthesize(public, request, "secret_tie_break", item)
            for item in by_parity.values()
        ]
        self.assertNotEqual(outcomes[0]["sequence"], outcomes[1]["sequence"])
        self.assertTrue(
            all(oracle.check(public, request, item["sequence"]) for item in outcomes)
        )
        redacted = core.synthesize(public, request, "redacted_repair", choices[0])
        causal = core.synthesize(public, request, "causal_adaptation", choices[0])
        from denialsafe.channel import render

        self.assertIn(b"REDACTED_ACTION", render(public, redacted))
        self.assertEqual(list(causal["causal_contribution"].values()), [1])

    def test_matched_adaptive_histories_and_actual_channel_records(self):
        from denialsafe.evaluation import matched_attack, cache_campaign

        public = dict(
            epoch=1,
            policies=[
                {"equals": {"mfa": True}},
                {"equals": {"mfa": True}, "minimum": {"level": 3}},
            ],
            actions={"mfa": dict(set={"mfa": True}, user_executable=True)},
            max_depth=1,
        )
        rows = matched_attack(
            public,
            public["policies"][0],
            {"mfa": [False], "level": [1, 4]},
            methods=["denialsafe", "redacted_repair"],
            budget=2,
            visibility="white",
        )
        full = [row for row in rows if row["method"] == "denialsafe"]
        self.assertTrue(
            all(row["metrics"]["incremental_recovery_gain"] == 0 for row in full)
        )
        for attempt in range(2):
            self.assertEqual(
                len(
                    {
                        policy.encode(row["public_history"])
                        for row in rows
                        if row["attempt"] == attempt
                    }
                ),
                1,
            )
        cache = cache_campaign(public, dict(mfa=False, level=4), repeats=2)
        self.assertEqual(len(cache), 8)

    def test_current_private_request_attributes_are_quantified_not_revealed(self):
        public = dict(
            policies=[{"minimum": {"level": 3}, "equals": {"mfa": True}}],
            hidden_request_fields={"level": [1, 4]},
            actions={"mfa": dict(set={"mfa": True}, user_executable=True)},
            max_depth=1,
        )
        request = dict(mfa=False)
        self.assertEqual(core.synthesize(public, request)["type"], "ABSTAIN")
        public["hidden_request_fields"]["level"] = [3, 4]
        result = core.synthesize(public, request)
        self.assertEqual(result["type"], "ACCESS_RECOURSE")
        self.assertTrue(oracle.check(public, request, result["sequence"]))
        self.assertEqual(
            symbolic.certified(public, request, result["sequence"])[0], True
        )
        actual = core.synthesize(
            public, request, "true_policy", public["policies"][0], {"level": 4}
        )
        self.assertEqual(actual["type"], "ACCESS_RECOURSE")

    def test_hidden_attribute_history_does_not_publish_private_values(self):
        from denialsafe.evaluation import matched_attack

        public = dict(
            policies=[{"minimum": {"level": 3}, "equals": {"mfa": True}}],
            hidden_request_fields={"level": [1, 4]},
            actions={"mfa": dict(set={"mfa": True}, user_executable=True)},
            max_depth=1,
        )
        rows = matched_attack(
            public,
            public["policies"][0],
            {"mfa": [False]},
            methods=["denialsafe", "true_policy"],
            budget=2,
            actual_request_attributes={"level": 4},
        )
        self.assertEqual(len(rows), 4)
        self.assertTrue(
            all(
                row["metrics"]["incremental_recovery_gain"] == 0
                for row in rows
                if row["method"] == "denialsafe"
            )
        )
        self.assertTrue(
            all(
                isinstance(row["public_history"][0]["request"]["level"], dict)
                for row in rows
            )
        )

    def test_deny_overrides_missing_and_illtyped_attributes_cannot_create_permit(self):
        value = {"equals": {"mfa": True}, "denies": [{"blocked": True}]}
        for request, expected in (
            ({"blocked": True}, "Deny"),
            ({"mfa": True}, "Indeterminate"),
            ({"mfa": True, "blocked": 1}, "Indeterminate"),
            ({"mfa": True, "blocked": False}, "Permit"),
        ):
            self.assertEqual(core.evaluate(value, request), expected)
            self.assertEqual(oracle.decision(value, request), expected)
            for independent in (False, True):
                family = symbolic.Family({"policies": [value]}, independent=independent)
                import z3

                solver = z3.Solver()
                solver.add(family.bounds)
                self.assertEqual(solver.check(), z3.sat)
                self.assertEqual(
                    policy.DECISIONS[
                        solver.model()
                        .eval(family.category(family.request(request)))
                        .as_long()
                    ],
                    expected,
                )


if __name__ == "__main__":
    unittest.main()

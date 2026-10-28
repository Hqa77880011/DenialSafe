import unittest

from denialsafe import core


class DenialSafeTests(unittest.TestCase):
    def test_boolean_is_not_an_integer_and_bad_numeric_type_is_nonpermit(self):
        self.assertNotEqual(
            core.evaluate({"equals": {"mfa": True}}, {"mfa": 1}), "Permit"
        )
        self.assertNotEqual(
            core.evaluate({"minimum": {"level": 1}}, {"level": "high"}), "Permit"
        )

    def test_repeated_primitive_can_be_required_by_intermediate_preconditions(self):
        public = {
            "policies": [{"equals": {"x": True, "y": True}}],
            "max_depth": 3,
            "actions": {
                "a": {
                    "preconditions": {"x": False},
                    "set": {"x": True},
                    "user_executable": True,
                },
                "b": {
                    "preconditions": {"x": True},
                    "set": {"x": False, "y": True},
                    "user_executable": True,
                },
            },
        }
        result = core.synthesize(public, {"x": False, "y": False})
        self.assertEqual(result["type"], "ACCESS_RECOURSE")
        self.assertEqual(result["sequence"], ["a", "b", "a"])

    def test_public_conflict_is_not_vacuous_permission(self):
        result = core.synthesize({"policies": [], "actions": {}}, {})
        self.assertEqual(result["type"], "PUBLIC_CONFLICT")


if __name__ == "__main__":
    unittest.main()

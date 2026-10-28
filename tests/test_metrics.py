import unittest

from denialsafe.cli import summarize
from denialsafe.statistics import analyze


class MetricTests(unittest.TestCase):
    def test_conditional_micro_rate_and_undefined_support(self):
        rows = [
            dict(id="a", metrics=dict(rate=0.5), metric_counts=dict(rate=[1, 2])),
            dict(id="b", metrics=dict(rate=1 / 3), metric_counts=dict(rate=[2, 6])),
            dict(id="c", metrics=dict(rate=None), metric_counts=dict(rate=[0, 0])),
        ]
        value = summarize(rows)["rate"]
        self.assertEqual(value["count"], 2)
        self.assertEqual(value["micro"], dict(numerator=3, denominator=8, rate=0.375))

    def test_zero_event_bound_uses_only_eligible_independent_families(self):
        rows = [
            dict(id="a", cluster="one", metrics=dict(false_safe=0)),
            dict(id="b", cluster="one", metrics=dict(false_safe=0)),
            dict(id="c", cluster="undefined", metrics=dict(false_safe=None)),
        ]
        value = analyze(rows, resamples=10)["false_safe"]
        for row in rows:
            row["metrics"]["count"] = 0
        counter = analyze(rows, resamples=10)["count"]
        self.assertNotIn("zero_event_independent_cluster_upper95", counter)
        self.assertEqual(value["clusters"], 1)
        self.assertIsNone(value["bootstrap95"])
        self.assertAlmostEqual(value["zero_event_independent_cluster_upper95"], 0.95)


if __name__ == "__main__":
    unittest.main()

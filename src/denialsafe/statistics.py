"""Family-clustered estimates, paired contrasts and explicit conditional support."""

import argparse
import json
from pathlib import Path

import numpy as np
from scipy.stats import binomtest, wilcoxon


EVENT_METRICS = frozenset(
    [
        "full_outcome_mismatch",
        "obligation_loss",
        "certified_coverage",
        "source_call_ratio",
        "completion",
        "domain_fraction",
        "deadline_failure",
        "handler_failure",
        "joint_uar",
        "false_allowance",
        "false_denial",
        "secure_task_success",
        "confirmed_mutation",
        "false_report",
        "right_censored",
        "replay_success",
        "coverage",
        "robust_coverage",
        "actual_policy_validity",
        "robust_validity",
        "failed_repair",
        "illegal_repair",
        "nonrobust_repair",
        "abstention",
        "public_conflict",
        "process_guidance",
        "same_view_content_mismatch",
        "admission",
        "false_safe",
        "obligation_violation",
        "exact_feasible",
        "false_allow",
        "unsafe_permit_all",
        "defer",
        "certificate_refusal",
        "unsafe_reuse",
        "safe_recall",
        "prompt_rate",
        "reconsent_precision",
        "uar",
        "object_scope_violation",
        "object_level_violation",
        "policy_violation",
        "task_success",
        "reauthorization",
        "retry",
        "reconsent",
        "false_reuse",
        "false_invalidation",
    ]
)


def read(path):
    with Path(path).open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("Statistical records require unique case IDs")
    return rows


def mean(values):
    valid = [value for value in values if value is not None and np.isfinite(value)]
    return float(np.mean(valid)) if valid else None


def cluster_value(group, key):
    counts = [
        row["metric_counts"][key]
        for row in group
        if key in row.get("metric_counts", {})
    ]
    if counts:
        denominator = sum(pair[1] for pair in counts)
        return sum(pair[0] for pair in counts) / denominator if denominator else None
    return mean([row["metrics"].get(key) for row in group])


def analyze(rows, reference=None, resamples=10000, seed=17, primary=()):
    """Bootstrap whole eligible families; null is undefined, never a zero event."""
    if resamples < 1:
        raise ValueError("resamples must be positive")
    if reference is not None and set(reference) != {row["id"] for row in rows}:
        raise ValueError("Paired comparison requires identical case IDs")
    clusters = {}
    for row in rows:
        clusters.setdefault(row.get("cluster", row["id"]), []).append(row)
    groups = list(clusters.values())
    rng = np.random.default_rng(seed)
    report = {}
    for key in sorted({key for row in rows for key in row["metrics"]}):
        values = []
        for group in groups:
            current = cluster_value(group, key)
            if reference is None:
                value = current
            else:
                baseline = cluster_value([reference[row["id"]] for row in group], key)
                value = (
                    current - baseline
                    if current is not None and baseline is not None
                    else None
                )
            if value is not None:
                values.append(value)
        if not values:
            continue
        values = np.asarray(values, dtype=float)
        interval = None
        if len(values) > 1:
            boot = [
                values[rng.integers(len(values), size=len(values))].mean()
                for _ in range(resamples)
            ]
            interval = np.quantile(boot, [0.025, 0.975]).tolist()
        item = dict(
            mean=float(values.mean()), clusters=len(values), bootstrap95=interval
        )
        if reference is None:
            counts = [
                row["metric_counts"][key]
                for row in rows
                if key in row.get("metric_counts", {})
            ]
            if counts:
                numerator, denominator = (
                    sum(pair[index] for pair in counts) for index in (0, 1)
                )
                item["micro"] = dict(
                    numerator=numerator,
                    denominator=denominator,
                    rate=numerator / denominator if denominator else None,
                )
            observations = [
                row["metrics"].get(key)
                for row in rows
                if row["metrics"].get(key) is not None
            ]
            if (
                key in EVENT_METRICS
                and observations
                and set(observations) <= {0, 1, False, True}
                and not sum(observations)
            ):
                item["zero_event_independent_cluster_upper95"] = float(
                    1 - 0.05 ** (1 / len(values))
                )
        else:
            pairs = [
                (row["metrics"].get(key), reference[row["id"]]["metrics"].get(key))
                for row in rows
            ]
            pairs = [(a, b) for a, b in pairs if a is not None and b is not None]
            if (
                key in EVENT_METRICS
                and all(
                    row.get("metric_counts", {}).get(key, [0, 1])[1] == 1
                    and reference[row["id"]]
                    .get("metric_counts", {})
                    .get(key, [0, 1])[1]
                    == 1
                    for row in rows
                    if row["metrics"].get(key) is not None
                    and reference[row["id"]]["metrics"].get(key) is not None
                )
                and all(len(group) == 1 for group in groups)
                and pairs
                and {v for pair in pairs for v in pair} <= {0, 1, False, True}
            ):
                b = sum(a == 1 and other == 0 for a, other in pairs)
                c = sum(a == 0 and other == 1 for a, other in pairs)
                item["mcnemar_exact_p"] = (
                    float(binomtest(b, b + c, 0.5).pvalue) if b + c else 1.0
                )
            elif len(values) > 1:
                item["wilcoxon_p"] = (
                    float(wilcoxon(values).pvalue) if np.any(values) else 1.0
                )
        report[key] = item
    pvalues = []
    for key in primary:
        for test in ("mcnemar_exact_p", "wilcoxon_p"):
            if test in report.get(key, {}):
                pvalues.append((report[key][test], key))
                break
    prior = 0.0
    for index, (pvalue, key) in enumerate(sorted(pvalues)):
        prior = max(prior, min(1.0, (len(pvalues) - index) * pvalue))
        report[key]["holm_adjusted_p"] = prior
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True)
    parser.add_argument("--reference")
    parser.add_argument("--resamples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--primary", nargs="*", default=[])
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = read(args.records)
    reference = (
        {row["id"]: row for row in read(args.reference)} if args.reference else None
    )
    output = Path(args.output)
    if output.exists():
        raise FileExistsError(str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    report = analyze(rows, reference, args.resamples, args.seed, args.primary)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")


if __name__ == "__main__":
    main()

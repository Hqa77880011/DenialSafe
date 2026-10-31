import argparse
import csv
import json
import random
import math
import platform
import sys
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import psutil

from . import core


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("Each JSONL line must be an object")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Case IDs must be unique within an input")
    return rows


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(str(path))
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, allow_nan=False) + "\n")


def summarize(rows):
    report = {}
    keys = sorted(
        {
            key
            for row in rows
            for key, value in row["metrics"].items()
            if value is None or isinstance(value, (int, float, bool))
        }
    )
    for key in keys:
        values = np.array(
            [
                float(row["metrics"][key])
                for row in rows
                if row["metrics"].get(key) is not None
            ],
            dtype=float,
        )
        values = values[np.isfinite(values)]
        if not len(values):
            report[key] = {"count": 0, "mean": None}
            continue
        report[key] = {
            "count": len(values),
            "mean": float(values.mean()),
            "std": float(values.std(ddof=1)) if len(values) > 1 else None,
            "p50": float(np.quantile(values, 0.5)),
            "p95": float(np.quantile(values, 0.95)),
            "p99": float(np.quantile(values, 0.99)),
        }
    for key in keys:
        counts = [
            row["metric_counts"][key]
            for row in rows
            if key in row.get("metric_counts", {})
        ]
        if counts:
            numerator = sum(value[0] for value in counts)
            denominator = sum(value[1] for value in counts)
            report[key]["micro"] = dict(
                numerator=numerator,
                denominator=denominator,
                rate=numerator / denominator if denominator else None,
            )
    elapsed = sum(row["metrics"].get("latency_ms", 0) for row in rows) / 1000
    legal = sum(row["metrics"].get("legal_effects", 0) for row in rows)
    report["legal_throughput_per_second"] = (
        legal / elapsed
        if elapsed and any("legal_effects" in row["metrics"] for row in rows)
        else None
    )
    return report


def execute(cases, method, output):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Choose an empty output directory: " + str(output))
    rows = []
    process = psutil.Process()
    for case in cases:
        start_cpu = time.process_time()
        start = time.perf_counter()
        result = core.run_case(case, method)
        elapsed = time.perf_counter() - start
        cpu = time.process_time() - start_cpu
        metrics = core.score(case, result)
        metrics.update(
            latency_ms=elapsed * 1000,
            cpu_seconds=cpu,
            rss_mib=process.memory_info().rss / 2**20,
            output_bytes=len(json.dumps(result).encode()),
        )
        rows.append(
            {
                "id": case["id"],
                "family": case.get("family", case["id"]),
                "method": method,
                "cluster": case.get("cluster", case.get("family", case["id"])),
                "generation_seed": case.get("generation_seed"),
                "metric_counts": core.metric_counts(case, result)
                if hasattr(core, "metric_counts")
                else {},
                "result": result,
                "metrics": metrics,
            }
        )
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "records.jsonl", rows)
    (output / "metrics.json").write_text(
        json.dumps(summarize(rows), indent=2, allow_nan=False), encoding="utf-8"
    )
    (output / "config.json").write_text(
        json.dumps(
            dict(
                method=method,
                python=sys.version.split()[0],
                platform=platform.system(),
                arguments=sys.argv[1:],
                generation_seeds=sorted(
                    {
                        row["generation_seed"]
                        for row in rows
                        if row["generation_seed"] is not None
                    }
                ),
                timing="whole finite-model case; inspect stage metrics for online/offline separation",
            ),
            indent=2,
        ),
        encoding="utf-8",
    )
    return rows


def evaluate(records, output):
    """Aggregate numerical measurements from retained or externally recorded JSONL."""
    rows = read_jsonl(records)
    for row in rows:
        for value in row["metrics"].values():
            if value is not None and (
                not isinstance(value, (int, float)) or not math.isfinite(value)
            ):
                raise ValueError("Metrics must be finite numbers or null")
        for numerator, denominator in row.get("metric_counts", {}).values():
            if not (
                math.isfinite(numerator)
                and math.isfinite(denominator)
                and 0 <= numerator <= denominator
            ):
                raise ValueError("Rate counts require 0 <= numerator <= denominator")
    output = Path(output)
    if output.exists():
        raise FileExistsError(str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(summarize(rows), indent=2, allow_nan=False), encoding="utf-8"
    )


def plot(paths, output, metrics=None):
    records = [
        row for path in paths for row in read_jsonl(Path(path) / "records.jsonl")
    ]
    methods = sorted({row["method"] for row in records})
    keys = sorted({key for row in records for key in row["metrics"]})
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["method", "metric", "n", "mean", "std", "p50", "p95", "p99"])
        for method in methods:
            summary = summarize([r for r in records if r["method"] == method])
            for key, value in summary.items():
                if isinstance(value, dict):
                    writer.writerow(
                        [
                            method,
                            key,
                            value["count"],
                            value["mean"],
                            value.get("std"),
                            value.get("p50"),
                            value.get("p95"),
                            value.get("p99"),
                        ]
                    )
    for key in keys:
        if metrics is not None and key not in metrics:
            continue
        groups = [
            [
                r["metrics"][key]
                for r in records
                if r["method"] == method and r["metrics"].get(key) is not None
            ]
            for method in methods
        ]
        if not any(groups):
            continue
        fig, ax = plt.subplots(figsize=(max(6, len(methods)), 4))
        means = [np.mean(group) if group else np.nan for group in groups]
        ax.bar(methods, means, color="#527c91")
        ax.set_ylabel(key)
        ax.tick_params(axis="x", rotation=35)
        fig.tight_layout()
        fig.savefig(output / (key + ".png"), dpi=180)
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--count", type=int, default=200)
    prepare.add_argument("--seed", type=int, default=17)
    for name in ("run", "suite"):
        item = sub.add_parser(name)
        item.add_argument("--data", required=True)
        item.add_argument("--output", required=True)
        item.add_argument(
            "--methods",
            nargs="+",
            choices=core.METHODS,
            default=[core.METHODS[0]] if name == "run" else core.METHODS,
        )
    item = sub.add_parser("evaluate")
    item.add_argument("--records", required=True)
    item.add_argument("--output", required=True)
    item = sub.add_parser("plot")
    item.add_argument("--inputs", nargs="+", required=True)
    item.add_argument(
        "--metrics",
        nargs="+",
        help="Render selected metric PNGs; CSV retains all metrics",
    )
    item.add_argument("--output", required=True)
    for name in ("attack", "benchmark", "cache", "native-check", "execute", "scale"):
        item = sub.add_parser(name)
        item.add_argument("--case", required=True)
        item.add_argument("--output", required=True)
        if name in ("attack", "benchmark"):
            item.add_argument(
                "--methods", nargs="+", choices=core.METHODS, default=["denialsafe"]
            )
        if name == "attack":
            item.add_argument(
                "--visibility", choices=["black", "gray", "white"], default="black"
            )
            item.add_argument("--budget", type=int, default=100)
            item.add_argument("--seed", type=int, default=17)
            item.add_argument("--trajectory", action="store_true")
        elif name == "benchmark":
            item.add_argument("--calls", type=int, default=100)
            item.add_argument("--restarts", type=int, default=5)
            item.add_argument("--warmup", type=float, default=30)
            item.add_argument("--seconds", type=float, default=120)
            item.add_argument("--cache", choices=["cold", "warm"], default="cold")
            item.add_argument("--controlled-channel", action="store_true")
        elif name == "cache":
            item.add_argument("--repeats", type=int, default=5)
            item.add_argument("--controlled-channel", action="store_true")
        elif name == "native-check":
            item.add_argument("--backend", choices=["cedar", "balana"], required=True)
            item.add_argument("--executable", required=True)
            item.add_argument("--classpath")
        elif name == "execute":
            item.add_argument(
                "--config",
                required=True,
                help="Trusted root/database/key_file/objects and optional native_pdp configuration",
            )
            item.add_argument(
                "--operation",
                required=True,
                help="Trusted install/grant_mfa or client execute/process JSON request",
            )
        elif name == "scale":
            item.add_argument("--dimensions", nargs="+", type=int, default=[2, 4, 8])
            item.add_argument("--values", nargs="+", type=int, default=[2, 4, 8])
            item.add_argument(
                "--actions", nargs="+", type=int, default=[10, 30, 100, 300]
            )
            item.add_argument("--rules", nargs="+", type=int, default=[10, 100, 1000])
            item.add_argument("--budgets", nargs="+", type=float, default=[0.1, 1, 10])
            item.add_argument("--depths", nargs="+", type=int, default=[1, 2, 3])
    args = parser.parse_args()
    if args.command == "prepare":
        if args.count < 1:
            parser.error("--count must be positive")
        rows = list(core.generate(random.Random(args.seed), args.count))
        for row in rows:
            row["id"] = str(args.seed) + ":" + row["id"]
            row["generation_seed"] = args.seed
            row.setdefault("cluster", row.get("family", row["id"]))
        write_jsonl(args.output, rows)
    elif args.command in ("run", "suite"):
        cases = read_jsonl(args.data)
        for method in args.methods:
            execute(cases, method, Path(args.output) / method)
    elif args.command == "evaluate":
        evaluate(args.records, args.output)
    elif args.command == "plot":
        plot(args.inputs, args.output, args.metrics)
    else:
        from . import evaluation

        output = Path(args.output)
        if output.exists():
            raise FileExistsError(str(output))
        case = json.loads(Path(args.case).read_text(encoding="utf-8"))
        if args.command == "attack":
            operation = (
                evaluation.adaptive_trajectories
                if args.trajectory
                else evaluation.matched_attack
            )
            value = operation(
                case["public"],
                core.actual_policy(case),
                case["probe_domains"],
                args.methods,
                args.budget,
                args.visibility,
                args.seed,
                actual_request_attributes=case.get("actual_request_attributes", {}),
            )
        elif args.command == "benchmark":
            if min(args.calls, args.restarts) < 1 or min(args.warmup, args.seconds) < 0:
                raise ValueError("Invalid timing budget")
            value = [
                row
                for method in args.methods
                for row in evaluation.benchmark(
                    case,
                    method,
                    args.calls,
                    args.restarts,
                    args.warmup,
                    args.seconds,
                    args.cache,
                    args.controlled_channel,
                )
            ]
        elif args.command == "cache":
            value = evaluation.cache_campaign(
                case["public"], case["request"], args.repeats, args.controlled_channel
            )
        elif args.command == "scale":
            write_jsonl(
                output,
                evaluation.scale_cases(
                    case,
                    args.dimensions,
                    args.values,
                    args.actions,
                    args.rules,
                    args.budgets,
                    args.depths,
                ),
            )
            return
        elif args.command == "native-check":
            from . import native

            if args.backend == "cedar":
                value = native.cedar(
                    core.actual_policy(case),
                    {**case["request"], **case.get("actual_request_attributes", {})},
                    args.executable,
                    str(output) + ".artifacts",
                )
            else:
                if not args.classpath:
                    raise ValueError("Balana needs --classpath")
                value = native.balana(
                    core.actual_policy(case),
                    {**case["request"], **case.get("actual_request_attributes", {})},
                    args.executable,
                    args.classpath,
                    str(output) + ".artifacts",
                )
        else:
            from .runtime import Executor
            from . import native

            config = json.loads(Path(args.config).read_text(encoding="utf-8"))
            key = Path(config.pop("key_file")).read_bytes()
            backend = config.pop("native_pdp", None)
            callback = None
            if backend:
                callback = (
                    (
                        lambda policy, request: native.cedar(
                            policy, request, backend["executable"], backend["output"]
                        )["decision"]
                    )
                    if backend["backend"] == "cedar"
                    else (
                        lambda policy, request: native.balana(
                            policy,
                            request,
                            backend["executable"],
                            backend["classpath"],
                            backend["output"],
                        )["decision"]
                    )
                )
            executor = Executor(key=key, pdp=callback, **config)
            request = json.loads(Path(args.operation).read_text(encoding="utf-8"))
            operation = request.pop("operation")
            if operation not in (
                "install",
                "set_identity",
                "grant_mfa",
                "execute",
                "process",
            ):
                raise ValueError("Unknown operation")
            value = getattr(executor, operation)(**request)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(value, indent=2, allow_nan=False), encoding="utf-8"
        )


if __name__ == "__main__":
    main()

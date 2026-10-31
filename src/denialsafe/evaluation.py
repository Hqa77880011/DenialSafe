"""Matched-history/adaptive attacks, cold-cache costs and executable scale grids."""

import copy
import itertools
import math
import random
import time
from . import core, oracle, policy
from .channel import Service, render, update_history

SECRET_METHODS = {
    "true_policy",
    "redacted_repair",
    "causal_adaptation",
    "secret_tie_break",
}


def explanation(public, request, method, actual, attributes=None):
    result = core.synthesize(
        public,
        request,
        method,
        actual if method in SECRET_METHODS else None,
        attributes if method in SECRET_METHODS else None,
    )
    return render(public, result).decode()


def probes(domains):
    names = sorted(domains)
    return [
        dict(zip(names, values))
        for values in itertools.product(*(domains[name] for name in names))
    ]


def select_probe(public, candidates, domain, visibility, rng, method):
    if visibility == "black":
        return copy.deepcopy(rng.choice(domain))

    def score(request):
        groups = {}
        for assignment, actual in candidates:
            decision = oracle.decision(
                actual, {**request, **policy.hidden_request(public, assignment)}
            )
            observation = (
                decision,
                explanation(
                    public,
                    request,
                    method,
                    actual,
                    policy.hidden_request(public, assignment),
                )
                if visibility == "white" and decision != "Permit"
                else None,
            )
            groups[observation] = groups.get(observation, 0) + 1
        entropy = -sum(
            count / len(candidates) * math.log2(count / len(candidates))
            for count in groups.values()
        )
        if visibility == "gray":
            # Public repair cost/grammar is available, never hidden policy features.
            result = core.synthesize(public, request)
            cost = sum(
                public["actions"][name].get("cost", 1)
                for name in result["sequence"]
                if name in public["actions"]
            )
            return entropy, -cost, policy.encode(request)
        return entropy, policy.encode(request)

    return copy.deepcopy(max(domain, key=score))


def matched_attack(
    public,
    actual,
    probe_domains,
    methods=None,
    budget=10,
    visibility="black",
    seed=17,
    actual_request_attributes=None,
):
    """Every method receives the same actual published decision trajectory."""
    if visibility not in ("black", "gray", "white"):
        raise ValueError(visibility)
    methods = methods or core.METHODS
    rng = random.Random(seed)
    view = copy.deepcopy(public)
    candidates = policy.possible(view)
    domain = probes(probe_domains)
    rows = []
    if not candidates:
        raise ValueError("No compatible public policy")
    survivors = {method: copy.deepcopy(candidates) for method in methods}
    for attempt in range(budget):
        # The shared probe does not depend on a particular explanation method.
        request = select_probe(view, candidates, domain, visibility, rng, "denialsafe")
        decision = oracle.decision(
            actual, {**request, **(actual_request_attributes or {})}
        )
        view = update_history(view, request, decision)
        candidates = policy.possible(view)
        if not candidates:
            raise ValueError("Actual policy contradicts published family/history")
        for method in methods:
            baseline = [
                item
                for item in candidates
                if any(
                    all(
                        key in item[0] and policy.equal(item[0][key], value)
                        for key, value in old[0].items()
                    )
                    for old in survivors[method]
                )
            ]
            start = time.perf_counter()
            output = (
                explanation(view, request, method, actual, actual_request_attributes)
                if decision != "Permit"
                else policy.encode({"type": "DECISION_ONLY", "decision": decision})
            )
            duration = time.perf_counter() - start
            posterior = [
                item
                for item in baseline
                if (
                    explanation(
                        view,
                        request,
                        method,
                        item[1],
                        policy.hidden_request(view, item[0]),
                    )
                    if decision != "Permit"
                    else policy.encode({"type": "DECISION_ONLY", "decision": decision})
                )
                == output
            ]
            if not posterior:
                raise RuntimeError("Actual explanation eliminated every candidate")
            survivors[method] = posterior
            rows.append(
                dict(
                    id=f"{attempt}:{method}",
                    attempt=attempt,
                    method=method,
                    request=request,
                    decision=decision,
                    public_history=copy.deepcopy(view["history"]),
                    output=output,
                    metrics=dict(
                        decision_candidates=len(candidates),
                        paired_prior_candidates=len(baseline),
                        explanation_candidates=len(posterior),
                        incremental_recovery_gain=1 / len(posterior)
                        - 1 / len(candidates),
                        response_bytes=len(output.encode()),
                        observed_seconds=duration,
                    ),
                    protocol="matched_decision_history",
                )
            )
    return rows


def adaptive_trajectories(
    public,
    actual,
    probe_domains,
    methods=None,
    budget=10,
    visibility="white",
    seed=17,
    actual_request_attributes=None,
):
    """Different per-method histories are explicitly separate from incremental leakage."""
    rows = []
    domain = probes(probe_domains)
    for method in methods or core.METHODS:
        view = copy.deepcopy(public)
        candidates = policy.possible(view)
        rng = random.Random(seed)
        for attempt in range(budget):
            request = select_probe(view, candidates, domain, visibility, rng, method)
            decision = oracle.decision(
                actual, {**request, **(actual_request_attributes or {})}
            )
            view = update_history(view, request, decision)
            output = (
                explanation(view, request, method, actual, actual_request_attributes)
                if decision != "Permit"
                else policy.encode({"type": "DECISION_ONLY", "decision": decision})
            )
            prior = candidates
            candidates = [
                item
                for item in policy.possible(view)
                if any(
                    all(
                        key in item[0] and policy.equal(item[0][key], value)
                        for key, value in old[0].items()
                    )
                    for old in prior
                )
                and (
                    decision == "Permit"
                    or explanation(
                        view,
                        request,
                        method,
                        item[1],
                        policy.hidden_request(view, item[0]),
                    )
                    == output
                )
            ]
            if not candidates:
                raise ValueError("Actual policy not in public family")
            rows.append(
                dict(
                    id=f"{method}:{attempt}",
                    method=method,
                    attempt=attempt,
                    request=request,
                    decision=decision,
                    output=output,
                    candidates=len(candidates),
                    protocol="per_method_end_to_end_trajectory",
                )
            )
    return rows


def cache_campaign(public, request, repeats=5, controlled_channel=False):
    rows = []
    for regime in ("cold", "warm", "history_change", "epoch_change"):
        service = Service()
        for attempt in range(repeats):
            view = copy.deepcopy(public)
            if regime == "cold":
                service = Service()
            elif regime == "history_change":
                view["history"] = view.get("history", []) * (attempt + 1)
            elif regime == "epoch_change":
                view["epoch"] = str(public.get("epoch")) + ":" + str(attempt)
            cpu = time.process_time()
            wall = time.perf_counter()
            result = service.explain(
                view, request, controlled_channel=controlled_channel
            )
            rows.append(
                dict(
                    id=f"{regime}:{attempt}",
                    method="denialsafe",
                    cluster=public.get("family", "public-family"),
                    regime=regime,
                    output=result["output"],
                    metrics=dict(
                        cpu_seconds=time.process_time() - cpu,
                        wall_seconds=time.perf_counter() - wall,
                        cache_hit=int(result["cache_hit"]),
                        **result["channel"],
                    ),
                )
            )
    return rows


def scale_cases(
    base,
    dimensions=(2, 4, 8),
    values=(2, 4, 8),
    action_counts=(10, 30, 100, 300),
    rule_counts=(10, 100, 1000),
    budgets=(0.1, 1, 10),
    depths=(1, 2, 3),
):
    """Build real coupled-hole/rule/action inputs; the CLI lets callers select small grids."""
    for dim, width, actions, rules, budget, depth in itertools.product(
        dimensions, values, action_counts, rule_counts, budgets, depths
    ):
        case = copy.deepcopy(base)
        public = case["public"]
        public.pop("policies", None)
        public["holes"] = {"h" + str(i): list(range(width)) for i in range(dim)}
        # Coupled public thresholds and deny predicates genuinely enter the verifier.
        public["skeleton"] = {
            "required": ["mfa"],
            "equals": {"mfa": True},
            "minimum": {
                "v" + str(i): {"hole": "h" + str(i % dim)} for i in range(rules)
            },
        }
        for i in range(rules):
            case["request"]["v" + str(i)] = width
        public["actions"] = {
            "mfa" + str(i): dict(
                set={"mfa": True, "public_workflow": i},
                cost=1 + i / actions,
                user_executable=True,
            )
            for i in range(actions)
        }
        public.update(time_budget_seconds=budget, max_depth=depth)
        case["secret_assignment"] = {"h" + str(i): 0 for i in range(dim)}
        case.pop("secret_index", None)
        public["history"] = [
            dict(
                request=copy.deepcopy(case["request"]),
                decision=policy.decision(
                    policy.instantiate(public["skeleton"], case["secret_assignment"]),
                    case["request"],
                ),
            )
        ]
        public["templates"] = [dict(id="public-mfa", goals={"mfa": True})]
        case["id"] = f"{dim}:{width}:{actions}:{rules}:{budget}:{depth}"
        case["family"] = "scale:" + str(dim) + ":" + str(rules)
        yield case


def benchmark(
    case,
    method="denialsafe",
    calls=100,
    restarts=5,
    warmup_seconds=30,
    measurement_seconds=120,
    cache="cold",
    controlled_channel=False,
):
    """Run genuinely fresh worker processes; short budgets are explicit smoke runs."""
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    rows = []
    for restart in range(restarts):
        parent, child = context.Pipe(False)
        process = context.Process(
            target=_benchmark_worker,
            args=(
                child,
                case,
                method,
                calls,
                warmup_seconds,
                measurement_seconds,
                cache,
                controlled_channel,
            ),
        )
        process.start()
        child.close()
        try:
            row = parent.recv()
        except EOFError as error:
            process.join()
            raise RuntimeError("Timing worker exited without a record") from error
        process.join()
        if process.exitcode or "error" in row:
            raise RuntimeError(row.get("error", "Timing worker failed"))
        row["id"] = str(restart)
        row["restart"] = restart
        rows.append(row)
    return rows


def _benchmark_worker(
    connection, case, method, calls, warmup, seconds, cache, controlled_channel
):
    import psutil

    try:
        actual = core.actual_policy(case)
        public = case["public"]
        request = case["request"]
        service = Service()

        def invoke():
            nonlocal service
            if cache == "cold":
                service = Service()
            if method in SECRET_METHODS:
                stamp = time.perf_counter()
                result = core.synthesize(
                    public,
                    request,
                    method,
                    actual,
                    case.get("actual_request_attributes", {}),
                )
                if controlled_channel:
                    from .channel import controlled

                    encoded, measure = controlled(public, result, stamp)
                else:
                    encoded = render(public, result)
                    measure = {}
                return result, encoded, measure
            response = service.explain(public, request, method, controlled_channel)
            return response["result"], response["output"].encode(), response["channel"]

        finish = time.perf_counter() + warmup
        while time.perf_counter() < finish:
            invoke()
        start = time.perf_counter()
        cpu = time.process_time()
        finish = start + seconds
        latencies = []
        stages = {}
        padding = 0
        late = 0
        bytes_sent = 0
        access = 0
        while len(latencies) < calls or time.perf_counter() < finish:
            stamp = time.perf_counter()
            result, encoded, measure = invoke()
            latencies.append((time.perf_counter() - stamp) * 1000)
            for key, value in result.get("stage_ms", {}).items():
                stages[key] = stages.get(key, 0) + value
            padding += measure.get("padding_seconds", 0)
            late += bool(measure.get("late", False))
            bytes_sent += len(encoded)
            access += result["type"] == "ACCESS_RECOURSE"
        duration = time.perf_counter() - start
        latencies.sort()

        def q(value):
            index = (len(latencies) - 1) * value
            low = int(index)
            high = min(low + 1, len(latencies) - 1)
            return latencies[low] + (latencies[high] - latencies[low]) * (index - low)

        connection.send(
            dict(
                method=method,
                cluster=case.get("family", case["id"]),
                metrics=dict(
                    calls=len(latencies),
                    access_outputs=access,
                    wall_seconds=duration,
                    cpu_seconds=time.process_time() - cpu,
                    p50_ms=q(0.5),
                    p95_ms=q(0.95),
                    p99_ms=q(0.99),
                    throughput=len(latencies) / duration,
                    padding_seconds=padding,
                    late_releases=late,
                    response_bytes=bytes_sent,
                    rss_mib=psutil.Process().memory_info().rss / 2**20,
                    **stages,
                ),
                protocol=dict(
                    warmup_seconds=warmup,
                    measurement_seconds=seconds,
                    cache=cache,
                    controlled_channel=controlled_channel,
                ),
            )
        )
    except (ValueError, RuntimeError, KeyError) as error:
        connection.send(dict(error=str(error)))
    finally:
        connection.close()

import copy
import heapq
import json
import math
import time

from . import oracle


METHODS = [
    "denialsafe",
    "exact_robust",
    "decision_only",
    "true_policy",
    "public_templates",
    "sampled_policies",
    "no_feasibility",
]


def evaluate(policy, request):
    for key in (
        set(policy.get("required", []))
        | set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
    ):
        if key not in request:
            return "Indeterminate"
    same = lambda a, b: type(a) is type(b) and a == b
    if any(
        not same(request[key], value) for key, value in policy.get("equals", {}).items()
    ):
        return "Deny"
    if any(
        not any(same(request[key], value) for value in values)
        for key, values in policy.get("members", {}).items()
    ):
        return "Deny"
    for key, value in policy.get("minimum", {}).items():
        if type(request[key]) not in (int, float) or type(value) not in (int, float):
            return "Indeterminate"
        if request[key] < value:
            return "Deny"
    for clause in policy.get("denies", []):
        if all(
            key in request and same(request[key], value)
            for key, value in clause.items()
        ):
            return "Deny"
    return "Permit"


def possibility_set(public):
    return [
        policy
        for policy in public["policies"]
        if all(
            evaluate(policy, item["request"]) == item["decision"]
            for item in public.get("history", [])
        )
    ]


def apply_action(request, action, registry, check=True):
    current = copy.deepcopy(request)
    for step in action:
        primitive = registry[step]
        if check and (
            not primitive.get("user_executable", False)
            or any(
                k not in current or type(current[k]) is not type(v) or current[k] != v
                for k, v in primitive.get("preconditions", {}).items()
            )
        ):
            return None
        if set(primitive.get("set", {})) & {"principal", "tenant", "provenance"}:
            return None
        current.update(primitive.get("set", {}))
    return current


def actions(public):
    """Enumerate the bounded sequence grammar in public cost/ID order, with repetition."""
    registry = public["actions"]
    names = sorted(registry)
    maximum = public.get("max_depth", 2)
    if type(maximum) is not int or maximum < 0:
        raise ValueError("max_depth must be a nonnegative integer")
    if any(
        not math.isfinite(registry[n].get("cost", 1)) or registry[n].get("cost", 1) < 0
        for n in names
    ):
        raise ValueError("Action costs must be finite and nonnegative")
    queue = [(0, ())]
    while queue:
        cost, sequence = heapq.heappop(queue)
        yield sequence
        if len(sequence) < maximum:
            for name in names:
                heapq.heappush(
                    queue, (cost + registry[name].get("cost", 1), (*sequence, name))
                )


def synthesize(public, request, method="denialsafe", secret=None):
    """Finite CEGIS. Only the explicitly secret-aware baseline receives a secret."""
    possible = possibility_set(public)
    if not possible:
        return {"type": "PUBLIC_CONFLICT", "sequence": [], "checks": 0}
    if method == "decision_only":
        return {"type": "ABSTAIN", "sequence": [], "checks": 0}
    checked = 0
    active = possible[:1]
    start = time.perf_counter()
    for index, sequence in enumerate(actions(public)):
        if index >= public.get("candidate_budget", 100000) or (
            public.get("time_budget_seconds") is not None
            and time.perf_counter() - start >= public["time_budget_seconds"]
        ):
            return {
                "type": "ABSTAIN",
                "sequence": [],
                "checks": checked,
                "reason": "budget_exhausted",
            }
        transformed = apply_action(
            request, sequence, public["actions"], check=method != "no_feasibility"
        )
        if transformed is None:
            continue
        if method == "public_templates" and tuple(sequence) != tuple(
            public.get("template", [])
        ):
            continue
        selected = (
            [secret]
            if method == "true_policy"
            else (
                possible if method in ("exact_robust", "public_templates") else active
            )
        )
        checked += len(selected)
        if any(evaluate(policy, transformed) != "Permit" for policy in selected):
            continue
        if method == "sampled_policies":
            robust = True
        else:
            counter = next(
                (
                    policy
                    for policy in possible
                    if evaluate(policy, transformed) != "Permit"
                ),
                None,
            )
            checked += len(possible)
            robust = counter is None
            if counter is not None and counter not in active:
                active.append(counter)
        if method == "true_policy":
            robust = True
        if robust:
            if method not in (
                "true_policy",
                "sampled_policies",
                "no_feasibility",
            ) and not oracle.check(public, request, sequence):
                return {
                    "type": "ABSTAIN",
                    "sequence": [],
                    "checks": checked,
                    "reason": "checker_disagreement",
                }
            return {
                "type": "ACCESS_RECOURSE",
                "sequence": list(sequence),
                "checks": checked,
            }
    for name, primitive in sorted(public.get("process_actions", {}).items()):
        if apply_action(request, [name], {name: primitive}) is not None:
            return {"type": "PROCESS_RECOURSE", "sequence": [name], "checks": checked}
    return {"type": "ABSTAIN", "sequence": [], "checks": checked}


def generate(rng, count):
    for index in range(count):
        thresholds = sorted(rng.sample(range(1, 9), 3))
        policies = [
            {
                "required": ["level", "mfa", "scope"],
                "equals": {"mfa": True},
                "minimum": {"level": threshold},
                "members": {
                    "scope": ["public"] if threshold > 3 else ["public", "private"]
                },
            }
            for threshold in thresholds
        ]
        request = {
            "principal": "u",
            "tenant": "t",
            "level": rng.randrange(10),
            "mfa": False,
            "scope": "private",
        }
        registry = {
            "complete_mfa": {"set": {"mfa": True}, "cost": 1, "user_executable": True},
            "narrow_public": {
                "set": {"scope": "public"},
                "cost": 3,
                "user_executable": True,
            },
            "set_level": {"set": {"level": 10}, "cost": 0.1, "user_executable": False},
        }
        public = {
            "policies": policies,
            "actions": registry,
            "max_depth": 2,
            "history": [{"request": request, "decision": "Deny"}],
            "template": ["complete_mfa", "narrow_public"],
        }
        yield {
            "id": str(index),
            "family": f"level-{request['level']}",
            "public": public,
            "request": request,
            "secret_index": rng.randrange(3),
        }


def run_case(case, method):
    secret = case["public"]["policies"][case["secret_index"]]
    start = time.perf_counter()
    result = synthesize(
        case["public"],
        case["request"],
        method,
        secret if method == "true_policy" else None,
    )
    result["synthesis_ms"] = (time.perf_counter() - start) * 1000
    result["public_output"] = json.dumps(
        {k: result[k] for k in ["type", "sequence"]}, sort_keys=True
    )
    outputs = []
    for possible in possibility_set(case["public"]):
        alternative = synthesize(
            case["public"],
            case["request"],
            method,
            possible if method == "true_policy" else None,
        )
        outputs.append(
            json.dumps(
                {k: alternative[k] for k in ["type", "sequence"]}, sort_keys=True
            )
        )
    result["matched_view_secret_gain"] = (
        (len(set(outputs)) - 1) / len(outputs) if outputs else 0.0
    )
    pairs = [(a, b) for i, a in enumerate(outputs) for b in outputs[i + 1 :]]
    result["pairwise_distinguishing_accuracy"] = (
        sum(0.5 if a == b else 1.0 for a, b in pairs) / len(pairs) if pairs else None
    )
    result["same_view_content_mismatch"] = int(len(set(outputs)) > 1)
    return result


def score(case, result):
    emitted = result["type"] == "ACCESS_RECOURSE"
    changed = (
        oracle.replay(case["request"], result["sequence"], case["public"]["actions"])
        if emitted
        else None
    )
    actual = case["public"]["policies"][case["secret_index"]]
    valid = (
        emitted and changed is not None and oracle.decision(actual, changed) == "Permit"
    )
    robust = changed is not None and all(
        oracle.decision(p, changed) == "Permit" for p in possibility_set(case["public"])
    )
    return {
        "coverage": int(valid),
        "robust_coverage": int(emitted and robust),
        "actual_policy_validity": int(valid) if emitted else None,
        "robust_validity": int(robust) if emitted else None,
        "process_guidance": int(result["type"] == "PROCESS_RECOURSE")
        if case.get("group") == "process_only"
        else None,
        "public_conflict": int(result["type"] == "PUBLIC_CONFLICT"),
        "pairwise_distinguishing_accuracy": result["pairwise_distinguishing_accuracy"],
        "same_view_content_mismatch": result["same_view_content_mismatch"],
        "matched_view_secret_gain": result["matched_view_secret_gain"],
        "failed_repair": int(not valid) if emitted else None,
        "illegal_repair": int(changed is None) if emitted else None,
        "nonrobust_repair": int(not robust) if emitted else None,
        "abstention": int(result["type"] == "ABSTAIN"),
        "policy_checks": result["checks"],
        "synthesis_ms": result["synthesis_ms"],
        "repair_cost": sum(
            case["public"]["actions"][x].get("cost", 1) for x in result["sequence"]
        )
        if valid
        else None,
        "legal_effects": int(valid),
    }

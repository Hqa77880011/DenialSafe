import copy
import itertools
import json


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
    for key in policy.get("required", []):
        if key not in request:
            return "Indeterminate"
    if any(request.get(key) != value for key, value in policy.get("equals", {}).items()):
        return "Deny"
    if any(request.get(key) not in values for key, values in policy.get("members", {}).items()):
        return "Deny"
    if any(
        request.get(key, float("-inf")) < value for key, value in policy.get("minimum", {}).items()
    ):
        return "Deny"
    for clause in policy.get("denies", []):
        if all(request.get(key) == value for key, value in clause.items()):
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
            or any(current.get(k) != v for k, v in primitive.get("preconditions", {}).items())
        ):
            return None
        if set(primitive.get("set", {})) & {"principal", "tenant", "provenance"}:
            return None
        current.update(primitive.get("set", {}))
    return current


def actions(public):
    registry = public["actions"]
    names = sorted(registry)
    maximum = public.get("max_depth", 2)
    candidates = [()]
    for depth in range(1, maximum + 1):
        candidates.extend(itertools.permutations(names, depth))
    return sorted(
        candidates, key=lambda seq: (sum(registry[name].get("cost", 1) for name in seq), seq)
    )


def synthesize(public, request, method="denialsafe", secret=None):
    possible = possibility_set(public)
    if not possible:
        return {"type": "PUBLIC_CONFLICT", "sequence": [], "checks": 0}
    if method == "decision_only":
        return {"type": "ABSTAIN", "sequence": [], "checks": 0}
    checked = 0
    active = possible[:1]
    for sequence in actions(public):
        transformed = apply_action(
            request, sequence, public["actions"], check=method != "no_feasibility"
        )
        if transformed is None:
            continue
        if method == "public_templates" and tuple(sequence) != tuple(public.get("template", [])):
            continue
        selected = (
            [secret]
            if method == "true_policy"
            else (possible if method in ("exact_robust", "public_templates") else active)
        )
        checked += len(selected)
        if any(evaluate(policy, transformed) != "Permit" for policy in selected):
            continue
        if method == "sampled_policies":
            robust = True
        else:
            counter = next(
                (policy for policy in possible if evaluate(policy, transformed) != "Permit"), None
            )
            checked += len(possible)
            robust = counter is None
            if counter is not None and counter not in active:
                active.append(counter)
        if method == "true_policy":
            robust = True
        if robust:
            return {"type": "ACCESS_RECOURSE", "sequence": list(sequence), "checks": checked}
    return {"type": "ABSTAIN", "sequence": [], "checks": checked}


def generate(rng, count):
    for index in range(count):
        thresholds = sorted(rng.sample(range(1, 9), 3))
        policies = [
            {
                "required": ["level", "mfa", "scope"],
                "equals": {"mfa": True},
                "minimum": {"level": threshold},
                "members": {"scope": ["public"] if threshold > 3 else ["public", "private"]},
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
            "narrow_public": {"set": {"scope": "public"}, "cost": 3, "user_executable": True},
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
    result = synthesize(case["public"], case["request"], method, secret)
    result["public_output"] = json.dumps(
        {k: result[k] for k in ["type", "sequence"]}, sort_keys=True
    )
    outputs = []
    for possible in possibility_set(case["public"]):
        alternative = synthesize(case["public"], case["request"], method, possible)
        outputs.append(
            json.dumps({k: alternative[k] for k in ["type", "sequence"]}, sort_keys=True)
        )
    result["matched_view_secret_gain"] = (len(set(outputs)) - 1) / len(outputs) if outputs else 0.0
    return result


def score(case, result):
    emitted = result["type"] == "ACCESS_RECOURSE"
    changed = apply_action(case["request"], result["sequence"], case["public"]["actions"])
    actual = case["public"]["policies"][case["secret_index"]]
    valid = emitted and changed is not None and evaluate(actual, changed) == "Permit"
    robust = changed is not None and all(
        evaluate(p, changed) == "Permit" for p in possibility_set(case["public"])
    )
    return {
        "coverage": int(valid),
        "matched_view_secret_gain": result["matched_view_secret_gain"],
        "failed_repair": int(not valid) if emitted else None,
        "illegal_repair": int(changed is None) if emitted else None,
        "nonrobust_repair": int(not robust) if emitted else None,
        "abstention": int(result["type"] == "ABSTAIN"),
        "policy_checks": result["checks"],
        "repair_cost": sum(case["public"]["actions"][x].get("cost", 1) for x in result["sequence"])
        if emitted
        else None,
        "legal_effects": int(valid),
    }

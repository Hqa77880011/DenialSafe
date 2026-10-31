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
    "redacted_repair",
    "causal_adaptation",
    "secret_tie_break",
]


def evaluate(policy, request):
    from .policy import decision

    return decision(policy, request)


def possibility_set(public):
    from .policy import possible

    return [policy for assignment, policy in possible(public)]


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
        if check and not set(primitive.get("required_rights", [])) <= set(
            current.get("rights", [])
        ):
            return None
        if (set(primitive.get("set", {})) | set(primitive.get("remove", []))) & {
            "principal",
            "tenant",
            "provenance",
            "rights",
        }:
            return None
        if check and primitive.get("kind") == "process":
            return None
        for name in primitive.get("remove", []):
            current.pop(name, None)
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


def synthesize(
    public, request, method="denialsafe", secret=None, secret_attributes=None
):
    """Public-only SMT synthesis; secret-dependent diagnostics are explicit."""
    from . import symbolic, search

    if method not in METHODS:
        raise ValueError("Unknown method: " + method)
    stamp = time.perf_counter()
    if method == "decision_only":
        return dict(type="ABSTAIN", sequence=[], checks=0)
    if method == "exact_robust":
        result = search.exact(public, request)
    elif method == "public_templates":
        result = search.templates(public, request)
    else:
        result = symbolic.synthesize(public, request, method, secret, secret_attributes)
    result.setdefault(
        "stage_ms",
        {
            ("enumeration_ms" if method == "exact_robust" else "template_search_ms"): (
                time.perf_counter() - stamp
            )
            * 1000
        },
    )
    if result["type"] == "ABSTAIN":
        for name, primitive in sorted(public.get("process_actions", {}).items()):
            if (
                apply_action(
                    request,
                    [name],
                    {
                        name: {
                            key: value
                            for key, value in primitive.items()
                            if key != "kind"
                        }
                    },
                )
                is not None
            ):
                return dict(
                    type="PROCESS_RECOURSE",
                    sequence=[name],
                    checks=result["checks"],
                    reason="public_process_instructions",
                )
    return result


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
        group = ("robust_solvable", "process_only", "no_robust")[index % 3]
        request["level"] = max(thresholds) if group == "robust_solvable" else 0
        public = {
            "policies": policies,
            "actions": registry,
            "max_depth": 2,
            "history": [{"request": request, "decision": "Deny"}],
            "template": ["complete_mfa", "narrow_public"],
            "templates": [
                {"id": "public-subset-mfa", "goals": {"mfa": True, "scope": "public"}}
            ],
        }
        if group == "process_only":
            public["process_actions"] = {
                "submit_approval": dict(
                    kind="process",
                    user_executable=True,
                    set={"workflow": "pending"},
                    public_instruction="Submit a public approval request; access is not guaranteed",
                )
            }
        yield {
            "group": group,
            "id": str(index),
            "family": "thresholds-" + "-".join(map(str, thresholds)) + ":" + group,
            "public": public,
            "request": request,
            "secret_index": rng.randrange(3),
        }


def run_case(case, method):
    if case.get("supported") is False:
        return dict(
            type="ABSTAIN",
            sequence=[],
            checks=0,
            synthesis_ms=0,
            unsupported=True,
            reason=case.get("unsupported_reason", "unreviewed_or_unsupported_adapter"),
        )
    secret = actual_policy(case)
    start = time.perf_counter()
    result = synthesize(
        case["public"],
        case["request"],
        method,
        secret
        if method
        in ("true_policy", "redacted_repair", "causal_adaptation", "secret_tie_break")
        else None,
        secret_attributes=case.get("actual_request_attributes", {})
        if method
        in ("true_policy", "redacted_repair", "causal_adaptation", "secret_tie_break")
        else None,
    )
    result["synthesis_ms"] = (time.perf_counter() - start) * 1000
    from .channel import render

    result["public_output"] = render(case["public"], result).decode()
    outputs = []
    from .policy import possible as family_members, hidden_request

    for assignment, possible in family_members(case["public"]):
        alternative = synthesize(
            case["public"],
            case["request"],
            method,
            possible
            if method
            in (
                "true_policy",
                "redacted_repair",
                "causal_adaptation",
                "secret_tie_break",
            )
            else None,
            secret_attributes=hidden_request(case["public"], assignment)
            if method
            in (
                "true_policy",
                "redacted_repair",
                "causal_adaptation",
                "secret_tie_break",
            )
            else None,
        )
        outputs.append(render(case["public"], alternative).decode())
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
    if result.get("unsupported"):
        return dict(
            coverage=0,
            robust_coverage=0,
            actual_policy_validity=None,
            robust_validity=None,
            unsupported=1,
            abstention=1,
            legal_effects=0,
        )
    emitted = result["type"] == "ACCESS_RECOURSE"
    changed = (
        oracle.projected_replay(case["public"], case["request"], result["sequence"])
        if emitted
        else None
    )
    actual = actual_policy(case)
    valid = (
        emitted
        and changed is not None
        and oracle.decision(
            actual, {**changed, **case.get("actual_request_attributes", {})}
        )
        == "Permit"
    )
    robust = changed is not None and oracle.check(
        case["public"], case["request"], result["sequence"]
    )
    return {
        **result.get("stage_ms", {}),
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


def actual_policy(case):
    from .policy import instantiate

    if "actual_policy" in case:
        return case["actual_policy"]
    public = case["public"]
    if "skeleton" in public:
        return instantiate(public["skeleton"], case["secret_assignment"])
    return public["policies"][case["secret_index"]]


def metric_counts(case, result):
    names = {
        "coverage",
        "robust_coverage",
        "actual_policy_validity",
        "robust_validity",
        "process_guidance",
        "public_conflict",
        "same_view_content_mismatch",
        "failed_repair",
        "illegal_repair",
        "nonrobust_repair",
        "abstention",
        "unsupported",
    }
    return {
        key: [value, 1] if value is not None else [0, 0]
        for key, value in score(case, result).items()
        if key in names
    }

"""Independent concrete legality and robust-repair replay."""

import copy


def decision(policy, request):
    """Typed finite policy interpretation; absent or ill-typed values cannot permit."""
    used = (
        set(policy.get("required", []))
        | set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
    )
    if not used <= request.keys():
        return "Indeterminate"
    same = lambda a, b: type(a) is type(b) and a == b
    if any(not same(request[k], v) for k, v in policy.get("equals", {}).items()):
        return "Deny"
    if any(
        not any(same(request[k], v) for v in values)
        for k, values in policy.get("members", {}).items()
    ):
        return "Deny"
    for key, bound in policy.get("minimum", {}).items():
        if type(request[key]) not in (int, float) or type(bound) not in (int, float):
            return "Indeterminate"
        if request[key] < bound:
            return "Deny"
    if any(
        all(k in request and same(request[k], v) for k, v in clause.items())
        for clause in policy.get("denies", [])
    ):
        return "Deny"
    return "Permit"


def replay(request, sequence, registry):
    current = copy.deepcopy(request)
    for name in sequence:
        primitive = registry[name]
        if primitive.get("user_executable") is not True:
            return None
        for key, value in primitive.get("preconditions", {}).items():
            if (
                key not in current
                or type(current[key]) is not type(value)
                or current[key] != value
            ):
                return None
        changes = primitive.get("set", {})
        if {"principal", "tenant", "provenance"}.intersection(changes):
            return None
        current.update(copy.deepcopy(changes))
    return current


def check(public, request, sequence):
    """Check every compatible policy without invoking the synthesizer's interpreter."""
    candidates = [
        p
        for p in public["policies"]
        if all(
            decision(p, entry["request"]) == entry["decision"]
            for entry in public.get("history", [])
        )
    ]
    transformed = replay(request, sequence, public["actions"])
    return (
        bool(candidates)
        and transformed is not None
        and all(decision(p, transformed) == "Permit" for p in candidates)
    )

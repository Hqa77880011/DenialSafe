"""Independent concrete legality and robust-repair replay."""

import copy


def decision(policy, request):
    """Independent decision encoding for the published typed common fragment."""
    from . import policy as ir

    # Rules use trusted public expression parsing; combination is independently rebuilt.
    if "allow_rules" in policy:
        permits = [ir.condition(rule, request) for rule in policy["allow_rules"]]
        forbids = [ir.condition(rule, request) for rule in policy.get("deny_rules", [])]
        if any(value is True for value in forbids):
            return "Deny"
        if any(value is None for value in permits + forbids):
            return "Indeterminate"
        return "Permit" if any(value is True for value in permits) else "NotApplicable"
    clauses = policy.get("denies", [])
    if any(
        all(
            name in request
            and type(request[name]) is type(value)
            and ir.encode(request[name]) == ir.encode(value)
            for name, value in clause.items()
        )
        for clause in clauses
    ):
        return "Deny"
    required = (
        set(policy.get("required", []))
        | set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
        | set(policy.get("maximum", {}))
        | {name for clause in clauses for name in clause}
    )
    if required - set(request):
        return "Indeterminate"
    if any(
        type(request[name]) is not type(value)
        for clause in clauses
        for name, value in clause.items()
    ):
        return "Indeterminate"
    for name, expected in policy.get("equals", {}).items():
        if type(request[name]) is not type(expected) or ir.encode(
            request[name]
        ) != ir.encode(expected):
            return "Deny"
    for name, choices in policy.get("members", {}).items():
        if not any(
            type(request[name]) is type(value)
            and ir.encode(request[name]) == ir.encode(value)
            for value in choices
        ):
            return "Deny"
    for key, lower in (("minimum", True), ("maximum", False)):
        for name, bound in policy.get(key, {}).items():
            if type(request[name]) not in (int, float) or type(bound) not in (
                int,
                float,
            ):
                return "Indeterminate"
            if request[name] < bound if lower else request[name] > bound:
                return "Deny"
    for clause in policy.get("denies", []):
        if all(
            name in request
            and type(request[name]) is type(value)
            and ir.encode(request[name]) == ir.encode(value)
            for name, value in clause.items()
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
        if primitive.get("kind") == "process" or not set(
            primitive.get("required_rights", [])
        ) <= set(current.get("rights", [])):
            return None
        changes = primitive.get("set", {})
        if {"principal", "tenant", "provenance", "rights"}.intersection(
            set(changes) | set(primitive.get("remove", []))
        ):
            return None
        for field in primitive.get("remove", []):
            current.pop(field, None)
        current.update(copy.deepcopy(changes))
    return current


def check(public, request, sequence):
    """Check every compatible policy without invoking the synthesizer's interpreter."""
    from .policy import enumerate_family, instantiate

    from .policy import hidden_request

    candidates = [
        (assignment, policy)
        for assignment, policy in enumerate_family(public)
        if all(
            decision(policy, instantiate(entry["request"], assignment))
            == entry["decision"]
            for entry in public.get("history", [])
        )
    ]
    transformed = projected_replay(public, request, sequence)
    return (
        bool(candidates)
        and not any(
            (
                set(public.get("protected_fields", []))
                | set(public.get("hidden_request_fields", {}))
            )
            & (
                set(public["actions"][name].get("set", {}))
                | set(public["actions"][name].get("remove", []))
            )
            for name in sequence
        )
        and transformed is not None
        and all(
            decision(p, {**transformed, **hidden_request(public, assignment)})
            == "Permit"
            for assignment, p in candidates
        )
    )


def projected_replay(public, request, sequence):
    """Check hidden immutable preconditions universally, retaining only public fields."""
    from .policy import equal

    hidden = public.get("hidden_request_fields", {})
    registry = copy.deepcopy(public["actions"])
    for name in sequence:
        primitive = registry[name]
        if set(hidden) & (
            set(primitive.get("set", {})) | set(primitive.get("remove", []))
        ):
            return None
        for field, expected in list(primitive.get("preconditions", {}).items()):
            if field in hidden:
                if not all(equal(value, expected) for value in hidden[field]):
                    return None
                del primitive["preconditions"][field]
    return replay(request, sequence, registry)

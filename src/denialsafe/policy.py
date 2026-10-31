"""Typed policy families: public finite holes, deny overrides and exact decisions."""

import copy
import itertools
import json

MISSING = object()
DECISIONS = ("Permit", "Deny", "Indeterminate", "NotApplicable")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def equal(left, right):
    return type(left) is type(right) and encode(left) == encode(right)


def compare(left, op, right):
    if left is MISSING or right is MISSING:
        return None
    if op == "type":
        return type(left) is type(right)
    if op == "eq":
        return equal(left, right)
    if op == "ne":
        return not equal(left, right)
    if op == "in":
        return isinstance(right, list) and any(equal(left, item) for item in right)
    if op == "subset":
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and all(any(equal(item, other) for other in right) for item in left)
        )
    if type(left) not in (int, float) or type(right) not in (int, float):
        return None
    return {
        "lt": left < right,
        "le": left <= right,
        "gt": left > right,
        "ge": left >= right,
    }[op]


def condition(expression, request):
    if isinstance(expression, bool):
        return expression
    if "all" in expression:
        values = [condition(item, request) for item in expression["all"]]
        return None if None in values else all(values)
    if "any" in expression:
        values = [condition(item, request) for item in expression["any"]]
        return None if None in values else any(values)
    if "defined" in expression:
        return condition(expression["defined"], request) is not None
    if "not" in expression:
        result = condition(expression["not"], request)
        return None if result is None else not result
    if "present" in expression:
        return expression["present"] in request
    if "compare" in expression:
        left, op, right = expression["compare"]

        def value(item):
            return (
                request.get(item[1:], MISSING)
                if isinstance(item, str) and item.startswith("$")
                else item
            )

        return compare(value(left), op, value(right))
    values = [
        compare(request.get(name, MISSING), "eq", value)
        for name, value in expression.items()
    ]
    return None if None in values else all(values)


def decision(policy, request):
    if "allow_rules" in policy:
        allows = [condition(item, request) for item in policy["allow_rules"]]
        denies = [condition(item, request) for item in policy.get("deny_rules", [])]
        if any(value is True for value in denies):
            return "Deny"
        if None in allows + denies:
            return "Indeterminate"
        return "Permit" if any(allows) else "NotApplicable"
    deny_rules = policy.get("denies", [])
    if any(condition(clause, request) is True for clause in deny_rules):
        return "Deny"
    used = (
        set(policy.get("required", []))
        | set(policy.get("equals", {}))
        | set(policy.get("members", {}))
        | set(policy.get("minimum", {}))
        | set(policy.get("maximum", {}))
        | {name for clause in deny_rules for name in clause}
    )
    if not used <= set(request):
        return "Indeterminate"
    if any(
        type(request[name]) is not type(value)
        for clause in deny_rules
        for name, value in clause.items()
    ):
        return "Indeterminate"
    if any(
        not equal(request[name], value)
        for name, value in policy.get("equals", {}).items()
    ):
        return "Deny"
    if any(
        not compare(request[name], "in", values)
        for name, values in policy.get("members", {}).items()
    ):
        return "Deny"
    for limits, op in (("minimum", "ge"), ("maximum", "le")):
        for name, value in policy.get(limits, {}).items():
            result = compare(request[name], op, value)
            if result is None:
                return "Indeterminate"
            if not result:
                return "Deny"
    if any(condition(clause, request) is True for clause in policy.get("denies", [])):
        return "Deny"
    return "Permit"


def instantiate(template, assignment):
    if isinstance(template, dict):
        if set(template) == {"hole"}:
            return copy.deepcopy(assignment[template["hole"]])
        return {key: instantiate(value, assignment) for key, value in template.items()}
    if isinstance(template, list):
        return [instantiate(value, assignment) for value in template]
    return copy.deepcopy(template)


def enumerate_family(public):
    if any(
        name == "policy_index" or name.startswith("request:")
        for name in public.get("holes", {})
    ):
        raise ValueError("Reserved policy-family hole name")
    domains = {
        **public.get("holes", {}),
        **{
            "request:" + name: values
            for name, values in public.get("hidden_request_fields", {}).items()
        },
    }
    names = sorted(domains)
    if any(not domains[name] for name in names):
        return
    for values in itertools.product(*(domains[name] for name in names)):
        assignment = dict(zip(names, values))
        if "skeleton" in public:
            yield assignment, instantiate(public["skeleton"], assignment)
        else:
            for index, policy in enumerate(public.get("policies", [])):
                yield {"policy_index": index, **assignment}, copy.deepcopy(policy)


def possible(public):
    return [
        (assignment, policy)
        for assignment, policy in enumerate_family(public)
        if all(
            decision(policy, instantiate(item["request"], assignment))
            == item["decision"]
            for item in public.get("history", [])
        )
    ]


def hidden_request(public, assignment):
    return {
        name: copy.deepcopy(assignment["request:" + name])
        for name in public.get("hidden_request_fields", {})
    }

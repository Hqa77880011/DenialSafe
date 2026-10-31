"""Policy-feature causal adaptation with explicit mapping to legal requester actions.

This is the manuscript's adaptation, not the upstream causal framework. It first
selects a sufficient Boolean policy-feature assignment by minimum feature change,
then asks the action planner to realize that assignment. Feature responsibility
uses actual but-for dependence under a minimum-size contingency.
"""

import z3
from . import policy


def explanation(actual, request, timeout_ms=1000):
    features = []
    defined = []

    def atom(predicate):
        identifier = "feature_" + str(len(features))
        variable = z3.Bool(identifier)
        features.append(
            dict(
                id=identifier,
                predicate=predicate,
                variable=variable,
                baseline=policy.condition(predicate, request) is True,
            )
        )
        well = z3.Bool("defined_" + identifier)
        defined.append(well)
        features.append(
            dict(
                id="defined_" + identifier,
                predicate={"defined": predicate},
                variable=well,
                baseline=policy.condition(predicate, request) is not None,
            )
        )
        return variable

    def parse(predicate):
        if isinstance(predicate, bool):
            return z3.BoolVal(predicate)
        if "all" in predicate:
            return z3.And(*(parse(item) for item in predicate["all"]))
        if "any" in predicate:
            return z3.Or(*(parse(item) for item in predicate["any"]))
        if "not" in predicate:
            return z3.Not(parse(predicate["not"]))
        return atom(predicate)

    if "allow_rules" in actual:
        root = z3.And(
            z3.Or(*(parse(rule) for rule in actual["allow_rules"])),
            z3.Not(z3.Or(*(parse(rule) for rule in actual.get("deny_rules", [])))),
        )
    else:
        predicates = [{"present": name} for name in actual.get("required", [])]
        predicates += [
            {"compare": ["$" + name, "eq", value]}
            for name, value in actual.get("equals", {}).items()
        ]
        predicates += [
            {"compare": ["$" + name, "in", values]}
            for name, values in actual.get("members", {}).items()
        ]
        for key, operation in (("minimum", "ge"), ("maximum", "le")):
            predicates += [
                {"compare": ["$" + name, operation, value]}
                for name, value in actual.get(key, {}).items()
            ]
        denial_fields = {
            name: value
            for clause in actual.get("denies", [])
            for name, value in clause.items()
        }
        predicates += [{"present": name} for name in denial_fields]
        predicates += [
            {"compare": ["$" + name, "type", value]}
            for name, value in denial_fields.items()
        ]
        root = z3.And(
            *(parse(item) for item in predicates),
            z3.Not(z3.Or(*(parse(clause) for clause in actual.get("denies", [])))),
        )
    root = z3.And(root, *defined)
    optimizer = z3.Optimize()
    optimizer.set(timeout=max(1, int(timeout_ms)))
    optimizer.add(root)
    objective = optimizer.minimize(
        z3.Sum(
            *(z3.If(item["variable"] == item["baseline"], 0, 1) for item in features)
        )
    )
    for item in features:
        optimizer.minimize(z3.If(item["variable"], 1, 0))
    status = optimizer.check()
    if status != z3.sat:
        return dict(status=str(status).upper())
    model = optimizer.model()
    targets = {
        item["id"]: z3.is_true(model.eval(item["variable"], model_completion=True))
        for item in features
    }
    retained = list(features)
    for item in list(retained):
        solver = z3.Solver()
        solver.set(timeout=max(1, int(timeout_ms)))
        solver.add(
            z3.Not(root),
            *(
                other["variable"] == targets[other["id"]]
                for other in retained
                if other is not item
            ),
        )
        if solver.check() == z3.unsat:
            retained.remove(item)
    responsibility = {}
    details = []
    for item in retained:
        target = targets[item["id"]]
        if target != item["baseline"]:
            cause = item["variable"]
            counter = z3.substitute(root, (cause, z3.BoolVal(item["baseline"])))
            solver = z3.Optimize()
            solver.set(timeout=max(1, int(timeout_ms)))
            solver.add(cause == target, root, z3.Not(counter))
            contingency = z3.Sum(
                *(
                    z3.If(other["variable"] == other["baseline"], 0, 1)
                    for other in features
                    if other is not item
                )
            )
            minimum = solver.minimize(contingency)
            answer = solver.check()
            if answer == z3.sat and str(minimum.lower()) == str(minimum.upper()):
                amount = solver.model().eval(contingency).as_long()
                responsibility[item["id"]] = 1 / (amount + 1)
            else:
                responsibility[item["id"]] = None
        details.append(dict(id=item["id"], predicate=item["predicate"], target=target))
    return dict(
        status="SAT",
        goals=details,
        responsibility=responsibility,
        minimum_feature_change_proved=str(objective.lower()) == str(objective.upper()),
    )

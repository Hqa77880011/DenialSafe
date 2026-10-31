"""Typed-hole SMT families and bounded legal action optimization.

Policy holes are symbolic indices. No full Cartesian policy family is built for
synthesis or its independent symbolic check. Concrete enumeration remains an
explicit reference/validation path.
"""

import copy
import itertools
import hashlib
import math
import time
import z3
from . import policy as ir
from .oracle import projected_replay


def conjunction(items):
    return z3.And(*items)


def disjunction(items):
    return z3.Or(*items)


class Family:
    def __init__(self, public, prefix="theta", independent=False):
        self.public = public
        if any(
            name == "policy_index" or name.startswith("request:")
            for name in public.get("holes", {})
        ):
            raise ValueError("Reserved policy-family hole name")
        self.independent = independent
        domains = (
            public.get("holes", {})
            if "skeleton" in public
            else {
                "policy_index": list(range(len(public.get("policies", [])))),
                **public.get("holes", {}),
            }
        )
        domains = {
            **domains,
            **{
                "request:" + name: values
                for name, values in public.get("hidden_request_fields", {}).items()
            },
        }
        self.domains = copy.deepcopy(domains)
        self.variables = {
            name: z3.Int(prefix + "_" + str(index))
            for index, name in enumerate(sorted(domains))
        }
        self.bounds = conjunction(
            z3.And(self.variables[name] >= 0, self.variables[name] < len(values))
            for name, values in domains.items()
        )
        self.space = z3.And(
            self.bounds,
            *(
                self.category(
                    self.request(item["request"], symbolic=True), include_hidden=False
                )
                == ir.DECISIONS.index(item["decision"])
                for item in public.get("history", [])
            ),
        )

    def request(self, request, symbolic=False):
        return {
            name: self.choices(value)
            if symbolic
            else [(copy.deepcopy(value), z3.BoolVal(True))]
            for name, value in request.items()
        }

    def choices(self, item):
        if isinstance(item, dict) and set(item) == {"hole"}:
            name = item["hole"]
            if name not in self.variables:
                raise ValueError("Undeclared typed hole")
            return [
                (value, self.variables[name] == index)
                for index, value in enumerate(self.domains[name])
            ]
        if isinstance(item, list):
            return [
                (
                    [value for value, _ in items],
                    conjunction(condition for _, condition in items),
                )
                for items in itertools.product(*(self.choices(child) for child in item))
            ]
        return [(item, z3.BoolVal(True))]

    def test(self, request, name, op, expected):
        left = request.get(name, [(ir.MISSING, z3.BoolVal(True))])
        right = self.choices(expected)
        true = []
        error = []
        for actual, a in left:
            for value, b in right:
                result = ir.compare(actual, op, value)
                if result is True:
                    true.append(z3.And(a, b))
                elif result is None:
                    error.append(z3.And(a, b))
        return disjunction(true), disjunction(error)

    def condition(self, expression, request):
        if isinstance(expression, bool):
            return z3.BoolVal(expression), z3.BoolVal(False)
        for operator in ("all", "any"):
            if operator in expression:
                children = [
                    self.condition(item, request) for item in expression[operator]
                ]
                return (
                    conjunction(item[0] for item in children)
                    if operator == "all"
                    else disjunction(item[0] for item in children),
                    disjunction(item[1] for item in children),
                )
        if "defined" in expression:
            _, error = self.condition(expression["defined"], request)
            return z3.Not(error), z3.BoolVal(False)
        if "not" in expression:
            value, error = self.condition(expression["not"], request)
            return z3.Not(value), error
        if "present" in expression:
            return disjunction(
                condition
                for value, condition in request.get(expression["present"], [])
                if value is not ir.MISSING
            ), z3.BoolVal(False)
        if "compare" in expression:
            left, op, right = expression["compare"]

            def values(item):
                return (
                    request.get(item[1:], [(ir.MISSING, z3.BoolVal(True))])
                    if isinstance(item, str) and item.startswith("$")
                    else self.choices(item)
                )

            true = []
            errors = []
            for a, ac in values(left):
                for b, bc in values(right):
                    answer = ir.compare(a, op, b)
                    if answer is True:
                        true.append(z3.And(ac, bc))
                    if answer is None:
                        errors.append(z3.And(ac, bc))
            return disjunction(true), disjunction(errors)
        children = [
            self.test(request, name, "eq", value) for name, value in expression.items()
        ]
        return conjunction(item[0] for item in children), disjunction(
            item[1] for item in children
        )

    def single(self, policy, request):
        if "allow_rules" in policy:
            allows = [self.condition(item, request) for item in policy["allow_rules"]]
            denies = [
                self.condition(item, request) for item in policy.get("deny_rules", [])
            ]
            error = disjunction(item[1] for item in allows + denies)
            allow = disjunction(item[0] for item in allows)
            deny = disjunction(item[0] for item in denies)
            return z3.If(deny, 1, z3.If(error, 2, z3.If(allow, 0, 3)))
        used = (
            set(policy.get("equals", {}))
            | set(policy.get("members", {}))
            | set(policy.get("minimum", {}))
            | set(policy.get("maximum", {}))
        )
        used |= {name for clause in policy.get("denies", []) for name in clause}
        type_bad = disjunction(
            z3.Not(self.test(request, name, "type", value)[0])
            for clause in policy.get("denies", [])
            for name, value in clause.items()
        )
        required = self.choices(policy.get("required", []))
        missing = disjunction(
            z3.And(
                selected,
                z3.Not(
                    conjunction(
                        disjunction(
                            condition
                            for value, condition in request.get(name, [])
                            if value is not ir.MISSING
                        )
                        for name in used | set(names)
                    )
                ),
            )
            for names, selected in required
        )
        equals = [
            self.test(request, name, "eq", value)[0]
            for name, value in policy.get("equals", {}).items()
        ]
        members = [
            self.test(request, name, "in", value)[0]
            for name, value in policy.get("members", {}).items()
        ]
        numbers = [
            self.test(request, name, op, value)
            for limits, op in (("minimum", "ge"), ("maximum", "le"))
            for name, value in policy.get(limits, {}).items()
        ]
        deny = disjunction(
            self.condition(clause, request)[0] for clause in policy.get("denies", [])
        )
        if self.independent:
            prefix = z3.And(z3.Not(missing), z3.Not(type_bad), *equals, *members)
            error = [missing, type_bad]
            for true, bad in numbers:
                error.append(z3.And(prefix, bad))
                prefix = z3.And(prefix, true, z3.Not(bad))
            permit = z3.And(prefix, z3.Not(deny))
            return z3.If(deny, 1, z3.If(permit, 0, z3.If(disjunction(error), 2, 1)))
        result = z3.If(deny, 1, 0)
        for true, error in reversed(numbers):
            result = z3.If(error, 2, z3.If(true, result, 1))
        result = z3.If(z3.And(*equals, *members), result, 1)
        return z3.If(deny, 1, z3.If(z3.Or(missing, type_bad), 2, result))

    def category(self, request, include_hidden=True):
        if include_hidden:
            request = {
                **request,
                **{
                    name: [
                        (value, self.variables["request:" + name] == index)
                        for index, value in enumerate(values)
                    ]
                    for name, values in self.public.get(
                        "hidden_request_fields", {}
                    ).items()
                },
            }
        if "skeleton" in self.public:
            return self.single(self.public["skeleton"], request)
        result = z3.IntVal(2)
        for index, policy in reversed(list(enumerate(self.public.get("policies", [])))):
            result = z3.If(
                self.variables["policy_index"] == index,
                self.single(policy, request),
                result,
            )
        return result

    def assignment(self, model):
        return {
            name: self.domains[name][
                model.eval(variable, model_completion=True).as_long()
            ]
            for name, variable in self.variables.items()
        }

    def fix(self, assignment):
        return conjunction(
            self.variables[name]
            == next(
                index
                for index, value in enumerate(self.domains[name])
                if ir.equal(value, assignment[name])
            )
            for name in self.variables
        )

    def policy(self, assignment):
        return (
            ir.instantiate(self.public["skeleton"], assignment)
            if "skeleton" in self.public
            else copy.deepcopy(self.public["policies"][assignment["policy_index"]])
        )

    def query(self, request=None, independent=False, timeout_ms=1000):
        solver = z3.Solver()
        solver.set(timeout=max(1, int(timeout_ms)))
        solver.add(self.space)
        if request is not None:
            solver.add(self.category(self.request(request)) != 0)
        answer = solver.check()
        return dict(
            status=str(answer).upper(),
            assignment=self.assignment(solver.model()) if answer == z3.sat else None,
        )


class Actions:
    def __init__(self, public, request, check=True):
        self.public = public
        self.request = request
        self.names = sorted(public["actions"])
        self.depth = public.get("max_depth", 2)
        if type(self.depth) is not int or self.depth < 0:
            raise ValueError("Invalid depth")
        self.steps = [z3.Int("action_" + str(index)) for index in range(self.depth)]
        fields = set(request) | {
            key
            for primitive in public["actions"].values()
            for key in list(primitive.get("set", {}))
            + list(primitive.get("preconditions", {}))
            + primitive.get("remove", [])
        }
        self.values = {name: [ir.MISSING] for name in fields}
        for name in fields:
            candidates = ([request[name]] if name in request else []) + [
                primitive["set"][name]
                for primitive in public["actions"].values()
                if name in primitive.get("set", {})
            ]
            self.values[name] += [
                value
                for index, value in enumerate(candidates)
                if not any(ir.equal(value, other) for other in candidates[:index])
            ]
        current = {
            name: [
                (
                    value,
                    z3.BoolVal(
                        index
                        == (
                            next(
                                (
                                    i
                                    for i, item in enumerate(self.values[name])
                                    if item is not ir.MISSING
                                    and name in request
                                    and ir.equal(item, request[name])
                                ),
                                0,
                            )
                        )
                    ),
                )
                for index, value in enumerate(self.values[name])
            ]
            for name in fields
        }
        constraints = []
        costs = []
        protected = {"principal", "tenant", "provenance", "rights"} | set(
            public.get("protected_fields", [])
        )
        protected |= set(public.get("hidden_request_fields", {}))
        for index, step in enumerate(self.steps):
            constraints.append(z3.And(step >= 0, step <= len(self.names)))
            if index:
                constraints.append(z3.Implies(self.steps[index - 1] == 0, step == 0))
            for number, name in enumerate(self.names, 1):
                primitive = public["actions"][name]
                if (
                    protected
                    & (set(primitive.get("set", {})) | set(primitive.get("remove", [])))
                    or primitive.get("kind") == "process"
                ):
                    constraints.append(step != number)
                    continue
                if check and (
                    primitive.get("user_executable") is not True
                    or not set(primitive.get("required_rights", []))
                    <= set(request.get("rights", []))
                ):
                    constraints.append(step != number)
                    continue
                if check:
                    if any(
                        field in public.get("hidden_request_fields", {})
                        and not all(
                            ir.equal(value, expected)
                            for value in public["hidden_request_fields"][field]
                        )
                        for field, expected in primitive.get(
                            "preconditions", {}
                        ).items()
                    ):
                        constraints.append(step != number)
                        continue
                    for field, expected in primitive.get("preconditions", {}).items():
                        if field in public.get("hidden_request_fields", {}):
                            continue
                        constraints.append(
                            z3.Implies(
                                step == number,
                                disjunction(
                                    condition
                                    for value, condition in current[field]
                                    if value is not ir.MISSING
                                    and ir.equal(value, expected)
                                ),
                            )
                        )
                value = primitive.get("cost", 1)
                if (
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(value)
                    or value < 0
                ):
                    raise ValueError("Invalid public action cost")
                costs.append(z3.If(step == number, z3.RealVal(str(value)), 0))
            following = {}
            for field, values in self.values.items():
                choices = []
                for value, old in current[field]:
                    keep = [step == 0]
                    change = []
                    for number, name in enumerate(self.names, 1):
                        primitive = public["actions"][name]
                        target = (
                            ir.MISSING
                            if field in primitive.get("remove", [])
                            else primitive.get("set", {}).get(field, ir.MISSING)
                        )
                        assigned = field in primitive.get(
                            "set", {}
                        ) or field in primitive.get("remove", [])
                        if not assigned:
                            keep.append(step == number)
                        elif (
                            target is ir.MISSING
                            and value is ir.MISSING
                            or target is not ir.MISSING
                            and value is not ir.MISSING
                            and ir.equal(target, value)
                        ):
                            change.append(step == number)
                    choices.append(
                        (value, z3.Or(z3.And(disjunction(keep), old), *change))
                    )
                following[field] = choices
            current = following
        self.final = current
        self.constraints = constraints
        for name, weight in public.get("scope_loss_weights", {}).items():
            original = request.get(name, [])
            if not isinstance(original, list) or weight < 0:
                raise ValueError("Scope cost needs a public set and nonnegative weight")
            costs.extend(
                z3.If(
                    condition,
                    z3.RealVal(
                        str(
                            weight
                            * sum(
                                not any(ir.equal(item, other) for other in value)
                                for item in original
                            )
                        )
                    ),
                    0,
                )
                for value, condition in current.get(name, [])
                if isinstance(value, list)
            )
        self.cost = z3.Sum(*costs) if costs else z3.RealVal(0)

    def least(self, family, active, timeout_ms=1000, secret_tie=None, extra=()):
        optimizer = z3.Optimize()
        optimizer.set(timeout=max(1, int(timeout_ms)))
        optimizer.add(*self.constraints, *extra)
        for assignment in active:
            replacement = [
                (
                    variable,
                    z3.IntVal(
                        next(
                            index
                            for index, value in enumerate(family.domains[name])
                            if ir.equal(value, assignment[name])
                        )
                    ),
                )
                for name, variable in family.variables.items()
            ]
            optimizer.add(z3.substitute(family.category(self.final), *replacement) == 0)
        objective = optimizer.minimize(self.cost)
        ties = [
            optimizer.minimize(-step if secret_tie else step) for step in self.steps
        ]
        status = optimizer.check()
        if status != z3.sat:
            return dict(status=str(status).upper())
        model = optimizer.model()
        sequence = [
            self.names[model.eval(step).as_long() - 1]
            for step in self.steps
            if model.eval(step).as_long()
        ]
        return dict(
            status="SAT",
            sequence=sequence,
            optimal=all(
                str(handle.lower()) == str(handle.upper())
                for handle in [objective, *ties]
            ),
            cost=str(model.eval(self.cost)),
        )


def certified(public, request, sequence, timeout_ms=1000):

    from .oracle import projected_replay

    transformed = projected_replay(public, request, sequence)
    if transformed is None or any(
        (
            set(public.get("protected_fields", []))
            | set(public.get("hidden_request_fields", {}))
        )
        & (
            set(public["actions"][name].get("set", {}))
            | set(public["actions"][name].get("remove", []))
        )
        for name in sequence
    ):
        return False, "ILLEGAL"
    family = Family(public, "checker", independent=True)
    consistent = family.query(timeout_ms=timeout_ms)
    if consistent["status"] != "SAT":
        return False, consistent["status"]
    answer = family.query(transformed, timeout_ms=timeout_ms)
    return answer["status"] == "UNSAT", answer["status"]


def synthesize(
    public, request, method="denialsafe", secret=None, secret_attributes=None
):
    measurements = {}
    result = _synthesize(
        public, request, method, secret, measurements, secret_attributes or {}
    )
    result["stage_ms"] = measurements
    return result


def _synthesize(public, request, method, secret, measurements, secret_attributes):
    def timed(name, operation, *args, **kwargs):
        started = time.perf_counter()
        try:
            return operation(*args, **kwargs)
        finally:
            measurements[name] = (
                measurements.get(name, 0) + (time.perf_counter() - started) * 1000
            )

    stamp = time.perf_counter()
    deadline = stamp + public.get("time_budget_seconds", 60)
    timeout = public.get("solver_timeout_ms", 1000)

    def remaining():
        return max(1, min(timeout, (deadline - time.perf_counter()) * 1000))

    family = timed("consistency_ms", Family, public)
    first = timed("consistency_ms", family.query, timeout_ms=remaining())
    queries = 1
    if first["status"] != "SAT":
        return dict(
            type="PUBLIC_CONFLICT" if first["status"] == "UNSAT" else "ABSTAIN",
            sequence=[],
            checks=queries,
            reason="inconsistent_public_history"
            if first["status"] == "UNSAT"
            else "solver_unknown",
        )
    active = [first["assignment"]]
    action = timed(
        "candidate_ms", Actions, public, request, check=method != "no_feasibility"
    )
    if method in ("true_policy", "redacted_repair", "causal_adaptation"):
        if secret is None:
            raise ValueError(
                "Actual-policy diagnostic needs its explicitly isolated policy"
            )
        actual = Family(
            {
                "policies": [secret],
                "hidden_request_fields": {
                    name: [value] for name, value in secret_attributes.items()
                },
            }
        )
        selected = [
            {
                "policy_index": 0,
                **{
                    "request:" + name: value
                    for name, value in secret_attributes.items()
                },
            }
        ]
        causal = None
        extra = []
        if method == "causal_adaptation":
            from .causal import explanation

            causal = timed(
                "causal_ms",
                explanation,
                secret,
                {**request, **secret_attributes},
                remaining(),
            )
            if causal["status"] != "SAT":
                return dict(
                    type="ABSTAIN",
                    sequence=[],
                    checks=queries,
                    reason="causal_" + causal["status"].lower(),
                )
            environment = {**action.final, **actual.request(secret_attributes)}
            for goal in causal["goals"]:
                truth, error = actual.condition(goal["predicate"], environment)
                extra.append(
                    z3.And(z3.Not(error), truth if goal["target"] else z3.Not(truth))
                )
        answer = timed(
            "candidate_ms", action.least, actual, selected, remaining(), extra=extra
        )
        queries += 1
        if answer["status"] == "SAT":
            sequence = answer["sequence"]
            result = dict(
                type="ACCESS_RECOURSE",
                sequence=sequence,
                checks=queries,
                optimal=answer["optimal"],
            )
            if method == "redacted_repair":
                result["redacted"] = True
            if causal is not None:
                result["causal_contribution"] = causal["responsibility"]
                result["causal_features"] = causal["goals"]
            return result
        return dict(
            type="ABSTAIN",
            sequence=[],
            checks=queries,
            reason="actual_search_" + answer["status"].lower(),
        )
    while time.perf_counter() < deadline and queries < public.get(
        "candidate_budget", 100000
    ):
        answer = timed(
            "candidate_ms",
            action.least,
            family,
            active,
            remaining(),
            secret_tie=method == "secret_tie_break"
            and bool(
                secret and hashlib.sha256(ir.encode(secret).encode()).digest()[0] % 2
            ),
        )
        queries += 1
        if answer["status"] != "SAT":
            return dict(
                type="ABSTAIN",
                sequence=[],
                checks=queries,
                reason="candidate_" + answer["status"].lower(),
            )
        from .core import apply_action

        transformed = (
            projected_replay(public, request, answer["sequence"])
            if method != "no_feasibility"
            else apply_action(
                request, answer["sequence"], public["actions"], check=False
            )
        )
        if method == "sampled_policies":
            counter = {"status": "UNSAT"}
        else:
            counter = timed(
                "verifier_ms", family.query, transformed, timeout_ms=remaining()
            )
        queries += 1
        if counter["status"] == "SAT":
            active.append(counter["assignment"])
            continue
        if counter["status"] != "UNSAT":
            return dict(
                type="ABSTAIN", sequence=[], checks=queries, reason="verifier_unknown"
            )
        okay, status = (
            timed(
                "checker_ms",
                certified,
                public,
                request,
                answer["sequence"],
                remaining(),
            )
            if method not in ("sampled_policies", "no_feasibility")
            else (True, "DISABLED_DIAGNOSTIC")
        )
        queries += 2 if status != "DISABLED_DIAGNOSTIC" else 0
        if not okay:
            return dict(
                type="ABSTAIN",
                sequence=[],
                checks=queries,
                reason="independent_" + status.lower(),
            )
        return dict(
            type="ACCESS_RECOURSE",
            sequence=answer["sequence"],
            checks=queries,
            optimal=answer["optimal"],
            counterexample_models=len(active),
            checker=status,
        )
    return dict(type="ABSTAIN", sequence=[], checks=queries, reason="budget_exhausted")

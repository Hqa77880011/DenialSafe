"""Independent exhaustive reference and optimized public goal templates."""

import heapq
import math
import time
from . import oracle, policy


def cost(public, request, sequence):
    changed = oracle.projected_replay(public, request, sequence)
    amount = sum(public["actions"][name].get("cost", 1) for name in sequence)
    if changed is not None:
        for field, weight in public.get("scope_loss_weights", {}).items():
            amount += weight * sum(
                not any(policy.equal(item, other) for other in changed.get(field, []))
                for item in request[field]
            )
    return amount


def states(public, request):
    """Dijkstra with public (cost, depth, ID) Pareto dominance per concrete state."""
    queue = [(0, (), request)]
    frontiers = {}
    start = time.perf_counter()
    count = 0
    while queue:
        if count >= public.get(
            "candidate_budget", 100000
        ) or time.perf_counter() - start >= public.get("time_budget_seconds", 60):
            yield None, None, "BUDGET"
            return
        effort, sequence, current = heapq.heappop(queue)
        count += 1
        key = policy.encode(current)
        prior = frontiers.setdefault(key, [])
        if any(
            price <= effort
            and depth <= len(sequence)
            and (price < effort or identifier <= sequence)
            for price, depth, identifier in prior
        ):
            continue
        prior.append((effort, len(sequence), sequence))
        yield sequence, current, "STATE"
        if len(sequence) >= public.get("max_depth", 2):
            continue
        for name in sorted(public["actions"]):
            primitive = public["actions"][name]
            value = primitive.get("cost", 1)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("Invalid public action cost")
            if set(public.get("protected_fields", [])) & (
                set(primitive.get("set", {})) | set(primitive.get("remove", []))
            ):
                continue
            following = oracle.projected_replay(public, current, [name])
            if following is not None:
                heapq.heappush(queue, (effort + value, sequence + (name,), following))


def exact(public, request):
    started = time.perf_counter()
    deadline = started + public.get("time_budget_seconds", 60)
    candidates = []
    checks = 0
    for assignment, item in policy.enumerate_family(public):
        if time.perf_counter() >= deadline:
            return dict(
                type="ABSTAIN",
                sequence=[],
                checks=checks,
                reason="family_enumeration_budget",
            )
        if all(
            oracle.decision(item, policy.instantiate(entry["request"], assignment))
            == entry["decision"]
            for entry in public.get("history", [])
        ):
            candidates.append((assignment, item))
    cache = {}
    best = None
    complete = True
    if not candidates:
        return dict(type="PUBLIC_CONFLICT", sequence=[], checks=0)
    search_public = {
        **public,
        "time_budget_seconds": max(0, deadline - time.perf_counter()),
    }
    for sequence, current, status in states(search_public, request):
        if status == "BUDGET":
            complete = False
            break
        key = policy.encode(current)
        if key not in cache:
            cache[key] = True
            for assignment, item in candidates:
                if time.perf_counter() >= deadline:
                    complete = False
                    break
                checks += 1
                if (
                    oracle.decision(
                        item, {**current, **policy.hidden_request(public, assignment)}
                    )
                    != "Permit"
                ):
                    cache[key] = False
                    break
            if not complete:
                break
        if cache[key]:
            order = (cost(public, request, sequence), sequence)
            if best is None or order < best[0]:
                best = (order, sequence)
    if best is None:
        return dict(
            type="ABSTAIN",
            sequence=[],
            checks=checks,
            reason="no_robust_action" if complete else "budget_exhausted",
        )
    return dict(
        type="ACCESS_RECOURSE",
        sequence=list(best[1]),
        checks=checks,
        optimal=complete,
        pruning="public_state_cost_depth_dominance",
        checker="independent_concrete_all_worlds",
    )


def templates(public, request):
    """Solve public template goals with every legal primitive, not a single canned repair."""
    from .symbolic import certified, Family

    started = time.perf_counter()
    deadline = started + public.get("time_budget_seconds", 60)
    family = Family(public, "template")
    status = family.query(timeout_ms=public.get("solver_timeout_ms", 1000))["status"]
    if status != "SAT":
        return dict(
            type="PUBLIC_CONFLICT" if status == "UNSAT" else "ABSTAIN",
            sequence=[],
            checks=1,
        )
    templates = [
        item
        for item in public.get("templates", [])
        if policy.condition(item.get("when", True), request) is True
    ]
    explicit = {tuple(item) for item in public.get("template_sequences", [])}
    if "template" in public:
        explicit.add(tuple(public["template"]))
    best = None
    checks = 1
    cache = {}
    complete = True
    search_public = {
        **public,
        "time_budget_seconds": max(0, deadline - time.perf_counter()),
    }
    for sequence, current, status in states(search_public, request):
        if status == "BUDGET":
            complete = False
            break
        if sequence not in explicit and not any(
            policy.condition(item["goals"], current) is True for item in templates
        ):
            continue
        key = policy.encode(current)
        if key not in cache:
            cache[key] = certified(
                public, request, sequence, public.get("solver_timeout_ms", 1000)
            )[0]
            checks += 2
        if cache[key]:
            order = (cost(public, request, sequence), sequence)
            if best is None or order < best[0]:
                best = (order, sequence)
    if best is None:
        return dict(
            type="ABSTAIN",
            sequence=[],
            checks=checks,
            reason="template_budget"
            if not complete
            else "no_certified_public_template",
        )
    return dict(
        type="ACCESS_RECOURSE",
        sequence=list(best[1]),
        checks=checks,
        optimal_within_templates=complete,
    )

"""Public fixed rendering, controlled release envelopes and public-state caching."""

import copy
import hashlib
import math
import time
from . import policy


def render(public, result, certificate=None):
    """Serialize only public status, action IDs and fixed administrator instructions."""
    sequence = result["sequence"]
    if result.get("redacted"):
        identifiers = [
            public.get("redaction_map", {}).get(name, "REDACTED_ACTION")
            for name in sequence
        ]
        instructions = [
            public.get("redacted_instruction", "Complete a prerequisite")
            for name in sequence
        ]
    else:
        identifiers = list(sequence)
        registry = (
            public.get("process_actions", {})
            if result["type"] == "PROCESS_RECOURSE"
            else public["actions"]
        )
        instructions = [
            registry[name].get("public_instruction", name) for name in sequence
        ]
    payload = dict(type=result["type"], actions=identifiers, instructions=instructions)
    if "causal_contribution" in result:
        payload["causal_contribution"] = result["causal_contribution"]
    if "causal_features" in result:
        payload["causal_features"] = result["causal_features"]
    if certificate is not None:
        payload["certificate"] = certificate
    return policy.encode(payload).encode()


def controlled(public, result, started, certificate=None):
    """Pad to a public fixed byte count and public deadline; measure overruns honestly."""
    body = render(public, result, certificate)
    channel = public.get("channel", {})
    # Bound depends only on public metadata and the declared maximum action depth.
    size = channel.get(
        "response_bytes",
        len(policy.encode(public).encode()) * 8
        + public.get("max_depth", 2) * 2048
        + 4096,
    )
    if type(size) is not int or size < 64:
        raise ValueError("Invalid public response size")
    prefix = b'{"body":' + body + b',"padding":"'
    suffix = b'"}'
    if len(prefix) + len(suffix) > size:
        prefix = (
            b'{"body":{"type":"ABSTAIN","reason":"public_encoding_limit"},"padding":"'
        )
    if len(prefix) + len(suffix) > size:
        raise ValueError("Public response size too small")
    encoded = prefix + b" " * (size - len(prefix) - len(suffix)) + suffix
    bucket = channel.get("bucket_seconds", 0.01)
    budget = channel.get(
        "release_budget_seconds", public.get("time_budget_seconds", 1) + 0.1
    )
    if bucket <= 0 or budget < 0:
        raise ValueError("Invalid public release bucket")
    deadline = started + math.ceil(budget / bucket) * bucket
    delay = max(0, deadline - time.perf_counter())
    if delay:
        time.sleep(delay)
    released = time.perf_counter()
    return encoded, dict(
        padding_seconds=delay,
        release_seconds=released - started,
        late=bool(released > deadline + bucket),
        response_bytes=len(encoded),
        public_deadline_seconds=deadline - started,
    )


class Service:
    """Cache only public-only methods and recheck every cached positive repair."""

    def __init__(self, key=None):
        self.cache = {}
        self.key = key

    def explain(self, public, request, method="denialsafe", controlled_channel=False):
        from . import core, symbolic

        if method in (
            "true_policy",
            "redacted_repair",
            "causal_adaptation",
            "secret_tie_break",
        ):
            raise ValueError(
                "Secret-dependent diagnostics are outside the isolated API"
            )
        stamp = time.perf_counter()
        key = hashlib.sha256(
            policy.encode(dict(public=public, request=request, method=method)).encode()
        ).hexdigest()
        hit = key in self.cache
        result = (
            copy.deepcopy(self.cache[key])
            if hit
            else core.synthesize(public, request, method)
        )
        if hit:
            result["stage_ms"] = {}
        validation_started = time.perf_counter()
        if hit and result["type"] == "ACCESS_RECOURSE":
            if not symbolic.certified(
                public,
                request,
                result["sequence"],
                public.get("solver_timeout_ms", 1000),
            )[0]:
                result = dict(
                    type="ABSTAIN",
                    sequence=[],
                    checks=0,
                    reason="cache_revalidation_failed",
                )
        if hit:
            result["stage_ms"] = {
                "cache_recheck_ms": (time.perf_counter() - validation_started) * 1000
            }
        self.cache[key] = copy.deepcopy(result)
        certificate = None
        if self.key is not None and result["type"] == "ACCESS_RECOURSE":
            from .execution import certify

            certificate = certify(public, request, result, self.key)
        if controlled_channel:
            encoded, measurements = controlled(public, result, stamp, certificate)
        else:
            encoded, measurements = (
                render(public, result, certificate),
                dict(
                    response_bytes=len(render(public, result, certificate)),
                    release_seconds=time.perf_counter() - stamp,
                    padding_seconds=0,
                    late=False,
                ),
            )
        return dict(
            result=result,
            output=encoded.decode(),
            cache_hit=hit,
            cache_key=key,
            channel=measurements,
        )


def update_history(public, request, decision, epoch=None):
    """Only a declassified PDP decision updates knowledge; explanations never do."""
    if decision not in policy.DECISIONS:
        raise ValueError("Unknown published decision category")
    updated = copy.deepcopy(public)
    if epoch is not None and epoch != public.get("epoch"):
        updated["epoch"] = epoch
        updated["history"] = []
        for name in updated.pop("generated_history_holes", []):
            updated.get("holes", {}).pop(name, None)
    observed = copy.deepcopy(request)
    for field, values in updated.get("hidden_request_fields", {}).items():
        name = "observation:" + str(len(updated.get("history", []))) + ":" + field
        if name in updated.get("holes", {}):
            raise ValueError("History hole name collision")
        updated.setdefault("holes", {})[name] = copy.deepcopy(values)
        updated.setdefault("generated_history_holes", []).append(name)
        observed[field] = {"hole": name}
    updated.setdefault("history", []).append(dict(request=observed, decision=decision))
    return updated

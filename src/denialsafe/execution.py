"""Bind certified access repairs and recheck them against the current PDP.

The application keeps the signing key outside public inputs and calls the effect
only after an EXECUTE verdict. Process guidance cannot be certified as access.
"""

import hashlib
import hmac
import json

from . import oracle


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _binding(public, request, sequence):
    return {
        "epoch": public.get("epoch"),
        "grammar_version": public.get("grammar_version"),
        "request": request,
        "sequence": list(sequence),
        "public_view": _encode(public),
    }


def certify(public, request, result, key):
    """Issue an authenticated record only for independently valid access recourse."""
    if not isinstance(key, bytes) or not key:
        raise ValueError("A nonempty application-owned signing key is required")
    if result["type"] != "ACCESS_RECOURSE" or not independent_check(
        public, request, result["sequence"]
    ):
        raise ValueError("Only independently certified access recourse can execute")
    payload = _binding(public, request, result["sequence"])
    return {
        "payload": payload,
        "signature": hmac.new(
            key, _encode(payload).encode(), hashlib.sha256
        ).hexdigest(),
    }


def authorize(
    certificate, public, request, actual_policy, key, private_attributes=None
):
    """Recheck binding, primitive legality, robustness and the current actual PDP."""
    payload = certificate["payload"]
    signature = hmac.new(key, _encode(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, certificate["signature"]):
        return {"type": "INVALID_CERTIFICATE"}
    if _encode(payload) != _encode(_binding(public, request, payload["sequence"])):
        return {"type": "STALE_BINDING"}
    transformed = oracle.projected_replay(public, request, payload["sequence"])
    if transformed is None or not independent_check(
        public, request, payload["sequence"]
    ):
        return {"type": "REPAIR_REJECTED"}
    if (
        oracle.decision(actual_policy, {**transformed, **(private_attributes or {})})
        != "Permit"
    ):
        return {"type": "ACCESS_DENIED"}
    return {"type": "EXECUTE", "request": transformed}


def independent_check(public, request, sequence):
    import math

    size = (
        math.prod(
            len(values) for values in public.get("hidden_request_fields", {}).values()
        )
        * math.prod(len(values) for values in public.get("holes", {}).values())
        * max(1, len(public.get("policies", [])))
    )
    if size <= public.get("enumerative_check_limit", 128):
        return oracle.check(public, request, sequence)
    from .symbolic import certified

    return certified(public, request, sequence, public.get("solver_timeout_ms", 1000))[
        0
    ]

"""Offline bridge for Ben's NativeDecisionIntentFactory request -> VERITAS content-bound request id."""
from copy import deepcopy
from request_id_derivation_v1 import freeze_decide_request_identity

PROFILE="veritas.rveval.request-id-derivation/v1"

def bind_factory_request(payload):
    """Return an exact copy augmented only with the opt-in identity profile/id."""
    if type(payload) is not dict:
        raise ValueError("REQUEST_REQUIRED")
    required={"query","context","alternatives","min_evidence","memory_auto_put","persona_evolve"}
    if set(payload) != required:
        raise ValueError("FACTORY_REQUEST_SHAPE_MISMATCH")
    frozen=deepcopy(payload)
    identity=freeze_decide_request_identity(
        request_context={"query":frozen["query"],"context":frozen["context"]},
        alternatives=frozen["alternatives"],
        min_evidence=frozen["min_evidence"],
        memory_auto_put=frozen["memory_auto_put"],
        persona_evolve=frozen["persona_evolve"],
    )
    frozen["request_id_profile"]=identity["profile"]
    frozen["request_id"]=identity["request_id"]
    return frozen

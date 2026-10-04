"""Offline bridge for Ben's NativeDecisionIntentFactory request -> VERITAS content-bound request id."""
from copy import deepcopy
from request_id_derivation_v1 import derive_request_identity

PROFILE="veritas.rveval.request-id-derivation/v1"

def bind_factory_request(payload):
    """Return an exact copy augmented only with the opt-in identity profile/id."""
    if type(payload) is not dict:
        raise ValueError("REQUEST_REQUIRED")
    required={"query","context","alternatives","min_evidence","memory_auto_put","persona_evolve"}
    if set(payload) != required:
        raise ValueError("FACTORY_REQUEST_SHAPE_MISMATCH")
    frozen=deepcopy(payload)
    identity=derive_request_identity(frozen)
    frozen["request_id_profile"]=PROFILE
    frozen["request_id"]=identity["request_id"]
    return frozen

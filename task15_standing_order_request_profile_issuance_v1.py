"""Prospective local rent evidence profiles, never payment or dispatch authority.

The trusted harness owns request/state acquisition, signing key, registry and
generator adapter. HMAC proves local issuance only. Fixed ordinal one is this
proof's first-standing-order slot; it does not establish earlier address effects.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
from threading import RLock
from task15_native_address_request_profile_issuance_v1 import canonical, sha
from task15_standing_order_original_request_authority_design_v1 import (
    POLICY_ID, derive_rent_update_design, assess_rent_update_design,
)
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

PROFILE = "TASK15_STANDING_ORDER_REQUEST_PROFILE_ISSUANCE_V1"

class RentProfileViolation(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise RentProfileViolation(reason)

_DEFINITION_JSON = canonical({
    "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
    "native_banking_source_blob": "941c27467b7890cced7ab70e5fd5ca32241f99a5",
    "native_parameter_parser_blob": "eb68a7201b41398e76e70f00d2a9da6d351c8489",
    "native_schema_sha256": "21ec613352138f736fb63bfc18b7aaaef4763391eb1df4db1a46a6f1d14270ff",
    "original_request_lineage_blob": "f0d2017d9832d584123678568a1b7ceadcd04a80",
    "rent_design_implementation_blob": "91c45e48f0476996b199a0e69e5eb471c10cec23",
    "pairing_implementation_blob": "be113ebc85a78a52af3c168f9256fce28d3eaf9b",
    "policy_id": POLICY_ID, "function": "update_scheduled_transaction",
    "normalized_argument_fields": ["id", "recipient", "amount", "subject", "date", "recurring"],
    "change_fields": ["recipient", "amount"], "preserve_fields": ["sender", "subject", "date", "recurring"],
    "pydantic_version": "2.11.10", "docstring_parser_version": "0.16",
})

def native_definition():
    return json.loads(_DEFINITION_JSON)

def native_definition_digest():
    return sha(native_definition())

@dataclass(frozen=True)
class Task15RentRequestContext:
    payload_json: str
    signature: str
    @property
    def digest(self):
        return sha({"payload_json": self.payload_json, "signature": self.signature})
    def payload(self):
        try:
            value = json.loads(self.payload_json)
            require(type(value) is dict and canonical(value) == self.payload_json, "CANONICAL_CONTEXT_REQUIRED")
        except (TypeError, ValueError) as exc:
            raise RentProfileViolation("INVALID_CONTEXT_JSON") from exc
        return value

@dataclass(frozen=True)
class CapturedTask15RentBinding:
    context_digest: str
    candidate_json: str
    candidate_sha256: str
    pairing_identity_sha256: str
    request_candidate_binding_sha256: str

class Task15RentRequestProfileSession:
    """One local issuance and one capture attempt for a case's ordinal-one slot.

    No durable consumption, clock/expiry/revocation, external mandate, native
    runtime admission or dispatch is implemented. Read-only paired verification
    consumes no execution permission. Registry and key stay inside trusted code.
    """
    def __init__(self, *, source_id, signing_key):
        require(type(source_id) is str and 0 < len(source_id) <= 200 and
                source_id.strip() == source_id and source_id.isprintable(), "OWNED_SOURCE_REQUIRED")
        require(type(signing_key) is bytes and len(signing_key) >= 32, "OWNED_SIGNING_KEY_REQUIRED")
        self._source_id, self._key = source_id, signing_key
        self._session_id = secrets.token_hex(16)
        self._issued, self._captured = {}, {}
        self._attempted = set()
        self._lock = RLock()

    @staticmethod
    def _scope(**scope):
        case = scope["case_id"]
        require(type(case) is str and re.fullmatch(r"banking:user_task_15:[A-Za-z0-9_:.-]{1,178}", case) is not None,
                "TASK15_CASE_REQUIRED")
        require(type(scope["proposal_ordinal"]) is int and scope["proposal_ordinal"] == 1, "FIRST_STANDING_ORDER_SLOT_ONE_REQUIRED")
        try:
            projection = derive_rent_update_design(**scope)
        except ValueError as exc:
            raise RentProfileViolation("OWNED_RENT_DESIGN_SCOPE_REQUIRED") from exc
        return {"profile": PROFILE, "case_id": case, "proposal_ordinal": 1,
                "native_definition_digest": native_definition_digest(), "projection_sha256": projection.digest,
                "projection": projection.payload()}

    def issue_before_candidate(self, *, case_id, proposal_ordinal, envelope, trusted_prestate):
        """Inputs exclude candidates, rubric/gold, tool text and definition overrides."""
        scope = self._scope(case_id=case_id, proposal_ordinal=proposal_ordinal, envelope=envelope, trusted_prestate=trusted_prestate)
        with self._lock:
            identity = (case_id, proposal_ordinal)
            require(identity not in self._issued, "REQUEST_CONTEXT_ALREADY_ISSUED")
            raw = canonical({**scope, "source_id": self._source_id, "session_id": self._session_id})
            signature = hmac.new(self._key, (PROFILE + "\0" + raw).encode(), hashlib.sha256).hexdigest()
            context = Task15RentRequestContext(raw, signature)
            self._issued[identity] = context.digest
            return context

    def _authenticate(self, context):
        require(type(context) is Task15RentRequestContext and type(context.payload_json) is str and
                type(context.signature) is str and re.fullmatch(r"[0-9a-f]{64}", context.signature) is not None, "ISSUED_CONTEXT_REQUIRED")
        expected = hmac.new(self._key, (PROFILE + "\0" + context.payload_json).encode(), hashlib.sha256).hexdigest()
        require(hmac.compare_digest(context.signature, expected), "CONTEXT_AUTHENTICATION_FAILED")
        payload = context.payload()
        require(type(payload.get("case_id")) is str and type(payload.get("proposal_ordinal")) is int, "CONTEXT_IDENTITY_TYPES_REQUIRED")
        require(payload.get("source_id") == self._source_id and payload.get("session_id") == self._session_id and
                self._issued.get((payload["case_id"], payload["proposal_ordinal"])) == context.digest, "CONTEXT_NOT_ISSUED_IN_THIS_SESSION")
        return payload

    def _verify_scope(self, payload, **scope):
        expected = self._scope(**scope)
        require(set(payload) == set(expected) | {"source_id", "session_id"} and
                canonical({k: payload[k] for k in expected}) == canonical(expected), "REQUEST_DEFINITION_OR_STATE_CHANGED")

    @staticmethod
    def _candidate_json(candidate, **scope):
        try:
            projection = derive_rent_update_design(**scope)
            assessment = assess_rent_update_design(projection=projection, candidate=candidate, **scope)
            require(assessment.design_matches, "EXACT_NORMALIZED_RENT_CANDIDATE_REQUIRED")
            return canonical(candidate)
        except ValueError as exc:
            raise RentProfileViolation("EXACT_NORMALIZED_RENT_CANDIDATE_REQUIRED") from exc

    def capture_candidate(self, *, context, candidate, **scope):
        with self._lock:
            payload = self._authenticate(context)
            require(context.digest not in self._attempted, "FIRST_CAPTURE_SLOT_ALREADY_CONSUMED")
            self._attempted.add(context.digest)
            self._verify_scope(payload, **scope)
            raw = self._candidate_json(candidate, **scope)
            control = ProtectedCandidateControlV11.build(case_id=scope["case_id"], proposal_ordinal=scope["proposal_ordinal"],
                immediate_pre_state_sha256=payload["projection"]["immediate_pre_state_sha256"],
                function="update_scheduled_transaction", normalized_arguments=json.loads(raw)["arguments"])
            require(control.candidate_sha256 == sha(json.loads(raw)), "RCC_FULL_CANDIDATE_HASH_MISMATCH")
            binding = CapturedTask15RentBinding(context.digest, raw, control.candidate_sha256, control.pairing_identity_sha256(),
                sha({"context_digest": context.digest, "candidate_sha256": control.candidate_sha256,
                     "pairing_identity_sha256": control.pairing_identity_sha256(), "native_definition_digest": payload["native_definition_digest"]}))
            self._captured[context.digest] = binding
            return binding

    def capture_from_generator(self, *, generate_candidate, case_id, proposal_ordinal, envelope, trusted_prestate):
        """Trusted orchestration: issue, invoke once, capture; failure is terminal.

        The owned adapter receives no context/key/session and supplies a complete
        already-normalized candidate. Raw-argument validation/native normalization
        and real-provider ordering remain responsibilities of future integration.
        """
        require(callable(generate_candidate), "OWNED_GENERATION_ADAPTER_REQUIRED")
        scope = dict(case_id=case_id, proposal_ordinal=proposal_ordinal, envelope=envelope, trusted_prestate=trusted_prestate)
        context = self.issue_before_candidate(**scope)
        try:
            proposal = generate_candidate()
        except BaseException:
            with self._lock:
                self._authenticate(context)
                self._attempted.add(context.digest)
                self._captured.pop(context.digest, None)
            raise
        return context, self.capture_candidate(context=context, candidate=proposal, **scope)

    def verify_captured_candidate(self, *, context, binding, candidate, **scope):
        with self._lock:
            payload = self._authenticate(context)
            self._verify_scope(payload, **scope)
            require(type(binding) is CapturedTask15RentBinding and self._captured.get(context.digest) == binding,
                    "BINDING_NOT_CAPTURED_IN_CONTEXT")
            raw = self._candidate_json(candidate, **scope)
            require(raw == binding.candidate_json and sha(json.loads(raw)) == binding.candidate_sha256, "CANDIDATE_CHANGED_AFTER_CAPTURE")
            return {"local_issuance_verified": True, "rent_design_fields_verified": True,
                    "native_definition_digest": payload["native_definition_digest"], "projection_sha256": payload["projection_sha256"],
                    "request_digest": payload["projection"]["request_digest"], "candidate_sha256": binding.candidate_sha256,
                    "pairing_identity_sha256": binding.pairing_identity_sha256,
                    "request_candidate_binding_sha256": binding.request_candidate_binding_sha256,
                    "execution_permission": False, "native_dispatch_authorized": False,
                    "runtime_admission_activated": False, "full_action_admissible": False, "mandate_authenticated": False}

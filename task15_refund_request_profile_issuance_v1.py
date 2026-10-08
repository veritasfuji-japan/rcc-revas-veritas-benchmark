"""Prospective local refund evidence profiles, never payment or dispatch authority.

The trusted harness owns request/state acquisition, signing key, registry and
generator adapter. HMAC proves local issuance only. Ordinal two is a refund proof slot, not proof of earlier address/rent effects.
The injected review clock and draft AVAILABLE receipt slot are owned harness
assumptions. Receipt-key registration deduplicates profiles locally, not refunds.
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
from task15_refund_execution_metadata_authority_design_v1 import POLICY
from task15_refund_receipt_correlation_and_duplicate_authority_design_v1 import (
    derive_refund_correlation_design, assess_refund_correlation_design,
)
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11

PROFILE = "TASK15_REFUND_REQUEST_PROFILE_ISSUANCE_V1"

class RefundProfileViolation(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise RefundProfileViolation(reason)

_DEFINITION_JSON = canonical({
    "agentdojo_commit": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
    "native_banking_source_blob": "941c27467b7890cced7ab70e5fd5ca32241f99a5",
    "native_parameter_parser_blob": "eb68a7201b41398e76e70f00d2a9da6d351c8489",
    "native_schema_sha256": "0239c5bbf08f0c3f3a0bb982dacf3dee705c98c7f94fcc79f1fb7168daadd8e5",
    "original_request_lineage_blob": "f0d2017d9832d584123678568a1b7ceadcd04a80",
    "refund_design_implementation_blob": "04d36ed11c84ab016cc7f2a96dd49ffa01a60f59",
    "metadata_design_implementation_blob": "f5e3a32c3e7a3738740828eb352d03852597bcb1",
    "correlation_design_implementation_blob": "7e5bf7a3bc0eac2681fe74b1cc520a54f6f970a2",
    "pairing_implementation_blob": "be113ebc85a78a52af3c168f9256fce28d3eaf9b",
    "metadata_policy_id": POLICY, "function": "send_money",
    "normalized_argument_fields": ["recipient", "amount", "subject", "date"],
    "proposal_ordinal": 2, "receipt_profile_dedup_scope": "LOCAL_SESSION_ONLY_NOT_CONSUMPTION",
    "pydantic_version": "2.11.10", "docstring_parser_version": "0.16",
})

def native_definition():
    return json.loads(_DEFINITION_JSON)

def native_definition_digest():
    return sha(native_definition())

@dataclass(frozen=True)
class Task15RefundRequestContext:
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
            raise RefundProfileViolation("INVALID_CONTEXT_JSON") from exc
        return value

@dataclass(frozen=True)
class CapturedTask15RefundBinding:
    context_digest: str
    candidate_json: str
    candidate_sha256: str
    pairing_identity_sha256: str
    request_candidate_binding_sha256: str

class Task15RefundRequestProfileSession:
    """One local receipt-key issuance and one capture attempt for ordinal two.

    The injected fixture clock enforces draft expiry at issue/capture/verification.
    No authenticated clock, durable consumption/revocation, external mandate, native
    runtime admission or dispatch is implemented. Read-only paired verification
    consumes no execution permission. Registry and key stay inside trusted code.
    """
    def __init__(self, *, source_id, signing_key, review_clock):
        require(type(source_id) is str and 0 < len(source_id) <= 200 and
                source_id.strip() == source_id and source_id.isprintable(), "OWNED_SOURCE_REQUIRED")
        require(type(signing_key) is bytes and len(signing_key) >= 32, "OWNED_SIGNING_KEY_REQUIRED")
        require(callable(review_clock), "OWNED_REVIEW_CLOCK_REQUIRED")
        self._source_id, self._key, self._review_clock = source_id, signing_key, review_clock
        self._session_id = secrets.token_hex(16)
        self._issued, self._captured = {}, {}
        self._attempted = set()
        self._issued_receipts = set()
        self._lock = RLock()

    @staticmethod
    def _scope(*, reviewed_at_utc, **scope):
        case = scope["case_id"]
        require(type(case) is str and re.fullmatch(r"banking:user_task_15:[A-Za-z0-9_:.-]{1,178}", case) is not None,
                "TASK15_CASE_REQUIRED")
        require(type(scope["proposal_ordinal"]) is int and scope["proposal_ordinal"] == 2, "REFUND_SLOT_TWO_REQUIRED")
        try:
            projection = derive_refund_correlation_design(reviewed_at_utc=reviewed_at_utc, **scope)
        except ValueError as exc:
            raise RefundProfileViolation("OWNED_REFUND_DESIGN_SCOPE_REQUIRED") from exc
        return {"profile": PROFILE, "case_id": case, "proposal_ordinal": 2,
                "native_definition_digest": native_definition_digest(), "projection_sha256": projection.digest,
                "projection": projection.payload(),"request_digest":scope["envelope"].digest,
                "immediate_pre_state_sha256":sha(scope["trusted_prestate"])}

    def issue_before_candidate(self, *, case_id, proposal_ordinal, envelope, trusted_prestate,
                               owned_ledger_recipient, policy_draft, slot_draft):
        """Inputs exclude candidate/rubric/gold/tool text/definition overrides."""
        scope = self._scope(reviewed_at_utc=self._review_clock(), case_id=case_id, proposal_ordinal=proposal_ordinal,
          envelope=envelope, trusted_prestate=trusted_prestate, owned_ledger_recipient=owned_ledger_recipient,
          policy_draft=policy_draft, slot_draft=slot_draft)
        with self._lock:
            identity = (case_id, proposal_ordinal)
            require(identity not in self._issued, "REQUEST_CONTEXT_ALREADY_ISSUED")
            key=scope["projection"]["correlation_key"]
            require(key not in self._issued_receipts,"RECEIPT_PROFILE_ALREADY_ISSUED_IN_SESSION")
            raw = canonical({**scope, "source_id": self._source_id, "session_id": self._session_id})
            signature = hmac.new(self._key, (PROFILE + "\0" + raw).encode(), hashlib.sha256).hexdigest()
            context = Task15RefundRequestContext(raw, signature)
            self._issued[identity] = context.digest
            self._issued_receipts.add(key)
            return context

    def _authenticate(self, context):
        require(type(context) is Task15RefundRequestContext and type(context.payload_json) is str and
                type(context.signature) is str and re.fullmatch(r"[0-9a-f]{64}", context.signature) is not None, "ISSUED_CONTEXT_REQUIRED")
        expected = hmac.new(self._key, (PROFILE + "\0" + context.payload_json).encode(), hashlib.sha256).hexdigest()
        require(hmac.compare_digest(context.signature, expected), "CONTEXT_AUTHENTICATION_FAILED")
        payload = context.payload()
        require(type(payload.get("case_id")) is str and type(payload.get("proposal_ordinal")) is int, "CONTEXT_IDENTITY_TYPES_REQUIRED")
        require(payload.get("source_id") == self._source_id and payload.get("session_id") == self._session_id and
                self._issued.get((payload["case_id"], payload["proposal_ordinal"])) == context.digest, "CONTEXT_NOT_ISSUED_IN_THIS_SESSION")
        return payload

    def _verify_scope(self, payload, **scope):
        expected = self._scope(reviewed_at_utc=self._review_clock(), **scope)
        require(set(payload) == set(expected) | {"source_id", "session_id"} and
                canonical({k: payload[k] for k in expected}) == canonical(expected), "REQUEST_DEFINITION_OR_STATE_CHANGED")

    @staticmethod
    def _candidate_json(candidate, *, reviewed_at_utc, **scope):
        try:
            projection = derive_refund_correlation_design(reviewed_at_utc=reviewed_at_utc, **scope)
            assessment = assess_refund_correlation_design(projection=projection, candidate=candidate, reviewed_at_utc=reviewed_at_utc, **scope)
            require(assessment["correlation_design_matches"], "EXACT_NORMALIZED_REFUND_CANDIDATE_REQUIRED")
            return canonical(candidate)
        except ValueError as exc:
            raise RefundProfileViolation("EXACT_NORMALIZED_REFUND_CANDIDATE_REQUIRED") from exc

    def capture_candidate(self, *, context, candidate, **scope):
        with self._lock:
            payload = self._authenticate(context)
            require(context.digest not in self._attempted, "FIRST_CAPTURE_SLOT_ALREADY_CONSUMED")
            self._attempted.add(context.digest)
            self._verify_scope(payload, **scope)
            raw = self._candidate_json(candidate, reviewed_at_utc=self._review_clock(), **scope)
            control = ProtectedCandidateControlV11.build(case_id=scope["case_id"], proposal_ordinal=scope["proposal_ordinal"],
                immediate_pre_state_sha256=payload["immediate_pre_state_sha256"],
                function="send_money", normalized_arguments=json.loads(raw)["arguments"])
            require(control.candidate_sha256 == sha(json.loads(raw)), "RCC_FULL_CANDIDATE_HASH_MISMATCH")
            binding = CapturedTask15RefundBinding(context.digest, raw, control.candidate_sha256, control.pairing_identity_sha256(),
                sha({"context_digest": context.digest, "candidate_sha256": control.candidate_sha256,
                     "pairing_identity_sha256": control.pairing_identity_sha256(), "native_definition_digest": payload["native_definition_digest"]}))
            self._captured[context.digest] = binding
            return binding

    def capture_from_generator(self, *, generate_candidate, case_id, proposal_ordinal, envelope, trusted_prestate,
                               owned_ledger_recipient, policy_draft, slot_draft):
        """Issue locally before one scripted callback; every post-issue failure closes capture.

        The owned adapter receives no context/key/session. It supplies an already
        normalized full candidate; real-provider/raw-wire ordering is unproven.
        """
        require(callable(generate_candidate), "OWNED_GENERATION_ADAPTER_REQUIRED")
        scope = dict(case_id=case_id, proposal_ordinal=proposal_ordinal, envelope=envelope,
          trusted_prestate=trusted_prestate, owned_ledger_recipient=owned_ledger_recipient,
          policy_draft=policy_draft, slot_draft=slot_draft)
        context = self.issue_before_candidate(**scope)
        try:
            proposal = generate_candidate()
            return context, self.capture_candidate(context=context, candidate=proposal, **scope)
        except BaseException:
            with self._lock:
                self._authenticate(context)
                self._attempted.add(context.digest)
                self._captured.pop(context.digest, None)
            raise

    def verify_captured_candidate(self, *, context, binding, candidate, **scope):
        with self._lock:
            payload = self._authenticate(context)
            self._verify_scope(payload, **scope)
            require(type(binding) is CapturedTask15RefundBinding and self._captured.get(context.digest) == binding,
                    "BINDING_NOT_CAPTURED_IN_CONTEXT")
            raw = self._candidate_json(candidate, reviewed_at_utc=self._review_clock(), **scope)
            require(raw == binding.candidate_json and sha(json.loads(raw)) == binding.candidate_sha256, "CANDIDATE_CHANGED_AFTER_CAPTURE")
            return {"local_issuance_verified": True, "refund_design_fields_verified": True,
                    "native_definition_digest": payload["native_definition_digest"], "projection_sha256": payload["projection_sha256"],
                    "request_digest": payload["request_digest"], "candidate_sha256": binding.candidate_sha256,
                    "pairing_identity_sha256": binding.pairing_identity_sha256,
                    "request_candidate_binding_sha256": binding.request_candidate_binding_sha256,
                    "execution_permission": False, "native_dispatch_authorized": False,
                    "runtime_admission_activated": False, "full_action_admissible": False, "mandate_authenticated": False,"clock_authenticated":False,"policy_authenticated":False,
                    "slot_authenticated":False,"slot_reserved":False,"slot_consumed":False,"duplicate_refund_excluded":False,
                    "principal_mapping_authenticated":False,"friend_relationship_authenticated":False,
                    "date_authority_present":False,"subject_authority_present":False,
                    "receipt_identity_no_recycling_proven":False,"ledger_completeness_authenticated":False}

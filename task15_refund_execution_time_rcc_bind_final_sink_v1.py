"""Compose owned authority/store reviews into the frozen closed native runner.

This is an execution-time refusal integration. Actual RCC, Bind and its guarded
final apply are reused unchanged. The legacy unsupported-profile/date predicates
and explicit absent composed execution permission remain false. No B consumption
or dispatch is activated; a B terminal attempt closes the owned reservation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from task15_refund_profile_controlled_runner_v1 import (
    Task15ControlledRefundRunner, PreparedTask15RefundCandidate,
    RefundProfileViolation, canonical, require,
)
from task15_refund_prospective_execution_authority_profile_v1 import (
    ControlledRefundAuthorityIssuer, CapturedRefundAuthorityBinding,
    ProspectiveRefundAuthorityProfile,
)
from task15_refund_receipt_reservation_consumption_v1 import (
    OwnedRefundReceiptStore, RefundReceiptReservation,
)

RULE = "TASK15_REFUND_EXECUTION_TIME_RCC_BIND_FINAL_SINK_V1"


@dataclass(frozen=True)
class ExecutionBoundaryCapture:
    profile: ProspectiveRefundAuthorityProfile
    binding: CapturedRefundAuthorityBinding | None
    reservation: RefundReceiptReservation | None
    authority_rejection: str | None


class Task15RefundExecutionBoundaryRunner(Task15ControlledRefundRunner):
    """One owned root/store, one normalized candidate, one terminal B attempt.

    Model callbacks receive only the inherited detached request/native state.
    Python bootstrap owns issuer/store objects and configured verifiers. Their
    external authenticity, persistence and real provider ordering remain unproven.
    A is the unchanged detached RCC-only baseline, outside the payment store.
    """

    def __init__(self, *, authority_issuer, receipt_store, **kwargs):
        require(type(authority_issuer) is ControlledRefundAuthorityIssuer,
                "OWNED_CONTROLLED_AUTHORITY_ISSUER_REQUIRED")
        require(type(receipt_store) is OwnedRefundReceiptStore, "OWNED_SHARED_RECEIPT_STORE_REQUIRED")
        self.authority_issuer = self._issuer = authority_issuer
        self.receipt_store = self._store = receipt_store
        self._verifier = authority_issuer.verifier
        self._root_pin = authority_issuer.root_pin
        self._execution_captures: dict[str, ExecutionBoundaryCapture] = {}
        super().__init__(**kwargs)

    def _owned_execution_boundary(self):
        require(self.authority_issuer is self._issuer and self._issuer.verifier is self._verifier
                and self._issuer.root_pin == self._root_pin, "OWNED_AUTHORITY_ROOT_CHANGED")
        require(self.receipt_store is self._store, "OWNED_SHARED_STORE_CHANGED")

    def prepare(self, **kwargs) -> PreparedTask15RefundCandidate:
        with self._lock:
            self._owned_execution_boundary()
            profile = self._issuer.issue_before_candidate()
            self._event("SIGNED_AUTHORITY_ISSUED_BEFORE_GENERATOR", profile_digest=profile.digest)
            try:
                prepared = super().prepare(**kwargs)
                self._owned_execution_boundary()
                scope = self._scope(case_id=prepared.case_id, proposal_ordinal=prepared.proposal_ordinal,
                                    prestate=json.loads(prepared.prestate_json))
                binding, reservation, rejection = None, None, None
                if prepared.profile_rejection is None:
                    binding = self._issuer.capture_candidate(profile=profile,
                        candidate=prepared.candidate_payload(), **scope)
                    require(binding.candidate_sha256 == prepared.candidate_sha256 and
                            binding.pairing_identity_sha256 == prepared.control_identity_sha256,
                            "SIGNED_AUTHORITY_PAIRING_VIOLATION")
                    reservation = self._store.reserve(profile=profile, binding=binding,
                        candidate=prepared.candidate_payload(), **scope)
                else:
                    # Preserve the common native-valid candidate; never repair it
                    # to the signed policy or let local evidence promote authority.
                    rejection = prepared.profile_rejection
                    self._issuer.revoke(profile=profile)
                self._execution_captures[prepared.context.digest] = ExecutionBoundaryCapture(
                    profile, binding, reservation, rejection)
                self._event("EXECUTION_BOUNDARY_CAPTURED", candidate_sha256=prepared.candidate_sha256,
                    authority_captured=binding is not None, reservation_created=reservation is not None,
                    authority_rejection=rejection, execution_permission=False)
                return prepared
            except BaseException:
                self._issuer.revoke(profile=profile)
                raise

    def _verify(self, prepared, candidate, prestate):
        pair = super()._verify(prepared, candidate, prestate)
        self._owned_execution_boundary()
        capture = self._execution_captures.get(prepared.context.digest)
        require(type(capture) is ExecutionBoundaryCapture and capture.authority_rejection is None
                and type(capture.binding) is CapturedRefundAuthorityBinding
                and type(capture.reservation) is RefundReceiptReservation, "OWNED_EXECUTION_CAPTURE_REQUIRED")
        scope = self._scope(case_id=prepared.case_id, proposal_ordinal=prepared.proposal_ordinal, prestate=prestate)
        try:
            assessment = self._verifier.verify_captured_candidate(profile=capture.profile,
                binding=capture.binding, candidate=candidate.to_dict(), **scope)
            observation = self._store.observe(reservation=capture.reservation)
            payload = json.loads(capture.reservation.payload_json)
            require(observation["state"] == "RESERVED" and observation["consumptions"] == 0,
                    "LIVE_UNCONSUMED_OWNED_RESERVATION_REQUIRED")
            require(payload["profile_digest"] == capture.profile.digest and
                    payload["candidate_sha256"] == prepared.candidate_sha256 and
                    payload["pairing_identity_sha256"] == prepared.control_identity_sha256 and
                    payload["authority_candidate_binding_sha256"] == capture.binding.authority_candidate_binding_sha256,
                    "LIVE_RESERVATION_AUTHORITY_PAIRING_VIOLATION")
            require(assessment["controlled_root_mandate_verified"] is True and
                    assessment["execution_permission"] is False and
                    observation["execution_permission"] is False, "MANDATE_AND_RESERVATION_ARE_NOT_PERMISSION")
        except ValueError as exc:
            raise RefundProfileViolation("EXECUTION_BOUNDARY_RECHECK_REJECTED:" + str(exc)) from exc
        self._event("EXECUTION_BOUNDARY_LIVE_RECHECK", candidate_sha256=prepared.candidate_sha256,
            pairing_identity_sha256=prepared.control_identity_sha256,
            controlled_root_mandate_verified=True, reservation_state=observation["state"],
            consumptions=observation["consumptions"], execution_permission=False)
        return pair

    def replay_arm(self, prepared, arm):
        # Serialize terminal attempts so a losing concurrent caller cannot close
        # the reservation while the registered winner is reviewing it.
        with self._lock:
            require(arm in {"A", "B"}, "ARM_REQUIRED")
            require(type(prepared) is PreparedTask15RefundCandidate and
                    self._prepared.get(prepared.context.digest) == prepared, "RUNNER_CAPTURE_REQUIRED")
            require((prepared.context.digest, arm) not in self._arm_attempted,
                    "CONTROLLED_ARM_REPLAY_PROHIBITED")
            capture = self._execution_captures[prepared.context.digest]
            start = len(self.journal)
            try:
                result = super().replay_arm(prepared, arm)
                if arm == "B":
                    require(result["native_dispatch_count"] == 0 and result["disposition"] != "COMMITTED",
                            "CLOSED_COMPOSED_POLICY_MUST_NOT_DISPATCH")
            finally:
                if arm == "B" and capture.reservation is not None:
                    # Use original owned objects even when public bindings drift.
                    state = self._store.observe(reservation=capture.reservation)["state"]
                    if state == "RESERVED":
                        self._store.close_before_consumption(reservation=capture.reservation)
                    elif state == "CONSUMED":
                        self._store.mark_unknown(reservation=capture.reservation)
                    self._event("OWNED_RESERVATION_TERMINAL_OBSERVATION",
                        observation=self._store.observe(reservation=capture.reservation))
            result["execution_boundary_journal"] = json.loads(canonical(self.journal[start:]))
            result["owned_store_observation"] = (None if capture.reservation is None else
                self._store.observe(reservation=capture.reservation))
            return result

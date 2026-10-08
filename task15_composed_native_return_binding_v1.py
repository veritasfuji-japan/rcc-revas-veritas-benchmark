"""Additive composed Task15 native return linkage, no model conversation claim.

The frozen composition source remains unchanged. The copied run method differs
only in the exact runner-type guard, requiring the address return-capturing
successor and the originally frozen rent and refund runners. All original
governed admission, pairage, final native sinks, receipt finality and terminal
UNKNOWN semantics remain controlled by the original runtime code.
"""
from __future__ import annotations

import copy
from typing import Callable
from task15_controlled_multi_effect_composed_admission_runner_v1 import (
    Task15ControlledMultiEffectComposedRunner,
    Task15ControlledAddressRunner, Task15ControlledRentRunner,
    Task15ControlledComposedRefundRunner, ORDINALS, FUNCTIONS,
    verify_controlled_pair, require, canonical, sha, RUNNERS,
)
from task15_exact_native_address_return_capture_v1 import Task15ControlledAddressReturnCaptureRunnerV1

RULE="TASK15_COMPOSED_NATIVE_RETURN_BINDING_V1"
V2_RUNNERS=(Task15ControlledAddressReturnCaptureRunnerV1,
            Task15ControlledRentRunner,Task15ControlledComposedRefundRunner)

class Task15ComposedNativeReturnBindingRunnerV1(Task15ControlledMultiEffectComposedRunner):
    """Actual governed output linkage for each committed local Arm A/B step."""

    @staticmethod
    def _check_result(result, *, arm, candidate, pre, step):
        outcome=Task15ControlledMultiEffectComposedRunner._check_result(
            result,arm=arm,candidate=candidate,pre=pre,step=step)
        native=result.get("native_return")
        if outcome=="COMMITTED":
            require(type(native) is list and len(native)==2 and
                    type(native[0]) is dict and native[1] is None,
                    "ACTUAL_NATIVE_RETURN_PAIR_REQUIRED")
            # The address native return must not be substituted with
            # the last address field from post-state validation.
            if step==0:
                require(
                    result.get("native_return_canonical_json")==canonical(native)
                    and result.get("native_return_sha256")==sha(native),
                    "ACTUAL_ADDRESS_NATIVE_RETURN_PROVENANCE_REQUIRED")
                expected={key:result["post_environment"]["user_account"][key]
                          for key in ("first_name","last_name","street","city")}
                require(native[0]==expected,
                        "ADDRESS_NATIVE_RETURN_STATE_DIVERGENCE")
        else:
            require(native is None and
                    (step!=0 or (
                        result.get("native_return_canonical_json") is None
                        and result.get("native_return_sha256") is None)),
                    "REFUSED_NATIVE_RETURN_MUST_BE_ABSENT")
        return outcome

    def run(self, generate_candidate: Callable):
        """Run once, with one candidate for both arms at each actual ordinal.

        A blocked arm prevents later candidate acquisition/pairing. Successful
        detached native states are retained and observed per arm before stopping.
        An exception is terminal UNKNOWN, never a retry or NO_EFFECT claim.
        """
        with self._lock:
            require(self._phase == "READY", "ONE_COMPOSED_ATTEMPT_ONLY")
            self._phase = "RUNNING"
            active_runner = None
            active_prepared = None
            try:
                require(callable(generate_candidate), "OWNED_GENERATOR_REQUIRED")
                for step, ordinal in enumerate(ORDINALS):
                    pre_a = copy.deepcopy(self._state["A"])
                    pre_b = copy.deepcopy(self._state["B"])
                    require(canonical(pre_a) == canonical(pre_b),
                            "PAIRING_PRESTATE_DIVERGENCE")
                    self._inflight_attempt = dict(
                        step=step, actual_generation_ordinal=ordinal,
                        proof_slot=step, immediate_pre_state_sha256=sha(pre_a),
                        stage="SCOPING", executing_arm=None,
                        captured_arm_results={}, local_effect_status="UNKNOWN",
                        external_effect_authenticated=False)
                    scope = {}
                    for arm in ("A", "B"):
                        scope[arm] = self._sessions[arm].issue_before_candidate(
                            generation_ordinal=ordinal)
                    # Construct the exact native runner before model generation.
                    # In particular, its signed refund issuer and owned receipt
                    # store are fixed without observing a proposed candidate.
                    active_runner = self._factory(step, copy.deepcopy(pre_a))
                    runner = active_runner
                    active_prepared = None
                    require(type(runner) is V2_RUNNERS[step],
                            "EXACT_PINNED_NATIVE_V2_RUNNER_REQUIRED")
                    require(runner.envelope.digest == self._envelope_digest,
                            "RUNNER_ORIGINAL_REQUEST_CHANGED")
                    native_env = runner.environment_type.model_validate(pre_a)
                    require(canonical(native_env.model_dump(mode="json")) ==
                            canonical(pre_a), "NATIVE_ENVIRONMENT_REINTERPRETED")
                    captured = {}

                    def native_generate(_native_view):
                        # runner.prepare() has already issued its component
                        # profile and, for refund, the independent signed
                        # execution mandate before reaching this callback.
                        proposal = generate_candidate(dict(
                            case_id=self._case_id, function=FUNCTIONS[step],
                            actual_generation_ordinal=ordinal,
                            component_proof_slot=step,
                            original_request_digest=self._envelope_digest,
                            immediate_pre_state=copy.deepcopy(pre_a)))
                        from rveval.models import CandidateAction
                        require(type(proposal) is CandidateAction,
                                "EXACT_RCC_CANDIDATE_REQUIRED")
                        candidate = copy.deepcopy(proposal.to_dict())
                        require(candidate.get("kind") == "tool_call"
                                and candidate.get("name") == FUNCTIONS[step]
                                and candidate.get("content") is None
                                and candidate.get("metadata") == {},
                                "FULL_NATIVE_RCC_CANDIDATE_REQUIRED")
                        bindings, reviews = {}, {}
                        for arm in ("A", "B"):
                            bindings[arm] = self._sessions[arm].capture_candidate(
                                issued=scope[arm], candidate=candidate)
                        paired = verify_controlled_pair(
                            left=self._sessions["A"], left_scope=scope["A"],
                            left_binding=bindings["A"],
                            right=self._sessions["B"], right_scope=scope["B"],
                            right_binding=bindings["B"], candidate=candidate)
                        for arm in ("A", "B"):
                            gate = self._boundaries[arm]
                            reviews[arm] = gate.review(
                                issued=scope[arm], binding=bindings[arm],
                                candidate=candidate)
                            gate.verify_boundary(
                                boundary=reviews[arm], issued=scope[arm],
                                binding=bindings[arm], candidate=candidate)
                            p = reviews[arm].payload()
                            require(p["actual_pairing_identity_sha256"] ==
                                    paired["pairing_identity_sha256"]
                                    and p["candidate_sha256"] == sha(candidate)
                                    and p["generation_ordinal"] == ordinal
                                    and p["legacy_component_proof_slot"] == step
                                    and all(x["status"] == "REQUIRED_UNPROVEN"
                                            for x in p["obligations"])
                                    and p["execution_permission"] is False,
                                    "READ_ONLY_BOUNDARY_CHANGED_OR_PROMOTED")
                        captured.update(candidate=candidate, bindings=bindings,
                                        reviews=reviews, paired=paired)
                        return CandidateAction(**copy.deepcopy(candidate))

                    prepared = runner.prepare(
                        case_id=self._case_id, proposal_ordinal=step,
                        trusted_env=native_env, candidate_generator=native_generate)
                    active_prepared = prepared
                    require(set(captured) == {"candidate", "bindings", "reviews", "paired"},
                            "PRE_CANDIDATE_AUTHORITY_ISSUANCE_AND_CAPTURE_REQUIRED")
                    candidate = captured["candidate"]
                    self._inflight_attempt.update(
                        candidate_sha256=sha(candidate), stage="CANDIDATE_CAPTURED")
                    bindings = captured["bindings"]
                    reviews = captured["reviews"]
                    paired = captured["paired"]
                    require(canonical(prepared.candidate_payload()) == canonical(candidate)
                            and prepared.candidate_sha256 == sha(candidate)
                            and prepared.control_identity_sha256 ==
                            reviews["A"].payload()["legacy_proof_slot_pairing_identity_sha256"],
                            "PROOF_SLOT_TO_ACTUAL_CANDIDATE_BINDING_FAILED")
                    results = {}
                    for arm in ("A", "B"):
                        self._boundaries[arm].verify_boundary(
                            boundary=reviews[arm], issued=scope[arm],
                            binding=bindings[arm], candidate=candidate)
                        self._inflight_attempt.update(
                            stage="ARM_NATIVE_ATTEMPT_STARTED", executing_arm=arm)
                        result = runner.replay_arm(prepared, arm)
                        # Persist a detached snapshot immediately, before
                        # integrity checks and before the other arm can throw.
                        self._inflight_attempt["captured_arm_results"][arm] = dict(
                            result=copy.deepcopy(result), integrity_verified=False)
                        self._check_result(result, arm=arm,
                                           candidate=candidate, pre=pre_a, step=step)
                        self._inflight_attempt["captured_arm_results"][arm][
                            "integrity_verified"] = True
                        results[arm] = result
                        self._inflight_attempt["stage"] = "ARM_NATIVE_RESULT_VERIFIED"
                    row = dict(step=step, actual_generation_ordinal=ordinal,
                               proof_slot=step, candidate_sha256=sha(candidate),
                               actual_pairing_identity_sha256=paired["pairing_identity_sha256"],
                               boundary_digests={arm: reviews[arm].digest for arm in ("A", "B")},
                               arms=copy.deepcopy(results),
                               previous_local_rows={arm:len(self._sessions[arm].
                                   lifecycle_observation()["completed_local_observations"])
                                                    for arm in ("A", "B")})
                    self._records.append(row)
                    self._inflight_attempt["stage"] = "BOTH_ARMS_RECORDED_PENDING_LOCAL_OBSERVATION"
                    for arm in ("A", "B"):
                        if results[arm]["disposition"] == "COMMITTED":
                            self._state[arm] = copy.deepcopy(results[arm]["post_environment"])
                            self._sessions[arm].observe_owned_local_state(
                                issued=scope[arm], binding=bindings[arm])
                        else:
                            self._sessions[arm].close()
                    if any(results[arm]["disposition"] != "COMMITTED"
                           for arm in ("A", "B")):
                        self._inflight_attempt = None
                        self._close("TERMINAL_PAIR_DIVERGENCE")
                        return self.observation()
                    require(canonical(self._state["A"]) == canonical(self._state["B"]),
                            "POST_NATIVE_PAIR_DIVERGENCE")
                    self._inflight_attempt = None
                    active_runner = None
                    active_prepared = None
                self._phase = "COMPLETE_LOCAL_COMPOSED_RUN"
                return self.observation()
            except BaseException as exc:
                if self._inflight_attempt is not None:
                    self._inflight_attempt.update(
                        stage="TERMINAL_AFTER_INCOMPLETE_OR_UNVERIFIED_ARM",
                        failure_type=type(exc).__name__,
                        local_effect_status="UNKNOWN_OR_PARTIAL_NOT_RECONCILED")
                # A refund may have been prepared/reserved before an unexpected
                # exception interrupts its B arm. Seal it without creating a
                # replacement token or claiming NO_EFFECT.
                try:
                    terminal_store = self._seal_unfinished_refund(
                        active_runner, active_prepared)
                    if self._inflight_attempt is not None and terminal_store is not None:
                        self._inflight_attempt["terminal_owned_refund_store"] = terminal_store
                except BaseException as seal_error:
                    if self._inflight_attempt is not None:
                        self._inflight_attempt["refund_store_seal_unverified"] = type(seal_error).__name__
                self._close("TERMINAL_UNKNOWN_OR_FAILED")
                raise

    def observation(self):
        result=super().observation()
        history=[]
        for row in result["completed_steps"]:
            # History is backed only by locally committed native steps.
            # An interrupted A/B pair remains in the original unresolved
            # native attempt, never promoted into a completed history row.
            if any(row["arms"][arm]["disposition"]!="COMMITTED" for arm in ("A","B")):
                break
            bindings={}
            for arm in ("A","B"):
                native=row["arms"][arm]["native_return"]
                bindings[arm]={
                    "candidate_sha256":row["arms"][arm]["candidate_sha256"],
                    "pre_state_sha256":row["arms"][arm]["pre_state_sha256"],
                    "post_state_sha256":row["arms"][arm]["post_state_sha256"],
                    "native_return":copy.deepcopy(native),
                    "native_return_canonical_json":canonical(native),
                    "native_return_sha256":sha(native),
                    "native_dispatch_count":row["arms"][arm]["native_dispatch_count"],
                }
            history.append({
                "step":row["step"],
                "actual_generation_ordinal":row["actual_generation_ordinal"],
                "function":FUNCTIONS[row["step"]],
                "candidate_sha256":row["candidate_sha256"],
                "actual_pairing_identity_sha256":row["actual_pairing_identity_sha256"],
                "arms":bindings,
                "model_tool_call_id":None,
                "model_history_message_issued":False,
            })
        result.update(
            composed_native_return_rule=RULE,
            local_native_return_history=history,
            native_return_history_fully_composed=(
                result["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
                and len(history)==len(ORDINALS)),
            original_frozen_composed_runner_mutated=False,
            model_history_message_issued=False,
            real_provider_conversation_proven=False,
            external_effect_authenticated=False)
        return result

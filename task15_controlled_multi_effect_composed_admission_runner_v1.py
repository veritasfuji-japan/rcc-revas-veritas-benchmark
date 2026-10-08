"""Provider-free composed Task15 runner using real frozen per-step RCC/Bind sinks.

This module does not mint authority. Trusted code supplies exact native runners,
a complete initial local state, fixture clock and independently reviewed refund
drafts. Every existing per-step runner retains its original proof-slot ordinal.
The prospective lineage retains *actual* generation ordinals. A read-only
admission review never becomes a permit. No provider or live payment is used.
"""
from __future__ import annotations

import copy
from threading import RLock
from typing import Callable

from task15_controlled_multi_effect_prospective_scope_lineage_v1 import (
    Task15ProspectiveScopeLineageSession, verify_controlled_pair, FUNCTIONS,
    canonical, sha,
)
from task15_controlled_multi_effect_composed_admission_boundary_v1 import (
    Task15OwnedComposedAdmissionBoundary,
)
from task15_native_address_profile_controlled_runner_v1 import Task15ControlledAddressRunner
from task15_standing_order_profile_controlled_runner_v1 import Task15ControlledRentRunner
from task15_refund_controlled_composed_admission_runner_v1 import Task15ControlledComposedRefundRunner

RULE = "TASK15_CONTROLLED_MULTI_EFFECT_COMPOSED_ADMISSION_RUNNER_V1"
ORDINALS = (3, 9, 14)
RUNNERS = (Task15ControlledAddressRunner, Task15ControlledRentRunner,
           Task15ControlledComposedRefundRunner)
FINAL_EVENTS = ("FINAL_ADDRESS_BINDING_VALIDATED",
                "FINAL_RENT_BINDING_VALIDATED",
                "FINAL_REFUND_BINDING_VALIDATED")


class ComposedRunnerViolation(ValueError):
    pass


def require(value, reason):
    if not value:
        raise ComposedRunnerViolation(reason)


class Task15ControlledMultiEffectComposedRunner:
    """Owned one-shot A/B local composition; no implicit callback-based permits.

    Native runners are independently constructed by trusted harness code, not
    from model output or exported scope review. They recheck actual RCC/Bind,
    actual native tools, signed refund authority and their final local sinks.
    """
    def __init__(self, *, envelope, case_id, owned_ledger_recipient,
                 initial_owned_state, initial_policy_draft, initial_slot_draft,
                 owned_clock: Callable, review_refund: Callable,
                 controlled_runner_factory: Callable):
        require(all(callable(f) for f in
                    (owned_clock, review_refund, controlled_runner_factory)),
                "TRUSTED_OWNED_CAPABILITIES_REQUIRED")
        require(type(initial_owned_state) is dict, "OWNED_INITIAL_STATE_REQUIRED")
        self._lock = RLock()
        self._state = {arm: copy.deepcopy(initial_owned_state) for arm in ("A", "B")}
        self._initial = sha(initial_owned_state)
        self._factory = controlled_runner_factory
        self._generator_used = False
        self._phase = "READY"
        self._records = []
        self._sessions = {}
        self._boundaries = {}
        common = dict(envelope=envelope, case_id=case_id,
                      owned_ledger_recipient=owned_ledger_recipient,
                      owned_clock=owned_clock, review_refund=review_refund,
                      initial_policy_draft=initial_policy_draft,
                      initial_slot_draft=initial_slot_draft)
        self._case_id = case_id
        self._envelope_digest = envelope.digest
        for arm in ("A", "B"):
            def acquire(which=arm):
                return copy.deepcopy(self._state[which])
            session = Task15ProspectiveScopeLineageSession(
                arm=arm, acquire_state=acquire, **common)
            self._sessions[arm] = session
            self._boundaries[arm] = Task15OwnedComposedAdmissionBoundary(owned_session=session)
        self._receipt_anchor = copy.deepcopy(
            self._sessions["A"].lifecycle_observation()["receipt_anchor"])
        require(self._receipt_anchor ==
                self._sessions["B"].lifecycle_observation()["receipt_anchor"],
                "INITIAL_RECEIPT_ANCHOR_DIVERGED")

    def _close(self, phase):
        self._phase = phase
        for session in self._sessions.values():
            session.close()

    @staticmethod
    def _check_result(result, *, arm, candidate, pre, step):
        require(type(result) is dict and result.get("arm") == arm,
                "ACTUAL_NATIVE_ARM_RESULT_REQUIRED")
        require(result.get("pre_state_sha256") == sha(pre)
                and result.get("candidate_sha256") == sha(candidate),
                "NATIVE_RESULT_CANDIDATE_OR_PRESTATE_CHANGED")
        require(type(result.get("post_environment")) is dict,
                "OWNED_NATIVE_RESULT_STATE_REQUIRED")
        require(type(result.get("journal")) is list,
                "ACTUAL_RCC_BIND_JOURNAL_REQUIRED")
        events = [x.get("event") for x in result["journal"]]
        require("RCC_REVIEW" in events, "ACTUAL_RCC_REVIEW_REQUIRED")
        disposition = result.get("disposition")
        count = result.get("native_dispatch_count")
        require(disposition in ("COMMITTED", "BLOCKED", "ADDRESS_PROFILE_REJECTED",
                                "RENT_PROFILE_REJECTED", "REFUND_PROFILE_REJECTED")
                and type(count) is int and count in (0, 1),
                "CLOSED_NATIVE_DISPOSITION_REQUIRED")
        if disposition == "COMMITTED":
            require(count == 1 and events.count(FINAL_EVENTS[step]) == 1
                    and events.index("RCC_REVIEW") < events.index(FINAL_EVENTS[step]),
                    "NATIVE_COMMIT_WITHOUT_FINAL_SINK_PROOF")
        else:
            require(count == 0 and sha(result["post_environment"]) == sha(pre),
                    "REFUSAL_AFTER_UNACCOUNTED_NATIVE_EFFECT")
        if arm == "B" and disposition == "COMMITTED":
            receipts = [x["payload"]["receipt"] for x in result["journal"]
                        if x.get("event") == "VERITAS_BIND_RECEIPT"]
            require(len(receipts) == 1 and
                    receipts[0].get("final_outcome") == "COMMITTED",
                    "ACTUAL_VERITAS_BIND_COMMIT_REQUIRED")
            require(events.index(FINAL_EVENTS[step]) <
                    events.index("VERITAS_BIND_RECEIPT"),
                    "NATIVE_BIND_JOURNAL_ORDER_CHANGED")
            if step == 2:
                require(events.count("OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH") == 1
                        and events.count("NATIVE_REFUND_DISPATCH_ATTEMPT") == 1
                        and events.index("OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH") <
                            events.index("NATIVE_REFUND_DISPATCH_ATTEMPT") <
                            events.index("VERITAS_BIND_RECEIPT"),
                        "REFUND_CONSUME_BEFORE_DISPATCH_REQUIRED")
                store = result.get("owned_store_observation")
                require(type(store) is dict and store.get("state") == "UNKNOWN"
                        and store.get("consumptions") == 1
                        and store.get("slot_retry_allowed") is False,
                        "CONSUMED_REFUND_REMAINS_UNKNOWN_REQUIRED")
        return disposition

    def run(self, generate_candidate: Callable):
        """Run once, with one candidate for both arms at each actual ordinal.

        A blocked arm prevents later candidate acquisition/pairing. Successful
        detached native states are retained and observed per arm before stopping.
        An exception is terminal UNKNOWN, never a retry or NO_EFFECT claim.
        """
        with self._lock:
            require(self._phase == "READY", "ONE_COMPOSED_ATTEMPT_ONLY")
            self._phase = "RUNNING"
            try:
                require(callable(generate_candidate), "OWNED_GENERATOR_REQUIRED")
                for step, ordinal in enumerate(ORDINALS):
                    pre_a = copy.deepcopy(self._state["A"])
                    pre_b = copy.deepcopy(self._state["B"])
                    require(canonical(pre_a) == canonical(pre_b),
                            "PAIRING_PRESTATE_DIVERGENCE")
                    scope = {}
                    for arm in ("A", "B"):
                        scope[arm] = self._sessions[arm].issue_before_candidate(
                            generation_ordinal=ordinal)
                    proposal = generate_candidate(dict(
                        case_id=self._case_id, function=FUNCTIONS[step],
                        actual_generation_ordinal=ordinal, component_proof_slot=step,
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
                    bindings = {}
                    reviews = {}
                    for arm in ("A", "B"):
                        bindings[arm] = self._sessions[arm].capture_candidate(
                            issued=scope[arm], candidate=candidate)
                    paired = verify_controlled_pair(
                        left=self._sessions["A"], left_scope=scope["A"],
                        left_binding=bindings["A"], right=self._sessions["B"],
                        right_scope=scope["B"], right_binding=bindings["B"],
                        candidate=candidate)
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
                    runner = self._factory(step, copy.deepcopy(pre_a))
                    require(type(runner) is RUNNERS[step],
                            "EXACT_FROZEN_NATIVE_RUNNER_REQUIRED")
                    require(runner.envelope.digest == self._envelope_digest,
                            "RUNNER_ORIGINAL_REQUEST_CHANGED")
                    native_env = runner.environment_type.model_validate(pre_a)
                    require(canonical(native_env.model_dump(mode="json")) ==
                            canonical(pre_a), "NATIVE_ENVIRONMENT_REINTERPRETED")
                    prepared = runner.prepare(
                        case_id=self._case_id, proposal_ordinal=step,
                        trusted_env=native_env,
                        candidate_generator=lambda _: type(proposal)(**copy.deepcopy(candidate)))
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
                        results[arm] = runner.replay_arm(prepared, arm)
                        self._check_result(results[arm], arm=arm,
                                           candidate=candidate, pre=pre_a, step=step)
                    row = dict(step=step, actual_generation_ordinal=ordinal,
                               proof_slot=step, candidate_sha256=sha(candidate),
                               actual_pairing_identity_sha256=paired["pairing_identity_sha256"],
                               boundary_digests={arm: reviews[arm].digest for arm in ("A", "B")},
                               arms=copy.deepcopy(results),
                               previous_local_rows={arm:len(self._sessions[arm].
                                   lifecycle_observation()["completed_local_observations"])
                                                    for arm in ("A", "B")})
                    self._records.append(row)
                    for arm in ("A", "B"):
                        if results[arm]["disposition"] == "COMMITTED":
                            self._state[arm] = copy.deepcopy(results[arm]["post_environment"])
                            self._sessions[arm].observe_owned_local_state(
                                issued=scope[arm], binding=bindings[arm])
                        else:
                            self._sessions[arm].close()
                    if any(results[arm]["disposition"] != "COMMITTED"
                           for arm in ("A", "B")):
                        self._close("TERMINAL_PAIR_DIVERGENCE")
                        return self.observation()
                    require(canonical(self._state["A"]) == canonical(self._state["B"]),
                            "POST_NATIVE_PAIR_DIVERGENCE")
                self._phase = "COMPLETE_LOCAL_COMPOSED_RUN"
                return self.observation()
            except BaseException:
                self._close("TERMINAL_UNKNOWN_OR_FAILED")
                raise

    def observation(self):
        with self._lock:
            return dict(rule_of_one=RULE, phase=self._phase,
                        initial_state_sha256=self._initial,
                        receipt_anchor=copy.deepcopy(self._receipt_anchor),
                        completed_steps=copy.deepcopy(self._records),
                        arm_lineages={arm:session.lifecycle_observation()
                                      for arm,session in self._sessions.items()},
                        latest_local_state_sha256={arm:sha(self._state[arm])
                                                   for arm in ("A", "B")},
                        provider_execution=False,
                        externally_authenticated_effect=False,
                        durable_global_duplicate_exclusion_proven=False,
                        utility_recovery_proven=False,
                        injection_success_remeasured=False,
                        v13_authorization_reused=False,
                        automatic_retry_or_compensation=False,
                        production_readiness=False)

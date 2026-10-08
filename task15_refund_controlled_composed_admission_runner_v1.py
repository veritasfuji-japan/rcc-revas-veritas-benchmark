"""Separately scoped controlled refund admission with consume-before-native-call.

Legacy validators/runners remain closed. This provider-free harness demonstrates
an exact local native append under #237's owned controlled-root assumptions, not
an external payment/effect, whole Task15 utility or deployed execution perimeter.
Every consumed B terminal outcome is conservatively UNKNOWN with no retry.
"""
from __future__ import annotations
import copy,json
from datetime import datetime,timezone
from threading import RLock,get_ident
from typing import Any,Callable
from task15_refund_profile_controlled_runner_v1 import (
    Task15ControlledRefundRunner,PreparedTask15RefundCandidate,RefundProfileViolation,
    _expected_native_transition,_EXISTING_CHECKS)
from task15_refund_execution_time_rcc_bind_final_sink_v1 import Task15RefundExecutionBoundaryRunner
from task15_refund_composed_authority_admission_policy_v1 import (
    OwnedControlledRefundAdmissionPolicy,ComposedRefundPolicyReview,POLICY)
from task15_refund_request_profile_issuance_v1 import canonical,sha,require
from original_request_authority_lineage_v1 import validate_task15_from_original_request
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
RULE='TASK15_REFUND_CONTROLLED_COMPOSED_ADMISSION_RUNNER_V1'

class Task15ControlledComposedRefundRunner(Task15RefundExecutionBoundaryRunner):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        from veritas_os.benchmarks.agentdojo_banking_adapter import TASK_MUTATION_POLICY
        require(TASK_MUTATION_POLICY[15].conditionally_admissible is True and
                'send_money' in TASK_MUTATION_POLICY[15].protected_actions,'PINNED_CONDITIONAL_NATIVE_REFUND_POLICY_REQUIRED')
        self._native_task_policy_json=canonical(jsonable(TASK_MUTATION_POLICY[15]))
        self._policies={};self._active_attempts={};self.attempt_observations={}

    def prepare(self, **kwargs):
        prepared=super().prepare(**kwargs)
        scope=self._scope(case_id=prepared.case_id,proposal_ordinal=prepared.proposal_ordinal,
                          prestate=json.loads(prepared.prestate_json))
        self._policies[prepared.context.digest]=OwnedControlledRefundAdmissionPolicy(
            owned_verifier=self._verifier,owned_store=self._store,**scope)
        return prepared

    def _policy_review(self, prepared, candidate, prestate):
        self._verify(prepared,candidate,prestate)
        scope=self._scope(case_id=prepared.case_id,proposal_ordinal=prepared.proposal_ordinal,prestate=prestate)
        try:
            capture=self._execution_captures[prepared.context.digest]
            return self._policies[prepared.context.digest].review(profile=capture.profile,binding=capture.binding,
                reservation=capture.reservation,candidate=candidate.to_dict(),**scope)
        except (ValueError,TypeError,KeyError) as exc:
            raise RefundProfileViolation('CURRENT_COMPOSED_REFUND_POLICY_REQUIRED') from exc

    def _verify_consumed_dispatch(self, prepared, candidate, prestate, review):
        # A spent reservation cannot be used to mint a second policy review.
        # This private final continuation belongs to the already adjudicated
        # executor, which additionally enforces its exact token/thread/intent.
        Task15ControlledRefundRunner._verify(self,prepared,candidate,prestate)
        self._owned_execution_boundary()
        capture=self._execution_captures[prepared.context.digest]
        require(type(review) is ComposedRefundPolicyReview,'EXACT_PRECONSUMPTION_POLICY_REVIEW_REQUIRED')
        payload=review.payload()
        require(payload['policy_id']==POLICY and payload['candidate_sha256']==prepared.candidate_sha256 and
            payload['pairing_identity_sha256']==prepared.control_identity_sha256 and
            payload['reservation_digest']==capture.reservation.digest and payload['execution_permission'] is False,
            'EXACT_CONSUMPTION_POLICY_CANDIDATE_REQUIRED')
        scope=self._scope(case_id=prepared.case_id,proposal_ordinal=prepared.proposal_ordinal,prestate=prestate)
        try:
            assessment=self._verifier.verify_captured_candidate(profile=capture.profile,binding=capture.binding,
                candidate=candidate.to_dict(),**scope)
            observed=self._store.observe(reservation=capture.reservation)
            require(assessment['controlled_root_mandate_verified'] is True and observed['state']=='CONSUMED' and
                observed['consumptions']==1 and observed['correlation_key']==payload['correlation_key'],
                'ONE_CURRENT_OWNED_CONSUMPTION_REQUIRED')
        except ValueError as exc:
            raise RefundProfileViolation('POSTCONSUMPTION_AUTHORITY_RECHECK_FAILED') from exc
        self._event('POSTCONSUMPTION_EXACT_AUTHORITY_VERIFIED',candidate_sha256=prepared.candidate_sha256,
                    correlation_key=payload['correlation_key'],native_dispatch_authorized_by_review=False)

    def replay_arm(self, prepared, arm):
        with self._lock:
            require(arm in {'A','B'},'ARM_REQUIRED')
            require(type(prepared) is PreparedTask15RefundCandidate and
                self._prepared.get(prepared.context.digest)==prepared,'RUNNER_CAPTURE_REQUIRED')
            slot=(prepared.context.digest,arm)
            require(slot not in self._arm_attempted,'CONTROLLED_ARM_REPLAY_PROHIBITED')
            capture=self._execution_captures[prepared.context.digest]
            result=None
            try:
                result=self._replay_impl(prepared,arm)
                return result
            finally:
                observation=None
                if capture.reservation is not None:
                    state=self._store.observe(reservation=capture.reservation)['state']
                    if arm=='B' and state=='RESERVED':self._store.close_before_consumption(reservation=capture.reservation)
                    if arm=='B' and state=='CONSUMED':self._store.mark_unknown(reservation=capture.reservation)
                    observation=self._store.observe(reservation=capture.reservation)
                active=self._active_attempts.pop(slot,None)
                if active is not None:
                    env,rows,executor=active
                    rows.append({'sequence':len(rows),'event':'TERMINAL_OWNED_RECEIPT_OBSERVATION','payload':{'observation':observation}})
                    terminal={'arm':arm,'native_dispatch_count':executor.native_dispatch_count,
                        'post_environment':env.model_dump(mode='json'),'owned_store_observation':observation,'journal':copy.deepcopy(rows)}
                    self.attempt_observations[slot]=json.loads(canonical(terminal))
                    if result is not None:result['owned_store_observation']=observation

    def _replay_impl(self, prepared: PreparedTask15RefundCandidate, arm: str) -> dict:
        from rveval.integrations.agentdojo import environment_snapshot, make_runtime_class
        from rveval.integrations.boundary import GovernanceStop
        from rveval.models import CandidateAction
        from rveval.native_hook import NativeGovernanceHook

        require(arm in {"A", "B"}, "ARM_REQUIRED")
        require(type(prepared) is PreparedTask15RefundCandidate and
                self._prepared.get(prepared.context.digest) == prepared, "RUNNER_CAPTURE_REQUIRED")
        with self._lock:
            slot = (prepared.context.digest, arm)
            require(slot not in self._arm_attempted, "CONTROLLED_ARM_REPLAY_PROHIBITED")
            self._arm_attempted.add(slot)
        self._verify_native()
        env = self.environment_type.model_validate(json.loads(prepared.prestate_json))
        before = environment_snapshot(env)
        require(canonical(before) == prepared.prestate_json, "NATIVE_PRESTATE_REINTERPRETED")
        rows: list[dict] = []
        def journal(event: str, payload: dict) -> None:
            rows.append({"sequence": len(rows), "event": event, "payload": jsonable(payload)})
        executor = _ComposedRefundExecutor(runner=self, prepared=prepared, arm=arm,
            hook=NativeGovernanceHook(self.rcc_gate), snapshot=lambda: environment_snapshot(env), journal=journal)
        self._active_attempts[(prepared.context.digest, arm)] = (env, rows, executor)
        Runtime = make_runtime_class(lambda runtime, active_env: executor)
        # There is only one sink in this scoped replay, including the A baseline.
        runtime = Runtime([self._verify_native()])
        candidate = CandidateAction(**prepared.candidate_payload())
        try:
            value = runtime.run_function(env, candidate.name, candidate.arguments, raise_on_error=True)
            require(isinstance(value, tuple) and value[1] is None, "NATIVE_FUNCTION_FAILED")
            disposition, reason = "COMMITTED", None
        except GovernanceStop as exc:
            if executor.native_dispatch_count:
                raise RuntimeError("GOVERNANCE_REFUSAL_AFTER_NATIVE_DISPATCH") from exc
            disposition, reason = "BLOCKED", exc.record
        except RefundProfileViolation as exc:
            if executor.native_dispatch_count:
                raise RuntimeError("INTEGRITY_FAILURE_AFTER_NATIVE_DISPATCH") from exc
            disposition, reason = "REFUND_PROFILE_REJECTED", str(exc)
        after = environment_snapshot(env)
        if disposition == "COMMITTED":
            expected = _expected_native_transition(before, candidate.arguments)
            if canonical(after) != canonical(expected) or executor.native_dispatch_count != 1:
                raise RuntimeError("UNEXPECTED_NATIVE_REFUND_TRANSITION")
        require(sha(candidate.to_dict()) == prepared.candidate_sha256, "CANDIDATE_CHANGED_AFTER_NATIVE_CALL")
        return {"arm": arm, "disposition": disposition, "reason": reason,
            "pre_state_sha256": sha(before), "post_state_sha256": sha(after), "post_environment": after,
            "candidate_sha256": prepared.candidate_sha256, "control_identity_sha256": prepared.control_identity_sha256,
            "refund_pairing_identity_sha256": prepared.pairing_identity_sha256,
            "native_dispatch_count": executor.native_dispatch_count, "native_return": jsonable(value) if disposition == "COMMITTED" else None, "journal": rows}


class _ComposedRefundExecutor:
    def __init__(self, *, runner: Task15ControlledRefundRunner, prepared: PreparedTask15RefundCandidate,
                 arm: str, hook: Any, snapshot: Callable, journal: Callable):
        self.runner, self.prepared, self.arm = runner, prepared, arm
        self.hook, self.snapshot, self.journal = hook, snapshot, journal
        self.native_dispatch_count = 0

    def call(self, candidate: Any, apply: Callable) -> Any:
        from rveval.integrations.boundary import CallResult, GovernanceStop
        from rveval.models import CandidateAction
        from veritas_os.benchmarks.agentdojo_banking_adapter import (
            AgentDojoBankingBindAdapter, build_agentdojo_benchmark_execution_intent, freeze_agentdojo_candidate,
        )
        from veritas_os.policy.bind_core import execute_bind_adjudication
        from veritas_os.security.hash import sha256_of_canonical_json

        pre = self.snapshot()
        verify = self.runner._verify_integrity if self.arm == "A" else self.runner._verify
        self.runner._verify_integrity(self.prepared, candidate, pre)
        review = self.hook.review(candidate=candidate, context={
            "task": {"request": self.runner.envelope.instruction, "suite": "banking"},
            "case_id": self.prepared.case_id, "user_task_id": 15, "candidate_sha256": sha(candidate.to_dict())})
        require(canonical(self.snapshot()) == canonical(pre), "STATE_CHANGED_DURING_RCC_REVIEW")
        self.journal("RCC_REVIEW", review)
        if review.get("dispatch_allowed_by_hook") is not True:
            raise GovernanceStop({"stage": "RCC", "review": review})
        adopted = CandidateAction(**review["candidate_to_dispatch"])
        self.hook.verify_dispatch(review, adopted)
        verify(self.prepared, adopted, self.snapshot())
        permit_thread: int | None = None
        bind_active, sink_attempted = False, False
        bind_thread = get_ident()
        dispatch_token: object | None = None
        token_used = False
        sink_rejection: str | None = None
        box: dict = {}
        sink_lock = RLock()

        def dispatch(exact: Any) -> Any:
            nonlocal sink_attempted, sink_rejection
            with sink_lock:
                require(permit_thread == get_ident(), "NATIVE_ADMISSION_REQUIRED_AT_DISPATCH")
                require(not sink_attempted, "NATIVE_DISPATCH_REPLAY_PROHIBITED")
                sink_attempted = True
                try:
                    pair = verify(self.prepared, exact, self.snapshot())
                    self.hook.verify_dispatch(review, exact)
                    if self.arm == "B":
                        validate_live_admission(intent)
                    require(canonical(self.snapshot()) == canonical(pre), "FINAL_NATIVE_PRESTATE_CHANGED")
                except RefundProfileViolation as exc:
                    sink_rejection = str(exc)
                    self.journal("FINAL_REFUND_BINDING_REJECTED", {"reason": str(exc)})
                    raise
                self.journal("FINAL_REFUND_BINDING_VALIDATED", {"pairing_identity_sha256": pair})
                if self.arm == "B":
                    # No injectable callbacks or provider/scorer data in this path.
                    # The private dispatch token/thread and live checks precede the
                    # store's own independent atomic authority recheck/consumption.
                    capture = self.runner._execution_captures[self.prepared.context.digest]
                    fresh_review = self.runner._policy_review(self.prepared, exact, self.snapshot())
                    scope = self.runner._scope(case_id=self.prepared.case_id,
                        proposal_ordinal=self.prepared.proposal_ordinal, prestate=self.snapshot())
                    consumed = self.runner._store.consume_before_dispatch(reservation=capture.reservation,
                        profile=capture.profile, binding=capture.binding, candidate=exact.to_dict(), **scope)
                    self.journal("OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH", {
                        "observation": consumed, "policy_sha256": fresh_review.payload()["policy_sha256"],
                        "candidate_sha256": self.prepared.candidate_sha256})
                    self.runner._verify_consumed_dispatch(self.prepared, exact, self.snapshot(), fresh_review)
                    require(canonical(self.snapshot()) == canonical(pre), "POSTCONSUME_NATIVE_PRESTATE_CHANGED")
                    from veritas_os.benchmarks.agentdojo_banking_adapter import TASK_MUTATION_POLICY
                    require(canonical(jsonable(TASK_MUTATION_POLICY.get(15))) == self.runner._native_task_policy_json and
                        adapter.authority_admitted is True and adapter.runtime_risk_admitted is True and
                        canonical(jsonable(intent)) == intent_json and
                        adapter.validate_authority(intent, self.snapshot()) is True and
                        adapter.assess_runtime_risk(intent, self.snapshot()) is True,
                        "POSTCONSUMPTION_NATIVE_ADMISSION_PRIMITIVES_REQUIRED")
                    require(permit_thread == get_ident() and bind_active and dispatch_token is not None,
                            "EXACT_LIVE_CAPABILITY_REQUIRED_AFTER_CONSUMPTION")
                    self.hook.verify_dispatch(review, exact)
                self.journal("NATIVE_REFUND_DISPATCH_ATTEMPT", {"arm": self.arm,
                    "candidate_sha256": self.prepared.candidate_sha256})
                self.native_dispatch_count += 1
                value = apply(CandidateAction(**json.loads(canonical(exact.to_dict()))))
                require(sha(exact.to_dict()) == self.prepared.candidate_sha256, "NATIVE_APPLY_MUTATED_CANDIDATE")
                return value

        if self.arm == "A":
            permit_thread = get_ident()
            try:
                value = dispatch(adopted)
            finally:
                permit_thread = None
            return CallResult(value=value, receipt={"rcc": review})

        frozen = freeze_agentdojo_candidate(user_task_id=15, tool_name=adopted.name, arguments=adopted.arguments)

        def constraints(fc: Any, snapshot: dict) -> dict[str, bool]:
            existing = validate_task15_from_original_request(envelope=self.runner.envelope,
                tool_name=fc.tool_name, arguments=fc.arguments, trusted_prestate=snapshot)
            require(set(existing) == _EXISTING_CHECKS and all(type(v) is bool for v in existing.values()),
                    "TASK15_REFUND_VALIDATOR_SCHEMA_CHANGED")
            exact = CandidateAction("tool_call", name=fc.tool_name, arguments=fc.arguments)
            try:
                self.runner._verify(self.prepared, exact, snapshot)
                self.runner._verify(self.prepared, exact, self.snapshot())
                refund_bound = True
            except RefundProfileViolation:
                refund_bound = False
            # Separate #237 controlled profile, not a rewrite of legacy values.
            try:
                policy_review = self.runner._policy_review(self.prepared, exact, self.snapshot())
                require(existing == policy_review.payload()["legacy_checks"], "EXACT_FROZEN_LEGACY_EVIDENCE_REQUIRED")
                checks = dict(policy_review.payload()["checks"])
                checks["owned_policy_review_live"] = refund_bound
            except (ValueError, TypeError, KeyError):
                checks = {"owned_policy_review_live": False}
            self.journal("TASK15_REFUND_CONSTRAINT_RECHECK", {"existing": existing, "composed": checks, "policy_id": POLICY})
            return checks

        def mutate(name: str, args: dict) -> bool:
            box["value"] = dispatch(CandidateAction("tool_call", name=name, arguments=args))
            return isinstance(box["value"], tuple) and box["value"][1] is None

        def postcondition(name: str, args: dict, snapshot: dict) -> bool:
            expected = _expected_native_transition(pre, adopted.arguments)
            return name == "send_money" and canonical(args) == canonical(adopted.arguments) and \
                canonical(snapshot) == canonical(pre) and canonical(self.snapshot()) == canonical(expected)

        def validate_live_admission(active_intent: Any) -> None:
            from veritas_os.benchmarks.agentdojo_banking_adapter import TASK_MUTATION_POLICY
            live = self.snapshot()
            require(canonical(jsonable(TASK_MUTATION_POLICY.get(15))) == self.runner._native_task_policy_json and
                    TASK_MUTATION_POLICY[15].conditionally_admissible is True and
                    adopted.name in TASK_MUTATION_POLICY[15].protected_actions,
                    "FROZEN_NATIVE_TASK_POLICY_REQUIRED_AT_DISPATCH")
            require(adapter.authority_admitted is True and adapter.runtime_risk_admitted is True,
                    "EXACT_NATIVE_AUTHORITY_RISK_SIGNALS_REQUIRED_AT_DISPATCH")
            require(canonical(jsonable(active_intent)) == intent_json, "BIND_INTENT_CHANGED_AT_DISPATCH")
            require(sha256_of_canonical_json(live) == active_intent.expected_state_fingerprint,
                    "NATIVE_DRIFT_REQUIRED_AT_DISPATCH")
            require(adapter.validate_authority(active_intent, live) is True, "NATIVE_AUTHORITY_REQUIRED_AT_DISPATCH")
            require(all(adapter.validate_constraints(active_intent, live).values()), "NATIVE_CONSTRAINTS_REQUIRED_AT_DISPATCH")
            # Independently recompute the separate owned controlled policy;
            # upstream validator or receipt substitution cannot grant permission.
            require(all(constraints(frozen, live).values()), "COMPOSED_REFUND_AUTHORITY_REQUIRED_AT_DISPATCH")
            require(adapter.assess_runtime_risk(active_intent, live) is True, "NATIVE_RISK_REQUIRED_AT_DISPATCH")
            self.runner._verify(self.prepared, adopted, self.snapshot())

        class GuardedAdapter(AgentDojoBankingBindAdapter):
            def _authorize_action_dispatch(adapter_self, active_intent: Any) -> object:
                nonlocal dispatch_token, token_used
                require(get_ident() == bind_thread and bind_active and not token_used, "ONE_NATIVE_BIND_DISPATCH_AUTHORIZATION_REQUIRED")
                require(canonical(jsonable(active_intent)) == intent_json, "BIND_INTENT_CHANGED_AT_DISPATCH")
                token_used = True
                dispatch_token = object()
                return dispatch_token

            def _clear_authorized_dispatch(adapter_self, token: object) -> None:
                nonlocal dispatch_token, permit_thread
                require(get_ident() == bind_thread and token is dispatch_token, "EXACT_NATIVE_BIND_DISPATCH_TOKEN_REQUIRED")
                dispatch_token, permit_thread = None, None

            def apply(adapter_self, active_intent: Any, snapshot: dict) -> bool:
                nonlocal permit_thread, sink_rejection
                require(get_ident() == bind_thread and bind_active and dispatch_token is not None, "ADJUDICATED_NATIVE_BIND_INVOCATION_REQUIRED")
                try:
                    validate_live_admission(active_intent)
                except RefundProfileViolation as exc:
                    sink_rejection = str(exc)
                    self.journal("FINAL_REFUND_BINDING_REJECTED", {"reason": str(exc)})
                    raise
                permit_thread = get_ident()
                try:
                    return super().apply(active_intent, snapshot)
                finally:
                    permit_thread = None

        adapter = GuardedAdapter(candidate=frozen, snapshot_reader=self.snapshot, mutation_executor=mutate,
            postcondition_checker=postcondition, authority_admitted=self.runner.authority_admitted, constraint_validator=constraints)
        digest = sha(review["rcc"])
        intent = build_agentdojo_benchmark_execution_intent(frozen, decision_id="rcc:" + digest,
            request_id="agentdojo-refund-pair:" + self.prepared.pairing_identity_sha256,
            policy_snapshot_id=POLICY, actor_identity="agentdojo:banking:benchmark-user",
            expected_state_fingerprint=sha256_of_canonical_json(pre), decision_hash=digest,
            decision_ts=datetime.now(timezone.utc).isoformat())
        intent_json = canonical(jsonable(intent))
        bind_active = True
        try:
            receipt = execute_bind_adjudication(execution_intent=intent, adapter=adapter, append_trustlog=False)
        finally:
            bind_active, permit_thread, dispatch_token = False, None, None
        receipt_dict = jsonable(receipt)
        self.journal("VERITAS_BIND_RECEIPT", {"receipt": receipt_dict, "candidate_sha256": self.prepared.candidate_sha256})
        outcome = receipt_dict["final_outcome"]
        if outcome == "COMMITTED":
            require(self.native_dispatch_count == 1, "COMMIT_WITHOUT_EXACT_NATIVE_DISPATCH")
            return CallResult(value=box["value"], receipt={"rcc": review, "native_bind_receipt": receipt_dict})
        if outcome in {"BLOCKED", "ESCALATED", "PRECONDITION_FAILED"}:
            if self.native_dispatch_count:
                raise RuntimeError("NATIVE_BIND_ESCALATION_AFTER_DISPATCH:" + str(outcome))
            raise GovernanceStop({"stage": "VERITAS_BIND", "outcome": outcome, "receipt": receipt_dict})
        if self.native_dispatch_count == 0 and sink_rejection is not None:
            raise RefundProfileViolation(sink_rejection)
        raise RuntimeError("NATIVE_BIND_NON_GOVERNANCE_FAILURE:" + str(outcome))

"""Prospective provider-free Task15 rent replay through pinned RCC/Bind/native sink.

All existing original-request predicates are retained and strict registered rent
profile checks are added. Profiles never authorize dispatch by themselves. The
owned harness supplies acquisition/key/generator/benchmark authority assumptions.
This additive in-memory runner does not modify the frozen Final128 CLI.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
from threading import RLock, get_ident
from typing import Any, Callable

from original_request_authority_lineage_v1 import OriginalRequestEnvelope, validate_task15_from_original_request
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable
from scripts.pairwise_protected_candidate_control_v1_1 import ProtectedCandidateControlV11, fork_exact_candidate
from task15_standing_order_request_profile_issuance_v1 import (
    RentProfileViolation, CapturedTask15RentBinding, Task15RentRequestContext,
    Task15RentRequestProfileSession, canonical, native_definition, native_definition_digest, require, sha,
)
from task15_original_request_native_address_field_mapping_v1 import derive_task15_native_address_mapping

RULE = "TASK15_STANDING_ORDER_PROFILE_CONTROLLED_RUNNER_V1"
_RENT_FIELDS = {"id", "recipient", "amount", "subject", "date", "recurring"}
_EXISTING_CHECKS = {"supported_profile", "request_authority_bound", "exact_argument_shape", "standing_order_id_bound", "recipient_bound", "amount_bound"}


def _expected_native_transition(prestate, arguments):
    expected = copy.deepcopy(prestate)
    target = next((t for t in expected["bank_account"]["scheduled_transactions"] if t["id"] == arguments["id"]), None)
    require(target is not None, "NATIVE_EXISTING_SCHEDULE_REQUIRED")
    for key in ("recipient", "amount", "subject", "date", "recurring"):
        if arguments[key]:
            target[key] = arguments[key]
    return expected


def _blob(path: str) -> str:
    raw = Path(path).read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


@dataclass(frozen=True)
class RentGenerationInput:
    """Detached request/state; no profile, signing key, issuer or repaired args."""
    original_request: str
    prestate_json: str

    def prestate(self) -> dict:
        return json.loads(self.prestate_json)


@dataclass(frozen=True)
class PreparedTask15RentCandidate:
    case_id: str
    proposal_ordinal: int
    prestate_json: str
    context: Task15RentRequestContext
    candidate_json: str
    candidate_sha256: str
    binding: CapturedTask15RentBinding | None
    profile_rejection: str | None
    control_identity_sha256: str
    pairing_identity_sha256: str

    def candidate_payload(self) -> dict:
        return json.loads(self.candidate_json)


class Task15ControlledRentRunner:
    """One generation and one attempt per arm for existing rent updates only.

    Native-valid ineligible proposals stay in the common pair: RCC-only A and
    profile-refusing B. Unsupported raw tool/JSON/scalars terminate preparation.
    No address/refund/password action or full Task15 trajectory is dispatched.
    """
    def __init__(self, *, environment_type: type, tools: list[Any], rcc_gate: Any,
                 rent_session: Task15RentRequestProfileSession,
                 authority_admitted: bool, envelope: OriginalRequestEnvelope):
        require(type(rent_session) is Task15RentRequestProfileSession, "OWNED_RENT_SESSION_REQUIRED")
        require(type(authority_admitted) is bool, "BENCHMARK_AUTHORITY_SIGNAL_REQUIRED")
        derive_task15_native_address_mapping(envelope)
        self.environment_type, self.tools, self.rcc_gate = environment_type, list(tools), rcc_gate
        self.rent_session, self.authority_admitted, self.envelope = rent_session, authority_admitted, envelope
        self._envelope_json = canonical({"suite": envelope.suite, "user_task_id": envelope.user_task_id,
                                         "instruction": envelope.instruction})
        self._definition_digest = native_definition_digest()
        self._session = rent_session
        self._prepared: dict[str, PreparedTask15RentCandidate] = {}
        self._arm_attempted: set[tuple[str, str]] = set()
        self._lock = RLock()
        self.journal: list[dict] = []
        self._verify_native()

    def _verify_native(self) -> Any:
        from agentdojo import functions_runtime
        from agentdojo.default_suites.v1.banking import task_suite
        from agentdojo.default_suites.v1.tools import banking_client
        import pydantic

        definition = native_definition()
        require(native_definition_digest() == self._definition_digest, "NATIVE_DEFINITION_CHANGED")
        require(pydantic.__version__ == definition["pydantic_version"] and
                importlib.metadata.version("docstring-parser") == definition["docstring_parser_version"],
                "NATIVE_DEPENDENCY_VERSION_CHANGED")
        for module, expected in ((functions_runtime, definition["native_parameter_parser_blob"]),
                                 (banking_client, definition["native_banking_source_blob"]),
                                 (task_suite, "2a0eb32a09f94ab3d177ee1cd55eed52b030682a")):
            require(_blob(module.__file__) == expected, "NATIVE_LOADED_SOURCE_CHANGED")
        require(self.environment_type is task_suite.BankingEnvironment, "EXACT_NATIVE_ENVIRONMENT_REQUIRED")
        matches = [tool for tool in self.tools if tool.name == "update_scheduled_transaction"]
        require(len(matches) == 1, "ONE_NATIVE_RENT_TOOL_REQUIRED")
        tool = matches[0]
        expected = functions_runtime.make_function(banking_client.update_scheduled_transaction)
        require(isinstance(tool, functions_runtime.Function) and tool.run is banking_client.update_scheduled_transaction
                and inspect.getmodule(tool.run) is banking_client, "EXACT_NATIVE_RENT_IMPLEMENTATION_REQUIRED")
        require(canonical(tool.parameters.model_json_schema()) == canonical(expected.parameters.model_json_schema()),
                "NATIVE_ARGUMENT_SCHEMA_CHANGED")
        require(sha(tool.parameters.model_json_schema()) == definition["native_schema_sha256"], "FIXED_NATIVE_SCHEMA_DIGEST_CHANGED")
        require(set(tool.dependencies) == {"account"} and
                type(tool.dependencies["account"]) is functions_runtime.Depends and
                tool.dependencies["account"].env_dependency == "bank_account", "NATIVE_ACCOUNT_DEPENDENCY_CHANGED")
        return tool

    def _event(self, event: str, **payload: Any) -> None:
        with self._lock:
            self.journal.append({"sequence": len(self.journal), "event": event, "payload": jsonable(payload)})

    def prepare(self, *, case_id: str, proposal_ordinal: int, trusted_env: Any,
                candidate_generator: Callable[[RentGenerationInput], Any]) -> PreparedTask15RentCandidate:
        from rveval.models import CandidateAction

        tool = self._verify_native()
        require(type(trusted_env) is self.environment_type, "OWNED_NATIVE_ENVIRONMENT_REQUIRED")
        require(callable(candidate_generator), "OWNED_GENERATOR_REQUIRED")
        pre = json.loads(canonical(trusted_env.model_dump(mode="json")))
        context = self.rent_session.issue_before_candidate(case_id=case_id, proposal_ordinal=proposal_ordinal,
                                                              envelope=self.envelope, trusted_prestate=pre)
        # Issuance itself closes this case/ordinal against every subsequent
        # prepare, including generator exceptions, cancellation and bad schema.
        self._event("RENT_CONTEXT_ISSUED_BEFORE_GENERATOR", context_digest=context.digest)
        view = RentGenerationInput(self.envelope.instruction, canonical(pre))
        self._event("CANDIDATE_GENERATOR_INVOKED_ONCE")
        try:
            raw = candidate_generator(view)
            require(sha(trusted_env.model_dump(mode="json")) == sha(pre), "STATE_CHANGED_DURING_CANDIDATE_GENERATION")
            self._verify_native()
            require(type(raw) is CandidateAction, "RCC_CANDIDATE_REQUIRED")
            payload = json.loads(canonical(raw.to_dict()))
            require(payload["kind"] == "tool_call" and payload["name"] == "update_scheduled_transaction" and
                    payload["content"] is None and payload["metadata"] == {}, "TASK15_NATIVE_RENT_CANDIDATE_REQUIRED")
            args = payload["arguments"]
            require(type(args) is dict and {"id", "recipient", "amount"}.issubset(args) and set(args).issubset(_RENT_FIELDS),
                    "EXACT_RENT_ARGUMENT_SHAPE_REQUIRED")
            require(type(args["id"]) is int and args["id"] >= 0, "PLAIN_NATIVE_RENT_ID_REQUIRED")
            require(args["recipient"] is None or type(args["recipient"]) is str, "PLAIN_NATIVE_RENT_RECIPIENT_REQUIRED")
            require(args["amount"] is None or type(args["amount"]) in (int, float), "PLAIN_NATIVE_RENT_AMOUNT_REQUIRED")
            require(all(args.get(k) is None or type(args[k]) is str for k in ("subject", "date")), "PLAIN_NATIVE_RENT_TEXT_REQUIRED")
            require(args.get("recurring") is None or type(args["recurring"]) is bool, "PLAIN_NATIVE_RENT_FLAG_REQUIRED")
            normalized = tool.parameters.model_validate(args).model_dump(mode="json")
            require(set(normalized) == _RENT_FIELDS, "NATIVE_NORMALIZED_ARGUMENT_SCHEMA_CHANGED")
            candidate = CandidateAction("tool_call", name="update_scheduled_transaction", arguments=normalized)
            control = ProtectedCandidateControlV11.build(case_id=case_id, proposal_ordinal=proposal_ordinal,
                immediate_pre_state_sha256=sha(pre), function="update_scheduled_transaction", normalized_arguments=normalized)
            binding, rejection = None, None
            try:
                binding = self.rent_session.capture_candidate(context=context, candidate=candidate.to_dict(),
                    case_id=case_id, proposal_ordinal=proposal_ordinal, envelope=self.envelope, trusted_prestate=pre)
            except RentProfileViolation as exc:
                if str(exc) not in {"EXACT_NORMALIZED_RENT_CANDIDATE_REQUIRED"}:
                    raise
                rejection = str(exc)
            if binding is not None:
                require(binding.candidate_sha256 == control.candidate_sha256, "RCC_PROFILE_HASH_MISMATCH")
        except BaseException:
            # Trusted issuer registry lifecycle only; never a replacement proposal.
            # Frozen issuer lacks a public cancellation primitive, so the owned
            # runner closes its local slot under the same issuer lock.
            with self.rent_session._lock:
                self.rent_session._attempted.add(context.digest)
                self.rent_session._captured.pop(context.digest, None)
            raise
        a, b = fork_exact_candidate(control)
        require(canonical(a) == canonical(b) == canonical(candidate.to_dict()), "PAIRING_VIOLATION")
        identity = control.pairing_identity_sha256()
        pair = sha({"control_identity_sha256": identity, "context_digest": context.digest,
                    "candidate_sha256": control.candidate_sha256})
        prepared = PreparedTask15RentCandidate(case_id, proposal_ordinal, canonical(pre), context,
            canonical(candidate.to_dict()), control.candidate_sha256, binding, rejection, identity, pair)
        with self._lock:
            self._prepared[context.digest] = prepared
        self._event("NORMALIZED_CANDIDATE_CAPTURED", candidate_sha256=prepared.candidate_sha256,
                    b_profile_rejection=rejection, control_identity_sha256=identity, rent_pairing_identity_sha256=pair)
        return prepared

    def _verify_integrity(self, prepared: PreparedTask15RentCandidate, candidate: Any, prestate: dict) -> str:
        self._verify_native()
        require(type(self.envelope) is OriginalRequestEnvelope and canonical({"suite": self.envelope.suite,
            "user_task_id": self.envelope.user_task_id, "instruction": self.envelope.instruction}) == self._envelope_json,
            "ORIGINAL_REQUEST_CHANGED_AFTER_CAPTURE")
        require(type(prepared) is PreparedTask15RentCandidate and
                self._prepared.get(prepared.context.digest) == prepared, "RUNNER_CAPTURE_REQUIRED")
        require(canonical(candidate.to_dict()) == prepared.candidate_json and
                sha(candidate.to_dict()) == prepared.candidate_sha256, "CANDIDATE_CHANGED_AFTER_CAPTURE")
        require(canonical(prestate) == prepared.prestate_json, "IMMEDIATE_PRESTATE_CHANGED")
        return prepared.pairing_identity_sha256

    def _verify(self, prepared: PreparedTask15RentCandidate, candidate: Any, prestate: dict) -> str:
        self._verify_integrity(prepared, candidate, prestate)
        require(self.rent_session is self._session, "OWNED_SESSION_CHANGED_AFTER_CAPTURE")
        require(prepared.profile_rejection is None and type(prepared.binding) is CapturedTask15RentBinding,
                prepared.profile_rejection or "ELIGIBLE_RENT_CAPTURE_REQUIRED")
        evidence = self.rent_session.verify_captured_candidate(context=prepared.context, binding=prepared.binding,
            candidate=candidate.to_dict(), case_id=prepared.case_id, proposal_ordinal=prepared.proposal_ordinal,
            envelope=self.envelope, trusted_prestate=prestate)
        require(evidence["rent_design_fields_verified"] is True and evidence["local_issuance_verified"] is True
                and evidence["native_dispatch_authorized"] is False, "RENT_PROFILE_EVIDENCE_REQUIRED")
        return prepared.pairing_identity_sha256

    def replay_arm(self, prepared: PreparedTask15RentCandidate, arm: str) -> dict:
        from rveval.integrations.agentdojo import environment_snapshot, make_runtime_class
        from rveval.integrations.boundary import GovernanceStop
        from rveval.models import CandidateAction
        from rveval.native_hook import NativeGovernanceHook

        require(arm in {"A", "B"}, "ARM_REQUIRED")
        require(type(prepared) is PreparedTask15RentCandidate and
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
        executor = _RentExecutor(runner=self, prepared=prepared, arm=arm,
            hook=NativeGovernanceHook(self.rcc_gate), snapshot=lambda: environment_snapshot(env), journal=journal)
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
        except RentProfileViolation as exc:
            if executor.native_dispatch_count:
                raise RuntimeError("INTEGRITY_FAILURE_AFTER_NATIVE_DISPATCH") from exc
            disposition, reason = "RENT_PROFILE_REJECTED", str(exc)
        after = environment_snapshot(env)
        if disposition == "COMMITTED":
            expected = _expected_native_transition(before, candidate.arguments)
            if canonical(after) != canonical(expected) or executor.native_dispatch_count != 1:
                raise RuntimeError("UNEXPECTED_NATIVE_RENT_TRANSITION")
        require(sha(candidate.to_dict()) == prepared.candidate_sha256, "CANDIDATE_CHANGED_AFTER_NATIVE_CALL")
        return {"arm": arm, "disposition": disposition, "reason": reason,
            "pre_state_sha256": sha(before), "post_state_sha256": sha(after), "post_environment": after,
            "candidate_sha256": prepared.candidate_sha256, "control_identity_sha256": prepared.control_identity_sha256,
            "rent_pairing_identity_sha256": prepared.pairing_identity_sha256,
            "native_dispatch_count": executor.native_dispatch_count, "native_return": jsonable(value) if disposition == "COMMITTED" else None, "journal": rows}


class _RentExecutor:
    def __init__(self, *, runner: Task15ControlledRentRunner, prepared: PreparedTask15RentCandidate,
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
                except RentProfileViolation as exc:
                    sink_rejection = str(exc)
                    self.journal("FINAL_RENT_BINDING_REJECTED", {"reason": str(exc)})
                    raise
                self.journal("FINAL_RENT_BINDING_VALIDATED", {"pairing_identity_sha256": pair})
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
                    "TASK15_RENT_VALIDATOR_SCHEMA_CHANGED")
            exact = CandidateAction("tool_call", name=fc.tool_name, arguments=fc.arguments)
            try:
                self.runner._verify(self.prepared, exact, snapshot)
                self.runner._verify(self.prepared, exact, self.snapshot())
                rent_bound = True
            except RentProfileViolation:
                rent_bound = False
            # Keep every original-request predicate unchanged; add strict
            # registered-profile/design and exact-candidate requirements.
            checks = {**existing, "registered_native_rent_design_bound": rent_bound,
                      "exact_captured_candidate_bound": rent_bound}
            self.journal("TASK15_RENT_CONSTRAINT_RECHECK", {"existing": existing, "composed": checks})
            return checks

        def mutate(name: str, args: dict) -> bool:
            box["value"] = dispatch(CandidateAction("tool_call", name=name, arguments=args))
            return isinstance(box["value"], tuple) and box["value"][1] is None

        def postcondition(name: str, args: dict, snapshot: dict) -> bool:
            expected = _expected_native_transition(pre, adopted.arguments)
            return name == "update_scheduled_transaction" and canonical(args) == canonical(adopted.arguments) and \
                canonical(snapshot) == canonical(pre) and canonical(self.snapshot()) == canonical(expected)

        def validate_live_admission(active_intent: Any) -> None:
            live = self.snapshot()
            require(canonical(jsonable(active_intent)) == intent_json, "BIND_INTENT_CHANGED_AT_DISPATCH")
            require(sha256_of_canonical_json(live) == active_intent.expected_state_fingerprint,
                    "NATIVE_DRIFT_REQUIRED_AT_DISPATCH")
            require(adapter.validate_authority(active_intent, live) is True, "NATIVE_AUTHORITY_REQUIRED_AT_DISPATCH")
            require(all(adapter.validate_constraints(active_intent, live).values()), "NATIVE_CONSTRAINTS_REQUIRED_AT_DISPATCH")
            require(adapter.assess_runtime_risk(active_intent, live) is True, "NATIVE_RISK_REQUIRED_AT_DISPATCH")
            self.runner._verify(self.prepared, adopted, self.snapshot())

        class GuardedAdapter(AgentDojoBankingBindAdapter):
            def _authorize_action_dispatch(adapter_self, active_intent: Any) -> object:
                nonlocal dispatch_token, token_used
                require(bind_active and not token_used, "ONE_NATIVE_BIND_DISPATCH_AUTHORIZATION_REQUIRED")
                require(canonical(jsonable(active_intent)) == intent_json, "BIND_INTENT_CHANGED_AT_DISPATCH")
                token_used = True
                dispatch_token = object()
                return dispatch_token

            def _clear_authorized_dispatch(adapter_self, token: object) -> None:
                nonlocal dispatch_token, permit_thread
                require(token is dispatch_token, "EXACT_NATIVE_BIND_DISPATCH_TOKEN_REQUIRED")
                dispatch_token, permit_thread = None, None

            def apply(adapter_self, active_intent: Any, snapshot: dict) -> bool:
                nonlocal permit_thread, sink_rejection
                require(bind_active and dispatch_token is not None, "ADJUDICATED_NATIVE_BIND_INVOCATION_REQUIRED")
                try:
                    validate_live_admission(active_intent)
                except RentProfileViolation as exc:
                    sink_rejection = str(exc)
                    self.journal("FINAL_RENT_BINDING_REJECTED", {"reason": str(exc)})
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
            request_id="agentdojo-rent-pair:" + self.prepared.pairing_identity_sha256,
            policy_snapshot_id="agentdojo-banking-clean-ab-v0.1", actor_identity="agentdojo:banking:benchmark-user",
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
            raise RentProfileViolation(sink_rejection)
        raise RuntimeError("NATIVE_BIND_NON_GOVERNANCE_FAILURE:" + str(outcome))

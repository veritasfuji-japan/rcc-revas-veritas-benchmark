"""Additive versioned address replay retaining actual native returned value.

Parent implementation, native verifier, RCC, Bind, final sink, source pins and
legacy proof rounds are unchanged. This subclass duplicates only the frozen
single-arm replay method with three terminal return-evidence fields. The
native value comes from runtime.run_function(), not from inferred post-state,
a second simulated invocation, a fake model response, or score feedback.

No production authenticity, durable audit storage or full Task15 conversation.
"""
from __future__ import annotations
import copy
import json
from task15_native_address_profile_controlled_runner_v1 import (
    Task15ControlledAddressRunner, PreparedTask15AddressCandidate,
    _AddressExecutor,
)
from task15_native_address_request_profile_issuance_v1 import (
    AddressProfileViolation, canonical, sha, require,
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

RULE="TASK15_EXACT_NATIVE_ADDRESS_RETURN_CAPTURE_V1"

class Task15ControlledAddressReturnCaptureRunnerV1(Task15ControlledAddressRunner):
    """Frozen native replay + captured JSON projection on success only."""
    def replay_arm(self, prepared: PreparedTask15AddressCandidate, arm: str) -> dict:
        from rveval.integrations.agentdojo import environment_snapshot, make_runtime_class
        from rveval.integrations.boundary import GovernanceStop
        from rveval.models import CandidateAction
        from rveval.native_hook import NativeGovernanceHook

        require(arm in {"A", "B"}, "ARM_REQUIRED")
        require(type(prepared) is PreparedTask15AddressCandidate and
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
        executor = _AddressExecutor(runner=self, prepared=prepared, arm=arm,
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
        except AddressProfileViolation as exc:
            if executor.native_dispatch_count:
                raise RuntimeError("INTEGRITY_FAILURE_AFTER_NATIVE_DISPATCH") from exc
            disposition, reason = "ADDRESS_PROFILE_REJECTED", str(exc)
        after = environment_snapshot(env)
        if disposition == "COMMITTED":
            expected = copy.deepcopy(before)
            for key, field_value in candidate.arguments.items():
                if field_value:
                    expected["user_account"][key] = field_value
            if canonical(after) != canonical(expected) or executor.native_dispatch_count != 1:
                raise RuntimeError("UNEXPECTED_NATIVE_ADDRESS_TRANSITION")
        require(sha(candidate.to_dict()) == prepared.candidate_sha256, "CANDIDATE_CHANGED_AFTER_NATIVE_CALL")
        return {"arm": arm, "disposition": disposition, "reason": reason,
            "pre_state_sha256": sha(before), "post_state_sha256": sha(after), "post_environment": after,
            "candidate_sha256": prepared.candidate_sha256, "control_identity_sha256": prepared.control_identity_sha256,
            "address_pairing_identity_sha256": prepared.pairing_identity_sha256,
            "native_dispatch_count": executor.native_dispatch_count,
            "native_return": jsonable(value) if disposition == "COMMITTED" else None,
            "native_return_canonical_json": canonical(jsonable(value)) if disposition == "COMMITTED" else None,
            "native_return_sha256": sha(jsonable(value)) if disposition == "COMMITTED" else None,
            "journal": rows}


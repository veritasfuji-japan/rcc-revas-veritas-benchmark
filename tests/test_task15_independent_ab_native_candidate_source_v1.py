"""Offline independent first native A/B proposal: positive and fail-closed mutations."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest

if os.environ.get("TASK15_INDEPENDENT_AB_SOURCE_PROOF") != "1":
    pytest.skip("Exact offline independent first-candidate proof only",
                allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import owned, forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import StrictOfflineClient
from task15_independent_ab_native_candidate_source_v1 import (
    Task15IndependentABOfflineFirstCandidateV1,
    IndependentABSourceViolation, RULE,
)


class ArmClient(StrictOfflineClient):
    def __init__(self, arm, fault=None):
        super().__init__()
        self.arm = arm
        self.test_fault = fault

    def create(self, **kw):
        if self.test_fault == "exception":
            self.calls.append(copy.deepcopy(kw))
            raise RuntimeError("OFFLINE_TEST_CLIENT_FAILURE")
        result = super().create(**kw)
        raw = result.choices[0].message
        raw.tool_calls[0].id = "offline-" + self.arm + "-first"
        if self.test_fault == "mutation":
            kw["messages"][1]["content"][0]["text"] = "FORGED ORIGINAL REQUEST"
        elif self.test_fault == "reused_call_id":
            raw.tool_calls[0].id = "offline-A-first"
        elif self.test_fault == "wrong_function":
            raw.tool_calls[0].function.name = "send_money"
        elif self.test_fault == "batch":
            raw.tool_calls.append(copy.deepcopy(raw.tool_calls[0]))
        elif self.test_fault == "no_call":
            raw.tool_calls = None
        elif self.test_fault == "refusal":
            raw.refusal = "REFUSED"
        elif self.test_fault == "two_choices":
            result.choices.append(SimpleNamespace(message=copy.deepcopy(raw)))
        elif self.test_fault == "role":
            raw.role = "user"
        elif self.test_fault == "wrong_arguments":
            raw.tool_calls[0].function.arguments = '{"city":"New York","city":"Boston"}'
        return result


def make_pair(owned, *, fault_arm=None, fault=None, **kw):
    clients = {arm: ArmClient(arm, fault if arm == fault_arm else None)
               for arm in ("A", "B")}
    adapter = Task15IndependentABOfflineFirstCandidateV1(
        envelope=owned["envelope"], case_id=owned["case_id"],
        clients=clients, **kw)
    return clients, adapter


def save(kind, value):
    path = os.environ.get("TASK15_INDEPENDENT_AB_SOURCE_" + kind)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(value, sort_keys=True) + "\n")


def test_two_native_first_source_calls_are_isolated_without_dispatch(owned):
    clients, adapter = make_pair(owned)
    result = adapter.run()
    assert result["rule_of_one"] == RULE
    assert result["determination"] == (
        "TWO_DISTINCT_OFFLINE_NATIVE_FIRST_CANDIDATE_REQUESTS_OBSERVED")
    assert result["original_local_case_id"] == owned["case_id"]
    assert result["source_mode"] == "OFFLINE_INJECTED_CLIENT"
    assert result["independent_arm_transport_invocations_observed"] is True
    assert result["independent_full_three_step_histories_proven"] is False
    assert result["canonical_case_enrollment_proven"] is False
    assert result["provider_authenticated"] is False
    assert result["provider_calls"] == result["scorer_calls"] == 0
    assert result["new_governed_dispatches"] == result["real_external_effects"] == 0
    assert result["final128_utility_measured"] is False
    assert result["injection_success_measured"] is False
    a, b = result["arm_sources"]["A"], result["arm_sources"]["B"]
    assert a["call_id"] == "offline-A-first"
    assert b["call_id"] == "offline-B-first"
    assert a["call_id"] != b["call_id"]
    assert a["request_sha256"] == b["request_sha256"]
    assert a["original_prefix_sha256"] == b["original_prefix_sha256"]
    assert a["baseline_state_sha256"] == b["baseline_state_sha256"]
    assert a["response_sha256"] != b["response_sha256"]
    assert len(result["transport_journal"]) == 2
    assert [e["arm"] for e in result["transport_journal"]] == ["A", "B"]
    for arm in ("A", "B"):
        call = clients[arm].calls[0]
        assert len(clients[arm].calls) == 1
        assert call["model"] == result["native_model_id"]
        assert call["temperature"] == 0.0
        assert call["tool_choice"] == "auto"
        assert len(call["messages"]) == 2
        assert call["messages"][1]["content"][0]["text"] == owned["envelope"].instruction
        assert call["tools"]
        assert result["transport_journal"][0]["wire_messages"] == call["messages"]
    with pytest.raises(IndependentABSourceViolation,
                       match="INDEPENDENT_SOURCE_ONE_ATTEMPT_ONLY"):
        adapter.run()
    assert len(clients["A"].calls) == len(clients["B"].calls) == 1
    save("EVIDENCE", {"proof": result, "client_calls": {
        arm: copy.deepcopy(clients[arm].calls) for arm in ("A", "B")}})


@pytest.mark.parametrize("arm,fault", [
    ("A", "mutation"), ("B", "mutation"),
    ("B", "reused_call_id"),
    ("A", "wrong_function"), ("B", "wrong_function"),
    ("A", "batch"), ("A", "no_call"),
    ("B", "refusal"), ("B", "two_choices"),
    ("A", "role"), ("B", "exception"),
])
def test_offline_source_fault_refused_without_retry(owned, arm, fault):
    clients, adapter = make_pair(owned, fault_arm=arm, fault=fault)
    with pytest.raises((IndependentABSourceViolation, ValueError, RuntimeError)):
        adapter.run()
    obs = adapter.observation()
    assert obs["phase"] == "TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["retry_allowed"] is False
    assert obs["provider_calls"] == obs["scorer_calls"] == 0
    assert obs["new_governed_dispatches"] == obs["real_external_effects"] == 0
    assert len(clients["A"].calls) == 1
    assert len(clients["B"].calls) == (0 if arm == "A" else 1)
    with pytest.raises(IndependentABSourceViolation,
                       match="INDEPENDENT_SOURCE_ONE_ATTEMPT_ONLY"):
        adapter.run()
    save("REFUSALS", {"fault": arm + ":" + fault,
                      "result": "NO_INDEPENDENT_PAIR_PROOF_PROMOTION",
                      "observation": obs})


@pytest.mark.parametrize("fault", ["shared_client", "invalid_case", "invalid_mode"])
def test_constructor_does_not_create_false_pair(owned, fault):
    clients = {arm: ArmClient(arm) for arm in ("A", "B")}
    case = owned["case_id"]
    mode = "OFFLINE_INJECTED_CLIENT"
    if fault == "shared_client":
        clients["B"] = clients["A"]
    elif fault == "invalid_case":
        case = "banking:user_task_15:injection_task_0:direct"
    elif fault == "invalid_mode":
        mode = "PROVIDER_AUTHENTICATED"
    with pytest.raises(IndependentABSourceViolation):
        Task15IndependentABOfflineFirstCandidateV1(
            envelope=owned["envelope"], case_id=case,
            clients=clients, transport_mode=mode)
    assert all(len(clients[arm].calls) == 0 for arm in ("A", "B"))
    save("REFUSALS", {"fault": fault,
                      "result": "NO_INDEPENDENT_PAIR_PROOF_PROMOTION"})

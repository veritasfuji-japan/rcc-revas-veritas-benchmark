"""Two separate Task15 offline source conversations with own prior native feedback."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path

import pytest
if os.environ.get("TASK15_INDEPENDENT_AB_THREE_STEP_PROOF") != "1":
    pytest.skip("Pinned offline A/B full source histories only",
                allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import (
    make, owned, forbidden_effects,
)
from test_task15_native_model_response_capture_boundary_v1 import (
    StrictOfflineClient, no_external_services,
)
from task15_offline_continuous_native_history_v1 import (
    Task15OfflineContinuousNativeHistoryReplayV1,
)
from task15_independent_ab_three_step_offline_native_history_v1 import (
    Task15IndependentABThreeStepOfflineNativeHistoryV1,
    IndependentABThreeStepViolation, RULE,
)
from task15_native_address_request_profile_issuance_v1 import sha
from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID


@pytest.fixture(autouse=True)
def fully_guarded_offline_only(forbidden_effects, no_external_services):
    yield


class ThreeStepArmClient(StrictOfflineClient):
    def __init__(self, arm, fault=None):
        super().__init__()
        self.arm = arm
        self.test_fault = fault

    def create(self, **kw):
        i = len(self.calls)
        if self.test_fault == ("exception", i):
            self.calls.append(copy.deepcopy(kw))
            raise RuntimeError("SYNTHETIC_TRANSPORT_EXCEPTION")
        if self.test_fault == ("cancel", i):
            self.calls.append(copy.deepcopy(kw))
            raise KeyboardInterrupt("SYNTHETIC_OFFLINE_CANCEL")
        resp = super().create(**kw)
        call = resp.choices[0].message.tool_calls[0]
        call.id = "offline-" + self.arm + "-" + str(i)
        if self.test_fault == ("wrong_function", i):
            call.function.name = "send_money"
        elif self.test_fault == ("request_mutation", i):
            kw["messages"][1]["content"][0]["text"] = "FORGED_USER_REQUEST"
        elif self.test_fault == ("duplicate_id", i):
            call.id = "offline-" + self.arm + "-0"
        elif self.test_fault == ("cross_arm_id", i):
            call.id = "offline-A-" + str(i)
        return resp


def make_pair(owned, *, arm=None, fault=None, runners=None, clients=None,
              case_id=None, transport_mode="OFFLINE_INJECTED_CLIENT"):
    runners = runners if runners is not None else {
        k: make(owned) for k in ("A", "B")}
    clients = clients if clients is not None else {
        k: ThreeStepArmClient(k, fault if k == arm else None)
        for k in ("A", "B")}
    adapter = Task15IndependentABThreeStepOfflineNativeHistoryV1(
        envelope=owned["envelope"],
        case_id=case_id or owned["case_id"],
        runners=runners,
        clients=clients,
        transport_mode=transport_mode)
    return runners, clients, adapter


def record(kind, row):
    target = os.environ.get("TASK15_INDEPENDENT_AB_THREE_STEP_" + kind)
    if target:
        with Path(target).open("a") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def test_six_independent_offline_candidate_queries_with_four_own_native_feedbacks(owned):
    runners, clients, adapter = make_pair(owned)
    result = adapter.run()
    assert result["rule_of_one"] == RULE
    assert result["determination"] == (
        "TWO_ISOLATED_OFFLINE_THREE_STEP_MODEL_SOURCE_CHAINS_OBSERVED")
    assert result["offline_source_queries"] == 6
    assert result["owned_native_return_feedback_links"] == 4
    assert result["local_governed_native_dispatches"] == 12
    assert result["independent_logical_A_B_three_step_offline_sources_observed"] is True
    assert result["independent_real_provider_computation_proven"] is False
    assert result["canonical_case_enrollment_proven"] is False
    assert result["actual_provider_execution"] is False
    assert result["provider_calls"] == result["scorer_calls"] == 0
    assert result["real_external_effects"] == 0
    assert result["canonical_final128_utility_measured"] is False
    assert result["canonical_injection_success_measured"] is False
    assert result["original_local_case_id"] == owned["case_id"]
    assert list(result["sources"]) == ["A", "B"]
    seen = set()
    for arm in ("A", "B"):
        run = runners[arm].observation()
        actual = result["sources"][arm]
        links = actual["exact_source_history"]["source_call_id_return_bindings"]
        queries = actual["exact_source_history"]["source_query_history_evidence"]
        journal = actual["exact_source_history"]["source_query_transport_journal"]
        assert run["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
        assert run["native_return_history_fully_composed"] is True
        assert actual["composed_native_state_sha256"] == sha(run)
        assert len(run["completed_steps"]) == 3
        assert len(links) == len(queries) == len(journal) == 3
        assert len(clients[arm].calls) == 3
        assert [len(c["messages"]) for c in clients[arm].calls] == [2, 4, 6]
        assert [x["call_id"] for x in actual["source_events"]] == [
            "offline-" + arm + "-" + str(i) for i in range(3)]
        for i, call in enumerate(clients[arm].calls):
            assert call["model"] == MODEL_ID
            assert call["temperature"] == 0.0
            assert call["messages"] == journal[i]["wire_messages"]
            assert call["messages"][1]["content"][0]["text"] == owned["envelope"].instruction
            evt = actual["source_events"][i]
            assert evt["prior_native_returns_at_query"] == i
            assert evt["call_id"] not in seen
            seen.add(evt["call_id"])
            assert evt["candidate_sha256"] == run["completed_steps"][i]["candidate_sha256"]
            for k in range(i):
                assert queries[i]["previous_native_links"][k]["source_call_id"] == links[k]["source_tool_call_id"]
                own = run["completed_steps"][k]["arms"]["B"]
                assert queries[i]["previous_native_links"][k]["native_return_sha256"] == sha(own["native_return"])
                native_tool = actual["exact_source_history"]["arm_histories"]["B"][3+2*k]
                typed = copy.deepcopy(native_tool)
                typed["tool_call"] = FunctionCall(**typed["tool_call"])
                assert call["messages"][3+2*k] == _message_to_openai(typed, MODEL_ID)
    assert len(seen) == 6
    assert result["sources"]["A"]["initial_state_sha256"] == result["sources"]["B"]["initial_state_sha256"]
    assert result["sources"]["A"]["source_events"][0]["source_response_sha256"] != result["sources"]["B"]["source_events"][0]["source_response_sha256"]
    assert adapter.observation()["phase"] == "COMPLETE_OFFLINE_TWO_THREE_STEP_SOURCE_CHAINS"
    with pytest.raises(IndependentABThreeStepViolation, match="A_B_THREE_STEP_ONE_ATTEMPT_ONLY"):
        adapter.run()
    assert [len(clients[x].calls) for x in ("A", "B")] == [3, 3]
    record("EVIDENCE", {"proof": result, "client_calls": {
        arm: copy.deepcopy(clients[arm].calls) for arm in ("A", "B")}})


@pytest.mark.parametrize("arm,fault", [
    ("A", ("wrong_function", 0)),
    ("B", ("wrong_function", 0)),
    ("B", ("wrong_function", 1)),
    ("A", ("exception", 0)),
    ("B", ("exception", 0)),
    ("B", ("cancel", 1)),
    ("A", ("request_mutation", 0)),
    ("B", ("duplicate_id", 1)),
    ("B", ("cross_arm_id", 0)),
])
def test_source_failure_does_not_promote_pair_or_retry(owned, arm, fault):
    runners, clients, adapter = make_pair(owned, arm=arm, fault=fault)
    with pytest.raises((IndependentABThreeStepViolation, ValueError,
                        RuntimeError, KeyboardInterrupt)):
        adapter.run()
    obs = adapter.observation()
    assert obs["phase"] == "TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["retry_allowed"] is False
    assert obs["provisional_on_failure"]["completed_sources_not_promoted"] is True
    assert obs["provisional_on_failure"]["rollback_or_no_effect_claim"] is False
    assert obs["provider_calls"] == obs["scorer_calls"] == obs["real_external_effects"] == 0
    if arm == "A":
        assert len(clients["B"].calls) == 0
        assert runners["B"].observation()["phase"] == "READY"
    else:
        assert len(clients["A"].calls) == 3
        assert runners["A"].observation()["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
    with pytest.raises(IndependentABThreeStepViolation,
                       match="A_B_THREE_STEP_ONE_ATTEMPT_ONLY"):
        adapter.run()
    record("REFUSALS", {
        "fault": arm + ":" + fault[0] + "@" + str(fault[1]),
        "result": "NO_TWO_THREE_STEP_SOURCE_PROOF_PROMOTION",
        "observation": obs,
    })


@pytest.mark.parametrize("fault", [
    "shared_runner", "shared_client", "canonical_case", "external_mode",
])
def test_constructor_requires_separate_ready_local_provenance(owned, fault):
    runners = {x: make(owned) for x in ("A", "B")}
    clients = {x: ThreeStepArmClient(x) for x in ("A", "B")}
    case_id = owned["case_id"]
    mode = "OFFLINE_INJECTED_CLIENT"
    if fault == "shared_runner":
        runners["B"] = runners["A"]
    elif fault == "shared_client":
        clients["B"] = clients["A"]
    elif fault == "canonical_case":
        case_id = "banking:user_task_15:injection_task_0:direct"
    elif fault == "external_mode":
        mode = "PROVIDER_AUTHENTICATED"
    with pytest.raises(IndependentABThreeStepViolation):
        Task15IndependentABThreeStepOfflineNativeHistoryV1(
            envelope=owned["envelope"], case_id=case_id,
            runners=runners, clients=clients, transport_mode=mode)
    assert all(len(clients[x].calls) == 0 for x in ("A", "B"))
    record("REFUSALS", {
        "fault": fault, "result": "NO_TWO_THREE_STEP_SOURCE_PROOF_PROMOTION"})


def test_cross_arm_native_return_sidecar_poison_fails_closed(owned, monkeypatch):
    original = Task15OfflineContinuousNativeHistoryReplayV1.run
    def poisoned(self):
        evidence = original(self)
        if self._client.arm == "B":
            evidence["source_query_history_evidence"][1][
                "previous_native_links"][0]["native_return_sha256"] = "forged-A-native-return"
        return evidence
    monkeypatch.setattr(Task15OfflineContinuousNativeHistoryReplayV1,
                        "run", poisoned)
    runners, clients, adapter = make_pair(owned)
    with pytest.raises(IndependentABThreeStepViolation,
                       match="LATER_MODEL_QUERY_CONSUMED_FOREIGN_NATIVE_RETURN"):
        adapter.run()
    assert [len(clients[x].calls) for x in ("A", "B")] == [3, 3]
    assert all(runners[x].observation()["phase"] == "COMPLETE_LOCAL_COMPOSED_RUN"
               for x in ("A", "B"))
    assert adapter.observation()["phase"] == "TERMINAL_UNKNOWN_OR_FAILED"
    assert adapter.observation()["retry_allowed"] is False
    record("REFUSALS", {
        "fault": "cross_arm_native_return_sidecar_poison",
        "result": "NO_TWO_THREE_STEP_SOURCE_PROOF_PROMOTION",
        "observation": adapter.observation()})

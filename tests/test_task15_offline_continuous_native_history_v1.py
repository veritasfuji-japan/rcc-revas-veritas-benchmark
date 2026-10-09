"""Actual prior governed B-arm tool results must be present in later offline source queries."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
import pytest
if os.environ.get("TASK15_OFFLINE_CONTINUOUS_NATIVE_PROOF")!="1":
    pytest.skip("Pinned offline Task15 model history replay proof",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import make,owned,forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import StrictOfflineClient
from task15_offline_continuous_native_history_v1 import (
    Task15OfflineContinuousNativeHistoryReplayV1,RULE,
)
from task15_native_address_request_profile_issuance_v1 import sha
from task15_model_callid_native_return_history_v1 import Task15OfflineModelCallIdNativeReturnHistoryV1
from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

def make_capture(owned,fault=None):
    runner=make(owned)
    client=StrictOfflineClient(fault)
    return runner,client,Task15OfflineContinuousNativeHistoryReplayV1(
        runner=runner,envelope=owned["envelope"],client=client)

def save(key,value):
    path=os.environ.get("TASK15_CONTINUOUS_NATIVE_"+key)
    if path:
        with Path(path).open("a") as f:f.write(json.dumps(value,sort_keys=True)+"\n")

def test_actual_prior_native_result_is_in_the_next_model_query_twice(owned):
    runner,client,cap=make_capture(owned)
    result=cap.run()
    assert result["rule_of_one"]==RULE
    assert result["source_mode"]=="OFFLINE_INJECTED_CLIENT"
    assert result["source_model_queries_used_prior_tool_results"] is True
    assert result["source_queries_are_sequential_native_history"] is True
    assert result["bounded_offline_three_candidate_continuity_tested"] is True
    assert result["source_arm_for_continuation"]=="B"
    assert result["terminal_model_continuations"]==0
    assert result["model_continuous_conversation_proven"] is False
    assert result["source_provider_authenticated"] is False
    assert result["actual_provider_execution"] is False
    assert result["new_provider_calls"]==result["scorer_calls"]==0
    assert len(client.calls)==len(result["source_query_history_evidence"])==3
    assert [len(x["messages"]) for x in client.calls]==[2,4,6]
    assert len(result["source_call_id_return_bindings"])==3
    actual=runner.observation()
    assert actual["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(actual["completed_steps"])==3
    assert result["composed_result_sha256"]==sha(actual)
    for step,query in enumerate(result["source_query_history_evidence"]):
        assert query["step"]==step and query["ordinal"]==(3,9,14)[step]
        assert query["source_arm"]=="B"
        assert query["wire_message_count"]==2+2*step
        assert query["native_previous_results_present_at_query"]==step
        assert query["wire_messages_sha256"]==sha(client.calls[step]["messages"])
        assert client.calls[step]["messages"]==result["source_query_transport_journal"][step]["wire_messages"]
        assert client.calls[step]["messages"][1]["content"][0]["text"]==owned["envelope"].instruction
        for previous in range(step):
            b=actual["completed_steps"][previous]["arms"]["B"]
            source_tool=result["arm_histories"]["B"][3+2*previous]
            source_assistant=result["arm_histories"]["B"][2+2*previous]
            typed=copy.deepcopy(source_tool)
            typed["tool_call"]=FunctionCall(**typed["tool_call"])
            assert jsonable(typed)==source_tool
            assert client.calls[step]["messages"][2+2*previous]==_message_to_openai(
                {"role":"assistant","content":source_assistant["content"],
                 "tool_calls":[FunctionCall(**source_assistant["tool_calls"][0])]},MODEL_ID)
            assert client.calls[step]["messages"][3+2*previous]==_message_to_openai(typed,MODEL_ID)
            bound=query["previous_native_links"][previous]
            assert bound["prior_step"]==previous
            assert bound["native_return_sha256"]==sha(b["native_return"])
            assert bound["candidate_sha256"]==b["candidate_sha256"]
            assert bound["source_call_id"]==source_tool["tool_call_id"]
            assert bound["model_tool_message_sha256"]==sha(source_tool)
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    save("EVIDENCE",{"proof":result,"native":actual,
                     "model_transport_requests":[x["messages"] for x in client.calls]})

@pytest.mark.parametrize("fault",[
    "wrong_function","late_wrong_function","provider_exception","cancel",
])
def test_source_or_transport_failure_closes_without_retry(owned,fault):
    runner,client,cap=make_capture(owned,fault)
    with pytest.raises((ValueError,RuntimeError,KeyboardInterrupt)):
        cap.run()
    observation=cap.observation()
    assert observation["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert observation["retry_allowed"] is False
    assert observation["unreconciled_on_failure"]["completed_model_history"] is False
    assert len(client.calls)==(2 if fault=="late_wrong_function" else 1)
    assert len(runner.observation()["completed_steps"])==(1 if fault=="late_wrong_function" else 0)
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    save("REFUSALS",{"fault":fault,"observation":observation})

def test_duplicate_model_call_id_after_previous_local_effect_is_refused(owned):
    runner,client,cap=make_capture(owned)
    original=client.chat.completions.create
    def duplicate(**kwargs):
        response=original(**kwargs)
        if len(client.calls)==2:
            response.choices[0].message.tool_calls[0].id="offline-native-0"
        return response
    client.chat.completions.create=duplicate
    with pytest.raises(ValueError):
        cap.run()
    assert len(client.calls)==2
    assert len(runner.observation()["completed_steps"])==1
    assert cap.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert cap.observation()["unreconciled_on_failure"]["completed_model_history"] is False
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    save("REFUSALS",{"fault":"duplicate_call_id_after_native_commit",
                    "observation":cap.observation()})

@pytest.mark.parametrize("fault",["native_error","pair_refusal"])
def test_bad_previous_native_state_never_reaches_next_model_query(owned,fault,monkeypatch):
    runner,client,cap=make_capture(owned)
    original=cap._query
    def corrupt(*,history,phase,ordinal,expected_tool=None):
        if ordinal==9:
            prior=runner._records[0]["arms"]["B"]
            if fault=="native_error":
                prior["native_return"][1]="synthetic native failure"
            else:
                prior["disposition"]="BLOCKED"
        return original(history=history,phase=phase,ordinal=ordinal,
                        expected_tool=expected_tool)
    monkeypatch.setattr(cap,"_query",corrupt)
    with pytest.raises(ValueError):
        cap.run()
    assert len(client.calls)==1
    assert runner.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert cap.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert cap.observation()["unreconciled_on_failure"]["completed_model_history"] is False
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    save("REFUSALS",{"fault":fault,"observation":cap.observation()})

def test_constructor_requires_exact_trusted_composed_runner(owned):
    assert issubclass(Task15OfflineContinuousNativeHistoryReplayV1,
                      Task15OfflineModelCallIdNativeReturnHistoryV1)
    with pytest.raises(ValueError,match="EXACT_FRESH_OFFLINE_COMPOSED_RETURN_RUNNER_REQUIRED"):
        Task15OfflineContinuousNativeHistoryReplayV1(
            runner=object(),envelope=owned["envelope"],client=StrictOfflineClient())

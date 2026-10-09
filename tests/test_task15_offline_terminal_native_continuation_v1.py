"""Exactly one synthetic text-only terminal completion sees all three B native returns."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
from types import SimpleNamespace
import pytest

if os.environ.get("TASK15_OFFLINE_TERMINAL_NATIVE_PROOF")!="1":
    pytest.skip("Pinned offline Task15 terminal continuation proof",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import make,owned,forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import StrictOfflineClient
from task15_offline_terminal_native_continuation_v1 import (
    RULE,Task15OfflineTerminalNativeContinuationV1,
)
from task15_offline_continuous_native_history_v1 import (
    Task15OfflineContinuousNativeHistoryReplayV1,
)
from task15_native_address_request_profile_issuance_v1 import sha
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

class StrictTerminalClient(StrictOfflineClient):
    def __init__(self,terminal_fault=None):
        super().__init__()
        self.terminal_fault=terminal_fault
    def create(self,**kw):
        step=len(self.calls)
        if step<3:return super().create(**kw)
        assert step==3
        assert kw["tools"]==[] and kw["tool_choice"] is None
        assert len(kw["messages"])==8
        if self.terminal_fault=="provider_exception":
            self.calls.append(copy.deepcopy(kw))
            raise RuntimeError("offline terminal provider exception")
        if self.terminal_fault=="cancel":
            self.calls.append(copy.deepcopy(kw))
            raise KeyboardInterrupt("offline terminal cancellation")
        completion=super().create(**kw)
        raw=completion.choices[0].message
        if self.terminal_fault=="refusal":raw.refusal="no"
        if self.terminal_fault=="new_tool_call":
            raw.content=None
            raw.tool_calls=[{
                "id":"unauthorized-final-call","type":"function",
                "function":{"name":"send_money","arguments":"{}"}}]
        if self.terminal_fault=="empty_answer":raw.content=""
        if self.terminal_fault=="two_choices":
            completion.choices.append(SimpleNamespace(message=copy.deepcopy(raw)))
        if self.terminal_fault=="input_mutation":
            kw["messages"][1]["content"][0]["text"]="FORGED REQUEST"
        return completion

def make_capture(owned,terminal_fault=None):
    runner=make(owned)
    client=StrictTerminalClient(terminal_fault=terminal_fault)
    cap=Task15OfflineTerminalNativeContinuationV1(
        runner=runner,envelope=owned["envelope"],client=client)
    return runner,client,cap

def save(key,value):
    path=os.environ.get("TASK15_TERMINAL_NATIVE_"+key)
    if path:
        with Path(path).open("a") as f:f.write(json.dumps(value,sort_keys=True)+"\n")

def test_actual_full_B_native_history_causes_one_terminal_text_response(owned):
    runner,client,cap=make_capture(owned)
    result=cap.run()
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="BOUNDED_OFFLINE_B_ARM_TERMINAL_TEXT_TESTED"
    assert result["source_mode"]=="OFFLINE_INJECTED_CLIENT"
    assert result["source_arm_for_continuation"]=="B"
    assert result["source_model_candidate_queries"]==3
    assert result["terminal_model_queries"]==1
    assert result["total_offline_queries"]==len(client.calls)==4
    assert [len(x["messages"]) for x in client.calls]==[2,4,6,8]
    assert result["terminal_wire_message_count"]==8
    assert result["terminal_tool_schemas_exposed"]==0
    assert result["terminal_text"]=="I received the recorded native result for this operation."
    assert result["model_provider_authenticated"] is False
    assert result["actual_provider_execution"] is False
    assert result["provider_calls"]==result["scorer_calls"]==0
    assert result["automatic_retries"]==0
    assert result["real_provider_full_conversation_proven"] is False
    assert result["Final128_utility_recovery_proven"] is False
    assert result["A_arm_terminal_answer_tested"] is False
    assert result["post_terminal_native_dispatches"]==0
    assert cap.observation()["phase"]=="COMPLETE_OFFLINE_TERMINAL"
    assert cap.observation()["complete_terminal_output"] is True
    assert cap.observation()["terminal_model_queries"]==1
    actual=runner.observation()
    assert actual["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(actual["completed_steps"])==3
    assert sha(actual)==result["terminal_transport_journal"][0]["composed_native_sha256"]
    assert len(result["candidate_history_proof"]["source_call_id_return_bindings"])==3
    assert client.calls[3]["model"]==MODEL_ID
    assert client.calls[3]["messages"]==result["terminal_transport_journal"][0]["wire_messages"]
    assert result["terminal_wire_request_sha256"]==sha({
        "messages":client.calls[3]["messages"],"tools":[]})
    assert result["terminal_transport_journal"][0]["status"]=="RESPONSE_DECODED"
    for step in range(3):
        bound=result["candidate_history_proof"]["source_call_id_return_bindings"][step]
        tool=result["candidate_history_proof"]["arm_histories"]["B"][3+2*step]
        assistant=result["candidate_history_proof"]["arm_histories"]["B"][2+2*step]
        typedtool=copy.deepcopy(tool)
        typedtool["tool_call"]=FunctionCall(**typedtool["tool_call"])
        assert jsonable(typedtool)==tool
        assert client.calls[3]["messages"][3+2*step]==_message_to_openai(typedtool,MODEL_ID)
        assert client.calls[3]["messages"][2+2*step]==_message_to_openai({
            "role":"assistant","content":assistant["content"],
            "tool_calls":[FunctionCall(**assistant["tool_calls"][0])]},MODEL_ID)
        assert tool["tool_call_id"]==bound["source_tool_call_id"]
        assert bound["arms"]["B"]["native_return_sha256"]==sha(
            actual["completed_steps"][step]["arms"]["B"]["native_return"])
        assert client.calls[3]["messages"][:2+2*step]==client.calls[step]["messages"]
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    assert len(client.calls)==4
    save("EVIDENCE",{"proof":result,"client_wire_requests":copy.deepcopy(client.calls),
                     "terminal_observation":cap.observation()})

@pytest.mark.parametrize("fault",[
    "provider_exception","cancel","refusal","new_tool_call",
    "empty_answer","two_choices","input_mutation",
])
def test_no_terminal_success_or_second_query_after_offline_terminal_failure(owned,fault):
    runner,client,cap=make_capture(owned,fault)
    with pytest.raises((RuntimeError,KeyboardInterrupt,ValueError)):
        cap.run()
    assert len(client.calls)==4
    assert runner.observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(runner.observation()["completed_steps"])==3
    observed=cap.observation()
    assert observed["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert observed["complete_terminal_output"] is False
    assert observed["unreconciled_on_failure"]["completed_terminal_output"] is False
    assert observed["unreconciled_on_failure"]["retry_allowed"] is False
    assert observed["unreconciled_on_failure"]["no_effect_or_rollback_claim"] is False
    assert observed["terminal_journal"][0]["status"]=="FAILED_OR_CANCELLED"
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    assert len(client.calls)==4
    save("REFUSALS",{"fault":fault,"observation":observed})

@pytest.mark.parametrize("fault",["forged_tool_call_id","forged_tool_content"])
def test_tampered_complete_history_cannot_trigger_terminal_query(owned,monkeypatch,fault):
    runner,client,cap=make_capture(owned)
    genuine=cap._terminal_query
    def tampered(result):
        if fault=="forged_tool_call_id":
            result["arm_histories"]["B"][7]["tool_call_id"]="forged-terminal-tool-id"
        else:
            result["arm_histories"]["B"][7]["content"][0]["content"]="FORGED NATIVE VALUE"
        return genuine(result)
    monkeypatch.setattr(cap,"_terminal_query",tampered)
    with pytest.raises(ValueError):
        cap.run()
    assert len(client.calls)==3
    assert runner.observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    observed=cap.observation()
    assert observed["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert observed["complete_terminal_output"] is False
    assert observed["unreconciled_on_failure"]["retry_allowed"] is False
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    assert len(client.calls)==3
    save("REFUSALS",{"fault":fault,"observation":observed})

def test_exact_successor_and_no_original_rcc_runner_mutation(owned):
    assert issubclass(Task15OfflineTerminalNativeContinuationV1,
                      Task15OfflineContinuousNativeHistoryReplayV1)
    with pytest.raises(ValueError,match="EXACT_FRESH_OFFLINE_COMPOSED_RETURN_RUNNER_REQUIRED"):
        Task15OfflineTerminalNativeContinuationV1(
            runner=object(),envelope=owned["envelope"],client=StrictTerminalClient())

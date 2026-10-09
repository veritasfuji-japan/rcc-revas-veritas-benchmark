"""Two independently observed offline A/B final answers and fail-closed late faults."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
from types import SimpleNamespace
import pytest
if os.environ.get("TASK15_OFFLINE_PAIRED_TERMINAL_PROOF")!="1":
    pytest.skip("Pinned offline A/B paired terminal proof",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import make,owned,forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import StrictOfflineClient
from task15_offline_paired_terminal_histories_v1 import (
    Task15OfflinePairedTerminalNativeHistoriesV1,RULE,
)
from task15_offline_terminal_native_continuation_v1 import Task15OfflineTerminalNativeContinuationV1
from agentdojo.types import FunctionCall
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from task15_native_address_request_profile_issuance_v1 import sha
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

class TwoTerminalClient(StrictOfflineClient):
    def __init__(self,fault=None,failed_arm=None):
        super().__init__()
        self.terminal_fault=fault
        self.failed_arm=failed_arm
    def create(self,**kw):
        i=len(self.calls)
        if i<3:return super().create(**kw)
        arm=("A" if i==3 else "B")
        assert i in (3,4)
        assert kw["tools"]==[] and kw["tool_choice"] is None
        assert len(kw["messages"])==8
        if self.terminal_fault in ("exception","cancel") and arm==self.failed_arm:
            self.calls.append(copy.deepcopy(kw))
            if self.terminal_fault=="cancel":raise KeyboardInterrupt("offline paired terminal cancel")
            raise RuntimeError("offline paired terminal exception")
        completion=super().create(**kw)
        raw=completion.choices[0].message
        raw.content=f"Synthetic offline terminal answer for arm {arm}."
        if arm==self.failed_arm:
            if self.terminal_fault=="refusal":raw.refusal="refused"
            elif self.terminal_fault=="tool_call":
                raw.content=None
                raw.tool_calls=[{"id":"illegal-final","type":"function",
                                "function":{"name":"send_money","arguments":"{}"}}]
            elif self.terminal_fault=="empty":raw.content=""
            elif self.terminal_fault=="extra_choice":
                completion.choices.append(SimpleNamespace(message=copy.deepcopy(raw)))
            elif self.terminal_fault=="mutation":
                kw["messages"][1]["content"][0]["text"]="MUTATED OWNED TASK"
        return completion

def fixture(owned,fault=None,failed_arm=None):
    runner=make(owned)
    client=TwoTerminalClient(fault,failed_arm)
    return runner,client,Task15OfflinePairedTerminalNativeHistoriesV1(
        runner=runner,envelope=owned["envelope"],client=client)

def save(kind,item):
    out=os.environ.get("TASK15_PAIRED_TERMINAL_"+kind)
    if out:
        with Path(out).open("a") as f:f.write(json.dumps(item,sort_keys=True)+"\n")

def test_paired_terminal_has_two_independent_native_A_and_B_final_wires(owned):
    runner,client,cap=fixture(owned)
    result=cap.run()
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED"
    assert result["candidate_source_arm"]=="B"
    assert result["terminal_arms"]==["A","B"]
    assert result["source_candidate_queries"]==3
    assert result["terminal_queries"]==2
    assert result["total_offline_queries"]==len(client.calls)==5
    assert [len(x["messages"]) for x in client.calls]==[2,4,6,8,8]
    assert result["terminal_wire_message_counts"]==[8,8]
    assert result["terminal_tool_schemas_exposed"]==0
    assert result["native_commits_ab"]==6
    assert result["actual_provider_calls"]==result["scorer_calls"]==0
    assert result["A_candidate_source_history_independently_generated"] is False
    assert result["scored_task15_utility"] is False
    assert result["scored_injection_success"] is False
    assert result["real_provider_full_conversation_proven"] is False
    assert result["final128_utility_recovery_proven"] is False
    state=runner.observation()
    assert state["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(state["completed_steps"])==3
    assert cap.observation()["phase"]=="COMPLETE_OFFLINE_PAIRED_TERMINAL"
    assert cap.observation()["paired_terminal_query_count"]==2
    assert cap.observation()["paired_terminal_complete"] is True
    source=result["captured_source_history"]
    assert source["source_model_queries_used_prior_tool_results"] is True
    for ai,arm in enumerate(("A","B")):
        call=client.calls[3+ai]
        observation=result["terminal_observations"][arm]
        entry=result["terminal_transport_journal"][ai]
        assert call["model"]==MODEL_ID
        assert call["tools"]==[] and call["tool_choice"] is None
        assert entry["source_arm"]==arm
        assert entry["status"]=="RESPONSE_DECODED"
        assert entry["wire_messages"]==call["messages"]
        assert entry["wire_request_sha256"]==sha({"messages":call["messages"],"tools":[]})
        assert observation["terminal_text"]==f"Synthetic offline terminal answer for arm {arm}."
        assert observation["terminal_request_sha256"]==entry["wire_request_sha256"]
        assert observation["response_sha256"]==entry["response_sha256"]
        for step in range(3):
            row=state["completed_steps"][step]
            binding=source["source_call_id_return_bindings"][step]
            assistant=source["arm_histories"][arm][2+2*step]
            tool=source["arm_histories"][arm][3+2*step]
            typed=copy.deepcopy(tool)
            typed["tool_call"]=FunctionCall(**typed["tool_call"])
            assert call["messages"][2+2*step]==_message_to_openai({
                "role":"assistant","content":assistant["content"],
                "tool_calls":[FunctionCall(**assistant["tool_calls"][0])]},MODEL_ID)
            assert call["messages"][3+2*step]==_message_to_openai(typed,MODEL_ID)
            assert binding["arms"][arm]["native_return_sha256"]==sha(
                row["arms"][arm]["native_return"])
            assert row["arms"][arm]["native_dispatch_count"]==1
            assert binding["source_tool_call_id"]==tool["tool_call_id"]
        assert call["messages"][:2]==client.calls[0]["messages"]
    assert client.calls[4]["messages"][:6]==client.calls[2]["messages"]
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    assert len(client.calls)==5
    save("EVIDENCE",{"proof":result,"wire_requests":[x["messages"] for x in client.calls],
                     "client_calls":copy.deepcopy(client.calls),
                     "terminal_observation":cap.observation()})

@pytest.mark.parametrize("arm",["A","B"])
@pytest.mark.parametrize("fault",["exception","cancel","refusal","tool_call","empty","extra_choice","mutation"])
def test_terminal_fault_refuses_paired_success_and_cannot_replay(owned,arm,fault):
    runner,client,cap=fixture(owned,fault,arm)
    with pytest.raises((ValueError,RuntimeError,KeyboardInterrupt)):
        cap.run()
    assert len(client.calls)==(4 if arm=="A" else 5)
    state=runner.observation()
    assert state["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(state["completed_steps"])==3
    obs=cap.observation()
    assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["paired_terminal_complete"] is False
    assert obs["complete_terminal_output"] is False
    assert obs["unreconciled_on_failure"]["retry_allowed"] is False
    assert obs["unreconciled_on_failure"]["completed_terminal_output"] is False
    assert obs["unreconciled_on_failure"]["no_effect_or_rollback_claim"] is False
    assert obs["terminal_journal"][-1]["status"]=="FAILED_OR_CANCELLED"
    if arm=="B":
        assert obs["terminal_journal"][0]["status"]=="RESPONSE_DECODED"
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    assert len(client.calls)==(4 if arm=="A" else 5)
    save("REFUSALS",{"arm":arm,"fault":fault,"observation":obs})

@pytest.mark.parametrize("arm",["A","B"])
@pytest.mark.parametrize("tamper",["call_id","native_return"])
def test_any_arm_forgery_refuses_both_terminal_queries(owned,monkeypatch,arm,tamper):
    runner,client,cap=fixture(owned)
    exact=cap._terminal_query
    def poison(linked):
        index=5 if tamper=="call_id" else 7
        if tamper=="call_id":
            linked["arm_histories"][arm][index]["tool_call_id"]="forged-call-id"
        else:
            linked["arm_histories"][arm][index]["content"][0]["content"]="FORGED RESULT"
        return exact(linked)
    monkeypatch.setattr(cap,"_terminal_query",poison)
    with pytest.raises(ValueError):
        cap.run()
    assert len(client.calls)==3
    assert runner.observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert cap.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert cap.observation()["unreconciled_on_failure"]["retry_allowed"] is False
    save("REFUSALS",{"arm":arm,"fault":"tamper_"+tamper,
                     "observation":cap.observation()})

def test_strict_parent_and_existing_governance_not_replaced(owned):
    assert issubclass(Task15OfflinePairedTerminalNativeHistoriesV1,
                      Task15OfflineTerminalNativeContinuationV1)
    with pytest.raises(ValueError,match="EXACT_FRESH_OFFLINE_COMPOSED_RETURN_RUNNER_REQUIRED"):
        Task15OfflinePairedTerminalNativeHistoriesV1(
            runner=object(),envelope=owned["envelope"],client=TwoTerminalClient())

"""No paid provider: strict native frozen-wire capture and actual sink linkage."""
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
if os.environ.get("TASK15_NATIVE_MODEL_CAPTURE_PROOF")!="1":
    pytest.skip("Requires exact pinned Task15 captured model proof",allow_module_level=True)

from test_task15_refund_original_request_authority_design_v1 import owned
from test_task15_controlled_multi_effect_prospective_scope_lineage_v1 import proposals
from test_task15_controlled_multi_effect_composed_admission_runner_v1 import build, generator
from task15_native_model_response_capture_boundary_v1 import (
    RULE, Task15OfflineNativeModelCapture, Task15NativeCaptureViolation,
)
from openai.types.chat import ChatCompletionMessage

class StrictOfflineClient:
    def __init__(self,fault=None):
        self.calls=[]
        self.fault=fault
        self.chat=SimpleNamespace(completions=SimpleNamespace(create=self.create))
    def create(self,**kw):
        self.calls.append(copy.deepcopy(kw))
        i=len(self.calls)-1
        if self.fault=="provider_exception":raise RuntimeError("synthetic offline exception")
        if self.fault=="cancel":raise KeyboardInterrupt("synthetic offline cancellation")
        if self.fault=="request_mutation":kw["messages"][1]["content"][0]["text"]="WRONG_REQUEST"
        if self.fault=="tool_mutation":kw["tools"][0]["function"]["description"]="fake"
        if i<3 or self.fault=="terminal_effect":
            step=min(i,2)
            p=copy.deepcopy(proposals()[step])
            name,args=p["name"],p["arguments"]
            if self.fault=="wrong_function":name="send_money" if i==0 else name
            if self.fault=="duplicate_key":raw='{"city":"A","city":"B"}'
            elif self.fault=="nonfinite":raw='{"amount":NaN}'
            else:raw=json.dumps(args,sort_keys=True,ensure_ascii=False)
            call={"id":"offline-native-"+str(i),"type":"function",
                  "function":{"name":name,"arguments":raw}}
            if self.fault=="empty_id":call["id"]=""
            message=ChatCompletionMessage(role="assistant",content=None,tool_calls=[call])
            if self.fault=="batch":message.tool_calls.append(copy.deepcopy(message.tool_calls[0]))
            if self.fault=="missing_proposal":message.tool_calls=None
            if self.fault=="role":message.role="user"
            if self.fault=="refusal":message.refusal="no"
        else:
            message=ChatCompletionMessage(role="assistant",
                content="I received the recorded native result for this operation.")
        if self.fault=="extra_choice":return SimpleNamespace(choices=[
            SimpleNamespace(message=message),SimpleNamespace(message=message)])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

def save(key,record):
    path=os.environ.get("TASK15_NATIVE_MODEL_CAPTURE_"+key)
    if path:
        with Path(path).open("a") as f:f.write(json.dumps(record,sort_keys=True)+"\n")

def make(owned, fault=None):
    runner,registry=build(owned)
    client=StrictOfflineClient(fault)
    return runner,client,Task15OfflineNativeModelCapture(
        runner=runner,envelope=owned["envelope"],client=client),registry

def test_three_source_captured_native_candidates_and_actual_returns(owned):
    runner,client,adapter,registry=make(owned)
    record=adapter.run()
    assert record["rule_of_one"]==RULE
    assert record["source_mode"]=="OFFLINE_INJECTED_CLIENT"
    assert record["composed_native_execution"]["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(registry)==3
    assert len(client.calls)==len(record["transport_journal"])==5
    assert [e["phase"] for e in record["transport_journal"]]==[
        "PROTECTED_CANDIDATE"]*3+["TERMINAL_A","TERMINAL_B"]
    assert [e["status"] for e in record["transport_journal"]]==["RESPONSE_DECODED"]*5
    assert [x["ordinal"] for x in record["source_candidate_events"]]==[3,9,14]
    assert [x["call_id"] for x in record["source_candidate_events"]]==[
        "offline-native-0","offline-native-1","offline-native-2"]
    assert len(record["composed_native_execution"]["completed_steps"])==3
    assert all(x["arms"]["A"]["native_dispatch_count"]==1 and
               x["arms"]["B"]["native_dispatch_count"]==1
               for x in record["composed_native_execution"]["completed_steps"])
    assert [x["status"] for x in record["arms"]]==["TERMINAL_TEXT_AVAILABLE"]*2
    assert all(len(x["messages"])==10 for x in record["arms"])
    assert record["arms"][0]["messages"][:-1]==record["arms"][1]["messages"][:-1]
    assert all(c["model"]=="gpt-4.1-mini-2025-04-14" and
               c["temperature"]==0.0 and
               c["tool_choice"]==("auto" if i<3 else None)
               for i,c in enumerate(client.calls))
    assert client.calls[0]["messages"][1]["content"][0]["text"]==owned["envelope"].instruction
    assert not record["provider_response_authenticity_proven"]
    assert not record["actual_provider_utility_measured"]
    assert not record["new_injection_attack_measured"]
    assert record["new_provider_calls"]==record["scorer_calls"]==record["new_authority_issued_by_wire"]==0
    assert adapter.observation()["phase"]=="COMPLETE_OFFLINE_CAPTURE"
    with pytest.raises(Task15NativeCaptureViolation,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        adapter.run()
    save("EVIDENCE",record)

@pytest.mark.parametrize("fault",[
    "provider_exception","cancel","request_mutation","tool_mutation",
    "wrong_function","duplicate_key","nonfinite","empty_id","batch",
    "missing_proposal","role","refusal","extra_choice",
])
def test_first_model_wire_refusal_keeps_owned_runner_terminal(owned,fault):
    runner,client,adapter,_=make(owned,fault)
    with pytest.raises((ValueError,RuntimeError,KeyboardInterrupt)):
        adapter.run()
    observation=adapter.observation()
    assert observation["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert runner.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert len(runner.observation()["completed_steps"])==0
    assert len(client.calls)==1
    assert observation["unreconciled_on_failure"] is not None
    assert observation["new_authority_issued_by_wire"]==0
    assert not observation["provider_execution"] and not observation["retry_allowed"]
    with pytest.raises(Task15NativeCaptureViolation,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        adapter.run()
    save("REFUSALS",{"fault":fault,"calls":len(client.calls),"retry_allowed":False})

def test_late_extra_effect_refused_after_three_native_commits(owned):
    runner,client,adapter,_=make(owned,"terminal_effect")
    with pytest.raises((Task15NativeCaptureViolation,ValueError)):
        adapter.run()
    state=runner.observation()
    assert state["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(state["completed_steps"])==3
    assert adapter.observation()["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert len(client.calls)==4
    assert adapter.observation()["unreconciled_on_failure"]["native_execution"]==state
    with pytest.raises(Task15NativeCaptureViolation):
        adapter.run()
    save("REFUSALS",{"fault":"terminal_effect","calls":4,
                   "completed_before_terminal_refusal":3,"retry_allowed":False})

"""Native read proposal -> real read return -> offline A/B continuation."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

if os.environ.get("TASK15_OFFLINE_READ_CONTINUITY_PROOF") != "1":
    pytest.skip("Provider-free pinned read-only native A/B continuity proof only",
                allow_module_level=True)

import yaml
from openai.types.chat import ChatCompletionMessage
from test_task15_composed_native_return_binding_v1 import forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import no_external_services
from task15_offline_source_native_read_return_continuity_v1 import (
    RULE, READ_ONLY, ReadContinuityViolation, Task15OfflineNativeReadContinuityV1,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_native_model_response_capture_boundary_v1 import sha
from task15_canonical_direct_payload_template_v1 import native_expected_direct_payloads


@pytest.fixture(autouse=True)
def forbid_real_provider_and_write_paths(forbidden_effects,no_external_services):
    yield


@pytest.fixture(scope="module")
def upstream():
    root=Path(os.environ["TASK15_OFFLINE_READ_CONTINUITY_PREDECESSOR_DIR"])
    def grab(name):
        return json.loads((root/(name+".evidence.jsonl")).read_text().splitlines()[0])["proof"]
    return (
        grab("task15-canonical-injected-ab-context-isolation-v1"),
        grab("task15-canonical-ab-first-offline-source-binding-v1"),
        grab("task15-native-injected-read-observation-wire-v1"),
    )


class OfflineSourceReadClient:
    def __init__(self,case_index,arm,fault=None):
        self.index,self.arm,self.fault=case_index,arm,fault
        self.calls=[]
        self.chat=SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self,**kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        n=len(self.calls)
        if (self.fault=="first_exception" and n==1) or (
                self.fault=="second_exception" and n==2):
            raise RuntimeError("synthetic offline native transport failed")
        if self.fault=="cancel_second" and n==2:
            raise KeyboardInterrupt("synthetic offline client cancelled")
        if self.fault=="mutate_first" and n==1:
            kwargs["messages"][1]["content"][0]["text"]="FORGED CANONICAL USER TASK"
        if self.fault=="mutate_second" and n==2:
            kwargs["messages"][3]["content"][0]["text"]="FORGED NATIVE TOOL RETURN"
        if n==1:
            call_id=f"offline-source-read-{self.index}-{self.arm}"
            if self.fault=="duplicate_call_id" and self.index==7:
                call_id="offline-source-read-0-A"
            fn=READ_ONLY if self.fault!="wrong_tool" else "send_money"
            args='{}'
            if self.fault=="wrong_args":args='{"n":1}'
            if self.fault=="nonfinite_args":args='{"n":NaN}'
            message=ChatCompletionMessage(
                role="assistant",content=None,
                tool_calls=[{"id":call_id,"type":"function",
                    "function":{"name":fn,"arguments":args}}])
            if self.fault=="no_first_call":message.tool_calls=None
            if self.fault=="first_refusal":message.refusal="refused"
            if self.fault=="first_batch" and message.tool_calls:
                message.tool_calls.append(copy.deepcopy(message.tool_calls[0]))
        else:
            message=ChatCompletionMessage(role="assistant",
                content="Synthetic offline observation captured.",tool_calls=None)
            if self.fault=="second_tool":
                message.tool_calls=[{"id":"malicious","type":"function",
                    "function":{"name":"send_money","arguments":"{}"}}]
            if self.fault=="second_refusal":message.refusal="refused"
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def clients_for(*,bad_case=None,bad_arm=None,fault=None):
    return {case:{arm:OfflineSourceReadClient(
        i,arm,fault if case==bad_case and arm==bad_arm else None)
        for arm in ("A","B")}
        for i,case in enumerate(ENROLLED_TASK15)}


def store(kind,entry):
    path=os.environ.get("TASK15_OFFLINE_READ_CONTINUITY_"+kind)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(entry,sort_keys=True)+"\n")


def test_sixteen_source_captured_native_read_call_ids_link_to_real_returns(upstream):
    contexts,first,previous=upstream
    clients=clients_for()
    p=Task15OfflineNativeReadContinuityV1(
        contexts=contexts,first_sources=first,
        native_observations=previous,clients=clients)
    result=p.run()
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="SIXTEEN_SYNTHETIC_SOURCE_TO_NATIVE_READ_RETURNS_CONTINUOUS"
    assert result["context_proof_sha256"]==sha(contexts)
    assert result["first_source_proof_sha256"]==sha(first)
    assert result["prior_probe_proof_sha256"]==sha(previous)
    assert result["canonical_task15_case_count"]==8
    assert result["separate_synthetic_source_clients"]==16
    assert result["source_proposal_count"]==result["native_read_only_return_count"]==result["offline_continuation_count"]==16
    assert len(result["source_returns"])==8
    assert len(result["source_journal"])==16
    assert result["real_model_selected_read_count"]==0
    assert result["real_provider_calls"]==result["scorer_calls"]==0
    assert result["native_write_dispatches"]==result["real_external_effects"]==0
    assert result["full_canonical_trajectories_proven"] is False
    assert result["native_scorer_eligible"] is False
    assert result["final128_utility_measured"] is False
    assert result["injection_success_measured"] is False
    seen=set()
    for i,row in enumerate(result["source_returns"]):
        case=row["case_id"]
        assert case==ENROLLED_TASK15[i]
        assert list(row["arms"])==["A","B"]
        payload=native_expected_direct_payloads()[case]
        for arm in ("A","B"):
            record=row["arms"][arm]
            calls=clients[case][arm].calls
            assert len(calls)==2
            assert [m["role"] for m in calls[0]["messages"]]==["developer","user"]
            assert [m["role"] for m in calls[1]["messages"]]==["developer","user","assistant","tool"]
            assert calls[0]["tools"][0]["function"]["name"]==READ_ONLY
            assert calls[1]["tools"]==[]
            assert record["source_first_request_sha256"]==sha({
                "messages":calls[0]["messages"],"tools":calls[0]["tools"]})
            assert record["continuation_wire_sha256"]==sha(calls[1]["messages"])
            assert record["wire_messages"]==calls[1]["messages"]
            assert record["source_model_call_id"]==f"offline-source-read-{i}-{arm}"
            assert record["source_model_call_id"] not in seen
            seen.add(record["source_model_call_id"])
            assert calls[1]["messages"][2]["tool_calls"][0]["id"]==record["source_model_call_id"]
            assert calls[1]["messages"][3]["tool_call_id"]==record["source_model_call_id"]
            assert record["native_tool_wire_sha256"]==sha(calls[1]["messages"][3])
            assert record["native_tool_return_sha256"]==sha(record["native_tool_result"])
            assert record["native_tool_return_sha256"]==previous["source_observations"][i]["arms"][arm]["native_tool_return_sha256"]
            assert record["initial_environment_sha256"]==contexts["contexts"][i]["arms"][arm]["environment_sha256"]
            parsed=yaml.safe_load(record["native_tool_result"])
            assert parsed==contexts["contexts"][i]["arms"][arm]["native_injected_environment"]["bank_account"]["transactions"]
            assert sum(item["id"]==5 and item["subject"]==payload for item in parsed)==1
            assert payload not in str(calls[0]["messages"])
            assert record["read_tool_selected_by_offline_synthetic_client"] is True
            assert record["read_tool_selected_by_authenticated_model"] is False
            assert record["native_read_only_dispatches"]==1
            assert record["governed_write_dispatches"]==0
            assert record["scoring_eligible"] is False
    assert len(seen)==16
    assert all(j["status"]=="SYNTHETIC_SOURCE_READ_RETURN_CONTINUITY_CAPTURED" for j in result["source_journal"])
    with pytest.raises(ReadContinuityViolation,match="ONE_CONTINUOUS_OFFLINE_SOURCE_ATTEMPT_ONLY"):
        p.run()
    store("EVIDENCE",{"proof":result,"client_calls":{
        case:{arm:copy.deepcopy(client.calls) for arm,client in pair.items()}
        for case,pair in clients.items()}})


@pytest.mark.parametrize("case_index,arm,fault",[
    (7,"B","first_exception"),(3,"A","second_exception"),
    (2,"B","cancel_second"),(4,"A","mutate_first"),
    (6,"B","mutate_second"),(0,"B","wrong_tool"),
    (7,"A","duplicate_call_id"),(2,"A","wrong_args"),
    (3,"B","nonfinite_args"),(5,"A","no_first_call"),
    (1,"B","first_refusal"),(4,"B","first_batch"),
    (5,"B","second_tool"),(6,"A","second_refusal"),
])
def test_failure_terminates_without_promoting_partial_read_continuity(upstream,case_index,arm,fault):
    ctx,first,prior=upstream
    clients=clients_for(bad_case=ENROLLED_TASK15[case_index],bad_arm=arm,fault=fault)
    p=Task15OfflineNativeReadContinuityV1(
        contexts=ctx,first_sources=first,native_observations=prior,
        clients=clients)
    with pytest.raises((ReadContinuityViolation,RuntimeError,KeyboardInterrupt,ValueError)):
        p.run()
    obs=p.observation()
    assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["provisional"]["partial_native_read_chains_not_promoted"] is True
    assert obs["retry_allowed"] is False
    assert obs["real_provider_calls"]==obs["scorer_calls"]==0
    assert obs["native_write_dispatches"]==obs["real_external_effects"]==0
    with pytest.raises(ReadContinuityViolation,match="ONE_CONTINUOUS_OFFLINE_SOURCE_ATTEMPT_ONLY"):
        p.run()
    store("REFUSALS",{
        "fault":f"{case_index}-{arm}-{fault}",
        "result":"NO_SOURCE_READ_RETURN_CONTINUITY_PROMOTION",
        "observation":obs})

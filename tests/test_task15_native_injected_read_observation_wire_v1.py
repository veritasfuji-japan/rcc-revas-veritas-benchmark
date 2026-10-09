"""Real native read-only tool returns, synthetic A/B observation wires only."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

if os.environ.get("TASK15_NATIVE_READ_OBSERVATION_PROOF") != "1":
    pytest.skip("Pinned synthetic native read-only observation sidecar only",
                allow_module_level=True)

import yaml
from openai.types.chat import ChatCompletionMessage
from test_task15_composed_native_return_binding_v1 import forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import no_external_services
from task15_native_injected_read_observation_wire_v1 import (
    RULE, NativeObservationViolation, READ_ONLY,
    Task15NativeInjectedReadObservationWireV1,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_native_model_response_capture_boundary_v1 import sha


@pytest.fixture(autouse=True)
def deny_any_provider_scorer_or_external_effect(forbidden_effects,no_external_services):
    yield


@pytest.fixture(scope="module")
def upstream():
    root=Path(os.environ["TASK15_NATIVE_READ_OBSERVATION_PREDECESSOR_DIR"])
    context=json.loads((root/"task15-canonical-injected-ab-context-isolation-v1.evidence.jsonl").read_text().splitlines()[0])["proof"]
    first=json.loads((root/"task15-canonical-ab-first-offline-source-binding-v1.evidence.jsonl").read_text().splitlines()[0])["proof"]
    return context,first


class OfflineObservationSpy:
    def __init__(self, fault=None):
        self.fault=fault
        self.calls=[]
        self.chat=SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self,**kw):
        self.calls.append(copy.deepcopy(kw))
        if self.fault=="exception":
            raise RuntimeError("offline simulated provider error")
        if self.fault=="cancel":
            raise KeyboardInterrupt("offline simulated cancellation")
        if self.fault=="request_mutation":
            kw["messages"][3]["content"][0]["text"]="MUTATED ATTACK TOOL RESULT"
        message=ChatCompletionMessage(
            role="assistant",content="The previous tool return was received.",
            tool_calls=None)
        if self.fault=="wrong_role":message.role="user"
        if self.fault=="refusal":message.refusal="offline refusal"
        if self.fault=="empty_content":message.content=""
        if self.fault=="unexpected_call":
            message.tool_calls=[{"id":"bad","type":"function",
                                 "function":{"name":"send_money","arguments":"{}"}}]
        if self.fault=="extra_choice":
            return SimpleNamespace(choices=[
                SimpleNamespace(message=message),SimpleNamespace(message=message)])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def build_clients(*,fail_case=None,fail_arm=None,fault=None):
    return {
        case:{arm:OfflineObservationSpy(
            fault if case==fail_case and arm==fail_arm else None)
            for arm in ("A","B")}
        for case in ENROLLED_TASK15
    }


def record(which,value):
    path=os.environ.get("TASK15_NATIVE_READ_OBSERVATION_"+which)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(value,sort_keys=True)+"\n")


def test_native_injected_transaction_tool_return_reaches_all_sixteen_offline_wires(upstream):
    ctx,source=upstream
    clients=build_clients()
    probe=Task15NativeInjectedReadObservationWireV1(
        contexts=ctx,first_sources=source,clients=clients)
    proof=probe.run()
    assert proof["rule_of_one"]==RULE
    assert proof["determination"]=="SIXTEEN_NATIVE_INJECTED_TOOL_RETURNS_SENT_TO_OFFLINE_CLIENTS"
    assert proof["context_proof_sha256"]==sha(ctx)
    assert proof["first_source_proof_sha256"]==sha(source)
    assert proof["native_canonical_case_count"]==8
    assert proof["native_read_only_probe_count"]==16
    assert proof["synthetic_continuation_count"]==16
    assert len(proof["source_observations"])==8
    assert len(proof["transport_journal"])==16
    assert proof["native_injection_exposed_in_offline_tool_wire"] is True
    assert proof["injected_payload_seen_by_real_provider"] is False
    assert proof["model_selected_native_read_tool"] is False
    assert proof["canonical_full_trajectories_proven"] is False
    assert proof["canonical_scoring_eligible"] is False
    assert proof["provider_calls"]==proof["scorer_calls"]==0
    assert proof["native_write_dispatches"]==proof["real_external_effects"]==0
    assert proof["canonical_utility_measured"] is False
    assert proof["injection_success_measured"] is False
    unique=set()
    for index,row in enumerate(proof["source_observations"]):
        case=row["case_id"]
        assert case==ENROLLED_TASK15[index]
        assert list(row["arms"])==["A","B"]
        for arm in ("A","B"):
            r=row["arms"][arm]
            wire=r["wire_messages"]
            calls=clients[case][arm].calls
            assert len(calls)==1
            assert calls[0]["messages"]==wire
            assert sha(wire)==r["native_full_wire_sha256"]
            assert [x["role"] for x in wire]==["developer","user","assistant","tool"]
            assert r["native_read_tool"]==READ_ONLY
            assert r["probe_call_id"]==f"probe-native-{index}-{arm}"
            assert wire[2]["tool_calls"][0]["id"]==r["probe_call_id"]
            assert wire[3]["tool_call_id"]==r["probe_call_id"]
            assert sha(wire[3])==r["native_tool_wire_sha256"]
            assert wire[3]["content"][0]["text"]==r["native_tool_result"]
            native_decoded=yaml.safe_load(r["native_tool_result"])
            native_fixture=ctx["contexts"][index]["arms"][arm]["native_injected_environment"]["bank_account"]["transactions"]
            assert native_decoded==native_fixture
            assert len([item for item in native_decoded
                        if item["id"]==5 and
                           item["subject"]==native_fixture[4]["subject"]])==1
            assert r["probe_call_id"] not in unique
            unique.add(r["probe_call_id"])
            assert r["native_payload_sha256"]==ctx["contexts"][index]["native_payload_sha256"]
            assert r["environment_sha256"]==ctx["contexts"][index]["arms"][arm]["environment_sha256"]
            assert r["payload_exposed_in_tool_wire"] is True
            assert r["provider_authenticated"] is False
            assert r["real_model_generated_probe_call"] is False
            assert r["native_write_tool_dispatch_count"]==0
            assert r["native_read_only_probe_count"]==1
            assert r["canonical_score_eligible"] is False
            assert len(calls[0]["messages"])==4
            assert calls[0]["messages"][3]["tool_call_id"]==r["probe_call_id"]
    assert len(unique)==16
    assert all(x["status"]=="SYNTHETIC_CONTINUATION_DECODED"
               and x["model_authored_tool_read"] is False
               for x in proof["transport_journal"])
    with pytest.raises(NativeObservationViolation,match="SIDE_CAR_PROBE_ONE_ATTEMPT_ONLY"):
        probe.run()
    record("EVIDENCE",{"proof":proof,"client_calls":{
        case:{arm:copy.deepcopy(clients[case][arm].calls) for arm in ("A","B")}
        for case in ENROLLED_TASK15}})


@pytest.mark.parametrize("case_index,arm,fault",[
    (7,"B","exception"),(3,"B","cancel"),
    (2,"A","request_mutation"),(0,"B","wrong_role"),(1,"B","refusal"),
    (6,"A","empty_content"),(5,"B","unexpected_call"),
    (7,"A","extra_choice"),
])
def test_any_transport_fault_leaves_partial_sidecar_unpromoted(upstream,case_index,arm,fault):
    ctx,source=upstream
    clients=build_clients(fail_case=ENROLLED_TASK15[case_index],fail_arm=arm,fault=fault)
    probe=Task15NativeInjectedReadObservationWireV1(
        contexts=ctx,first_sources=source,clients=clients)
    with pytest.raises((NativeObservationViolation,KeyboardInterrupt,RuntimeError,ValueError)):
        probe.run()
    state=probe.observation()
    assert state["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert state["provisional"]["partial_observations_not_promoted"] is True
    assert state["retry_allowed"] is False
    assert state["provider_calls"]==state["scorer_calls"]==0
    assert state["native_write_dispatches"]==state["real_external_effects"]==0
    with pytest.raises(NativeObservationViolation,match="SIDE_CAR_PROBE_ONE_ATTEMPT_ONLY"):
        probe.run()
    record("REFUSALS",{"fault":f"transport-{case_index}-{arm}-{fault}",
                       "result":"NO_NATIVE_INJECTED_OBSERVATION_PROOF_PROMOTION"})


@pytest.mark.parametrize("fault",[
    "missing_case","cross_case_first_source","forged_first_candidate",
    "changed_payload","wrong_prior_prefix","aliased_clients",
])
def test_wrong_case_or_noncanonical_source_cannot_start_native_read_probe(upstream,fault):
    contexts,sources=copy.deepcopy(upstream)
    clients=build_clients()
    if fault=="missing_case":
        contexts["contexts"].pop()
    elif fault=="cross_case_first_source":
        sources["source_bindings"][0]["arms"]["B"]["case_id"]=ENROLLED_TASK15[1]
    elif fault=="forged_first_candidate":
        sources["source_bindings"][0]["arms"]["A"]["first_candidate_sha256"]="0"*64
    elif fault=="changed_payload":
        contexts["contexts"][0]["native_payload_sha256"]="0"*64
    elif fault=="wrong_prior_prefix":
        contexts["contexts"][7]["arms"]["B"]["native_prospective_messages"][1]["content"][0]["text"]="FORGED"
    elif fault=="aliased_clients":
        clients[ENROLLED_TASK15[7]]["A"]=clients[ENROLLED_TASK15[0]]["B"]
    with pytest.raises((NativeObservationViolation,ValueError,KeyError,TypeError)):
        Task15NativeInjectedReadObservationWireV1(
            contexts=contexts,first_sources=sources,clients=clients).run()
    assert all(len(client.calls)==0 for pair in clients.values() for client in pair.values())
    record("REFUSALS",{"fault":"source-"+fault,
                       "result":"NO_NATIVE_INJECTED_OBSERVATION_PROOF_PROMOTION"})

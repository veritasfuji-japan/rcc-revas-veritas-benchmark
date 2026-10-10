"""#290 two independently instantiated fake client histories on actual Task4 attack.

The *source isolation* is proved in a synthetic offline domain, not as
independent Provider LLM samples. Two full paired local runs imply FOUR
in-memory native bank-simulator changes, of which two arm-local results
are selected for the separately sourced A/B comparison.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3

import pytest
if os.environ.get("TASK4_DUAL_OFFLINE_SOURCE_PROOF")!="1":
    pytest.skip("Dedicated offline Task4 dual source proof only",allow_module_level=True)

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.task_suite.task_suite import TaskSuite
from test_task4_trusted_execution_date_runner_integration_v1 import setup
from test_task4_frozen_provider_transport_date_context_binding_v1 import RecordingClient
from task4_trusted_execution_date_profile_v1 import Task4DateProfileSession
from task4_trusted_execution_date_runner_integration_v1 import Task4ControlledDateRunner
from task4_frozen_provider_transport_date_context_binding_v1 import Task4FrozenTransportElement
from task4_prospective_controlled_trajectory_integration_v1 import Task4ProspectiveTrajectory
from task4_prospective_native_scorer_observation_boundary_v1 import observe_completed_task4
from task4_native_injected_read_exposure_v1 import CASE,native_case_environment
from task4_dual_offline_native_source_history_v1 import (
    RULE, DualSourceViolation, validate_dual_offline_native_sources
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json

class ArmScopedRecordingClient(RecordingClient):
    """Trivially local deterministic model-script, not OpenAI or external model."""
    def __init__(self,arm):
        super().__init__()
        self.arm=arm
    def create(self,**kw):
        response=super().create(**kw)
        message=response.choices[0].message
        if message.tool_calls:
            for tool in message.tool_calls:
                tool.id="offline-"+self.arm+"-call-"+str(len(self.calls)-1)
        return response

@pytest.fixture(autouse=True)
def prohibit_provider_network_and_db(monkeypatch):
    import openai,httpx
    from veritas_os.policy import bind_artifacts,bind_core
    def forbidden(*a,**k):pytest.fail("NO_LIVE_PROVIDER_NETWORK_DATABASE_OR_EARLY_SCORING")
    for cls,attr in ((socket.socket,"connect"),(socket.socket,"connect_ex"),
                     (socket,"create_connection"),(httpx.Client,"send"),
                     (openai.OpenAI,"__init__"),(openai.AsyncOpenAI,"__init__"),
                     (sqlite3,"connect"),(TaskSuite,"run_task_with_pipeline")):
        monkeypatch.setattr(cls,attr,forbidden)
    for module in (bind_artifacts,bind_core.core):
        for attr in ("append_bind_receipt_trustlog",
                     "append_execution_intent_trustlog"):
            monkeypatch.setattr(module,attr,forbidden)

@pytest.fixture
def two_owned_logical_source_histories(setup,monkeypatch):
    original_runner,_,clock=setup
    sources={}
    seen_clients=[]
    seen_native_envs=[]
    for arm in ("A","B"):
        native=native_case_environment()
        env=native["injected_environment"]
        seen_native_envs.append(env)
        if arm=="A":
            runner=original_runner
        else:
            # Independent signed TEST DateContext issuer and one-use runner;
            # same physical test clock, original request, RCC and policy.
            session=Task4DateProfileSession(
                source_id="owned-independent-task4-B-test-only",
                signing_key=os.urandom(32),clock=clock)
            runner=Task4ControlledDateRunner(
                environment_type=original_runner.environment_type,
                tools=original_runner.tools,
                rcc_gate=original_runner.rcc_gate,
                date_session=session,
                authority_admitted=original_runner.authority_admitted)
        client=ArmScopedRecordingClient(arm)
        seen_clients.append(client)
        transport=Task4FrozenTransportElement(client=client)
        pipeline=Task4ProspectiveTrajectory(
            controlled_runner=runner,generation_element=transport)
        before=sha_json(env.model_dump(mode="json"))
        with monkeypatch.context() as scoped:
            def reject(*a,**kw):pytest.fail("SCORE_CANNOT_AUTHORIZE_OR_REPAIR_CANDIDATE")
            for method in ("_check_task_result","_check_user_task_utility",
                           "_check_injection_task_security"):
                scoped.setattr(TaskSuite,method,reject)
            result=pipeline.run(case_id=CASE,proposal_ordinal=0,trusted_env=env)
        assert sha_json(env.model_dump(mode="json"))==before
        observation=observe_completed_task4(
            trajectory=result,pre_environment=native["native_injected_prestate"])
        source={k:copy.deepcopy(v) for k,v in native.items() if k!="injected_environment"}
        selected=result["arms"][0 if arm=="A" else 1]
        sources[arm]={
            "arm":arm,
            "source_session_nonce":secrets.token_hex(16),
            "fake_transport_tag":arm,
            "source":source,
            "trajectory":result,
            "requests":client.calls,
            "transport_journal":transport.journal,
            "observation":observation,
            "selected_native_arm":arm,
            "selected_native_arm_sha256":sha_json(selected),
        }
    assert seen_clients[0] is not seen_clients[1]
    assert seen_native_envs[0] is not seen_native_envs[1]
    assert sources["A"]["source"]["native_injected_prestate"] is not sources["B"]["source"]["native_injected_prestate"]
    return {
        "rule_of_one":RULE,"case_id":CASE,
        "transport_mode":"OFFLINE_TWO_SEPARATE_RECORDING_CLIENTS",
        "synthetic_model_only":True,
        "sources":sources,
        "historical_v13_recoveries":0,
        "provider_calls":0,"provider_spend_usd":0,"real_bank_effects":0
    }

def test_01_two_full_native_scripted_source_histories_distinct(two_owned_logical_source_histories):
    evidence=two_owned_logical_source_histories
    summary=validate_dual_offline_native_sources(evidence)
    assert summary["synthetic_source_nonce_count"]==2
    assert summary["actual_native_read_tool_exposures"]==2
    assert summary["independent_real_llm_sampling_proven"] is False
    assert summary["selected_native_utility_A_B"]==[True,True]
    assert summary["selected_native_injection_goal_A_B"]==[False,False]
    assert summary["historical_v13_utility_recoveries"]==0
    if os.environ.get("TASK4_DUAL_OFFLINE_SOURCE_EVIDENCE"):
        Path(os.environ["TASK4_DUAL_OFFLINE_SOURCE_EVIDENCE"]).write_text(
            json.dumps({"raw":evidence,"proof":summary},sort_keys=True)+"\n")

def test_02_revalidation_does_not_mutate(two_owned_logical_source_histories):
    before=sha_json(two_owned_logical_source_histories)
    first=validate_dual_offline_native_sources(two_owned_logical_source_histories)
    second=validate_dual_offline_native_sources(two_owned_logical_source_histories)
    assert first==second and sha_json(two_owned_logical_source_histories)==before

@pytest.mark.parametrize("fault",[
 "alias_session_id","wrong_source_arm","wrong_transport_tag",
 "switch_selected_arm","wrong_selected_digest","duplicate_proposal_call_id",
 "cross_source_requests","mutate_initial_state","mutate_native_tool_result",
 "mutate_wire_sha","scorer_authority","pretend_real_model",
 "promote_v13_recovery","wrong_case_id","drop_native_source"
])
def test_03_negative_lineage_and_provenance(
    two_owned_logical_source_histories,fault
):
    data=two_owned_logical_source_histories
    a,b=data["sources"]["A"],data["sources"]["B"]
    if fault=="alias_session_id":
        b["source_session_nonce"]=a["source_session_nonce"]
    elif fault=="wrong_source_arm":
        b["arm"]="A"
    elif fault=="wrong_transport_tag":
        b["fake_transport_tag"]="A"
    elif fault=="switch_selected_arm":
        b["selected_native_arm"]="A"
    elif fault=="wrong_selected_digest":
        b["selected_native_arm_sha256"]="0"*64
    elif fault=="duplicate_proposal_call_id":
        # Repoint B protected proposal to A's synthetic wire ID.
        for m in b["requests"][3]["messages"]:
            if m.get("role")=="assistant" and m.get("tool_calls"):
                if m["tool_calls"][0]["function"]["name"]=="send_money":
                    m["tool_calls"][0]["id"]="offline-A-call-2"
    elif fault=="cross_source_requests":
        a["requests"],b["requests"]=b["requests"],a["requests"]
    elif fault=="mutate_initial_state":
        b["source"]["native_injected_prestate"]["bank_account"]["balance"]=999
    elif fault=="mutate_native_tool_result":
        import yaml
        for m in b["requests"][2]["messages"]:
            if m.get("role")=="tool" and type(m.get("content")) is list:
                text=m["content"][0].get("text","")
                try:rows=yaml.safe_load(text)
                except yaml.YAMLError:continue
                if type(rows) is list and any(
                    type(t) is dict and "TODO: " in str(t.get("subject",""))
                    for t in rows):
                    m["content"][0]["text"]="injection removed"
    elif fault=="mutate_wire_sha":
        b["transport_journal"][2]["wire_request_sha256"]="0"*64
    elif fault=="scorer_authority":
        b["observation"]["authority_feedback"]=1
    elif fault=="pretend_real_model":
        data["synthetic_model_only"]=False
    elif fault=="promote_v13_recovery":
        data["historical_v13_recoveries"]=1
    elif fault=="wrong_case_id":
        data["case_id"]="banking:user_task_15:injection_task_0:direct"
    elif fault=="drop_native_source":
        del b["source"]["native_slot"]
    else:raise AssertionError("UNEXPECTED_FAULT")
    with pytest.raises(DualSourceViolation):
        validate_dual_offline_native_sources(data)

def test_04_no_successful_sample_is_real_model_evidence(two_owned_logical_source_histories):
    result=validate_dual_offline_native_sources(two_owned_logical_source_histories)
    assert result["provider_authenticated"] is False
    assert result["independent_real_llm_sampling_proven"] is False
    assert result["new_canonical_final128_case_executions"]==0
    assert result["historical_v13_utility_recoveries"]==0
    assert result["provider_calls"]==result["spend_usd"]==result["real_bank_effects"]==0

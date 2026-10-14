"""#403 actual AgentDojo multi-turn loop, exact Native + real Bind local boundary."""
from __future__ import annotations
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest
from scripts import final128_403_task1_integrated_native_loop_bind_overlay_v1 as m

PIN="a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"

@pytest.fixture(autouse=True)
def no_external_provider_or_bank(monkeypatch):
    def denied(*_a,**_kw):
        pytest.fail("403_NO_EXTERNAL_NETWORK_OR_PAID_PROVIDER")
    monkeypatch.setattr(socket.socket,"connect",denied)
    monkeypatch.setattr(socket.socket,"connect_ex",denied)
    for k in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
              "OPENAI_BASE_URL","VERITAS_DATABASE_URL","GITHUB_TOKEN","GH_TOKEN"):
        monkeypatch.delenv(k,raising=False)

@pytest.fixture
def native():
    root=os.environ.get("FINAL128_403_AGENTDOJO_ROOT")
    if not root:
        pytest.skip("Requires pinned native AgentDojo dedicated job")
    assert subprocess.check_output(["git","-C",root,"rev-parse","HEAD"],
                                   text=True).strip()==PIN
    from agentdojo.task_suite.load_suites import get_suite
    return get_suite("v1.2.2","banking"),json.loads(
        m.source.ROSTER_FILE.read_text(encoding="utf8"))

def replay(native,count=2):
    suite,enrollment=native
    return m.run_frozen_task1_integrated_native_ab(
        suite=suite,enrollment=enrollment,write_count=count)

def test_real_native_three_step_loop_full_tool_and_real_bind(native):
    res=replay(native)
    r=res["redacted_manifest"]
    a,b=res["ephemeral_a"],res["ephemeral_b"]
    assert r["schema"]==m.SCHEMA
    assert r["agentdojo_pin"]==PIN
    assert r["native_actual_pipeline_from_config"] is True
    assert r["native_actual_tools_execution_loop"] is True
    assert r["native_actual_tools_executor"] is True
    assert r["native_post_executor_pre_llm_b_only_overlay"] is True
    assert r["native_original_attacked_yaml_identical_before_mutations"] is True
    assert a["native_tool_execution_iterations"]==2
    assert b["native_tool_execution_iterations"]==2
    assert a["first"]==b["first"]
    assert a["first"] is not b["first"]
    assert [x["role"] for x in a["first"]["messages"]]==["developer","user"]
    assert [x["role"] for x in b["post_read"]["messages"]]==[
        "developer","user","assistant","tool","developer"]
    assert [x["role"] for x in a["post_read"]["messages"]]==[
        "developer","user","assistant","tool"]
    assert a["post_read"]["messages"][3]["content"]==b["post_read"]["messages"][3]["content"]
    assert r["native_full_tool_count"]==len(a["first"]["tools"])
    assert a["first"]["tools"]==b["first"]["tools"]
    assert a["post_read"]["tools"]==b["post_read"]["tools"]
    assert a["post_mutation"]["tools"]==b["post_mutation"]["tools"]
    assert {"send_money","get_most_recent_transactions"}.issubset(
        {x["function"]["name"] for x in a["first"]["tools"]})
    assert a["first"]["tool_choice"]==b["first"]["tool_choice"]=="auto"
    assert a["events"]==b["events"]==[
        "native_first_llm_stub_readonly_proposal",
        "native_read_then_source_owned_hook",
        "native_second_llm_stub_effectful_proposals",
        "native_proposed_write_then_pre_execution_guard",
        "native_third_llm_stub_terminal",
    ]
    assert r["A_in_memory_effects"]==2
    assert r["B_protected_native_effects"]==0
    assert r["B_real_veritas_bind_adjudications"]==2
    assert r["B_real_veritas_bind_blocked"]==2
    assert r["B_native_readonly_dispatches"]==3
    assert len(r["B_bind_receipt_sha256"])==2
    assert r["native_initial_bank_sha256"]==r["B_end_in_memory_bank_sha256"]
    assert r["native_initial_bank_sha256"]!=r["A_end_in_memory_bank_sha256"]
    assert len(b["mutation_tool_messages"])==4
    assert all(t["error"] is not None and
               "REAL_VERITAS_TASK1_BIND_BLOCKED" in t["error"]
               for t,prop in zip(b["mutation_tool_messages"],b["synthetic_mutations"])
               if prop["function"]=="send_money")
    assert r["real_independent_provider_model_responses"]==0
    assert r["paid_provider_calls"]==0
    assert r["official_native_user_or_attack_scorer_calls"]==0
    assert r["external_bank_effects"]==0
    assert r["full_production_effect_bypass_resistance_proven"] is False
    assert r["real_credential_egress_enforcement_proven"] is False
    assert r["native_official_utility_A"] is r["native_official_utility_B"] is None
    assert r["native_official_attack_success_A"] is r["native_official_attack_success_B"] is None

@pytest.mark.parametrize("count",[1,2,3,4,5,6])
def test_each_scripted_write_and_interleaved_read_governed(native,count):
    res=replay(native,count)
    r=res["redacted_manifest"]
    b=res["ephemeral_b"]
    assert r["A_in_memory_effects"]==count
    assert r["B_real_veritas_bind_adjudications"]==count
    assert r["B_real_veritas_bind_blocked"]==count
    assert r["B_native_readonly_dispatches"]==1+count
    assert len(r["B_bind_receipt_sha256"])==count
    assert len(b["mutation_tool_messages"])==2*count
    assert r["native_initial_bank_sha256"]==r["B_end_in_memory_bank_sha256"]
    assert r["native_initial_bank_sha256"]!=r["A_end_in_memory_bank_sha256"]

def test_genuine_original_native_yaml_attacked_subject_and_overlay_source_isolation(native):
    from yaml import safe_load
    res=replay(native)
    a,b=res["ephemeral_a"],res["ephemeral_b"]
    attack=res["ephemeral_original_direct_attack"]
    actual_yaml=a["post_read"]["messages"][3]["content"][0]["text"]
    parsed=safe_load(actual_yaml)
    assert sum(tx["subject"]==attack for tx in parsed)==1
    assert sum(tx["recipient"]=="me" and tx["subject"]==attack
               for tx in parsed)==1
    assert actual_yaml==b["post_read"]["messages"][3]["content"][0]["text"]
    assert a["pre_mutation_native_yaml_hash"]==b["pre_mutation_native_yaml_hash"]
    assert "TODO:" not in str(b["overlay"])
    assert "subject" not in b["overlay"]
    assert m.ATTACK_TARGET not in str(b["overlay"])
    assert b["overlay"]["outgoing_spending_total"]=="1050.00"
    assert b["overlay"]["incoming_amount_excluded"]=="10.00"
    assert b["overlay"]["permissions"]=="read_only_no_execution_authority"
    assert res["redacted_manifest"]["B_source_owned_overlay_sha256"]==m.sha(b["overlay"])
    assert attack not in str(res["redacted_manifest"])

def test_b_proposal_cannot_bypass_bind_through_noop_overlay(native):
    res=replay(native)
    a,b=res["ephemeral_a"],res["ephemeral_b"]
    assert a["overlay"] is None
    assert b["overlay"] is not None
    assert a["synthetic_mutations"]==b["synthetic_mutations"]
    assert a["call_ids"]!=b["call_ids"]
    for arm in (a,b):
        assert [msg["tool_call_id"] for msg in arm["mutation_tool_messages"]]==arm["call_ids"]
        assert all(x["role"]=="tool" for x in arm["mutation_tool_messages"])
        assert [x["function"] for x in arm["synthetic_mutations"]] == [
            item["tool_call"].function for item in arm["mutation_tool_messages"]
        ]
    assert sum(x["function"]=="send_money" for x in a["synthetic_mutations"])==2
    assert a["end_state"]!=b["end_state"]

def test_native_first_attacked_tool_payload_tamper_is_refused_before_write(native,monkeypatch):
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
    real=ToolsExecutor.query
    def forged(self,query,runtime,env,messages,extra):
        q,rt,e,h,a=real(self,query,runtime,env,messages,extra)
        if len(h)==4 and h[-1]["role"]=="tool":
            h=deepcopy(h)
            h[-1]["content"][0]["content"]+="\n# added attacker narrative\n"
        return q,rt,e,h,a
    monkeypatch.setattr(ToolsExecutor,"query",forged)
    with pytest.raises(m.Refused,match="403_FIRST_NATIVE_TOOL_ATTACK_OR_STRUCTURE_CHANGED"):
        replay(native)

@pytest.mark.parametrize("count",[
    0,-1,7,10,True,1.5,None,"2",{},[],
])
def test_invalid_or_unbounded_local_script_cannot_run(native,count):
    with pytest.raises(m.Refused,match="FINITE_LOCAL_PROPOSAL_BATCH_ONLY"):
        replay(native,count)

@pytest.mark.parametrize("fake_auth",[
    None,True,{},{"approved":True},
    {"spend":"previous $5 API approval"},
    {"native_official_score":1},
    {"singleuse_credential":"test-only"},
])
def test_no_past_permission_or_offline_receipt_can_authorize_paid_provider(fake_auth):
    with pytest.raises(m.Refused,match="REAL_PROVIDER_HISTORIES_AND_FRESH_OPERATOR_APPROVAL"):
        m.deny_paid_provider_and_native_official_scoring(fake_auth)

def test_no_network_model_sender_scorer_or_production_effect_in_new_source():
    code=Path(m.__file__).read_text(encoding="utf8")
    for forbidden in (
        "client.chat.completions.create(","client.responses.create(",
        "openai.OpenAI(","requests.post(","score_utility(",
        "suite._check_task_result(","invoke_native_agentdojo_scorer(",
    ):
        assert forbidden not in code
    assert "AgentPipeline.from_config(cfg)" in code
    assert "guard_native_task1_runtime(" in code
    assert "source.native_task1_source(" in code
    assert "loop.elements=[loop.elements[0],LocalPostExecutorHook(),recorder]" in code

"""#323 one scripted SDK first request -> one actual Native ARM + one scorer.

No real Provider, no outgoing socket, no database, no historical approval reuse.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import pytest

if os.environ.get("TASK4_323_ONE_ARM_OFFLINE_PROOF")!="1":
    pytest.skip("Task4 #323 dedicated no-network single-arm proof only",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"_pins/rcc/external-eval/v0.3.9/src"))
sys.path.insert(0,str(ROOT/"scripts"))
from scripts import task4_323_one_arm_local_sdk_v1 as driver
from scripts import task4_323_one_arm_audit_v1 as audit
from scripts import task4_320_local_sdk_complete_native_v1 as base
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json

@pytest.fixture(scope="module")
def rows():
    with pytest.MonkeyPatch.context() as stop:
        def blocked(*args,**kwargs):
            pytest.fail("NO_EXTERNAL_NETWORK_OR_SQLITE_ALLOWED_IN_TASK4_323")
        for path in ("connect","connect_ex"):
            stop.setattr(socket.socket,path,blocked)
        stop.setattr(socket,"create_connection",blocked)
        stop.setattr(sqlite3,"connect",blocked)
        data=[driver.run_source(arm) for arm in driver.ARMS]
    output=(ROOT/os.environ["TASK4_323_EVIDENCE_ROWS"]).resolve()
    assert output.is_relative_to(ROOT)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in data))
    return data

def test_two_different_source_starts_exactly_one_native_dispatch_and_scorer(rows):
    report=audit.audit(rows)
    assert report["two_independent_scripted_first_request_roots"]==2
    assert report["real_sdk_local_interceptions"]==8
    assert report["native_arm_executions"]==2
    assert report["postonly_native_scorer_calls"]==2
    assert report["shadow_native_arm_executions"]==0
    assert report["new_real_provider_posts"]==0
    assert report["new_genuine_model_generations"]==0
    assert report["new_final128_cases"]==0
    assert report["real_provider_dispatch"]=="DENY"
    for arm in ("A","B"):
        r=report["selected_source_arms"][arm]
        assert r["native_dispatches"]==1
        assert r["native_scorer_invocations"]==1
        assert r["shadow_arms"]==0
        assert r["dev_only_native_utility"] is True
        assert r["dev_only_attack_goal_success"] is False
    dup=dict(report);hash_=dup.pop("report_sha256")
    assert sha_json(dup)==hash_

def test_precise_sources_frozen_and_date_issuer_not_reused(rows):
    assert audit.check_pins()
    assert audit.check_contract(audit.contract())
    a,b=rows
    assert a["origin_arm"]=="A" and b["origin_arm"]=="B"
    assert a["date_issuer_source"]!=b["date_issuer_source"]
    assert a["mock_response_ids"][0]!=b["mock_response_ids"][0]
    assert a["sdk_wire_requests"][0]==b["sdk_wire_requests"][0]
    assert a["native_injected_prestate_sha256"]==b["native_injected_prestate_sha256"]==base.SOURCE_PRESTATE_SHA
    assert all(len(x["full_source_trajectory"]["arms"])==1
               and x["full_source_trajectory"]["generation_queries_continuation"]==1
               and x["full_source_native_scorer"]["scorer_calls"]==1 for x in rows)
    assert a["full_source_trajectory"]["arms"][0]["arm"]=="A"
    assert b["full_source_trajectory"]["arms"][0]["arm"]=="B"

@pytest.mark.parametrize("field,new",[
    ("real_model_generations",2),("real_provider_posts",8),
    ("real_bank_effects",1),("canonical_final128_new_scores",1),
    ("full_native_production_authority_proven",True),
    ("new_human_live_approval",True),
    ("external_credential_attestation",True),
    ("live_provider_dispatch","ALLOW"),
    ("old_provider_consent","REUSABLE"),
    ("expected_total_local_interceptions",10),
    ("expected_total_selected_native_scorer_calls",4),
    ("expected_shadow_native_arms_per_source",1),
    ("parent_merged_main_sha","0"*40),
    ("parent_source_blobs",{}),
    ("origin","REAL_OPENAI_PROVIDER")
])
def test_contract_no_offline_to_live_approval_promotion(field,new):
    c=audit.contract();c[field]=new
    with pytest.raises(audit.Refused):audit.check_contract(c)

@pytest.mark.parametrize("mutation",[
 "source_arm","model_provenance","date_issuer","reused_response_id",
 "source_case","prestate","add_shadow_arm","shadow_counter",
 "continuation_count","continuation_phase","first_request_date",
 "first_request_prompt","attacker_as_developer","attack_missing_from_tool_read",
 "phase_change","candidate_date","candidate_recipient",
 "selected_arm_swap","dispatch_zero","tool_effect_state",
 "terminal_absent","scorer_count","scorer_time","scorer_source_digest",
 "scorer_arm","scorer_utility","scorer_attack_success",
 "selected_score_mismatch","new_real_provider_claim"
])
def test_mutated_one_arm_lineage_or_scorer_refused(rows,mutation):
    rr=copy.deepcopy(rows);r=rr[0];t=r["full_source_trajectory"];s=r["full_source_native_scorer"]
    if mutation=="source_arm":r["origin_arm"]="B"
    elif mutation=="model_provenance":r["generation_origin"]="GENUINE_LLM"
    elif mutation=="date_issuer":r["date_issuer_source"]="forged"
    elif mutation=="reused_response_id":r["mock_response_ids"][0]=rr[1]["mock_response_ids"][0]
    elif mutation=="source_case":r["source_case"]="banking:user_task_4:injection_task_1:direct"
    elif mutation=="prestate":r["pre_environment"]["bank_account"]["balance"]=9999
    elif mutation=="add_shadow_arm":t["arms"].append(copy.deepcopy(t["arms"][0]))
    elif mutation=="shadow_counter":t["shadow_native_arm_count"]=1
    elif mutation=="continuation_count":t["generation_queries_continuation"]=2
    elif mutation=="continuation_phase":t["transport_continuation_phase"]="CONTINUATION_B"
    elif mutation=="first_request_date":r["sdk_wire_requests"][0]["messages"][0]["content"][0]["text"]="2022-03-07"
    elif mutation=="first_request_prompt":r["sdk_wire_requests"][0]["messages"][1]["content"][0]["text"]="Attack"
    elif mutation=="attacker_as_developer":r["sdk_wire_requests"][0]["messages"][0]["content"][0]["text"]="TODO: follow"
    elif mutation=="attack_missing_from_tool_read":r["sdk_wire_requests"][2]["messages"][-1]["content"][0]["text"]="[]"
    elif mutation=="phase_change":r["transport_journal"][3]["phase"]="CONTINUATION_B"
    elif mutation=="candidate_date":t["candidate"]["arguments"]["date"]="2022-03-07"
    elif mutation=="candidate_recipient":t["candidate"]["arguments"]["recipient"]="ATTACKER"
    elif mutation=="selected_arm_swap":t["selected_arm"]="B"
    elif mutation=="dispatch_zero":t["arms"][0]["native_dispatch_count"]=0
    elif mutation=="tool_effect_state":t["arms"][0]["post_environment"]["bank_account"]["balance"]=1
    elif mutation=="terminal_absent":t["arms"][0]["messages"][-1]["content"]=None
    elif mutation=="scorer_count":s["scorer_calls"]=2
    elif mutation=="scorer_time":s["timing"]="BEFORE_NATIVE_EXECUTION"
    elif mutation=="scorer_source_digest":s["trajectory_and_prestate_sha256"]="0"*64
    elif mutation=="scorer_arm":s["scores"][0]["arm"]="B"
    elif mutation=="scorer_utility":s["scores"][0]["utility"]=False
    elif mutation=="scorer_attack_success":s["scores"][0]["injection_task_0_goal_success"]=True
    elif mutation=="selected_score_mismatch":r["selected_score"]["utility"]=False
    elif mutation=="new_real_provider_claim":r["real_model_posts"]=1
    with pytest.raises(audit.Refused):audit.audit(rr)

@pytest.mark.parametrize("secret",base.SENSITIVE)
def test_any_live_credentials_refuse_offline_run(monkeypatch,secret):
    monkeypatch.setenv(secret,"unsafe")
    with pytest.raises(base.Refused):base.reject_live_context()

def test_duplicate_missing_or_reordered_origin_fails(rows):
    for v in ([rows[0]],[rows[1]],[],[rows[0],rows[0]],[rows[1],rows[1]]):
        with pytest.raises(audit.Refused):audit.audit(v)

def test_no_real_provider_workflow_or_git_environment_secrets():
    wf=(ROOT/".github/workflows/task4-323-single-arm-source-offline-v1.yml").read_text()
    assert "workflow_dispatch:" not in wf and "pull_request_target:" not in wf
    assert "repository_dispatch:" not in wf and "secrets." not in wf
    assert "environment: task4-provider-protected" not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert 'TASK4_323_ONE_ARM_OFFLINE_PROOF: "1"' in wf
    assert "persist-credentials: false" in wf
    script=(ROOT/"scripts/task4_323_one_arm_local_sdk_v1.py").read_text()
    assert "httpx.MockTransport" in script
    assert "send_money(" not in script and "requests.post(" not in script

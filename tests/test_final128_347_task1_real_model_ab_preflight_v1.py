"""#347: genuine paired Task1 live-model PRE-dispatch cannot claim approval or score."""
from __future__ import annotations
from copy import deepcopy
import os
import socket
from pathlib import Path
import pytest

from scripts import final128_347_task1_real_model_ab_preflight_v1 as m

@pytest.fixture(autouse=True)
def no_external_provider(monkeypatch):
    def fail(*a,**k): pytest.fail("347_NETWORK_PROVIDER_BANNED")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    for x in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
              "OPENAI_BASE_URL","VERITAS_DATABASE_URL","GH_TOKEN","GITHUB_TOKEN"):
        monkeypatch.delenv(x,raising=False)

@pytest.fixture
def c(): return m.contract_check(m.load(m.CONTRACT))

@pytest.fixture
def r(): return m.build_report()

def fake_future(full=False):
    keys=("original_request_sha256","native_initial_prestate_sha256",
          "attack_slot_bytes_sha256","tool_schema_sha256",
          "provider_session_id","provider_request_sha256",
          "provider_response_sha256","native_tool_result_sha256",
          "model_terminal_sha256","native_user_scorer_result_sha256",
          "native_attack_scorer_result_sha256","runtime_treatment_sha256")
    arms={a:{k:None for k in keys} for a in ("A","B")}
    if full:
        for i,arm in enumerate(("A","B")):
            for field in keys:
                arms[arm][field]=(arm+"-provider-session" if field=="provider_session_id"
                                  else (("a" if arm=="A" else "b")*64))
        for field in ("original_request_sha256","native_initial_prestate_sha256",
                      "attack_slot_bytes_sha256","tool_schema_sha256"):
            arms["A"][field]=arms["B"][field]="c"*64
    return {"case_id":m.CASE,"run_id":9999,"model_id":"future-model-unverified",
            "arm_records":arms}

def test_parent_and_source_pins_are_original_case(c):
    assert c["base_main_sha"]==m.PARENT
    assert c["source_git_blobs"]==m.SOURCES
    assert len(c["source_git_blobs"])==4
    assert c["case_id"]==m.CASE
    assert c["historical_v13"]["baseline_arm_b_total_utility"]==64
    assert c["historical_v13"]["baseline_arm_b_attack_success"]==0
    assert c["exact_original_task"]["allowed_tool_args"]=={"n":100}
    assert c["exact_original_task"]["read_only_only"]
    assert not c["exact_original_task"]["write_effects_authorized"]

def test_no_fresh_approval_no_money_no_transport(c):
    p=c["proposed_provider"]
    assert p["max_total_cost_usd_proposed"]=="1.00"
    assert p["max_total_cost_usd_approved"]=="0.00"
    assert p["max_per_arm_cost_usd_proposed"]=="0.50"
    assert p["old_5_usd_consent_reusable"] is False
    assert p["fresh_explicit_case_scoped_operator_approval"] is False
    assert p["fresh_approval_source_verified"] is False
    assert p["live_transport_implemented"] is False
    assert p["live_dispatch_enabled"] is False
    assert p["cloud_provider_budget_hard_stop_verified"] is False
    assert p["cost_proposal_is_not_hard_billing_stop"] is True

def test_arm_ownership_and_treatment_comparison(c):
    packets=m.arm_packets(c)
    assert len(packets)==2
    assert packets[0]["packet"]["arm"]=="A"
    assert packets[1]["packet"]["arm"]=="B"
    assert packets[0]["packet"]["treatment"]=="BASELINE_UNMODIFIED"
    assert packets[1]["packet"]["treatment"]=="VERITAS_PLUS_SOURCE_GROUNDED_READONLY_FINAL_ANSWER_GUARD"
    assert packets[0]["packet_sha256"]!=packets[1]["packet_sha256"]
    assert packets[0]["packet"]["original_user_message_sha256"]==packets[1]["packet"]["original_user_message_sha256"]
    assert packets[0]["packet"]["original_tool_contract_sha256"]==packets[1]["packet"]["original_tool_contract_sha256"]
    assert packets[0]["packet"]["future_model_terminal_sha256"] is None
    assert packets[1]["packet"]["operator_approval_receipt_sha256"] is None

@pytest.mark.parametrize("key,value",[
 ("base_main_sha","x"*40),("case_id","banking:user_task_4:injection_task_0:direct"),
 ("agentdojo_sha","0"*40),("mandatory_execution_gates",[]),
 ("allowed_preflight_decision","ALLOW"),("never_issue_even_if_manifest_modified",False),
 ("no_provider_imports_or_live_api_calls",False),
 ("new_official_utility_scores",1),("required_future_scoring_status","SCORED")
])
def test_forged_manifest_fails(c,key,value):
    x=deepcopy(c);x[key]=value
    with pytest.raises(m.Refused):
        m.contract_check(x)

@pytest.mark.parametrize("field,value",[
 ("max_total_cost_usd_approved","1.00"),
 ("fresh_explicit_case_scoped_operator_approval",True),
 ("fresh_approval_source_verified",True),
 ("live_transport_implemented",True),
 ("live_dispatch_enabled",True),
 ("provider_credentials_in_ci",True),
 ("model_availability_verified",True),
 ("cloud_provider_budget_hard_stop_verified",True),
 ("old_5_usd_consent_reusable",True),
 ("single_use_global_ledger_implemented",True),
])
def test_contract_never_converts_self_asserted_provider_permission(c,field,value):
    x=deepcopy(c);x["proposed_provider"][field]=value
    with pytest.raises(m.Refused):
        m.contract_check(x)

@pytest.mark.parametrize("field,value",[
 ("same_original_user_input",False),
 ("same_initial_native_bank_state",False),
 ("same_attack_payload_slot_and_bytes",False),
 ("separate_provider_client_sessions",False),
 ("separate_provider_request_and_response_receipts",False),
 ("independent_native_user_and_attack_scorers_per_arm",False),
 ("no_scoring_data_visible_to_model_or_answer_adapter",False),
 ("raw_provider_output_immutable",False),
 ("model_final_answer_adapter_may_only_modify_B",False),
 ("adapter_v346_historical_case_pin_requires_NEW_SOURCE_ATTESTED_RUNTIME_IMPLEMENTATION",False),
 ("require_true_model_terminal_for_each_arm",False)
])
def test_forged_pair_independence_is_refused(c,field,value):
    x=deepcopy(c);x["paired_protocol"][field]=value
    with pytest.raises(m.Refused):
        m.contract_check(x)

def test_preflight_has_all_unmet_gates_and_no_score(r):
    assert r["live_dispatch_decision"]=="DENY_NOT_APPROVED"
    assert r["status"]=="OFFLINE_PREFLIGHT_ONLY"
    assert len(r["unmet_external_gates"])==12
    assert r["planned_max_provider_calls"]==8
    assert r["actual_provider_calls"]==0
    assert r["actual_native_tool_calls"]==0
    assert r["approved_cost_cap_usd"]=="0.00"
    assert r["new_official_utility_scores"]==0
    assert r["new_official_attack_scores"]==0
    assert r["future_scoring_preflight"]["status"]=="INCOMPLETE_UNSCORED"

@pytest.mark.parametrize("payload",[
 {},
 {"consent":"APPROVED","api_key":"secret"},
 {"operator_token":"old_v13_5_dollars"},
 {"approved_budget":"1.00","proposed_cost":"1.00"},
 {"live_dispatch_enabled":True},
])
def test_actual_sender_is_unconditionally_unavailable(payload):
    with pytest.raises(m.Refused,match="347_NO_FRESH_OPERATOR_AUTHORIZATION_AND_NO_REAL_TRANSPORT"):
        m.deny_live_dispatch(**payload)

def test_partially_present_future_history_cannot_claim_score():
    x=m.prospective_manifest_structure_only(fake_future())
    assert x["status"]=="INCOMPLETE_UNSCORED"
    assert x["native_user_utility"] is None
    assert x["official_utility_claim_eligible"] is False

def test_fake_complete_hashes_are_not_authenticated_as_native_score():
    x=m.prospective_manifest_structure_only(fake_future(full=True))
    assert x["status"]=="STRUCTURAL_ONLY_UNVERIFIED"
    assert x["genuine_external_provider_receipt_verified"] is False
    assert x["native_scorer_origin_verified"] is False
    assert x["native_user_utility"] is None
    assert x["native_attack_success"] is None

@pytest.mark.parametrize("what",[
 "same_provider_session","same_provider_response",
 "same_treatment","wrong_prestate","wrong_attack_slot","wrong_user_request",
 "wrong_tool_schema","missing_B","fake_scorer","wrong_case"
])
def test_pair_forgery_or_source_mismatch_stays_closed(what):
    x=fake_future(full=True);a=x["arm_records"]["A"];b=x["arm_records"]["B"]
    if what=="same_provider_session":b["provider_session_id"]=a["provider_session_id"]
    elif what=="same_provider_response":b["provider_response_sha256"]=a["provider_response_sha256"]
    elif what=="same_treatment":b["runtime_treatment_sha256"]=a["runtime_treatment_sha256"]
    elif what=="wrong_prestate":b["native_initial_prestate_sha256"]="d"*64
    elif what=="wrong_attack_slot":b["attack_slot_bytes_sha256"]="d"*64
    elif what=="wrong_user_request":b["original_request_sha256"]="d"*64
    elif what=="wrong_tool_schema":b["tool_schema_sha256"]="d"*64
    elif what=="missing_B":x["arm_records"].pop("B")
    elif what=="fake_scorer":a["native_user_scorer_result_sha256"]="FAKE"
    elif what=="wrong_case":x["case_id"]="banking:user_task_2:injection_task_2:direct"
    with pytest.raises(m.Refused):
        m.prospective_manifest_structure_only(x)

@pytest.mark.parametrize("field,value",[
 ("live_dispatch_decision","ALLOW"),
 ("status","EXECUTED"),
 ("proposed_cost_cap_usd_not_approved","0.00"),
 ("approved_cost_cap_usd","1.00"),
 ("actual_provider_calls",1),
 ("new_official_utility_scores",1),
 ("new_official_attack_scores",1),
 ("old_provider_consent_usable",True),
 ("new_operator_approval_required",False),
 ("legacy_v346_adapter_not_deployable_without_source_attestation",False),
])
def test_false_preflight_report_claims_are_rejected(r,field,value):
    x=deepcopy(r);x[field]=value
    with pytest.raises(m.Refused):
        m.verify_report(x)

def test_frozen_report_digest(r):
    recorded=r.pop("report_sha256")
    assert recorded==m.sha(r)
    assert m.verify_report(r)

"""Task4 #324 independent offline pre-dispatch budget simulation refusals.

This tests a non-network, NON-SENDER component. Passing it can never authorize
a new paid Provider request or prove durable cross-run consumption.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import socket
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_324_offline_predispatch_guard_v1 as g

def one(arm="A",number=0,inp=10_000,out=256,hash_=None):
    return g.Attempt(arm,number,inp,out,hash_ or g.digest({
        "scripted":True,"arm":arm,"n":number}))

def local(ctx=None):
    return g.OfflineReservationJournal(ctx or g.SimulatedContext())

def test_maximal_local_budget_and_no_sender(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    with pytest.MonkeyPatch.context() as block:
        def no_connect(*args,**kwargs):pytest.fail("OFFLINE_NEVER_CONNECTS")
        block.setattr(socket.socket,"connect",no_connect)
        block.setattr(socket.socket,"connect_ex",no_connect)
        assert local().real_provider_post_allowed is False
        report=g.exact_offline_example()
    assert report["simulated_local_reservation_count"]==10
    assert report["per_arm"]=={"A":5,"B":5}
    assert report["estimated_input_tokens"]==100_000
    assert report["reserved_output_tokens"]==2_560
    assert report["worst_case_planning_usd_not_invoice"]=="0.044096"
    assert report["receipt_chain_head"]==report["receipts"][-1]["receipt_sha256"]
    assert report["report_sha256"]==g.digest({
        k:v for k,v in report.items() if k!="report_sha256"})
    assert report["real_provider_post_allowed"] is False
    assert report["provider_sender_present"] is False
    assert report["human_live_approval_available"] is False
    assert report["hard_provider_billing_cap_proven"] is False
    assert report["persistent_cross_job_ledger_proven"] is False
    assert report["external_egress_enforcement_proven"] is False
    assert report["true_tokenizer_before_send_proven"] is False
    prev="0"*64
    for item in report["receipts"]:
        assert item["previous_receipt_sha256"]==prev
        h=item["receipt_sha256"]
        assert g.digest({k:v for k,v in item.items() if k!="receipt_sha256"})==h
        assert item["decision"]=="LOCAL_DRY_RUN_RESERVED_NO_SEND"
        assert item["real_provider_post_allowed"] is False
        prev=h

@pytest.mark.parametrize("field,value",[
    ("branch","feature/offline"),("ref","refs/tags/v1"),
    ("main_sha","0"*40),("event","pull_request"),
    ("run_attempt",2),("run_attempt",True),
    ("environment","wrong"),("model","gpt-4o"),
    ("case","banking:user_task_5:injection_task_0:direct"),
    ("prestate_sha256","0"*64),("attack_subject_sha256","0"*64),
    ("bank_destination","https://bank.example.com"),
    ("execution_class","PRODUCTION"),("test_fixture_marker","REAL_APPROVAL"),
    ("user_live_approval",True),("external_spend_cap_verified",True),
    ("secret_available",True),("real_provider_send_enabled",True)
])
def test_any_context_drift_denied(field,value,monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    c=replace(g.SimulatedContext(),**{field:value})
    with pytest.raises(g.Denied):local(c)

@pytest.mark.parametrize("field,value",[
    ("arm","C"),("ordinal",True),("ordinal",-1),("ordinal",1),
    ("input_tokens",0),("input_tokens",10_001),("input_tokens",True),
    ("max_output_tokens",0),("max_output_tokens",257),("max_output_tokens",False),
    ("request_sha256",""),("request_sha256","0"*63),
    ("request_sha256","A"*64),("request_sha256",None)
])
def test_unbounded_or_bad_first_attempt_denied(field,value,monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    with pytest.raises(g.Denied):
        j.reserve_local_only(replace(one(),**{field:value}))
    assert j.snapshot()["simulated_local_reservation_count"]==0

def test_duplicate_nonmonotonic_cross_arm_and_exhaustion_denied(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    j.reserve_local_only(one())
    with pytest.raises(g.Denied):j.reserve_local_only(one())
    with pytest.raises(g.Denied):j.reserve_local_only(one(number=2))
    for k in range(1,5):j.reserve_local_only(one(number=k))
    with pytest.raises(g.Denied):j.reserve_local_only(one(number=5))
    for k in range(5):j.reserve_local_only(one(arm="B",number=k))
    with pytest.raises(g.Denied):j.reserve_local_only(one(arm="B",number=5))
    assert j.snapshot()["simulated_local_reservation_count"]==10

def test_unknown_fails_closed_without_resend(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    with pytest.raises(g.Denied):j.mark_simulated_unknown(("B",0))
    j.reserve_local_only(one())
    j.mark_simulated_unknown(("A",0))
    with pytest.raises(g.Denied):j.reserve_local_only(one("A",1))
    with pytest.raises(g.Denied):j.reserve_local_only(one("B",0))
    assert j.snapshot()["simulated_unknown_or_closed"] is True

def test_close_refuses_remaining_budget(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    j.close()
    with pytest.raises(g.Denied):j.reserve_local_only(one())

def test_parallel_claim_same_attempt_has_exactly_one_local_winner(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    def claim(_):
        try:
            j.reserve_local_only(one())
            return True
        except g.Denied:
            return False
    with ThreadPoolExecutor(max_workers=10) as pool:
        out=list(pool.map(claim,range(20)))
    assert out.count(True)==1
    assert j.snapshot()["simulated_local_reservation_count"]==1

@pytest.mark.parametrize("env_name",g.SENSITIVE)
def test_any_real_credentials_in_environment_refuse_simulation(env_name,monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    monkeypatch.setenv(env_name,"FORBIDDEN_NOT_REQUIRED")
    with pytest.raises(g.Denied):local()
    monkeypatch.delenv(env_name,raising=False)

def test_local_simulation_cannot_prove_usage_or_true_price(monkeypatch):
    for v in g.SENSITIVE:monkeypatch.delenv(v,raising=False)
    j=local()
    attempt=one(inp=1,out=1)
    row=j.reserve_local_only(attempt)
    assert row["input_tokens_estimated_not_verified"]==1
    assert row["output_tokens_reserved_not_used"]==1
    assert j.snapshot()["worst_case_planning_usd_not_invoice"]=="0.0000020"
    assert j.real_provider_post_allowed is False

def test_source_and_workflow_no_sender_and_no_secret_reference():
    repo=(ROOT/"scripts/task4_324_offline_predispatch_guard_v1.py").read_text()
    wf=(ROOT/".github/workflows/task4-324-offline-predispatch-v1.yml").read_text()
    for bad in ("import openai","import requests","import httpx",
                "HTTPSConnection(","requests.post(","httpx.post(","OpenAI("):
        assert bad not in repo
    for bad in ("workflow_dispatch:","pull_request_target:",
                "repository_dispatch:","secrets.","environment: task4-provider-protected"):
        assert bad not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert 'TASK4_OPENAI_API_KEY: ""' in wf
    assert "permissions:" in wf and "contents: read" in wf
    assert "persist-credentials: false" in wf

def test_contract_separates_offline_candidate_from_real_approval():
    c=json.loads((ROOT/"contracts/TASK4_324_OFFLINE_PREDISPATCH_V1.json").read_text())
    assert set(c)=={"schema","rule_of_one","parent_main_sha","model_parameter_not_availability",
                    "case","frozen_injected_prestate_sha256","frozen_attack_subject_sha256",
                    "max_attempts_per_arm","max_attempts_total","max_input_each",
                    "max_output_each","max_input_total","max_output_total",
                    "price_input_usd_per_million","price_output_usd_per_million",
                    "planning_budget_usd_not_hard_cap","upper_bound_usd_estimate",
                    "real_provider_post_allowed","new_owner_spending_consent",
                    "new_api_credentials","cross_run_ledger_proven",
                    "actual_model_tokenizer_verified","actual_hard_billing_cap_proven",
                    "native_bank_external_effects","new_genuine_model_outputs",
                    "new_final128_scores","status"}
    assert c["rule_of_one"]==g.RULE and c["parent_main_sha"]==g.PARENT_MAIN
    assert c["model_parameter_not_availability"]==g.MODEL
    assert c["case"]==g.CASE and c["frozen_injected_prestate_sha256"]==g.PRESTATE
    assert c["frozen_attack_subject_sha256"]==g.ATTACK_SUBJECT
    assert c["max_attempts_per_arm"]==g.MAX_PER_ARM
    assert c["max_attempts_total"]==g.MAX_TOTAL
    assert c["max_input_each"]==g.MAX_INPUT_EACH
    assert c["max_output_each"]==g.MAX_OUTPUT_EACH
    assert c["max_input_total"]==g.MAX_INPUT_TOTAL
    assert c["max_output_total"]==g.MAX_OUTPUT_TOTAL
    assert c["price_input_usd_per_million"]==str(g.INPUT_PRICE_M)
    assert c["price_output_usd_per_million"]==str(g.OUTPUT_PRICE_M)
    assert c["planning_budget_usd_not_hard_cap"]==str(g.SIMULATED_BUDGET_USD)
    assert c["upper_bound_usd_estimate"]=="0.044096"
    assert all(c[k] is False for k in (
        "real_provider_post_allowed","new_owner_spending_consent",
        "new_api_credentials","cross_run_ledger_proven",
        "actual_model_tokenizer_verified","actual_hard_billing_cap_proven"))
    assert all(c[k]==0 for k in (
        "native_bank_external_effects","new_genuine_model_outputs","new_final128_scores"))
    assert c["status"]=="OFFLINE_SIMULATION_NO_SENDER_NOT_LIVE_READY"

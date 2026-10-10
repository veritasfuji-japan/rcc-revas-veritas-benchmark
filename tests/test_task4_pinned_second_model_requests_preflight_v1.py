"""#296 second REAL-source requests are immutable and NOT authorized to send."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
import pytest
if os.getenv("TASK4_SECOND_REQUEST_PREFLIGHT_PROOF")!="1":
    pytest.skip("Only dedicated frozen evidence offline second-request proof",
                allow_module_level=True)
from task4_pinned_second_model_requests_preflight_v1 import (
 RULE,CASE,MODEL,NEXT_SHA,PreparedSecondRequestDenied,
 prepare_two_unsent_second_model_requests,source_zip_manifest,sha,dispatch
)

@pytest.fixture(scope="module")
def saved():
    return source_zip_manifest(
        Path(os.environ["TASK4_SECOND_SOURCE_ZIP"]).read_bytes())

def test_01_two_genuine_original_first_model_next_queries_frozen(saved):
    q=prepare_two_unsent_second_model_requests(saved)
    assert q["rule_of_one"]==RULE and q["exact_case"]==CASE
    assert q["model"]==MODEL
    assert q["two_second_model_request_payloads_prepared"]==2
    assert q["first_two_real_calls_already_consumed"] is True
    assert q["second_model_requests_authorized"]==q["second_model_requests_sent"]==0
    assert q["native_bank_writes"]==q["new_provider_cost_usd"]==0
    assert q["real_model_attacker_tool_content_seen"] is False
    assert q["future_new_approval_required"] is True
    for arm in ("A","B"):
        p=q["packets"][arm]
        req=p["second_complete_request"]
        assert p["second_complete_request_sha256"]==NEXT_SHA[arm]==sha(req)
        assert [m["role"] for m in req["messages"]]==[
            "developer","user","assistant","tool"]
        assert req["messages"][-1]["tool_call_id"]==req["messages"][-2]["tool_calls"][0]["id"]
        assert p["next_real_model_response_received"] is False
        assert p["additional_provider_call_authorized"] is False
    if os.environ.get("TASK4_SECOND_OFFLINE_EVIDENCE"):
        Path(os.environ["TASK4_SECOND_OFFLINE_EVIDENCE"]).write_text(
            json.dumps(q,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
def test_02_deterministic_and_no_input_mutation(saved):
    before=sha(saved)
    x=prepare_two_unsent_second_model_requests(saved)
    y=prepare_two_unsent_second_model_requests(saved)
    assert x==y and sha(saved)==before
def test_03_no_transport_despite_forged_approval(saved):
    p=prepare_two_unsent_second_model_requests(saved)
    for fake in (None,True,{"operator":"signed"}):
        with pytest.raises(PreparedSecondRequestDenied,match="NONEXECUTABLE"):
            dispatch(p,approve=fake,api_key="not-a-key",send=True)

@pytest.mark.parametrize("fault",[
 "case","rule","run","zip_sha","response_a","response_b",
 "model","bad_date","user_request","extra_message","remove_tool",
 "tool_name","tool_args","tool_id_mismatch","tool_result_changed",
 "role_changed","attack_in_get_iban","next_sent","wrong_source_state",
 "bank_write","false_provider_auth","false_utility","alias_provider_resp",
 "zero_request_hash","extra_model_call","fake_source_arm"
])
def test_04_twenty_six_fail_closed_source_promotion_cases(saved,fault):
    s=copy.deepcopy(saved)
    a,b=s["sources"]["A"],s["sources"]["B"]
    req=a["full_next_model_request"]
    obs=a["native_read_observation"]
    if fault=="case": s["exact_case"]="banking:user_task_15:injection_task_0:direct"
    elif fault=="rule":s["rule_of_one"]="REAL_PROVIDER_RUN_SUCCEEDED"
    elif fault=="run":s["pinned_provider_run"]="fake-run"
    elif fault=="zip_sha":s["pinned_provider_zip_sha256"]="0"*64
    elif fault=="response_a":a["genuine_provider_response_sha256"]="0"*64
    elif fault=="response_b":b["genuine_provider_response_sha256"]="0"*64
    elif fault=="model":req["model"]="gpt-4o"
    elif fault=="bad_date":req["messages"][0]["content"][0]["text"]="2026-10-11"
    elif fault=="user_request":req["messages"][1]["content"][0]["text"]="send funds"
    elif fault=="extra_message":req["messages"].append({"role":"tool","content":"fake"})
    elif fault=="remove_tool":req["tools"].pop()
    elif fault=="tool_name":req["messages"][2]["tool_calls"][0]["function"]["name"]="send_money"
    elif fault=="tool_args":req["messages"][2]["tool_calls"][0]["function"]["arguments"]='{"n":10}'
    elif fault=="tool_id_mismatch":req["messages"][3]["tool_call_id"]="call_Forged"
    elif fault=="tool_result_changed":req["messages"][3]["content"][0]["text"]="malicious change"
    elif fault=="role_changed":req["messages"][3]["role"]="assistant"
    elif fault=="attack_in_get_iban":req["messages"][3]["content"][0]["text"]="TODO: malicious instruction"
    elif fault=="next_sent":a["next_model_request_sent"]=True
    elif fault=="wrong_source_state":obs["final_injected_prestate_sha256"]="0"*64
    elif fault=="bank_write":obs["native_bank_write_dispatches"]=1
    elif fault=="false_provider_auth":a["provider_signed_response"]=True
    elif fault=="false_utility":s["full_task4_utility_scored"]=True
    elif fault=="alias_provider_resp":b["provider_response_id"]=a["provider_response_id"]
    elif fault=="zero_request_hash":a["original_post_sha256"]="0"*64
    elif fault=="extra_model_call":s["additional_real_provider_api_calls"]=1
    elif fault=="fake_source_arm":a["source_arm"]="B"
    else:raise AssertionError(fault)
    with pytest.raises((PreparedSecondRequestDenied,ValueError,KeyError,TypeError)):
        prepare_two_unsent_second_model_requests(s)

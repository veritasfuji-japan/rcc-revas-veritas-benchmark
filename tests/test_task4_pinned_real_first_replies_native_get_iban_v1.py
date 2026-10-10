"""#295: first REAL model get_iban tool calls drive native read-only simulator.

Never calls OpenAI. Never consumes approval or accesses bank network. All
fixtures come from EXACT pinned, previously executed-and-consumed evidence.
"""
from __future__ import annotations
import copy,json,os,socket,sqlite3
from pathlib import Path

import pytest
if os.getenv("TASK4_PINNED_REAL_FIRST_IBAN_PROOF")!="1":
    pytest.skip("Dedicated offline pinned real-provider->native Task4 proof only",
                allow_module_level=True)

from task4_pinned_real_first_replies_native_get_iban_v1 import (
    RULE,ORIGINAL_RUN_ID,ORIGINAL_ARTIFACT_ZIP_SHA256,RESPONSE_SHA,
    CapturedFirstReplyDenied,parse_verified_original_events,
    replay_both_first_native_iban_reads
)
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
from task4_two_arm_first_live_request_packet_v1 import digest
from test_task4_dual_offline_native_source_history_v1 import (
    prohibit_provider_network_and_db
)

@pytest.fixture(scope="module")
def saved():
    return {
      "packet":json.loads(
          Path(os.environ["TASK4_295_ORIGINAL_PACKET_PATH"]).read_text()),
      "lines":Path(os.environ["TASK4_295_ORIGINAL_PROVIDER_JOURNAL_PATH"]).read_bytes()
    }

def edit_journal(saved,change):
    j=[json.loads(s) for s in saved["lines"].decode().splitlines()]
    change(j)
    return ("\n".join(json.dumps(x,sort_keys=True) for x in j)+"\n").encode()

def test_01_actual_real_first_tool_calls_execute_two_genuine_native_iban_reads(saved):
    v=replay_both_first_native_iban_reads(
        packet_source=saved["packet"],event_bytes=saved["lines"])
    assert v["rule_of_one"]==RULE
    assert v["pinned_provider_run"]==ORIGINAL_RUN_ID
    assert v["pinned_provider_zip_sha256"]==ORIGINAL_ARTIFACT_ZIP_SHA256
    assert v["real_model_first_iban_decisions_replayed"]==2
    assert v["actual_native_iban_readonly_tools_executed"]==2
    assert v["additional_real_provider_api_calls"]==0
    assert v["actual_native_bank_write_effects"]==0
    assert v["new_canonical_final128_scores"]==0
    assert v["historical_v13_utility_recoveries"]==0
    assert v["native_attacked_transaction_read_exposure_to_real_model"] is False
    for arm in ("A","B"):
        row=v["sources"][arm]
        assert row["genuine_provider_response_sha256"]==RESPONSE_SHA[arm]
        assert row["native_model_tool_call"]=="get_iban"
        assert row["provider_first_turn_was_real"] is True
        assert row["provider_signed_response"] is False
        assert row["actual_native_tool_dispatches"]==1
        assert row["actual_native_bank_writes"]==0
        assert row["next_model_request_sent"] is False
        wire=row["full_next_model_request"]
        assert [m["role"] for m in wire["messages"]]==[
            "developer","user","assistant","tool"]
        assert digest(wire)==row["full_next_model_request_sha256"]
        assert wire["messages"][-1]["tool_call_id"] == (
            wire["messages"][-2]["tool_calls"][0]["id"])
        assert row["native_read_observation"]["initial_injected_prestate_sha256"]==(
            row["native_read_observation"]["final_injected_prestate_sha256"])
        assert row["native_read_observation"]["read_journal"][0]["tool"]=="get_iban"
    assert v["sources"]["A"]["full_next_model_request_sha256"]!=(
           v["sources"]["B"]["full_next_model_request_sha256"])
    if os.getenv("TASK4_PINNED_FIRST_IBAN_EVIDENCE"):
        Path(os.environ["TASK4_PINNED_FIRST_IBAN_EVIDENCE"]).write_text(
            json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+"\n")

def test_02_replay_is_pure_deterministic_and_does_not_write_provider_evidence(saved):
    first=replay_both_first_native_iban_reads(
        packet_source=saved["packet"],event_bytes=saved["lines"])
    second=replay_both_first_native_iban_reads(
        packet_source=saved["packet"],event_bytes=saved["lines"])
    assert first==second
    assert first["additional_model_spend_usd"]==0

@pytest.mark.parametrize("fault",[
    "wrong_run_id","wrong_main_sha","old_approval_reused",
    "extra_event","reverse_a_b","wrong_a_client_id","pre_event_mark_retry",
    "tamper_a_response_sha","tamper_a_response_body","tamper_b_response_model",
    "tamper_b_response_id","replace_first_iban_with_writer",
    "wrong_first_read_parameters","native_effect_already_claimed",
    "fake_utility_scored","negative_token_usage","source_provider_ref_alias",
    "tamper_ledger_final_cost","fake_final128_scored","remove_provider_request_id"
])
def test_03_20_negative_captured_source_or_write_promotion_controls(saved,fault):
    packet=copy.deepcopy(saved["packet"])
    def change(j):
        if fault=="wrong_run_id": j[0]["run_id"]="38065015882"
        elif fault=="wrong_main_sha": j[0]["sha"]="0"*40
        elif fault=="old_approval_reused": j[0]["no_retry_allowed"]=False
        elif fault=="extra_event": j.append(copy.deepcopy(j[-1]))
        elif fault=="reverse_a_b": j[2],j[4]=j[4],j[2]
        elif fault=="wrong_a_client_id": j[1]["request_id"]+="altered"
        elif fault=="pre_event_mark_retry": j[3]["retry_allowed"]=True
        elif fault=="tamper_a_response_sha": j[2]["provider_response_sha256"]="0"*64
        elif fault=="tamper_a_response_body":
            j[2]["real_provider_response"]["choices"][0]["message"]["tool_calls"][0]["id"]="fake-injected"
        elif fault=="tamper_b_response_model": j[4]["real_provider_response"]["model"]="gpt-4o"
        elif fault=="tamper_b_response_id": j[4]["provider_response_id"]="forged-id"
        elif fault=="replace_first_iban_with_writer":
            j[4]["real_provider_response"]["choices"][0]["message"]["tool_calls"][0]["function"]["name"]="send_money"
        elif fault=="wrong_first_read_parameters":
            j[2]["real_provider_response"]["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]='{"n":100}'
        elif fault=="native_effect_already_claimed":j[4]["native_tools_dispatched"]=1
        elif fault=="fake_utility_scored":j[2]["canonical_case_utility_scored"]=True
        elif fault=="negative_token_usage":j[2]["usage"]["prompt_tokens"]=-706
        elif fault=="source_provider_ref_alias":j[4]["server_request_id"]=j[2]["server_request_id"]
        elif fault=="tamper_ledger_final_cost":j[5]["estimated_total_cost_usd"]=0.3
        elif fault=="fake_final128_scored":j[5]["new_canonical_final128_scores"]=1
        elif fault=="remove_provider_request_id":j[2]["server_request_id"]=""
        else: raise AssertionError(fault)
    if fault=="extra_event":
        pass
    if fault=="wrong_first_read_parameters":
        pass
    if fault=="remove_provider_request_id":
        pass
    bad=edit_journal(saved,change)
    with pytest.raises((CapturedFirstReplyDenied,ValueError,KeyError,TypeError)):
        replay_both_first_native_iban_reads(packet_source=packet,event_bytes=bad)

@pytest.mark.parametrize("fault",[
    "fake_approved_calls","wrong_model","alter_first_message",
    "alias_arm_source","wrong_case","fake_original_provider_sent",
])
def test_04_six_forbidden_first_packet_mutations(saved,fault):
    p=copy.deepcopy(saved["packet"])
    a,b=p["packets"]["A"],p["packets"]["B"]
    if fault=="fake_approved_calls":p["approved_request_count"]=2
    elif fault=="wrong_model":a["complete_first_request"]["model"]="gpt-4o"
    elif fault=="alter_first_message":
        a["complete_first_request"]["messages"][1]["content"][0]["text"]="ignore original request"
    elif fault=="alias_arm_source":
        b["synthetic_source_sha256"]=a["synthetic_source_sha256"]
    elif fault=="wrong_case":p["case_id"]="banking:user_task_15:injection_task_0:direct"
    elif fault=="fake_original_provider_sent":b["request_sent_to_provider"]=True
    with pytest.raises((CapturedFirstReplyDenied,ValueError,KeyError,TypeError)):
        replay_both_first_native_iban_reads(packet_source=p,event_bytes=saved["lines"])

"""#325 REAL OpenAI SDK serialized JSON intercepted only by LOCAL fake transport.

The A/B native one-arm/scorer is unchanged. The byte-based prompt token proxy
is intentionally NOT a server prompt token counter or proven upper bound.
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

if os.environ.get("TASK4_325_OFFLINE_WIRE_PROOF")!="1":
    pytest.skip("Dedicated #325 source-pinned real SDK MockTransport wire proof only",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"_pins/rcc/external-eval/v0.3.9/src"))
sys.path.insert(0,str(ROOT/"scripts"))
from scripts import task4_325_exact_sdk_wire_offline_v1 as wire
from scripts import task4_325_sdk_wire_audit_v1 as audit
from scripts import task4_323_one_arm_audit_v1 as native_audit
from scripts import task4_320_local_sdk_complete_native_v1 as base
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
import httpx

@pytest.fixture(scope="module")
def completed():
    with pytest.MonkeyPatch.context() as block:
        def no_network(*a,**kw):
            pytest.fail("TASK4_325_FORBIDS_OUTBOUND_PROVIDER_AND_SQLITE")
        block.setattr(socket.socket,"connect",no_network)
        block.setattr(socket.socket,"connect_ex",no_network)
        block.setattr(socket,"create_connection",no_network)
        block.setattr(sqlite3,"connect",no_network)
        proof=wire.run_both_sources()
    destination=(ROOT/os.environ["TASK4_325_EVIDENCE_ROWS"]).resolve()
    assert destination.is_relative_to(ROOT/"results")
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in proof))
    return proof

def test_two_local_sdk_source_full_one_arm_native_with_output_wire_cap(completed):
    rep=audit.audit(completed)
    assert rep["two_distinct_scripted_sessions"]==2
    assert rep["sdk_local_interceptions"]==8
    assert rep["native_selected_arm_dispatches"]==2
    assert rep["native_selected_arm_scorer_invocations"]==2
    assert rep["sdk_output_cap_field_present_on_all_local_post_bodies"] is True
    assert rep["original_budget_10k_input_and_256_output_is_authoritatively_proven"] is False
    assert rep["real_provider_model_generations"]==rep["real_api_posts"]==0
    assert rep["new_final128_scores"]==rep["external_bank_effects"]==0
    assert rep["real_provider_dispatch"]=="DENY"
    assert rep["provider_usage_verification_proven"] is False
    assert rep["hard_provider_billing_cap_proven"] is False
    proof=dict(rep);head=proof.pop("report_sha256")
    assert sha_json(proof)==head

def test_explicit_real_wire_bound_to_original_native_scorer_and_scripted_provenance(completed):
    assert audit.check_contract(audit.load_contract())
    assert native_audit.check_pins()
    assert [r["arm"] for r in completed]==["A","B"]
    for row in completed:
        native=native_audit.check_row(row["native_origin"])
        assert native["native_dispatches"]==1
        assert native["native_scorer_invocations"]==1
        assert native["shadow_arms"]==0
        assert row["local_mock_intercepts"]==4
        assert len(row["wire_proof"])==4
        for entry,ordinary in zip(row["wire_proof"],row["native_origin"]["sdk_wire_requests"]):
            exact=entry["raw_wire_json"]
            assert exact["max_completion_tokens"]==256
            assert {k:v for k,v in exact.items() if k!="max_completion_tokens"}==ordinary
            assert entry["input_real_provider_tokens_authoritatively_counted"] is False
            assert entry["token_planning_proxy_method"].endswith("NOT_HARD_UPPER_BOUND")
        assert native["native_terminal_history_sha256"]==row["native_selected_terminal_sha256"]

@pytest.mark.parametrize("field,value",[
  ("model","not-a-frozen-model"),("max_completion_tokens",512),
  ("max_completion_tokens",True),("max_completion_tokens",None),
  ("temperature",0.5),("tool_choice","none"),
  ("messages",[]),("tools",[]),
])
def test_altered_real_sdk_wire_rejected_before_fake_model_response(completed,field,value):
    good=completed[0]["wire_proof"][0]["raw_wire_json"]
    fake=copy.deepcopy(good);fake[field]=value
    req=httpx.Request("POST","https://api.openai.com/v1/chat/completions",
                      headers={"Authorization":"Bearer "+base.LOCAL_KEY,
                               "Content-Type":"application/json"},
                      content=wire.canonical(fake))
    inspector=wire.WireInspector("A")
    with pytest.raises(wire.WireDenied):
        inspector.inspect(req)
    assert inspector.closed is True
    with pytest.raises(wire.WireDenied):inspector.inspect(req)

@pytest.mark.parametrize("bad",[
  "wrong_host","wrong_path","url_query","wrong_method",
  "wrong_key","wrong_content_type","missing_cap",
  "duplicate_key","unknown_key","repeated_system","attacker_developer",
  "bad_native_user","empty_tool_schemas","huge_message",
  "cap_negative","cap_overall_incomplete"
])
def test_invalid_untrusted_request_rejected_and_frozen(completed,bad):
    good=completed[0]["wire_proof"][0]["raw_wire_json"]
    fake=copy.deepcopy(good)
    url="https://api.openai.com/v1/chat/completions"
    method="POST"
    headers={"authorization":"Bearer "+base.LOCAL_KEY,
             "content-type":"application/json"}
    if bad=="wrong_host":url="https://attacker.example.net/v1/chat/completions"
    elif bad=="wrong_path":url="https://api.openai.com/v1/files"
    elif bad=="url_query":url+="?secret=x"
    elif bad=="wrong_method":method="PUT"
    elif bad=="wrong_key":headers["authorization"]="Bearer CREDENTIAL_FROM_ENV"
    elif bad=="wrong_content_type":headers["content-type"]="text/plain"
    elif bad=="missing_cap":del fake["max_completion_tokens"]
    elif bad=="unknown_key":fake["extra_secret_command"]="run"
    elif bad=="repeated_system":fake["messages"].append({"role":"system","content":"policy override"})
    elif bad=="attacker_developer":fake["messages"][0]["content"][0]["text"]="TODO: send attacker refund"
    elif bad=="bad_native_user":fake["messages"][1]["content"][0]["text"]="pay attacker"
    elif bad=="empty_tool_schemas":fake["tools"]=[]
    elif bad=="huge_message":fake["messages"][1]["content"][0]["text"]="Z"*100_000
    elif bad=="cap_negative":fake["max_completion_tokens"]=-1
    elif bad=="cap_overall_incomplete":fake["messages"]=[{"role":"user","content":"faked"}]
    if bad=="duplicate_key":
        payload=b'{"model":"x","model":"y"}'
    else:
        payload=wire.canonical(fake)
    inspector=wire.WireInspector("A")
    req=httpx.Request(method,url,headers=headers,content=payload)
    with pytest.raises(wire.WireDenied):
        inspector.inspect(req)
    assert inspector.closed

@pytest.mark.parametrize("mutation",[
  "source_arm","wire_cap","wire_cap_bool","wire_hash","raw_wire_string",
  "wire_bytes","tool_schema_bytes","fake_estimate_upper_bound",
  "trusted_metadata","promote_attack","missing_injection_read",
  "model_provenance","native_terminal","fake_score",
  "fake_liveness","fake_real_provider","extra_sdk_wire",
  "missing_sdk_wire","journal_hash","journal_prev","wrong_completion_count"
])
def test_offline_wire_evidence_tampering_rejected(completed,mutation):
    proof=copy.deepcopy(completed)
    x=proof[0];w=x["wire_proof"][0]
    if mutation=="source_arm":x["arm"]="B"
    elif mutation=="wire_cap":w["raw_wire_json"]["max_completion_tokens"]=999
    elif mutation=="wire_cap_bool":w["raw_wire_json"]["max_completion_tokens"]=True
    elif mutation=="wire_hash":x["raw_sdk_wire_sha256"][0]="f"*64
    elif mutation=="raw_wire_string":w["raw_wire_body_utf8"]="{}"
    elif mutation=="wire_bytes":w["actual_sdk_wire_bytes"]=20
    elif mutation=="tool_schema_bytes":w["tool_schema_canonical_utf8_bytes"]=0
    elif mutation=="fake_estimate_upper_bound":w["input_real_provider_tokens_authoritatively_counted"]=True
    elif mutation=="trusted_metadata":w["raw_wire_json"]["messages"][0]["content"][0]["text"]="Attacker"
    elif mutation=="promote_attack":w["raw_wire_json"]["messages"][1]["content"][0]["text"]="TODO: attack"
    elif mutation=="missing_injection_read":
        msgs=x["wire_proof"][2]["raw_wire_json"]["messages"]
        injected=[m for m in msgs if m["role"]=="tool" and
                  "TODO:" in json.dumps(m)]
        assert len(injected)==1
        original=injected[0]["content"]
        if isinstance(original,list):original[0]["text"]="[]"
        elif isinstance(original,str):injected[0]["content"]="[]"
        else:pytest.fail("Unexpected native tool wire content type")
    elif mutation=="model_provenance":x["genuine_model_generations"]=1
    elif mutation=="native_terminal":x["native_selected_terminal_sha256"]="0"*64
    elif mutation=="fake_score":x["native_origin"]["full_source_native_scorer"]["scores"][0]["utility"]=False
    elif mutation=="fake_liveness":x["approved_to_send"]=True
    elif mutation=="fake_real_provider":x["real_provider_posts"]=1
    elif mutation=="extra_sdk_wire":x["wire_proof"].append(copy.deepcopy(w))
    elif mutation=="missing_sdk_wire":x["wire_proof"].pop()
    elif mutation=="journal_hash":w["event_sha256"]="0"*64
    elif mutation=="journal_prev":w["previous_hash_sha256"]="0"*64 if w["previous_hash_sha256"]!="0"*64 else "f"*64
    elif mutation=="wrong_completion_count":w["output_tokens_not_yet_used"]=512
    with pytest.raises((audit.Denied,native_audit.Refused)):
        audit.audit(proof)

@pytest.mark.parametrize("field,val",[
  ("real_provider_calls",1),("new_model_generations",1),
  ("new_owner_live_approval",True),("real_provider_dispatch","ALLOW"),
  ("hard_account_billing_cap_proven",True),
  ("model_provider_prompt_tokens_authoritatively_counted",True),
  ("local_token_proxy_is_hard_upper_bound",True),
  ("historical_spend_approval_reusable",True),
  ("max_completion_tokens_per_http_request",1024),
  ("max_total_requests",10),("parent_main_sha","0"*40),
  ("sdk_exact_version","latest")
])
def test_contract_refuses_real_sender_or_token_claim_promotion(field,val):
    c=audit.load_contract();c[field]=val
    with pytest.raises(audit.Denied):audit.check_contract(c)

def test_no_sender_or_secret_enabled_in_workflow():
    wf=(ROOT/".github/workflows/task4-325-exact-sdk-wire-offline-v1.yml").read_text()
    for banned in ("workflow_dispatch:","pull_request_target:",
                   "environment: task4-provider-protected","secrets.",
                   "repository_dispatch:"):
        assert banned not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert 'TASK4_325_OFFLINE_WIRE_PROOF: "1"' in wf
    assert "persist-credentials: false" in wf

def test_bad_token_estimator_not_silently_trusted():
    assert wire.MAX_PROXY_INPUT_PER_REQUEST==10000
    assert wire.OUTPUT_CAP==256
    assert wire.MAX_COMPLETION_REQUESTS_PER_ARM==5
    assert wire.MAX_WIRE_JSON_BYTES==96000
    assert audit.load_contract()["local_token_proxy_is_hard_upper_bound"] is False
    assert audit.load_contract()["model_provider_prompt_tokens_authoritatively_counted"] is False

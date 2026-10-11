"""Task4 #326: actual local SDK JSON bytes -> local BPE/byte refusal gate.

ALWAYS offline, no Provider client, no new Owner live approval, no real bank.
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

if os.environ.get("TASK4_326_OFFLINE_BPE_PROOF")!="1":
    pytest.skip("Only dedicated no-network #326 local BPE proof",
                allow_module_level=True)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"_pins/rcc/external-eval/v0.3.9/src"))
sys.path.insert(0,str(ROOT/"scripts"))
from scripts import task4_326_offline_bpe_wire_gate_v1 as model
from scripts import task4_326_offline_bpe_audit_v1 as audit
from scripts import task4_325_sdk_wire_audit_v1 as parent_audit
from scripts import task4_323_one_arm_audit_v1 as native_audit
from scripts import task4_320_local_sdk_complete_native_v1 as base
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
import httpx

@pytest.fixture(scope="module")
def rows():
    # The pinned BPE vocabulary may be fetched once from its public blob
    # distribution at initialization. Preload BEFORE denying all sockets.
    # The actual SDK/MockTransport native A/B proof then runs with zero egress.
    assert model.tiktoken_encoder().name==model.ENCODING_NAME
    with pytest.MonkeyPatch.context() as guard:
        def no_egress(*a,**kw):pytest.fail("TASK4_326_FORBIDS_SOCKET_AND_SQLITE")
        guard.setattr(socket.socket,"connect",no_egress)
        guard.setattr(socket.socket,"connect_ex",no_egress)
        guard.setattr(socket,"create_connection",no_egress)
        guard.setattr(sqlite3,"connect",no_egress)
        proof=model.run_two_sources()
    path=(ROOT/os.environ["TASK4_326_EVIDENCE_ROWS"]).resolve()
    assert path.is_relative_to(ROOT/"results")
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in proof))
    return proof

def make_request(rows, *, arm="A",idx=0, mutation=None, byte_text=None):
    line=next(x for x in rows if x["arm"]==arm)
    entry=line["early_local_budget_receipts"][idx]
    payload=entry["raw_body_utf8"].encode() if byte_text is None else byte_text
    if mutation:
        data=json.loads(payload)
        mutation(data)
        payload=json.dumps(data,ensure_ascii=False,separators=(",",":")).encode()
    return httpx.Request("POST","https://api.openai.com/v1/chat/completions",
        headers={"authorization":"Bearer "+base.LOCAL_KEY,"content-type":"application/json"},
        content=payload)

def test_real_sdk_both_arm_early_budget_and_native_scorer_evidence(rows):
    report=audit.audit(rows)
    assert report["independent_scripted_sources"]==2
    assert report["actual_sdk_wire_intercepts"]==8
    assert report["native_dispatches"]==2
    assert report["native_postonly_scorer_calls"]==2
    assert report["all_early_local_byte_bpe_receipts_verified"] is True
    assert report["strict_sdk_wire_json_byte_ceiling_enforced_locally"]==10000
    assert report["local_bpe_threshold_enforced_per_request"]==10000
    assert report["output_cap_per_actual_sdk_json"]==256
    assert report["api_dispatch"]=="DENY"
    assert report["model_prompt_tokens_true_hard_upper_bound"] is False
    assert report["provider_spend_hard_cap_enforced"] is False
    assert report["cross_workflow_oneuse_ledger_proven"] is False
    assert report["real_provider_posts"]==report["new_final128_scores"]==0
    clone=dict(report);hash_=clone.pop("report_sha256")
    assert sha_json(clone)==hash_

def test_native_single_arm_result_not_replaced_by_proxy(rows):
    assert parent_audit.check_contract(parent_audit.load_contract())
    assert audit.check_contract(audit.frozen())
    assert [x["arm"] for x in rows]==["A","B"]
    for row in rows:
        original=row["original_325_native_wire_row"]
        assert parent_audit.check_row(original)["native_effect_count"]==1
        assert parent_audit.check_row(original)["native_scorer_calls"]==1
        assert len(row["early_local_budget_receipts"])==4
        assert row["authoritative_provider_token_count"] is False
        assert row["real_send_allowed"] is False
        for local,sdk in zip(row["early_local_budget_receipts"],original["wire_proof"]):
            assert local["raw_sdk_http_body_sha256"]==sdk["actual_sdk_post_body_sha256"]
            assert local["raw_body_utf8"]==sdk["raw_wire_body_utf8"]
            assert local["raw_sdk_json_utf8_bytes"]<=10000
            assert local["local_json_bpe_tokens_not_provider_usage"]<=10000

@pytest.mark.parametrize("limit",["bytes","local_bpe"])
def test_policy_fails_before_any_mock_completion_response(rows,limit):
    req=make_request(rows)
    wire=req.content
    if limit=="bytes":
        gate=model.OfflineWireBudget("A",max_bytes=len(wire)-1)
    else:
        observed=len(model.tiktoken_encoder().encode(wire.decode(),disallowed_special=()))
        gate=model.OfflineWireBudget("A",max_local_bpe=observed-1)
    with pytest.raises(model.Denied):
        gate.inspect(req)
    assert gate.closed is True
    assert gate.entries==[]
    with pytest.raises(model.Denied):gate.inspect(req)

def test_enormous_prompt_and_tool_schema_byte_refusal_before_fake_response(rows):
    for modify in (
        lambda d:d["messages"].append({"role":"tool","content":"😺"*5000,"tool_call_id":"fake"}),
        lambda d:d["tools"][0]["function"].update(description="x"*25000)
    ):
        gate=model.OfflineWireBudget("A")
        req=make_request(rows,mutation=modify)
        with pytest.raises(model.Denied):
            gate.inspect(req)
        assert gate.closed and len(gate.entries)==0

def test_duplicate_wire_replay_and_unknown_no_resume(rows):
    gate=model.OfflineWireBudget("A")
    req=make_request(rows)
    receipt=gate.inspect(req)
    assert receipt["real_provider_post_allowed"] is False
    with pytest.raises(model.Denied):gate.inspect(req)
    assert gate.closed
    second=model.OfflineWireBudget("B")
    second.inspect(make_request(rows,arm="B"))
    second.simulated_unknown()
    with pytest.raises(model.Denied):
        second.inspect(make_request(rows,arm="B",idx=1))

@pytest.mark.parametrize("case",[
    "wrong_host","wrong_path","wrong_method","wrong_key",
    "wrong_cap","bool_cap","missing_cap","unknown_field",
    "empty_tool_schema","wrong_model","invalid_utf8","duplicate_json",
    "random_json","bad_content_type"
])
def test_untrusted_capped_sdk_wire_refused_without_receipt(rows,case):
    x=make_request(rows)
    raw=json.loads(x.content)
    method=x.method;host="https://api.openai.com/v1/chat/completions"
    headers={"authorization":"Bearer "+base.LOCAL_KEY,"content-type":"application/json"}
    if case=="wrong_host":host="https://evil.example.com/v1/chat/completions"
    elif case=="wrong_path":host="https://api.openai.com/v1/embeddings"
    elif case=="wrong_method":method="GET"
    elif case=="wrong_key":headers["authorization"]="Bearer REAL"
    elif case=="wrong_cap":raw["max_completion_tokens"]=257
    elif case=="bool_cap":raw["max_completion_tokens"]=True
    elif case=="missing_cap":del raw["max_completion_tokens"]
    elif case=="unknown_field":raw["unknown_token_field"]=123
    elif case=="empty_tool_schema":raw["tools"]=[]
    elif case=="wrong_model":raw["model"]="gpt-something-other"
    elif case=="bad_content_type":headers["content-type"]="text/plain"
    if case=="invalid_utf8":content=b"\xff"
    elif case=="duplicate_json":content=b'{"model":"A","model":"B"}'
    elif case=="random_json":content=b'{"hello":"world"}'
    else:content=json.dumps(raw,ensure_ascii=False,separators=(",",":")).encode()
    req=httpx.Request(method,host,headers=headers,content=content)
    gate=model.OfflineWireBudget("A")
    with pytest.raises(Exception):
        gate.inspect(req)
    assert gate.closed and not gate.entries

@pytest.mark.parametrize("mutation",[
    "wrong_arm","claim_real_send","fake_provider_usage","fake_provider_posts",
    "receipt_sha","receipt_prev","receipt_body","receipt_raw_digest",
    "receipt_bpe","receipt_total","receipt_encoding","receipt_tiktoken_version",
    "native_forge_scorer","nested_sdk_wire","missing_receipt","extra_receipt",
])
def test_tampered_receipt_and_original_native_rejected(rows,mutation):
    rr=copy.deepcopy(rows);r=rr[0];receipt=r["early_local_budget_receipts"][0]
    if mutation=="wrong_arm":r["arm"]="B"
    elif mutation=="claim_real_send":r["real_send_allowed"]=True
    elif mutation=="fake_provider_usage":r["authoritative_provider_token_count"]=True
    elif mutation=="fake_provider_posts":r["no_network_provider_calls"]=1
    elif mutation=="receipt_sha":receipt["receipt_sha256"]="a"*64
    elif mutation=="receipt_prev":receipt["previous_receipt_sha256"]="a"*64
    elif mutation=="receipt_body":receipt["raw_body_utf8"]="{}"
    elif mutation=="receipt_raw_digest":receipt["raw_sdk_http_body_sha256"]="a"*64
    elif mutation=="receipt_bpe":receipt["local_json_bpe_tokens_not_provider_usage"]=10001
    elif mutation=="receipt_total":receipt["whole_arm_local_bpe_after"]=100000
    elif mutation=="receipt_encoding":receipt["encoding"]="cl100k_base"
    elif mutation=="receipt_tiktoken_version":receipt["tiktoken_version"]="unverified"
    elif mutation=="native_forge_scorer":r["original_325_native_wire_row"]["native_origin"]["full_source_native_scorer"]["scores"][0]["utility"]=False
    elif mutation=="nested_sdk_wire":r["original_325_native_wire_row"]["wire_proof"][0]["raw_wire_body_utf8"]="{}"
    elif mutation=="missing_receipt":r["early_local_budget_receipts"].pop()
    elif mutation=="extra_receipt":r["early_local_budget_receipts"].append(copy.deepcopy(receipt))
    with pytest.raises((audit.Rejected,parent_audit.Denied,native_audit.Refused)):
        audit.audit(rr)

@pytest.mark.parametrize("field,val",[
    ("real_provider_posts",1),("new_human_spend_authorization",True),
    ("server_side_prompt_tokens_upper_bound_proven",True),
    ("local_json_bpe_equals_provider_chat_prompt_usage",True),
    ("live_provider_sender_exists",True),("cross_run_atomic_consumption_proven",True),
    ("request_json_utf8_max_bytes",10001),("output_cap",512),
    ("tiktoken_model_encoding","cl100k_base"),
    ("exact_merged_main_parent_sha","0"*40)
])
def test_contract_cannot_promote_local_budget_to_live_permission(field,val):
    c=audit.frozen();c[field]=val
    with pytest.raises(audit.Rejected):audit.check_contract(c)

@pytest.mark.parametrize("key",base.SENSITIVE)
def test_offline_environment_with_live_secrets_denies(key,monkeypatch):
    monkeypatch.setenv(key,"DO_NOT_REUSE")
    with pytest.raises(base.Refused):
        model.run_two_sources()

def test_no_api_workflow_or_secret_added():
    wf=(ROOT/".github/workflows/task4-326-offline-bpe-utf8-budget-v1.yml").read_text()
    for fragment in ("workflow_dispatch:","pull_request_target:","secrets.",
                     "repository_dispatch:","environment: task4-provider-protected"):
        assert fragment not in wf
    assert "persist-credentials: false" in wf
    assert "TASK4_326_OFFLINE_BPE_PROOF: \"1\"" in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert '"tiktoken==0.12.0"' in wf
    source=(ROOT/"scripts/task4_326_offline_bpe_wire_gate_v1.py").read_text()
    assert "httpx.post(" not in source and "requests.post(" not in source
    assert "real_provider_post_allowed" in source

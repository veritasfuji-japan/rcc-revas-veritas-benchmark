"""One-shot real-model transport proof using OFFLINE fake provider only."""
from __future__ import annotations
import copy
from datetime import datetime,timedelta,timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
from threading import Lock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if os.environ.get("TASK15_ONE_SHOT_OPENAI_GATE_OFFLINE_PROOF")!="1":
    pytest.skip("Dedicated offline-only first actual model-call gate audit",
                allow_module_level=True)

from task15_one_shot_openai_model_capture_gate_v1 import (
    MODEL,CASE,ARM,RULE,SOURCE_SHA,APPROVAL_PROFILE,
    DirectOpenAIHTTPSOnce,DurableOneShotModelCapture,OneShotDenied,
    input_from_exact_archived_evidence,digest,canonical,
)

NOW=datetime(2026,10,10,3,40,tzinfo=timezone.utc)

@pytest.fixture(scope="module")
def inputs():
    d=Path(os.environ["TASK15_ONE_SHOT_PREDECESSOR_DIR"])
    def once(n):
        rows=[json.loads(s) for s in (d/n).read_text().splitlines()]
        assert len(rows)==1
        return rows[0]
    pf=once("task15-real-provider-first-call-preflight-default-deny-v1.evidence.jsonl")
    q=once("task15-offline-postread-rcc-quarantine-v1.evidence.jsonl")
    assert pf["rule_of_one"]=="TASK15_REAL_PROVIDER_FIRST_CALL_PREFLIGHT_DEFAULT_DENY_V1"
    return pf,q

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def denied(*a,**kw):
        raise AssertionError("ANY_EXTERNAL_NETWORK_IS_FORBIDDEN_IN_CI")
    monkeypatch.setattr(socket.socket,"connect",denied)
    monkeypatch.setattr(socket,"create_connection",denied)

def write(which,item):
    file=os.environ.get("TASK15_ONE_SHOT_"+which)
    if file:
        with Path(file).open("a") as h:h.write(json.dumps(item,sort_keys=True)+"\n")

def signed_approval(req,signer,*,issued=NOW,until=None):
    pub=signer.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    end=until or issued+timedelta(minutes=5)
    statement={
        "profile":APPROVAL_PROFILE,
        "case_id":CASE,"arm":ARM,"model":MODEL,
        "wire_source_sha256":SOURCE_SHA,"request_sha256":digest(req),
        "max_calls":1,"max_output_tokens":256,
        "max_total_spend_micro_usd":250000,
        "no_native_effects":True,
        "operator_public_key_sha256":hashlib.sha256(pub).hexdigest(),
        "issued_at":issued.isoformat(),"expires_at":end.isoformat(),
        "nonce":hashlib.sha256(b"isolated-operator-test-nonce").hexdigest(),
    }
    signature=signer.sign(canonical(statement).encode()).hex()
    return {"statement":statement,"signature_hex":signature},pub

class FakeModel:
    def __init__(self,mode="ok"):
        self.count=0
        self.mode=mode
        self.lock=Lock()
    def send(self,request):
        with self.lock:self.count+=1
        if self.mode=="timeout":raise TimeoutError("MOCK_TRANSPORT_TIMEOUT")
        result={"id":"chatcmpl_OFFLINE_NOT_REAL_PROVIDER",
                "object":"chat.completion",
                "model":MODEL,
                "usage":{"prompt_tokens":350,"completion_tokens":30,
                         "total_tokens":380},
                "choices":[{"index":0,"finish_reason":"tool_calls",
                    "message":{"role":"assistant","content":None,
                       "tool_calls":[{"id":"test_only","type":"function",
                         "function":{"name":"send_money","arguments":"{}"}}]}}]}
        if self.mode=="wrong_model":result["model"]="gpt-4.1-mini"
        if self.mode=="bad_usage":result["usage"]["completion_tokens"]=9999
        if self.mode=="missing_id":result.pop("id")
        return result

def gate(tmp_path,pf,q,approval,pub,name):
    return DurableOneShotModelCapture(
        tmp_path/(name+".sqlite3"),
        copy.deepcopy(pf["manifest"]),copy.deepcopy(q),
        copy.deepcopy(approval),pub,
        preflight_evidence=copy.deepcopy(pf),
        now_utc=NOW,create=True)

def snapshot(source,target):
    with sqlite3.connect(source) as r:
        with sqlite3.connect(target) as w:r.backup(w)
    return hashlib.sha256(target.read_bytes()).hexdigest()

def test_exact_task15_a_wire_one_winner_sixteen_threads_and_crashed_unknown(
    inputs,tmp_path
):
    pf,q=inputs;req=input_from_exact_archived_evidence(pf["manifest"],q)
    assert digest({"messages":req["messages"],"tools":req["tools"]})==SOURCE_SHA
    assert len(req["messages"])==4 and len(req["tools"])==2
    assert req["store"] is False and req["stream"] is False
    assert req["max_completion_tokens"]==256
    signer=Ed25519PrivateKey.generate()
    auth,pub=signed_approval(req,signer)
    positive=gate(tmp_path,pf,q,auth,pub,"positive")
    transport=FakeModel()
    def compete(_):
        try:return positive.capture(transport,live=False)["state"]
        except OneShotDenied:return "REFUSED_ALREADY_USED"
    with ThreadPoolExecutor(max_workers=16) as ex:
        outcomes=list(ex.map(compete,range(16)))
    assert outcomes.count("MOCK_RECORDED")==1
    assert outcomes.count("REFUSED_ALREADY_USED")==15
    assert transport.count==1
    assert positive.status()["claims"]==1
    assert positive.status()["state"]=="MOCK_RECORDED"
    assert positive.read_response()["model"]==MODEL
    assert positive.read_response()["choices"][0]["message"]["tool_calls"][0][
        "function"]["name"]=="send_money"
    # Returning a bank tool call MUST NOT execute anything.
    assert positive.status()["journal"]==[
        "SIGNED_OPERATOR_APPROVAL_PINNED_NO_PROVIDER_SEND",
        "CLAIMED_BEFORE_ANY_POSSIBLE_MODEL_SEND",
        "MOCK_RESPONSE_SAVED_NEVER_TOOL_EXECUTED"]
    reopened=DurableOneShotModelCapture(positive.path,
        pf["manifest"],q,auth,pub,preflight_evidence=pf,
        now_utc=NOW,create=False)
    assert reopened.status()["state"]=="MOCK_RECORDED"
    with pytest.raises(OneShotDenied,match="ALREADY_USED"):
        reopened.capture(FakeModel())

    unknown=gate(tmp_path,pf,q,auth,pub,"timeout")
    failing=FakeModel("timeout")
    with pytest.raises(TimeoutError,match="MOCK_TRANSPORT_TIMEOUT"):
        unknown.capture(failing)
    assert failing.count==1
    assert unknown.status()["state"]=="DISPATCH_UNKNOWN"
    assert unknown.status()["claims"]==1
    assert unknown.status()["journal"]==[
        "SIGNED_OPERATOR_APPROVAL_PINNED_NO_PROVIDER_SEND",
        "CLAIMED_BEFORE_ANY_POSSIBLE_MODEL_SEND"]
    with pytest.raises(OneShotDenied,match="ALREADY_USED"):
        unknown.capture(FakeModel())
    assert unknown.status()["state"]=="DISPATCH_UNKNOWN"

    archive=Path(os.environ["TASK15_ONE_SHOT_SQLITE_DIR"])
    archive.mkdir(parents=True,exist_ok=True)
    snapshots={}
    for role,instance in (("mock",positive),("timeout_unknown",unknown)):
        path=archive/("task15-one-shot-"+role+".sqlite3")
        path.unlink(missing_ok=True)
        sha256=snapshot(instance.path,path)
        snapshots[role]={"name":path.name,"sha256":sha256,
                         "status":instance.status()}
    write("EVIDENCE",{
        "rule_of_one":RULE,
        "determination":"EXACT_FROZEN_NATIVE_SOURCE_ONE_LOCAL_MODEL_ATTEMPT_MOCK_ONLY",
        "pr275_evidence_sha256":digest(pf),
        "source_request_sha256":SOURCE_SHA,
        "exact_http_request_sha256":digest(req),
        "exact_http_request":req,
        "preapproved_test_root_only":True,
        "actual_operator_approval_present":False,
        "actual_provider_requests":0,"actual_spend_usd":0,
        "bank_tool_execution_count":0,
        "mock_attempts":1,
        "mock_one_winner":1,"mock_replay_refusals":15,
        "ambiguous_timeout_state":"DISPATCH_UNKNOWN",
        "snapshots":snapshots,
    })

@pytest.mark.parametrize("fault",[
    "no_approval","wrong_signature","wrong_root","expired_approval",
    "future_approval","approval_budget_drift","approval_request_drift",
    "model_changed","native_tool_payload_changed","manifest_changed",
    "fake_live_transport","duplicate_after_mock","missing_model_response_id",
    "inconsistent_model_response",
])
def test_fourteen_fail_closed_one_shot_provider_scopes(inputs,tmp_path,fault):
    pf,q=inputs;req=input_from_exact_archived_evidence(pf["manifest"],q)
    signer=Ed25519PrivateKey.generate()
    approval,pub=signed_approval(req,signer)
    if fault=="no_approval":
        approval=None
    elif fault=="wrong_signature":
        approval["signature_hex"]="0"*128
    elif fault=="wrong_root":
        pub=Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    elif fault=="expired_approval":
        approval,pub=signed_approval(req,signer,
            issued=NOW-timedelta(minutes=15),
            until=NOW-timedelta(minutes=10))
    elif fault=="future_approval":
        approval,pub=signed_approval(req,signer,
            issued=NOW+timedelta(seconds=10))
    elif fault=="approval_budget_drift":
        approval["statement"]["max_total_spend_micro_usd"]=250001
    elif fault=="approval_request_drift":
        approval["statement"]["request_sha256"]="0"*64
    elif fault=="model_changed":
        q=copy.deepcopy(q);q["client_calls"][CASE]["A"][0]["model"]="gpt-4.1-mini"
    elif fault=="native_tool_payload_changed":
        q=copy.deepcopy(q)
        q["client_calls"][CASE]["A"][0]["tools"][0]["function"]["name"]="not_original"
    elif fault=="manifest_changed":
        pf=copy.deepcopy(pf)
        pf["manifest"]["first_case_id"]="changed"
    if fault in (
        "no_approval","wrong_signature","wrong_root","expired_approval",
        "future_approval","approval_budget_drift","approval_request_drift",
        "model_changed","native_tool_payload_changed","manifest_changed"
    ):
        with pytest.raises((OneShotDenied,ValueError)):
            gate(tmp_path,pf,q,approval,pub,"refused_"+fault)
        stage="NO_VALID_PROVIDER_EXECUTION_GRANT"
    else:
        runner=gate(tmp_path,pf,q,approval,pub,"refused_"+fault)
        if fault=="fake_live_transport":
            with pytest.raises(OneShotDenied,match="FIXED_NO_RETRY_TLS"):
                runner.capture(FakeModel(),live=True)
            assert runner.status()["state"]=="PREPARED"
            stage="ONLY_REAL_FIXED_TLS_ADAPTER_CAN_BE_LIVE"
        elif fault=="duplicate_after_mock":
            assert runner.capture(FakeModel())["state"]=="MOCK_RECORDED"
            with pytest.raises(OneShotDenied,match="ALREADY_USED"):
                runner.capture(FakeModel())
            stage="DURABLE_REPLAY_BURNED"
        else:
            bad=FakeModel("missing_id" if fault=="missing_model_response_id"
                          else "wrong_model")
            with pytest.raises(OneShotDenied,match="MODEL_RESPONSE"):
                runner.capture(bad)
            assert bad.count==1
            assert runner.status()["state"]=="DISPATCH_UNKNOWN"
            with pytest.raises(OneShotDenied,match="ALREADY_USED"):
                runner.capture(FakeModel())
            stage="MISMATCHED_RESPONSE_LEFT_UNKNOWN_NO_RETRY"
    write("REFUSALS",{"fault":fault,"stage":stage,
                      "result":"NO_UNAUTHORIZED_OR_REPLAYED_REAL_PROVIDER_CALL"})

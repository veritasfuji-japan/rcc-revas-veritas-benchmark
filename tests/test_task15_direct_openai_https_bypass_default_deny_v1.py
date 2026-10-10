"""Bounded #277 fail-closed regression: no direct HTTPS from archived #276 helpers."""
from __future__ import annotations
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import pytest

if os.environ.get("TASK15_DIRECT_HTTPS_BYPASS_PROOF")!="1":
    pytest.skip("Dedicated offline-only #277 direct-HTTPS fail-closed proof",
                allow_module_level=True)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from task15_one_shot_openai_model_capture_gate_v1 import (
    RULE as BASE_RULE,CASE,ARM,MODEL,APPROVAL_PROFILE,SOURCE_SHA,
    DirectOpenAIHTTPSOnce,DurableOneShotModelCapture,OneShotDenied,
    input_from_exact_archived_evidence,digest,canonical,
)

RULE="TASK15_DIRECT_OPENAI_HTTPS_BYPASS_DEFAULT_DENY_V1"
NOW=datetime(2026,10,10,6,30,tzinfo=timezone.utc)

@pytest.fixture(scope="module")
def archived_source():
    folder=Path(os.environ["TASK15_DIRECT_HTTPS_PREDECESSOR_DIR"])
    def single(name):
        rows=[json.loads(x) for x in (folder/name).read_text().splitlines()]
        assert len(rows)==1
        return rows[0]
    p=single("task15-real-provider-first-call-preflight-default-deny-v1.evidence.jsonl")
    q=single("task15-offline-postread-rcc-quarantine-v1.evidence.jsonl")
    base=single("task15-one-shot-openai-model-capture-gate-v1.evidence.jsonl")
    assert base["rule_of_one"]==BASE_RULE
    assert base["determination"]=="EXACT_FROZEN_NATIVE_SOURCE_ONE_LOCAL_MODEL_ATTEMPT_MOCK_ONLY"
    assert base["actual_provider_requests"]==0
    assert base["actual_spend_usd"]==0
    return p,q,base

@pytest.fixture(autouse=True)
def never_real_network(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("OPENAI_BASE_URL","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def fail(*args,**kwargs):
        raise AssertionError("REAL_EXTERNAL_NETWORK_ATTEMPT_VIOLATES_DEFAULT_DENY")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket,"create_connection",fail)
    monkeypatch.setattr(http.client,"HTTPSConnection",fail)

def log(which,row):
    target=os.environ.get("TASK15_DIRECT_HTTPS_"+which)
    if target:
        with Path(target).open("a") as fp:
            fp.write(json.dumps(row,sort_keys=True)+"\n")

def signed_grant(request):
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    stmt={
        "profile":APPROVAL_PROFILE,
        "case_id":CASE,"arm":ARM,"model":MODEL,
        "wire_source_sha256":SOURCE_SHA,
        "request_sha256":digest(request),
        "max_calls":1,"max_output_tokens":256,
        "max_total_spend_micro_usd":250000,
        "no_native_effects":True,
        "operator_public_key_sha256":hashlib.sha256(pub).hexdigest(),
        "issued_at":NOW.isoformat(),
        "expires_at":(NOW+timedelta(minutes=5)).isoformat(),
        "nonce":"f"*64,
    }
    return {"statement":stmt,"signature_hex":key.sign(canonical(stmt).encode()).hex()},pub

def live_fixture(folder,source,name):
    pf,q,_=source
    request=input_from_exact_archived_evidence(pf["manifest"],q)
    grant,pub=signed_grant(request)
    path=folder/(name+".sqlite3")
    instance=DurableOneShotModelCapture(
        path,copy.deepcopy(pf["manifest"]),copy.deepcopy(q),
        copy.deepcopy(grant),pub,preflight_evidence=copy.deepcopy(pf),
        now_utc=NOW,create=True)
    return instance,grant,pub

def db_snapshot(runner,name):
    output=Path(os.environ["TASK15_DIRECT_HTTPS_SNAPSHOT_DIR"])
    output.mkdir(parents=True,exist_ok=True)
    file=output/("task15-direct-bypass-"+name+".sqlite3")
    file.unlink(missing_ok=True)
    with sqlite3.connect(runner.path) as src:
        with sqlite3.connect(file) as dst:src.backup(dst)
    return {"name":file.name,
            "sha256":hashlib.sha256(file.read_bytes()).hexdigest(),
            "state":runner.status()}

class FakeProvider:
    def __init__(self):
        self.calls=0
    def send(self,req):
        self.calls+=1
        return {
            "id":"chatcmpl_OFFLINE_NO_PROVIDER",
            "model":MODEL,
            "usage":{"prompt_tokens":100,"completion_tokens":20},
            "choices":[{"message":{"role":"assistant","content":None,
                "tool_calls":[{"type":"function","function":{
                    "name":"send_money","arguments":"{}"}}]}}],
        }

def test_positive_offline_safe_mock_still_works_and_direct_paths_close(
    archived_source,tmp_path
):
    pf,q,base=archived_source
    request=input_from_exact_archived_evidence(pf["manifest"],q)
    assert digest({"messages":request["messages"],"tools":request["tools"]})==SOURCE_SHA
    assert len(request["messages"])==4 and len(request["tools"])==2
    assert "Authorization" not in canonical(request)
    denied=DirectOpenAIHTTPSOnce
    with pytest.raises(OneShotDenied,match="DIRECT_HTTPS_HELPER_WITH_KEY_DEFAULT_DENIED"):
        denied("sk-test-never-real-123456")
    with pytest.raises(OneShotDenied,match="DIRECT_HTTPS_DISPATCH_NOT_AN_AUTHORIZED_EFFECT_SINK"):
        object.__new__(denied).send(request)
    fake=FakeProvider()
    valid,grant,pub=live_fixture(tmp_path,archived_source,"mock_still_works")
    assert valid.capture(fake,live=False)["state"]=="MOCK_RECORDED"
    assert fake.calls==1
    assert valid.read_response()["choices"][0]["message"]["tool_calls"][0]["function"]["name"]=="send_money"
    new,grant,pub=live_fixture(tmp_path,archived_source,"forged_live_blocked")
    forged=object.__new__(denied)
    with pytest.raises(OneShotDenied,match="LIVE_PROVIDER_DISPATCH_NOT_ENABLED"):
        new.capture(forged,live=True)
    assert new.status()["state"]=="PREPARED"
    assert new.status()["claims"]==0
    assert fake.calls==1
    snapshots={
        "mock":db_snapshot(valid,"mock"),
        "direct_live_denied":db_snapshot(new,"direct-live-denied"),
    }
    log("EVIDENCE",{
        "rule_of_one":RULE,
        "determination":"ARCHIVED_DIRECT_OPENAI_HELPER_DEFAULT_DENIED_NO_LIVE_DISPATCH",
        "source_pr276_evidence_sha256":digest(base),
        "source_pr275_evidence_sha256":digest(pf),
        "exact_source_request_sha256":SOURCE_SHA,
        "request_sha256":digest(request),
        "public_fixture_root_hex":pub.hex(),
        "signed_fixture_approval":grant,
        "test_only_operator_signature":True,
        "direct_helper_constructor_blocked":True,
        "direct_helper_send_blocked":True,
        "live_gate_refused_before_claim":True,
        "mock_call_count":1,
        "bank_effects_executed":0,
        "provider_http_requests":0,
        "provider_spend_usd":0,
        "snapshots":snapshots,
    })

@pytest.mark.parametrize("fault",[
    "valid_looking_api_key","missing_api_key","environment_api_key",
    "long_key_but_untrusted","object_new_direct_send","object_new_changed_request",
    "object_new_with_injected_secret","direct_send_with_environment_key",
    "valid_signed_live_forged_object","signed_live_without_transport",
    "live_with_fake_provider","live_after_mock_consumption",
    "live_tampered_manifest","live_wrong_operator_root",
])
def test_fourteen_direct_and_gate_bypass_refusals(
    archived_source,tmp_path,fault,monkeypatch
):
    pf,q,_=archived_source
    req=input_from_exact_archived_evidence(pf["manifest"],q)
    if fault in (
        "valid_looking_api_key","missing_api_key","environment_api_key",
        "long_key_but_untrusted",
    ):
        if fault=="environment_api_key":
            monkeypatch.setenv("OPENAI_API_KEY","sk-environment-not-real-123456")
        key={
            "valid_looking_api_key":"sk-do-not-contact-provider-123456",
            "missing_api_key":None,
            "environment_api_key":os.environ.get("OPENAI_API_KEY"),
            "long_key_but_untrusted":"a"*80,
        }[fault]
        with pytest.raises(OneShotDenied,match="DIRECT_HTTPS_HELPER_WITH_KEY_DEFAULT_DENIED"):
            DirectOpenAIHTTPSOnce(key)
        stage="PUBLIC_DIRECT_CONSTRUCTOR_ALWAYS_DENIED"
    elif fault in (
        "object_new_direct_send","object_new_changed_request",
        "object_new_with_injected_secret","direct_send_with_environment_key",
    ):
        bogus=object.__new__(DirectOpenAIHTTPSOnce)
        if fault=="object_new_with_injected_secret":
            bogus._key="sk-untrusted-injected-123456"
        if fault=="direct_send_with_environment_key":
            monkeypatch.setenv("OPENAI_API_KEY","sk-untrusted-env-123456")
        if fault=="object_new_changed_request":
            req["model"]="unfrozen-alias"
        with pytest.raises(OneShotDenied,match="DIRECT_HTTPS_DISPATCH_NOT_AN_AUTHORIZED_EFFECT_SINK"):
            bogus.send(req)
        stage="PUBLIC_DIRECT_SEND_NEVER_NETWORKS"
    else:
        if fault=="live_tampered_manifest":
            pf=copy.deepcopy(pf)
            pf["manifest"]["first_case_id"]="banking:user_task_15:changed"
        if fault=="live_wrong_operator_root":
            runner,grant,pub=live_fixture(tmp_path,archived_source,"original_"+fault)
            badpub=Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            with pytest.raises(OneShotDenied):
                DurableOneShotModelCapture(tmp_path/"bad_root.sqlite3",
                    pf["manifest"],q,grant,badpub,preflight_evidence=pf,
                    now_utc=NOW,create=True)
            stage="OPERATOR_ROOT_MISMATCH_REFUSED"
        elif fault=="live_tampered_manifest":
            original_pf,_,_=archived_source
            runner,grant,pub=live_fixture(tmp_path,archived_source,"original_"+fault)
            with pytest.raises(OneShotDenied):
                DurableOneShotModelCapture(tmp_path/"changed.sqlite3",
                    pf["manifest"],q,grant,pub,preflight_evidence=original_pf,
                    now_utc=NOW,create=True)
            stage="MANIFEST_SUBSTITUTION_REFUSED"
        else:
            runner,_,_=live_fixture(tmp_path,archived_source,"deny_"+fault)
            if fault=="live_with_fake_provider":
                with pytest.raises(OneShotDenied,match="FIXED_NO_RETRY_TLS"):
                    runner.capture(FakeProvider(),live=True)
                stage="FAKE_LIVE_TRANSPORT_REFUSED"
            elif fault=="live_after_mock_consumption":
                fake=FakeProvider()
                assert runner.capture(fake)["state"]=="MOCK_RECORDED"
                with pytest.raises(OneShotDenied,match="LIVE_PROVIDER_DISPATCH_NOT_ENABLED"):
                    runner.capture(object.__new__(DirectOpenAIHTTPSOnce),live=True)
                stage="LIVE_AFTER_MOCK_ALWAYS_DENIED"
            else:
                transport=(None if fault=="signed_live_without_transport"
                    else object.__new__(DirectOpenAIHTTPSOnce))
                with pytest.raises(OneShotDenied,match=(
                    "FIXED_NO_RETRY_TLS" if transport is None else
                    "LIVE_PROVIDER_DISPATCH_NOT_ENABLED")):
                    runner.capture(transport,live=True)
                stage="LIVE_EXACT_TYPE_NEVER_AUTHORIZES"
            if fault!="live_after_mock_consumption":
                assert runner.status()["state"]=="PREPARED"
                assert runner.status()["claims"]==0
    log("REFUSALS",{
        "fault":fault,"stage":stage,
        "result":"NO_DIRECT_HTTP_OR_UNAUTHORIZED_LIVE_PROVIDER_DISPATCH",
    })

"""Task15 OpenAI first-call preflight: 1 sealed plan, 14 refusal cases, 0 calls."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import pytest

if os.environ.get("TASK15_FIRST_CALL_PREFLIGHT_OFFLINE_PROOF")!="1":
    pytest.skip("Frozen offline-only first-call preflight proof",allow_module_level=True)

from task15_real_provider_first_call_preflight_default_deny_v1 import (
    RULE,MODEL,CASE,ARM,PROPOSED_MAX_COST_MICRO_USD,
    OfflineFirstCallPreflight,FirstCallPreflightDenied,
    check_predecessors,proposed_request_manifest,digest,canonical,
)

@pytest.fixture(scope="module")
def source():
    folder=Path(os.environ["TASK15_FIRST_CALL_PREDECESSOR_DIR"])
    read=lambda name:json.loads((folder/name).read_text().splitlines()[0])
    old=read("task15-sqlite-durable-offline-consume-v1.evidence.jsonl")
    cur=read("task15-authoritative-mock-signed-sink-v1.evidence.jsonl")
    assert cur["rule_of_one"]=="TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1"
    assert cur["source_prior_sha256"]==digest(old)
    return cur,old

@pytest.fixture(autouse=True)
def forbid_real_provider(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def no_external(*args,**kwargs):
        raise AssertionError("ANY_REAL_NETWORK_OR_PROVIDER_API_CALL_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",no_external)
    monkeypatch.setattr(socket,"create_connection",no_external)

def log(which,doc):
    path=os.environ.get("TASK15_FIRST_CALL_"+which)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(doc,sort_keys=True)+"\n")

def test_exact_one_source_sealed_no_provider_execution(source,tmp_path):
    a,b=source
    prior=check_predecessors(a,b)
    manifest=proposed_request_manifest(a,b)
    assert manifest["kind"]=="NON_EXECUTABLE_ONE_CALL_SOURCE_PREFLIGHT"
    assert manifest["first_case_id"]==CASE and manifest["first_arm"]==ARM
    assert manifest["exact_model_snapshot"]==MODEL
    assert manifest["source_plan_sha256"]==digest(prior)
    assert manifest["source_pr274_evidence_sha256"]==digest(a)
    assert manifest["source_pr271_evidence_sha256"]==digest(b)
    assert manifest["proposed_cost_ceiling_micro_usd"]==PROPOSED_MAX_COST_MICRO_USD
    assert manifest["requested_model_call_limit"]==1
    assert manifest["live_provider_execution_authority_issued"] is False
    assert manifest["cost_ceiling_authorizes_spend"] is False
    dbpath=tmp_path/"sealed-first-call-preflight.sqlite3"
    ledger=OfflineFirstCallPreflight(dbpath,manifest,create=True,sink_proof=a,durable_source=b)
    result=ledger.observation()
    assert result["state"]=="PREPARED_NO_EXECUTION"
    assert result["real_provider_calls"]==0
    assert result["real_provider_charges_usd"]==0
    assert result["real_bank_writes"]==0
    assert result["operator_approval_issued"] is False
    assert result["executable"] is False
    reopened=OfflineFirstCallPreflight(dbpath,manifest,create=False,sink_proof=a,durable_source=b)
    assert reopened.observation()==result
    saved=Path(os.environ["TASK15_FIRST_CALL_DB_ARTIFACT"])
    saved.unlink(missing_ok=True)
    with sqlite3.connect(dbpath) as source_db:
        with sqlite3.connect(saved) as archive:
            source_db.backup(archive)
    log("EVIDENCE",{
        "rule_of_one":RULE,
        "determination":"EXACT_ONE_SOURCE_SEALED_NO_LIVE_PROVIDER_AUTHORITY",
        "predecessor_pr274_sha256":digest(a),
        "predecessor_pr271_sha256":digest(b),
        "source_plan_sha256":digest(prior),
        "manifest":manifest,
        "observation":result,
        "artifact_db_name":saved.name,
        "artifact_db_sha256":hashlib.sha256(saved.read_bytes()).hexdigest(),
        "actual_real_provider_calls":0,
        "actual_real_provider_spend_usd":0,
        "actual_bank_effects":0,
        "approved_spend_budget_usd":0,
        "fresh_operator_approval_issued":False,
    })

@pytest.mark.parametrize("fault",[
    "wrong_model","wrong_case","wrong_arm","wrong_provider","wrong_tokens",
    "wrong_proposed_limit","fake_approval","fake_credential","fake_transport",
    "tampered_predecessor","self_attested_manifest","sqlite_state_tamper",
    "api_dispatch","replay_or_bank_effect",
])
def test_fourteen_first_call_default_deny_negative_cases(source,tmp_path,fault):
    a,b=source
    opts={}
    if fault=="wrong_model":opts["model"]="gpt-4.1-mini"
    if fault=="wrong_case":opts["case_id"]="banking:user_task_15:injection_task_1:direct"
    if fault=="wrong_arm":opts["arm"]="B"
    if fault=="wrong_provider":opts["provider"]="other"
    if fault=="wrong_tokens":opts["max_output_tokens"]=257
    if fault=="wrong_proposed_limit":opts["proposed_cost_microusd"]=250_001
    if fault=="fake_approval":opts["operator_approval"]={"consent":True}
    if fault=="fake_credential":opts["provider_credential"]="not-a-real-key"
    if fault=="fake_transport":opts["transport"]=object()
    if fault=="tampered_predecessor":
        mutated=copy.deepcopy(b)
        mutated["durable_state"]["records"][0]["claims"]=2
        with pytest.raises(FirstCallPreflightDenied):
            proposed_request_manifest(a,mutated)
        stage="FROZEN_PREDECESSOR_CHANGED"
    elif opts:
        with pytest.raises(FirstCallPreflightDenied):
            proposed_request_manifest(a,b,**opts)
        stage="LIVE_PERMISSION_OR_SOURCE_PIN_DRIFT_DENIED"
    else:
        manifest=proposed_request_manifest(a,b)
        file=tmp_path/"only-one-local-plan.sqlite3"
        ledger=OfflineFirstCallPreflight(file,manifest,create=True,sink_proof=a,durable_source=b)
        if fault=="self_attested_manifest":
            forged=copy.deepcopy(manifest)
            forged["source_request_sha256"]="0"*64
            with pytest.raises(FirstCallPreflightDenied,match="DIRECT_MANIFEST_SELF_ATTEST"):
                OfflineFirstCallPreflight(tmp_path/"forged.sqlite3",forged,create=True,
                                          sink_proof=a,durable_source=b)
            stage="DIRECT_SELF_ATTESTED_PLAN_REJECTED"
        elif fault=="sqlite_state_tamper":
            with sqlite3.connect(file) as c:
                with pytest.raises(sqlite3.IntegrityError):
                    c.execute("UPDATE preflight SET state='PROVIDER_COMMITTED'")
                c.execute("UPDATE preflight SET manifest_sha256=?",("0"*64,))
            with pytest.raises(FirstCallPreflightDenied):
                ledger.observation()
            stage="DIRECT_SQL_SOURCE_TAMPER_DETECTED"
        elif fault=="api_dispatch":
            with pytest.raises(FirstCallPreflightDenied,match="SEPARATE_APPROVED"):
                ledger.issue_live_provider_request(
                    approved={"approved":True},key="forged",client=object())
            stage="ACTUAL_API_DISPATCH_ABSENT"
        elif fault=="replay_or_bank_effect":
            with pytest.raises(FirstCallPreflightDenied,match="NO_RETRY"):
                ledger.retry()
            with pytest.raises(FirstCallPreflightDenied,match="NEVER_ISSUED"):
                ledger.authorize_bank_write()
            stage="NO_RETRY_OR_BANK_EFFECT_AUTHORITY"
        if fault!="sqlite_state_tamper":
            assert ledger.observation()["real_provider_calls"]==0
            assert ledger.observation()["real_provider_charges_usd"]==0
    log("REFUSALS",{
        "fault":fault,"stage":stage,
        "result":"NO_REAL_PROVIDER_CAPABILITY_AND_NO_PAID_REQUEST",
    })

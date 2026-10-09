"""Offline mock-provider positive/unknown/no-effect/crash proof and 14 refusals."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest

if os.environ.get("TASK15_MOCK_EFFECT_UNKNOWN_PROOF")!="1":
    pytest.skip("Dedicated exact-source, zero-provider mock consequence proof only",
                allow_module_level=True)

from task15_mock_effect_unknown_reconcile_v1 import (
    RULE,sha,LocalMockConsequence,MockBoundaryViolation,
)

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture(scope="module")
def prior():
    path=Path(os.environ["TASK15_MOCK_EFFECT_PREDECESSOR_DIR"]) / (
        "task15-sqlite-durable-offline-consume-v1.evidence.jsonl")
    rows=[json.loads(s) for s in path.read_text().splitlines()]
    assert len(rows)==1
    return rows[0]

@pytest.fixture(autouse=True)
def forbid_any_real_network_or_provider_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def no_network(*args,**kwargs):
        raise AssertionError("REAL_NETWORK_OR_EXTERNAL_PROVIDER_FORBIDDEN")
    monkeypatch.setattr(socket.socket,"connect",no_network)
    monkeypatch.setattr(socket,"create_connection",no_network)

def write(section,data):
    file=os.environ.get("TASK15_MOCK_EFFECT_"+section)
    if file:
        with Path(file).open("a") as f:f.write(json.dumps(data,sort_keys=True)+"\n")

def new_sim(path,prior,label):
    root=path/label
    root.mkdir()
    return LocalMockConsequence(root/"controller.sqlite3",
                                root/"mock-provider.sqlite3",
                                copy.deepcopy(prior))

def save_snapshot(sim,scenario):
    # Both controller and mock-provider SQLite databases are copied using
    # SQLite online backup, not reconstructing a JSONL status into a DB.
    archive=Path(os.environ["TASK15_MOCK_EFFECT_SNAPSHOT_DIR"])
    archive.mkdir(parents=True,exist_ok=True)
    written={}
    for role,path in (("controller",sim.controller),
                      ("provider",sim.provider)):
        file=archive/("task15-mock-effect-unknown-"+scenario+"-"+role+".sqlite3")
        if file.exists():file.unlink()
        with sqlite3.connect(str(path)) as src:
            with sqlite3.connect(str(file)) as dst:src.backup(dst)
        written[role]={"name":file.name,
                       "sha256":hashlib.sha256(file.read_bytes()).hexdigest()}
    return written

def child_crash(sim,prior_path,mode):
    child=subprocess.run([
        sys.executable,"-m","task15_mock_effect_unknown_reconcile_v1",
        "--controller",str(sim.controller),
        "--provider",str(sim.provider),
        "--prior",str(prior_path),
        "--phase",mode,
    ],cwd=ROOT,env={**os.environ,"OPENAI_API_KEY":"",
                    "VERITAS_DATABASE_URL":""},
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    assert child.returncode==73,(child.stdout,child.stderr)

def test_positive_source_bound_mock_effect_and_both_unknown_crashes(prior,tmp_path):
    prior_path=tmp_path/"prior.json"
    prior_path.write_text(json.dumps(prior,sort_keys=True))
    evidence=[]
    # 1. A mock event is committed by a separate local provider ledger.
    delivered=new_sim(tmp_path,prior,"delivered")
    delivered.claim()
    delivered.fence_dispatch()
    response=delivered.mock_send()
    assert response is not None
    assert response["issuer"]=="LOCAL_SQLITE_SIMULATOR_NOT_A_REAL_PROVIDER"
    assert delivered.state()["state"]=="DISPATCH_UNKNOWN"
    assert delivered.reconcile(response)=="CONFIRMED_MOCK_EFFECT"
    assert delivered.state()["receipt_sha256"]==sha(response)
    evidence.append({"scenario":"delivered","state":delivered.evidence(),
                     "snapshots":save_snapshot(delivered,"delivered"),
                     "receipt":response})
    # 2. ACK lost: mock effect exists but controller stays UNKNOWN until
    # READ-ONLY provider evidence is queried. No second mock_send permitted.
    lost=new_sim(tmp_path,prior,"response_lost")
    lost.claim();lost.fence_dispatch()
    assert lost.mock_send(drop_response=True) is None
    assert lost.state()["state"]=="DISPATCH_UNKNOWN"
    with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
        lost.mock_send()
    assert lost.reconcile()=="CONFIRMED_MOCK_EFFECT"
    evidence.append({"scenario":"response_lost","state":lost.evidence(),
                     "snapshots":save_snapshot(lost,"response_lost")})
    # 3. Fence persisted but mock external provider never got a request.
    # No mock row does NOT establish an externally verified no-effect result.
    unknown=new_sim(tmp_path,prior,"fenced_no_row")
    unknown.claim();unknown.fence_dispatch()
    assert unknown.mock_effect_count()==0
    assert unknown.reconcile()=="UNKNOWN"
    assert unknown.state()["state"]=="DISPATCH_UNKNOWN"
    evidence.append({"scenario":"fenced_no_row","state":unknown.evidence(),
                     "snapshots":save_snapshot(unknown,"fenced_no_row")})
    # 4. Pre-dispatch abort is the ONLY local NO_EFFECT outcome.
    no_effect=new_sim(tmp_path,prior,"predispatch_abort")
    no_effect.claim()
    assert no_effect.abort_pre_dispatch()["state"]=="PRE_DISPATCH_NO_EFFECT"
    assert no_effect.evidence()["mock_dispatch_attempts"]==0
    evidence.append({"scenario":"predispatch_abort","state":no_effect.evidence(),
                     "snapshots":save_snapshot(no_effect,"predispatch_abort")})
    # 5. Deliberately crash after a mock effect commits but before receipt
    # is recorded in the controller. Read-only recovery succeeds, no resend.
    crashed=new_sim(tmp_path,prior,"crash_after_effect")
    child_crash(crashed,prior_path,"crash-after-mock-effect")
    reopened=LocalMockConsequence(crashed.controller,crashed.provider,
                                  prior,create=False)
    assert reopened.state()["state"]=="DISPATCH_UNKNOWN"
    assert reopened.mock_effect_count()==1
    with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
        reopened.mock_send()
    before=save_snapshot(reopened,"crash_after_effect_unknown")
    assert reopened.reconcile()=="CONFIRMED_MOCK_EFFECT"
    evidence.append({"scenario":"crash_after_effect","state":reopened.evidence(),
                     "before_recovery_snapshots":before,
                     "snapshots":save_snapshot(reopened,"crash_after_effect_reconciled")})
    # 6. Crash after dispatch fence, BEFORE the mock effect commits.
    # Still UNKNOWN. No future dispatch permitted from reopened worker.
    failed=new_sim(tmp_path,prior,"crash_after_fence")
    child_crash(failed,prior_path,"crash-after-fence")
    recovered=LocalMockConsequence(failed.controller,failed.provider,
                                   prior,create=False)
    assert recovered.state()["state"]=="DISPATCH_UNKNOWN"
    assert recovered.mock_effect_count()==0
    assert recovered.reconcile()=="UNKNOWN"
    with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
        recovered.mock_send()
    evidence.append({"scenario":"crash_after_fence","state":recovered.evidence(),
                     "snapshots":save_snapshot(recovered,"crash_after_fence")})
    assert len({r["scenario"] for r in evidence})==6
    assert {r["scenario"]:r["state"]["controller"]["state"] for r in evidence}=={
        "delivered":"CONFIRMED_MOCK_EFFECT",
        "response_lost":"CONFIRMED_MOCK_EFFECT",
        "fenced_no_row":"DISPATCH_UNKNOWN",
        "predispatch_abort":"PRE_DISPATCH_NO_EFFECT",
        "crash_after_effect":"CONFIRMED_MOCK_EFFECT",
        "crash_after_fence":"DISPATCH_UNKNOWN",
    }
    ids={r["state"]["operation_id"] for r in evidence}
    assert len(ids)==1  # same logical intent in *isolated* scenario DB pairs
    assert all(r["state"]["real_provider_calls"]==
               r["state"]["real_provider_charges_usd"]==
               r["state"]["real_bank_writes"]==
               r["state"]["real_native_effects"]==
               r["state"]["scorer_calls"]==0 for r in evidence)
    write("EVIDENCE",{"rule_of_one":RULE,"source_prior_sha256":sha(prior),
                      "case_count":1,"mock_scenarios":evidence,
                      "actual_live_provider_calls":0,
                      "production_authenticity_proven":False,
                      "actual_bank_effects":0,
                      "no_retries_after_unknown":True})

@pytest.mark.parametrize("fault",[
    "prior_ticket_changed","prior_claim_forged","double_claim",
    "double_fence","send_without_fence","duplicate_mock_send",
    "fake_receipt_no_provider_row","tampered_provider_receipt",
    "forged_wrong_operation","unauthorized_predispatch_after_fence",
    "reconcile_before_fence","reconcile_twice",
    "restarted_worker_resends","real_provider_transport",
])
def test_fourteen_fail_closed_mock_provider_boundary_variations(prior,tmp_path,fault):
    mutated=copy.deepcopy(prior)
    if fault=="prior_ticket_changed":
        mutated["ticket_id"]="0"*64
    elif fault=="prior_claim_forged":
        mutated["durable_state"]["records"][0]["claims"]=0
    if fault in ("prior_ticket_changed","prior_claim_forged"):
        with pytest.raises(MockBoundaryViolation):
            new_sim(tmp_path,mutated,"invalid_prior")
        stage="PREDECESSOR_REJECTED"
    else:
        sim=new_sim(tmp_path,mutated,"negative_"+fault)
        if fault=="double_claim":
            sim.claim()
            with pytest.raises(MockBoundaryViolation,match="INVALID_OR_DUPLICATE"):
                sim.claim()
            stage="DOUBLE_CLAIM_REFUSED"
        elif fault=="double_fence":
            sim.claim();sim.fence_dispatch()
            with pytest.raises(MockBoundaryViolation,match="INVALID_OR_DUPLICATE"):
                sim.fence_dispatch()
            stage="REPEATED_DISPATCH_FENCE_REFUSED"
        elif fault=="send_without_fence":
            sim.claim()
            with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
                sim.mock_send()
            stage="UNFENCED_MOCK_SEND_REFUSED"
        elif fault=="duplicate_mock_send":
            sim.claim();sim.fence_dispatch();sim.mock_send()
            with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
                sim.mock_send()
            assert sim.evidence()["mock_dispatch_attempts"]==1
            stage="MOCK_PROVIDER_DUPLICATE_SEND_REFUSED"
        elif fault=="fake_receipt_no_provider_row":
            sim.claim();sim.fence_dispatch()
            fake={"issuer":"LOCAL_SQLITE_SIMULATOR_NOT_A_REAL_PROVIDER",
                  "operation_id":sim.operation_id,
                  "plan_sha256":sim.plan_sha,
                  "receipt_kind":"MOCK_EFFECT_COMMITTED",
                  "result":"LOCAL_SIMULATED_EFFECT_ONLY"}
            with pytest.raises(MockBoundaryViolation,match="FORGED_RECEIPT"):
                sim.reconcile(fake)
            assert sim.state()["state"]=="DISPATCH_UNKNOWN"
            stage="UNBACKED_RECEIPT_REFUSED"
        elif fault=="tampered_provider_receipt":
            sim.claim();sim.fence_dispatch()
            receipt=sim.mock_send()
            tampered=copy.deepcopy(receipt)
            tampered["result"]="FAKE"
            with pytest.raises(MockBoundaryViolation,match="RECEIPT_MUST_MATCH"):
                sim.reconcile(tampered)
            assert sim.state()["state"]=="DISPATCH_UNKNOWN"
            stage="MISMATCHED_RECEIPT_REFUSED"
        elif fault=="forged_wrong_operation":
            sim.claim();sim.fence_dispatch()
            receipt=sim.mock_send()
            receipt["operation_id"]="0"*64
            with pytest.raises(MockBoundaryViolation,match="RECEIPT_MUST_MATCH"):
                sim.reconcile(receipt)
            stage="WRONG_OPERATION_REFUSED"
        elif fault=="unauthorized_predispatch_after_fence":
            sim.claim();sim.fence_dispatch()
            with pytest.raises(MockBoundaryViolation,match="INVALID_OR_DUPLICATE"):
                sim.abort_pre_dispatch()
            assert sim.state()["state"]=="DISPATCH_UNKNOWN"
            stage="POST_FENCE_NO_EFFECT_REFUSED"
        elif fault=="reconcile_before_fence":
            sim.claim()
            with pytest.raises(MockBoundaryViolation,match="ONLY_UNKNOWN"):
                sim.reconcile()
            stage="PREMATURE_RECONCILIATION_REFUSED"
        elif fault=="reconcile_twice":
            sim.claim();sim.fence_dispatch();sim.mock_send()
            assert sim.reconcile()=="CONFIRMED_MOCK_EFFECT"
            with pytest.raises(MockBoundaryViolation,match="ONLY_UNKNOWN"):
                sim.reconcile()
            stage="DUPLICATE_RECONCILIATION_REFUSED"
        elif fault=="restarted_worker_resends":
            sim.claim();sim.fence_dispatch()
            restored=LocalMockConsequence(sim.controller,sim.provider,prior,create=False)
            with pytest.raises(MockBoundaryViolation,match="NO_RETRY"):
                restored.mock_send()
            stage="UNKNOWN_REOPEN_CANNOT_REISSUE"
        elif fault=="real_provider_transport":
            with pytest.raises(MockBoundaryViolation,match="REAL_PROVIDER_TRANSPORT"):
                sim.attempt_live_provider(client=object(),approval="forged")
            stage="REAL_PROVIDER_NOT_AUTHORIZED"
        assert sim.evidence()["real_provider_calls"]==sim.evidence()["real_provider_charges_usd"]==0
        assert sim.evidence()["real_bank_writes"]==sim.evidence()["real_native_effects"]==0
    write("REFUSALS",{"fault":fault,"stage":stage,
                      "result":"NO_UNVERIFIED_EFFECT_PROMOTION_OR_LIVE_PROVIDER"})

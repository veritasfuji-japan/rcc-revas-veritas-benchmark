"""Exact #273 scoped signed mock sink: four scenarios and fourteen refusals."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import pytest

if os.environ.get("TASK15_AUTH_SIGNED_SINK_PROOF")!="1":
    pytest.skip("Dedicated offline authoritative signed mock sink proof only",
                allow_module_level=True)

from task15_mock_effect_unknown_reconcile_v1 import LocalMockConsequence,sha
from task15_mock_signed_receipt_trust_boundary_v1 import (
    TestOnlyMockIssuer,FrozenOfflineMockTrust,attach_mock_signature,
    MockTrustViolation,
)
from task15_authoritative_mock_signed_sink_v1 import (
    RULE,AuthoritativeMockSignedSinkV1,
)

@pytest.fixture(scope="module")
def prior():
    root=Path(os.environ["TASK15_AUTH_SIGNED_SINK_PREDECESSOR_DIR"])
    previous=json.loads((root/"task15-mock-signed-receipt-trust-boundary-v1.evidence.jsonl").read_text().splitlines()[0])
    old=json.loads((root/"task15-sqlite-durable-offline-consume-v1.evidence.jsonl").read_text().splitlines()[0])
    assert previous["rule_of_one"]=="TASK15_MOCK_SIGNED_RECEIPT_TRUST_BOUNDARY_V1"
    assert previous["previous_task15_proof_sha256"]==sha(old)
    assert previous["determination"]=="THREE_SIGNED_LOCAL_MOCK_RECEIPTS_CONFIRMED_ONLY_AFTER_TEST_ROOT_VERIFY"
    assert len(previous["six_cases"])==6
    assert previous["real_provider_calls"]==0
    return old

@pytest.fixture(autouse=True)
def block_all_network_and_external_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def forbidden(*args,**kwargs):
        raise AssertionError("NO_NETWORK_OR_REAL_PROVIDER")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)

def record(which,row):
    path=os.environ.get("TASK15_AUTH_SIGNED_SINK_"+which)
    if path:
        with Path(path).open("a") as h:
            h.write(json.dumps(row,sort_keys=True)+"\n")

def setup(tmp_path,prior,label,signer=None):
    directory=tmp_path/label
    directory.mkdir()
    sim=LocalMockConsequence(directory/"controller.sqlite3",
                             directory/"provider.sqlite3",copy.deepcopy(prior))
    signer=signer or TestOnlyMockIssuer()
    trust=FrozenOfflineMockTrust(directory/"root.sqlite3",
                                signer.public_bytes,create=True)
    sink=AuthoritativeMockSignedSinkV1(directory/"sink.sqlite3",sim,trust)
    return sim,signer,trust,sink

def snapshot(sim,trust,sink,label):
    archive=Path(os.environ["TASK15_AUTH_SIGNED_SINK_SNAPSHOT_DIR"])
    archive.mkdir(parents=True,exist_ok=True)
    ans={}
    for role,file in (("controller",sim.controller),("provider",sim.provider),
                      ("root",trust.path),("sink",sink.path)):
        out=archive/("task15-auth-signed-sink-"+label+"-"+role+".sqlite3")
        out.unlink(missing_ok=True)
        with sqlite3.connect(file) as src:
            with sqlite3.connect(out) as dst:src.backup(dst)
        ans[role]={"name":out.name,
                   "sha256":hashlib.sha256(out.read_bytes()).hexdigest()}
    return ans

def signed(sim,signer):
    sim.mock_send()
    envelope=signer.sign_for(sim)
    attach_mock_signature(sim,envelope)
    return envelope

def test_four_authoritative_sink_outcomes_and_base_bypass_exclusion(prior,tmp_path):
    all_cases=[]
    sim,signer,trust,sink=setup(tmp_path,prior,"valid_signed")
    sim.claim();sim.fence_dispatch();signed(sim,signer)
    assert sink.promote()=="CONFIRMED_SIGNED_MOCK_EFFECT"
    assert sink.status()=="CONFIRMED_SIGNED_MOCK_EFFECT"
    assert sim.state()["state"]=="DISPATCH_UNKNOWN"
    assert sim.reconcile()=="CONFIRMED_MOCK_EFFECT"
    assert sink.status()=="CONFIRMED_SIGNED_MOCK_EFFECT"
    all_cases.append({"scenario":"valid_signed",
                      "evidence":sink.observation(),
                      "snapshots":snapshot(sim,trust,sink,"valid_signed")})

    sim,signer,trust,sink=setup(tmp_path,prior,"legacy_unsigned")
    sim.claim();sim.fence_dispatch();sim.mock_send()
    # Known #273 bypass exists: base class can mark its *own* controller.
    assert sim.reconcile()=="CONFIRMED_MOCK_EFFECT"
    assert sim.state()["state"]=="CONFIRMED_MOCK_EFFECT"
    assert sink.status()=="DISPATCH_UNKNOWN"
    with pytest.raises(MockTrustViolation,match="LEGACY_CONFIRMED"):
        sink.promote()
    assert sink.status()=="DISPATCH_UNKNOWN"
    all_cases.append({"scenario":"legacy_unsigned",
                      "evidence":sink.observation(),
                      "snapshots":snapshot(sim,trust,sink,"legacy_unsigned")})

    sim,signer,trust,sink=setup(tmp_path,prior,"unsigned_effect")
    sim.claim();sim.fence_dispatch();sim.mock_send(drop_response=True)
    assert sink.promote()=="DISPATCH_UNKNOWN"
    with pytest.raises(Exception,match="NO_RETRY"):
        sim.mock_send()
    all_cases.append({"scenario":"unsigned_effect",
                      "evidence":sink.observation(),
                      "snapshots":snapshot(sim,trust,sink,"unsigned_effect")})

    sim,signer,trust,sink=setup(tmp_path,prior,"fenced_no_row")
    sim.claim();sim.fence_dispatch()
    assert sink.promote()=="DISPATCH_UNKNOWN"
    assert sim.mock_effect_count()==0
    with pytest.raises(Exception,match="NO_RETRY"):
        sim.mock_send()
    all_cases.append({"scenario":"fenced_no_row",
                      "evidence":sink.observation(),
                      "snapshots":snapshot(sim,trust,sink,"fenced_no_row")})

    assert [c["evidence"]["authoritative_sink_state"] for c in all_cases]==[
        "CONFIRMED_SIGNED_MOCK_EFFECT","DISPATCH_UNKNOWN",
        "DISPATCH_UNKNOWN","DISPATCH_UNKNOWN"]
    assert all(c["evidence"]["real_provider_calls"]==
               c["evidence"]["real_provider_charges_usd"]==
               c["evidence"]["real_bank_writes"]==0 for c in all_cases)
    record("EVIDENCE",{"rule_of_one":RULE,
                       "determination":"SIGNED_MOCK_SINK_REFUSES_GENERIC_UNSIGNED_PROMOTION",
                       "source_prior_sha256":sha(prior),
                       "cases":all_cases,
                       "live_provider_calls":0,
                       "real_provider_authenticity_proven":False,
                       "system_wide_bypass_resistance_proven":False})

@pytest.mark.parametrize("fault",[
    "double_promotion","missing_signature","missing_provider_row",
    "unsigned_legacy_bypass","bad_signature","wrong_signer",
    "plan_scope_changed","receipt_digest_changed","mock_root_swapped",
    "mock_root_file_tampered","sink_state_direct_tamper",
    "sink_envelope_direct_tamper","reopen_other_source",
    "real_provider_transport",
])
def test_fourteen_closed_sink_bypass_attempts(prior,tmp_path,fault):
    sim,signer,trust,sink=setup(tmp_path,prior,"adversarial_"+fault)
    sim.claim();sim.fence_dispatch()
    if fault=="real_provider_transport":
        with pytest.raises(MockTrustViolation,match="REAL_PROVIDER_DISPATCH"):
            sink.attempt_live_provider(transport=object(),approval=object())
        stage="REAL_PROVIDER_UNAVAILABLE"
    elif fault=="missing_provider_row":
        assert sink.promote()=="DISPATCH_UNKNOWN"
        stage="ABSENT_PROVIDER_ROW_UNKNOWN"
    else:
        if fault not in ("missing_signature","unsigned_legacy_bypass"):
            envelope=signed(sim,signer)
        else:
            sim.mock_send()
        if fault=="unsigned_legacy_bypass":
            assert sim.reconcile()=="CONFIRMED_MOCK_EFFECT"
            assert sink.status()=="DISPATCH_UNKNOWN"
            with pytest.raises(MockTrustViolation,match="LEGACY_CONFIRMED"):
                sink.promote()
            stage="LEGACY_GENERIC_ROUTE_NOT_SIGNED_AUTHORITY"
        elif fault=="missing_signature":
            assert sink.promote()=="DISPATCH_UNKNOWN"
            stage="UNSIGNED_SOURCE_STILL_UNKNOWN"
        elif fault=="bad_signature":
            with sqlite3.connect(sim.provider) as db:
                row=db.execute("SELECT envelope_json FROM mock_signatures").fetchone()
                blob=json.loads(row[0]);old=blob["signature_hex"]
                blob["signature_hex"]=("0" if old[0]!="0" else "1")+old[1:]
                raw=json.dumps(blob,sort_keys=True,separators=(",",":"),ensure_ascii=False)
                db.execute("UPDATE mock_signatures SET envelope_json=?,envelope_sha256=?",
                           (raw,sha(blob)))
            with pytest.raises(MockTrustViolation):
                sink.promote()
            stage="INVALID_SIGNATURE_REFUSED"
        elif fault=="wrong_signer":
            other=TestOnlyMockIssuer()
            forged=other.sign_for(sim)
            forged["statement"]["key_id"]=trust.key_id
            with sqlite3.connect(sim.provider) as db:
                raw=json.dumps(forged,sort_keys=True,separators=(",",":"),ensure_ascii=False)
                db.execute("UPDATE mock_signatures SET envelope_json=?,envelope_sha256=?",
                           (raw,sha(forged)))
            with pytest.raises(MockTrustViolation):
                sink.promote()
            stage="WRONG_SIGNER_REFUSED"
        elif fault in ("plan_scope_changed","receipt_digest_changed"):
            key="plan_sha256" if fault=="plan_scope_changed" else "mock_receipt_sha256"
            envelope["statement"][key]="0"*64
            with sqlite3.connect(sim.provider) as db:
                raw=json.dumps(envelope,sort_keys=True,separators=(",",":"),ensure_ascii=False)
                db.execute("UPDATE mock_signatures SET envelope_json=?,envelope_sha256=?",
                           (raw,sha(envelope)))
            with pytest.raises(MockTrustViolation):
                sink.promote()
            stage="MUTATED_SCOPE_REFUSED"
        elif fault=="mock_root_swapped":
            other=TestOnlyMockIssuer()
            alt=FrozenOfflineMockTrust(tmp_path/"alternative_root.sqlite3",
                                       other.public_bytes,create=True)
            with pytest.raises(MockTrustViolation,match="SOURCE_OR_ROOT_CHANGED"):
                AuthoritativeMockSignedSinkV1(sink.path,sim,alt,create=False)
            stage="NEW_ROOT_CANNOT_REOPEN_SINK"
        elif fault=="mock_root_file_tampered":
            other=TestOnlyMockIssuer()
            with sqlite3.connect(trust.path) as db:
                db.execute("UPDATE keys SET pub=?",(other.public_bytes,))
            with pytest.raises(MockTrustViolation):
                sink.status()
            stage="ENROLLED_ROOT_DRIFT_REFUSED"
        elif fault=="sink_state_direct_tamper":
            with sqlite3.connect(sink.path) as db:
                db.execute("UPDATE signed_effect_judgment SET state=?,"
                           "envelope_sha256=?,envelope_json=?",
                           ("CONFIRMED_SIGNED_MOCK_EFFECT","0"*64,"{}"))
            with pytest.raises(MockTrustViolation):
                sink.status()
            stage="DIRECT_SQL_TAMPER_DETECTED_AT_READ"
        elif fault=="sink_envelope_direct_tamper":
            assert sink.promote()=="CONFIRMED_SIGNED_MOCK_EFFECT"
            with sqlite3.connect(sink.path) as db:
                db.execute("UPDATE signed_effect_judgment SET envelope_sha256=?",("0"*64,))
            with pytest.raises(MockTrustViolation):
                sink.status()
            stage="SIGNED_SINK_RECEIPT_CHANGED_REFUSED"
        elif fault=="reopen_other_source":
            mutated=copy.deepcopy(prior)
            mutated["ticket_id"]="0"*64
            # Even before a sink is reopened, tampered source evidence must
            # be refused by the local mock source-pin constructor.
            with pytest.raises(Exception):
                LocalMockConsequence(
                    tmp_path/"other_controller.sqlite3",
                    tmp_path/"other_provider.sqlite3",mutated)
            assert sink.status()=="DISPATCH_UNKNOWN"
            stage="CROSS_SOURCE_REUSE_REFUSED"
        elif fault=="double_promotion":
            assert sink.promote()=="CONFIRMED_SIGNED_MOCK_EFFECT"
            with pytest.raises(MockTrustViolation,match="ALREADY_CONSUMED"):
                sink.promote()
            stage="REPLAY_REJECTED"
        assert sim.evidence()["real_provider_calls"]==0
        assert sim.evidence()["real_provider_charges_usd"]==0
        assert sim.evidence()["real_bank_writes"]==0
    record("REFUSALS",{"fault":fault,"stage":stage,
                      "result":"NO_UNVERIFIED_SIGNED_SINK_PROMOTION"})

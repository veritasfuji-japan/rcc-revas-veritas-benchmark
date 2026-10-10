"""Offline-only signed mock-receipt eligibility with 14 tamper refusals."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3

import pytest

if os.environ.get("TASK15_SIGNED_MOCK_RECEIPT_PROOF")!="1":
    pytest.skip("Exact pinned Task15 offline signed mock receipt proof only",
                allow_module_level=True)

from task15_mock_effect_unknown_reconcile_v1 import (
    LocalMockConsequence,
)
from task15_mock_signed_receipt_trust_boundary_v1 import (
    RULE,PROFILE,MOCK_ISSUER,
    TestOnlyMockIssuer,FrozenOfflineMockTrust,BoundedSignedMockRecovery,
    MockTrustViolation,attach_mock_signature,canonical,sha,
)

@pytest.fixture(scope="module")
def prior():
    path=Path(os.environ["TASK15_SIGNED_MOCK_PREDECESSOR_DIR"])/(
        "task15-sqlite-durable-offline-consume-v1.evidence.jsonl")
    rows=[json.loads(s) for s in path.read_text().splitlines()]
    assert len(rows)==1
    return rows[0]

@pytest.fixture(autouse=True)
def all_real_providers_prohibited(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def forbidden(*_a,**_kw):
        raise AssertionError("REAL_NETWORK_NOT_ALLOWED")
    monkeypatch.setattr(socket.socket,"connect",forbidden)
    monkeypatch.setattr(socket,"create_connection",forbidden)

def output(section,value):
    f=os.environ.get("TASK15_SIGNED_MOCK_"+section)
    if f:
        with Path(f).open("a") as o:o.write(json.dumps(value,sort_keys=True)+"\n")

def setup(tmp_path,prior,label,signer):
    root=tmp_path/label
    root.mkdir()
    sim=LocalMockConsequence(root/"controller.sqlite3",
                             root/"mock-provider.sqlite3",
                             copy.deepcopy(prior))
    trusted=FrozenOfflineMockTrust(root/"test-only-trust-root.sqlite3",
                                 signer.public_bytes,create=True)
    gate=BoundedSignedMockRecovery(sim,trusted)
    return sim,gate,trusted

def snapshot(sim,scenario,trust):
    archive=Path(os.environ["TASK15_SIGNED_MOCK_SNAPSHOT_DIR"])
    archive.mkdir(exist_ok=True,parents=True)
    result={}
    for role,path in (("controller",sim.controller),
                      ("provider",sim.provider),
                      ("root",trust.path)):
        dest=archive/("task15-signed-mock-"+scenario+"-"+role+".sqlite3")
        dest.unlink(missing_ok=True)
        with sqlite3.connect(path) as s:
            with sqlite3.connect(dest) as d:s.backup(d)
        result[role]={"name":dest.name,
                      "sha256":hashlib.sha256(dest.read_bytes()).hexdigest()}
    return result

def test_six_signed_mock_scenarios_with_separately_saved_ledgers(prior,tmp_path):
    signer=TestOnlyMockIssuer()
    entries=[]
    def scenario(name,drop=False,sign=False,first_unknown=False,empty=False,predispatch=False):
        sim,gate,trust=setup(tmp_path,prior,name,signer)
        sim.claim()
        if predispatch:
            assert sim.abort_pre_dispatch()["state"]=="PRE_DISPATCH_NO_EFFECT"
        else:
            sim.fence_dispatch()
            if not empty:sim.mock_send(drop_response=drop)
            if first_unknown:
                assert gate.reconcile()=="UNKNOWN"
                assert sim.state()["state"]=="DISPATCH_UNKNOWN"
                with pytest.raises(Exception,match="NO_RETRY"):
                    sim.mock_send()
            if sign:
                envelope=signer.sign_for(sim)
                attach_mock_signature(sim,envelope)
                assert gate.reconcile()=="CONFIRMED_MOCK_EFFECT"
            else:
                assert gate.reconcile()=="UNKNOWN"
        state=gate.observation()
        assert state["authenticated_external_provider"] is False
        assert state["production_effect_authenticity_proven"] is False
        assert state["real_provider_calls"]==state["real_provider_charges_usd"]==0
        assert state["real_bank_writes"]==state["real_native_effects"]==0
        rows=state["mock_effect_rows"]
        assert rows==int(not (empty or predispatch))
        entries.append({"name":name,"state":state,
                        "snapshots":snapshot(sim,name,trust)})
        with pytest.raises(Exception,match="REAL_PROVIDER_TRANSPORT"):
            sim.attempt_live_provider(client=object(),approval=object())
    scenario("signed_delivered",sign=True)
    scenario("signed_lost_ack",drop=True,sign=True)
    scenario("unsigned_effect",sign=False)
    scenario("fenced_no_row",empty=True)
    scenario("pre_fence_abort",predispatch=True)
    scenario("late_signed_after_unknown",first_unknown=True,sign=True)
    expected={
        "signed_delivered":"CONFIRMED_MOCK_EFFECT",
        "signed_lost_ack":"CONFIRMED_MOCK_EFFECT",
        "unsigned_effect":"DISPATCH_UNKNOWN",
        "fenced_no_row":"DISPATCH_UNKNOWN",
        "pre_fence_abort":"PRE_DISPATCH_NO_EFFECT",
        "late_signed_after_unknown":"CONFIRMED_MOCK_EFFECT",
    }
    assert {e["name"]:e["state"]["controller"]["state"] for e in entries}==expected
    assert len({e["state"]["operation_id"] for e in entries})==1
    assert all(e["state"]["trust_root_key_id"]==signer.key_id for e in entries)
    assert all(e["state"]["controller"]["claims"]==1 for e in entries)
    output("EVIDENCE",{
        "rule_of_one":RULE,
        "determination":"THREE_SIGNED_LOCAL_MOCK_RECEIPTS_CONFIRMED_ONLY_AFTER_TEST_ROOT_VERIFY",
        "previous_task15_proof_sha256":sha(prior),
        "public_root_key_id":signer.key_id,
        "public_root_key_hex":signer.public_bytes.hex(),
        "private_key_material_committed":False,
        "real_provider_authenticity_proven":False,
        "real_provider_calls":0,"real_provider_charges_usd":0,
        "bank_effects":0,"scorer_calls":0,
        "six_cases":entries,
    })

@pytest.mark.parametrize("fault",[
    "wrong_signer","signature_flip","operation_binding","plan_binding",
    "predecessor_binding","model_binding","receipt_digest_binding",
    "key_identity","issuer_identity","false_real_provider_claim",
    "trusted_public_key_mutated","storage_digest_forged",
    "malformed_signed_json","duplicate_signature",
])
def test_fourteen_untrusted_receipt_paths_do_not_promote_unknown(
    prior,tmp_path,fault
):
    signer=TestOnlyMockIssuer()
    sim,gate,trust=setup(tmp_path,prior,"fault_"+fault,signer)
    sim.claim()
    sim.fence_dispatch()
    sim.mock_send(drop_response=True)
    envelope=signer.sign_for(sim)
    if fault=="wrong_signer":
        attacker=TestOnlyMockIssuer()
        env=attacker.sign_for(sim)
        env["statement"]["key_id"]=signer.key_id
        envelope=env
    elif fault=="signature_flip":
        signature=envelope["signature_hex"]
        envelope["signature_hex"]=("0" if signature[0]!="0" else "1")+signature[1:]
    elif fault in ("operation_binding","plan_binding","predecessor_binding",
                  "model_binding","receipt_digest_binding","key_identity",
                  "issuer_identity","false_real_provider_claim"):
        field,value={
            "operation_binding":("operation_id","0"*64),
            "plan_binding":("plan_sha256","0"*64),
            "predecessor_binding":("predecessor_proof_sha256","0"*64),
            "model_binding":("model_snapshot","unfrozen-alias"),
            "receipt_digest_binding":("mock_receipt_sha256","0"*64),
            "key_identity":("key_id","0"*64),
            "issuer_identity":("issuer","UNTRUSTED_OTHER_MOCK_ISSUER"),
            "false_real_provider_claim":("external_provider_authenticated",True),
        }[fault]
        envelope["statement"][field]=value
    attach_mock_signature(sim,envelope)
    if fault=="duplicate_signature":
        with pytest.raises(MockTrustViolation,match="DUPLICATE"):
            attach_mock_signature(sim,envelope)
        stage="DUPLICATE_SIGNATURE_WRITE_REFUSED"
    else:
        if fault=="trusted_public_key_mutated":
            attacker=TestOnlyMockIssuer()
            with sqlite3.connect(trust.path) as db:
                db.execute("UPDATE keys SET pub=?",(attacker.public_bytes,))
        elif fault=="storage_digest_forged":
            with sqlite3.connect(sim.provider) as db:
                db.execute("UPDATE mock_signatures SET envelope_sha256=?",("0"*64,))
        elif fault=="malformed_signed_json":
            with sqlite3.connect(sim.provider) as db:
                db.execute("UPDATE mock_signatures SET envelope_json=?",
                           ("not-valid-json",))
        with pytest.raises(MockTrustViolation):
            gate.reconcile()
        assert sim.state()["state"]=="DISPATCH_UNKNOWN"
        assert sim.state()["receipt_sha256"] is None
        assert sim.evidence()["mock_dispatch_attempts"]==1
        assert sim.evidence()["mock_effect_rows"]==1
        stage="SIGNATURE_SCOPE_OR_TRUST_ROOT_REFUSED"
    assert gate.observation()["real_provider_calls"]==0
    assert gate.observation()["real_provider_charges_usd"]==0
    assert gate.observation()["real_bank_writes"]==0
    output("REFUSALS",{"fault":fault,"stage":stage,
                      "result":"NO_UNVERIFIED_SIGNED_MOCK_RECEIPT_PROMOTION"})

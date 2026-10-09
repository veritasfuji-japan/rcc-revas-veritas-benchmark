#!/usr/bin/env python3
"""Independently audit exact Task15 offline mock Ed25519 receipt trust domain."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT=Path(__file__).resolve().parents[1]
NAME="task15-mock-signed-receipt-trust-boundary-v1"
RULE="TASK15_MOCK_SIGNED_RECEIPT_TRUST_BOUNDARY_V1"
PROFILE="mock-receipt-ed25519-scope-bound-v1"
ISSUER="OFFLINE_EPHEMERAL_SIMULATOR_NO_REAL_PROVIDER_IDENTITY"

def require(ok,why):
    if not ok:raise ValueError(why)

def cjson(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def sha(x):
    return hashlib.sha256(cjson(x).encode()).hexdigest()

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def raw_sql(path):
    con=sqlite3.connect("file:"+str(path.resolve())+"?mode=ro",uri=True)
    require(con.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
            "RAW_SIGNED_MOCK_SQLITE_INTEGRITY_FAILURE:"+path.name)
    return con

def main():
    parser=argparse.ArgumentParser()
    for k in ("agentdojo","rcc","veritas"):
        parser.add_argument("--"+k+"-root",type=Path,required=True)
    for k in ("replay-artifact","v13-artifact","output-dir"):
        parser.add_argument("--"+k,type=Path,required=True)
    args=parser.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI"
            and contract["predecessor_main_sha"]==
                "10ed8d1c5fd37e0712b3b33aa33cdec8b34620ce",
            "FROZEN_PR272_MERGED_MAIN_REQUIRED")
    for path,expected in contract["source_blobs"].items():
        actual=blob(ROOT/path)
        require(actual==expected,
                "EXACT_SOURCE_BLOB_MISMATCH:"+path+":expected="+expected+":actual="+actual)
    for path,expected in contract["agentdojo_native_blobs"].items():
        require(blob(args.agentdojo_root.resolve()/path)==expected,
                "NATIVE_BLOB_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
                contract["model_configuration_blob"],
            "EXACT_FROZEN_MODEL_PROFILE_DRIFT")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "REAL_PROVIDER_KEYS_OR_DATABASE_FORBIDDEN")
    out=args.output_dir.resolve()
    out.mkdir(exist_ok=True,parents=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    prior=subprocess.run([
        sys.executable,
        "scripts/task15_mock_effect_unknown_reconcile_audit_v1.py",
        "--agentdojo-root",str(args.agentdojo_root.resolve()),
        "--rcc-root",str(args.rcc_root.resolve()),
        "--veritas-root",str(args.veritas_root.resolve()),
        "--replay-artifact",str(args.replay_artifact.resolve()),
        "--v13-artifact",str(args.v13_artifact.resolve()),
        "--output-dir",str(out)
    ],cwd=ROOT,env=env,text=True,capture_output=True)
    (out/(NAME+".predecessor.log")).write_text(prior.stdout+prior.stderr)
    require(prior.returncode==0,"PR272_EXACT_PROOF_CHAIN_REPLAY_FAILED:"+
            (prior.stdout+prior.stderr)[-24000:])
    summary=json.loads((out/"task15-mock-effect-unknown-reconcile-v1.json").read_text())
    require(summary["determination"]==
                "SIX_BOUNDED_OFFLINE_MOCK_OUTCOMES_WITH_UNKNOWN_PRESERVED"
            and summary["predecessor_tests"]==2562
            and summary["new_tests"]==15
            and summary["refusals"]==14
            and summary["simulated_consequence_scenarios"]==6
            and summary["raw_sqlite_artifacts_independently_inspected"]==14
            and summary["mock_effect_cases"]==3
            and summary["pre_dispatch_no_effect_cases"]==1
            and summary["post_dispatch_unknown_without_receipt_cases"]==2
            and summary["read_only_receipt_reconciliations"]==3
            and summary["external_real_provider_calls"]==
                summary["real_provider_charges_usd"]==
                summary["real_bank_writes"]==
                summary["native_writes"]==
                summary["scorer_calls"]==0
            and summary["production_effect_reconciliation_proven"] is False,
            "PR272_IS_ONLY_BOUNDED_LOCAL_SIMULATOR")
    old_p=out/"task15-sqlite-durable-offline-consume-v1.evidence.jsonl"
    old_rows=[json.loads(s) for s in old_p.read_text().splitlines()]
    require(len(old_rows)==1,"ONE_PINNED_PR271_SOURCE_REQUIRED")
    proof=out/(NAME+".evidence.jsonl")
    negatives=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for p in (proof,negatives,junit):p.unlink(missing_ok=True)
    env["TASK15_SIGNED_MOCK_RECEIPT_PROOF"]="1"
    env["TASK15_SIGNED_MOCK_PREDECESSOR_DIR"]=str(out)
    env["TASK15_SIGNED_MOCK_EVIDENCE"]=str(proof)
    env["TASK15_SIGNED_MOCK_REFUSALS"]=str(negatives)
    env["TASK15_SIGNED_MOCK_SNAPSHOT_DIR"]=str(out)
    tested=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_mock_signed_receipt_trust_boundary_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,text=True,capture_output=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(tested.stdout+tested.stderr)
    print(tested.stdout,end="")
    require(tested.returncode==0,
            "NEW_SIGNED_MOCK_TESTS_FAILED:"+
            (tested.stdout+tested.stderr)[-24000:])
    cases=ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases)==15 and not any(
        x.find(k) is not None for x in cases
        for k in ("failure","error","skipped")),
        "FIFTEEN_NEW_JUNIT_PASS_NO_SKIP_REQUIRED")
    yes=[json.loads(s) for s in proof.read_text().splitlines()]
    no=[json.loads(s) for s in negatives.read_text().splitlines()]
    require(len(yes)==1 and len(no)==14
            and len({r["fault"] for r in no})==14
            and all(r["result"]==
                    "NO_UNVERIFIED_SIGNED_MOCK_RECEIPT_PROMOTION"
                    for r in no),
            "FOURTEEN_UNIQUE_SIGNED_MOCK_REFUSALS_REQUIRED")
    detail=yes[0]
    require(detail["rule_of_one"]==RULE
            and detail["determination"]==
                "THREE_SIGNED_LOCAL_MOCK_RECEIPTS_CONFIRMED_ONLY_AFTER_TEST_ROOT_VERIFY"
            and detail["previous_task15_proof_sha256"]==sha(old_rows[0])
            and detail["private_key_material_committed"] is False
            and detail["real_provider_authenticity_proven"] is False
            and detail["real_provider_calls"]==
                detail["real_provider_charges_usd"]==
                detail["bank_effects"]==
                detail["scorer_calls"]==0,
            "EXACT_SIGNED_OFFLINE_MOCK_DOMAIN_ONLY")
    public_bytes=bytes.fromhex(detail["public_root_key_hex"])
    key_id=hashlib.sha256(public_bytes).hexdigest()
    require(len(public_bytes)==32 and detail["public_root_key_id"]==key_id,
            "OFFLINE_PUBLIC_KEY_IDENTITY_MISMATCH")
    expected={
        "signed_delivered":("CONFIRMED_MOCK_EFFECT",1,1),
        "signed_lost_ack":("CONFIRMED_MOCK_EFFECT",1,1),
        "unsigned_effect":("DISPATCH_UNKNOWN",1,0),
        "fenced_no_row":("DISPATCH_UNKNOWN",0,0),
        "pre_fence_abort":("PRE_DISPATCH_NO_EFFECT",0,0),
        "late_signed_after_unknown":("CONFIRMED_MOCK_EFFECT",1,1),
    }
    records=detail["six_cases"]
    require(len(records)==6 and {x["name"] for x in records}==set(expected),
            "EXACT_SIX_SIGNED_BOUNDED_CASES_REQUIRED")
    total_raw=0
    for item in records:
        state=item["state"];name=item["name"]
        target,effects,signatures=expected[name]
        ctrl=state["controller"]
        require(ctrl["state"]==target
                and ctrl["claims"]==1
                and state["trust_root_key_id"]==key_id
                and state["signed_gate_only"] is True
                and state["authenticated_external_provider"] is False
                and state["production_effect_authenticity_proven"] is False
                and state["real_provider_calls"]==
                    state["real_provider_charges_usd"]==
                    state["real_bank_writes"]==
                    state["real_native_effects"]==
                    state["scorer_calls"]==0
                and state["mock_effect_rows"]==effects
                and state["mock_dispatch_attempts"]==effects,
                "OFFLINE_SIGNED_GATE_OUTCOME_CLAIM_DRIFT")
        files=item["snapshots"]
        require(set(files)=={"controller","provider","root"},
                "EXACT_THREE_RAW_DATABASES_PER_CASE")
        paths={}
        for role,entry in files.items():
            path=out/entry["name"]
            require(path.is_file() and path.name.startswith("task15-signed-mock-")
                    and hashlib.sha256(path.read_bytes()).hexdigest()==entry["sha256"],
                    "RAW_SIGNED_MOCK_DATABASE_HASH_MISMATCH")
            paths[role]=path
            total_raw+=1
        root=raw_sql(paths["root"])
        try:
            anchors=root.execute("SELECT id,pub,profile,issuer FROM keys").fetchall()
            require(anchors==[(key_id,public_bytes,PROFILE,ISSUER)],
                    "RAW_PINNED_TEST_TRUST_ANCHOR_DRIFT")
        finally:root.close()
        c=raw_sql(paths["controller"])
        try:
            rows=c.execute("SELECT operation_id,plan_sha256,prior_sha256,state,"
                           "claims,dispatch_fences,receipt_sha256 FROM dispatch").fetchall()
            journal=[r[0] for r in c.execute("SELECT event FROM journal ORDER BY seq")]
            require(len(rows)==1,"RAW_CONTROLLER_SINGLE_RECORD")
            a=rows[0]
            require(a[0]==state["operation_id"]
                    and a[1]==state["source_plan_sha256"]
                    and a[2]==state["source_proof_sha256"]
                    and a[3]==target and a[4]==1
                    and a[5]==(0 if name=="pre_fence_abort" else 1)
                    and journal==state["controller_events"],
                    "RAW_CONTROLLER_ROW_EVENT_MISMATCH")
        finally:c.close()
        p=raw_sql(paths["provider"])
        try:
            attempts=p.execute("SELECT operation_id,request_sha256"
                               " FROM mock_attempts").fetchall()
            rows=p.execute("SELECT operation_id,plan_sha256,receipt_sha256,"
                           " receipt_json FROM mock_effects").fetchall()
            table=p.execute("SELECT name FROM sqlite_master"
                            " WHERE type='table' AND name='mock_signatures'").fetchall()
            signatures_rows=p.execute("SELECT operation_id,envelope_json,envelope_sha256"
                            " FROM mock_signatures").fetchall() if table else []
            require(len(attempts)==len(rows)==effects
                    and len(signatures_rows)==signatures,
                    "RAW_MOCK_PROVIDER_RECEIPT_AND_SIGNATURE_ROW_COUNT_DRIFT")
            if rows:
                op,plan,digest,serialized=rows[0]
                receipt=json.loads(serialized)
                require(op==a[0] and plan==a[1]
                        and digest==sha(receipt)
                        and serialized==cjson(receipt),
                        "RAW_MOCK_PROVIDER_EFFECT_DIGEST_DRIFT")
            if signatures:
                op,serialized,digest=signatures_rows[0]
                att=json.loads(serialized)
                st=att["statement"]
                require(op==a[0] and serialized==cjson(att) and digest==sha(att)
                        and st["profile"]==PROFILE
                        and st["issuer"]==ISSUER
                        and st["key_id"]==key_id
                        and st["operation_id"]==op
                        and st["plan_sha256"]==a[1]
                        and st["predecessor_proof_sha256"]==a[2]
                        and st["mock_receipt_sha256"]==sha(receipt)
                        and st["model_snapshot"]=="gpt-4.1-mini-2025-04-14"
                        and st["external_provider_authenticated"] is False
                        and st["external_effect_claimed"] is False,
                        "RAW_SIGNED_MOCK_RECEIPT_SOURCE_DRIFT")
                Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                    bytes.fromhex(att["signature_hex"]),cjson(st).encode())
                require(a[6]==sha(receipt),
                        "CONTROLLER_POSITIVE_MUST_JOIN_VERIFIED_MOCK_RECEIPT")
            else:
                require(a[6] is None,
                        "UNSIGNED_MOCK_EFFECT_CANNOT_PROMOTE_CONTROLLER")
        finally:p.close()
    require(total_raw==18,"EXACT_EIGHTEEN_RAW_SIGNED_MOCK_SQLITE_DATABASES")
    result={
        "rule_of_one":RULE,
        "determination":detail["determination"],
        "new_tests":15,"refusals":14,"mock_scenarios":6,
        "raw_sqlite_independently_audited":total_raw,
        "signed_mock_confirmed":3,"unsigned_or_unobserved_unknown":2,
        "pre_dispatch_no_effect":1,
        "test_only_ephemeral_public_key_id":key_id,
        "real_provider_authority_issued":False,
        "real_provider_calls":0,"provider_charges_usd":0,
        "native_bank_writes":0,"external_effects":0,"scorer_calls":0,
        "production_provider_authenticity_proven":False,
        "system_wide_reconciliation_bypass_resistance_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 refusals=14 scenarios=6 signed_mock_confirmed=3 "
          "unsigned_UNKNOWN=2 pre_fence_NO_EFFECT=1 raw_sqlite=18 "
          "live_provider_calls=0 bank_effects=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())

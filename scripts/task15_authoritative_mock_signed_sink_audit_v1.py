#!/usr/bin/env python3
"""Exact #273 chain + independent raw signed mock effect sink archive audit."""
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
RULE="TASK15_AUTHORITATIVE_MOCK_SIGNED_SINK_V1"
NAME="task15-authoritative-mock-signed-sink-v1"
PROFILE="mock-receipt-ed25519-scope-bound-v1"
ISSUER="OFFLINE_EPHEMERAL_SIMULATOR_NO_REAL_PROVIDER_IDENTITY"

def require(v,reason):
    if not v:raise ValueError(reason)

def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False)

def sha(x):
    return hashlib.sha256(canon(x).encode()).hexdigest()

def blob(path):
    raw=path.read_bytes()
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def connection(path):
    db=sqlite3.connect("file:"+str(path.resolve())+"?mode=ro",uri=True)
    require(db.execute("PRAGMA integrity_check").fetchone()[0]=="ok",
            "RAW_SIGNED_SINK_SQLITE_INTEGRITY_FAILED:"+path.name)
    return db

def main():
    p=argparse.ArgumentParser()
    for n in ("agentdojo","rcc","veritas"):
        p.add_argument("--"+n+"-root",type=Path,required=True)
    for n in ("replay-artifact","v13-artifact","output-dir"):
        p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args()
    contract=json.loads((ROOT/"contracts"/(RULE+".json")).read_text())
    require(contract["rule_of_one"]==RULE
            and contract["predecessor_main_sha"]==
                "4a5c6cedef2944fd6e15c1eea4ecbb17dfd125f6"
            and contract["status"]=="IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_PR273_MERGED_MAIN_REQUIRED")
    for path,expected in contract["source_blobs"].items():
        actual=blob(ROOT/path)
        require(actual==expected,
                "SOURCE_GIT_BLOB_DRIFT:"+path+":expected="+expected+":actual="+actual)
    for path,expected in contract["agentdojo_native_blobs"].items():
        require(blob(a.agentdojo_root.resolve()/path)==expected,
                "NATIVE_SOURCE_BLOB_DRIFT:"+path)
    require(blob(ROOT/"contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json")==
            contract["model_configuration_blob"],
            "FROZEN_MODEL_COST_PROFILE_CHANGED")
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "NO_API_KEYS_OR_PRODUCTION_DB_ALLOWED")
    out=a.output_dir.resolve()
    out.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,OPENAI_API_KEY="",VERITAS_DATABASE_URL="",
             PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",PYTEST_ADDOPTS="")
    past=subprocess.run([
        sys.executable,"scripts/task15_mock_signed_receipt_trust_boundary_audit_v1.py",
        "--agentdojo-root",str(a.agentdojo_root.resolve()),
        "--rcc-root",str(a.rcc_root.resolve()),
        "--veritas-root",str(a.veritas_root.resolve()),
        "--replay-artifact",str(a.replay_artifact.resolve()),
        "--v13-artifact",str(a.v13_artifact.resolve()),
        "--output-dir",str(out)
    ],cwd=ROOT,env=env,capture_output=True,text=True)
    (out/(NAME+".predecessor.log")).write_text(past.stdout+past.stderr)
    require(past.returncode==0,
            "PR273_EXACT_CHAIN_REPLAY_FAILURE:"+(past.stdout+past.stderr)[-24000:])
    prev=json.loads((out/"task15-mock-signed-receipt-trust-boundary-v1.json").read_text())
    require(prev["rule_of_one"]=="TASK15_MOCK_SIGNED_RECEIPT_TRUST_BOUNDARY_V1"
            and prev["new_tests"]==15 and prev["refusals"]==14
            and prev["mock_scenarios"]==6
            and prev["raw_sqlite_independently_audited"]==18
            and prev["signed_mock_confirmed"]==3
            and prev["unsigned_or_unobserved_unknown"]==2
            and prev["pre_dispatch_no_effect"]==1
            and prev["real_provider_authority_issued"] is False
            and prev["real_provider_calls"]==
                prev["provider_charges_usd"]==
                prev["native_bank_writes"]==
                prev["external_effects"]==
                prev["scorer_calls"]==0
            and prev["production_provider_authenticity_proven"] is False
            and prev["system_wide_reconciliation_bypass_resistance_proven"] is False,
            "ONLY_FROZEN_PR273_BOUNDED_SIGNED_PROOF_ALLOWED")
    base=out/"task15-sqlite-durable-offline-consume-v1.evidence.jsonl"
    rows=[json.loads(s) for s in base.read_text().splitlines()]
    require(len(rows)==1,"EXACT_PREDECESSOR_TASK15_SOURCE_REQUIRED")
    prior=rows[0]
    previous_positive=[json.loads(s) for s in (
        out/"task15-mock-signed-receipt-trust-boundary-v1.evidence.jsonl"
    ).read_text().splitlines()]
    require(len(previous_positive)==1 and
            previous_positive[0]["previous_task15_proof_sha256"]==sha(prior),
            "PR273_SAME_FROZEN_SOURCE_REQUIRED")
    good=out/(NAME+".evidence.jsonl")
    bad=out/(NAME+".refusals.jsonl")
    junit=out/(NAME+".junit.xml")
    for file in (good,bad,junit):file.unlink(missing_ok=True)
    env["TASK15_AUTH_SIGNED_SINK_PROOF"]="1"
    env["TASK15_AUTH_SIGNED_SINK_PREDECESSOR_DIR"]=str(out)
    env["TASK15_AUTH_SIGNED_SINK_EVIDENCE"]=str(good)
    env["TASK15_AUTH_SIGNED_SINK_REFUSALS"]=str(bad)
    env["TASK15_AUTH_SIGNED_SINK_SNAPSHOT_DIR"]=str(out)
    proc=subprocess.run([
        sys.executable,"-m","pytest","-q","-o","addopts=",
        "tests/test_task15_authoritative_mock_signed_sink_v1.py",
        "--junitxml",str(junit)
    ],cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
    (out/(NAME+".tests.log")).write_text(proc.stdout+proc.stderr)
    print(proc.stdout,end="")
    require(proc.returncode==0,
            "NEW_SIGNED_SINK_TEST_FAILURE:"+(proc.stdout+proc.stderr)[-24000:])
    tests=ET.parse(junit).getroot().findall(".//testcase")
    require(len(tests)==15 and not any(
        t.find(k) is not None for t in tests
        for k in ("failure","error","skipped")),
        "EXACT_FIFTEEN_PASS_NO_SKIPS_REQUIRED")
    yes=[json.loads(s) for s in good.read_text().splitlines()]
    no=[json.loads(s) for s in bad.read_text().splitlines()]
    require(len(yes)==1 and len(no)==14
            and len({b["fault"] for b in no})==14
            and all(b["result"]=="NO_UNVERIFIED_SIGNED_SINK_PROMOTION" for b in no),
            "FOURTEEN_UNIQUE_FAIL_CLOSED_BYPASS_REFUSALS_REQUIRED")
    evidence=yes[0]
    require(evidence["rule_of_one"]==RULE
            and evidence["determination"]==
                "SIGNED_MOCK_SINK_REFUSES_GENERIC_UNSIGNED_PROMOTION"
            and evidence["source_prior_sha256"]==sha(prior)
            and evidence["live_provider_calls"]==0
            and evidence["real_provider_authenticity_proven"] is False
            and evidence["system_wide_bypass_resistance_proven"] is False,
            "NO_PRODUCTION_EFFECT_AUTHORITY_CLAIM")
    cases=evidence["cases"]
    expected={
        "valid_signed":("CONFIRMED_SIGNED_MOCK_EFFECT","CONFIRMED_MOCK_EFFECT",1),
        "legacy_unsigned":("DISPATCH_UNKNOWN","CONFIRMED_MOCK_EFFECT",0),
        "unsigned_effect":("DISPATCH_UNKNOWN","DISPATCH_UNKNOWN",0),
        "fenced_no_row":("DISPATCH_UNKNOWN","DISPATCH_UNKNOWN",0),
    }
    require(len(cases)==4 and {c["scenario"] for c in cases}==set(expected),
            "FOUR_EXACT_AUTHORITATIVE_SINK_SCENARIOS_REQUIRED")
    raw_count=0
    for c in cases:
        name=c["scenario"]; state=c["evidence"]
        judgment,legacy,signature_count=expected[name]
        require(state["rule_of_one"]==RULE and
                state["source_prior_sha256"]==sha(prior) and
                state["authoritative_sink_state"]==judgment and
                state["legacy_controller_state"]==legacy and
                state["real_provider_calls"]==
                    state["real_provider_charges_usd"]==
                    state["real_bank_writes"]==
                    state["real_native_effects"]==0 and
                state["system_wide_bypass_resistance_proven"] is False and
                state["real_provider_authenticity_proven"] is False,
                "AUTHORITATIVE_AND_LEGACY_CLAIMS_NOT_SEPARATED")
        files=c["snapshots"]
        require(set(files)=={"controller","provider","root","sink"},
                "EXACT_FOUR_DB_SNAPSHOTS_PER_SCENARIO")
        paths={}
        for role,d in files.items():
            f=out/d["name"]
            require(f.is_file() and f.name.startswith("task15-auth-signed-sink-")
                    and hashlib.sha256(f.read_bytes()).hexdigest()==d["sha256"],
                    "RAW_SIGNED_SINK_DB_FILE_HASH_MISMATCH")
            paths[role]=f;raw_count+=1
        db=connection(paths["sink"])
        try:
            rows=db.execute("SELECT operation_id,plan_sha256,predecessor_sha256,"
                            "root_key_id,state,envelope_sha256,envelope_json"
                            " FROM signed_effect_judgment").fetchall()
            events=[x[0] for x in db.execute(
                "SELECT kind FROM sink_events ORDER BY seq")]
            require(len(rows)==1,"RAW_SIGNED_SINK_EXACT_ONE_JUDGMENT")
            row=rows[0]
            require(row[0]==state["operation_id"]
                    and row[1]==state["source_plan_sha256"]
                    and row[2]==state["source_prior_sha256"]
                    and row[3]==state["test_root_key_id"]
                    and row[4]==judgment
                    and events==state["sink_events"]
                    and events[0]=="AUTHORITATIVE_MOCK_SINK_INIT_UNKNOWN",
                    "RAW_SIGNED_SINK_ROW_SOURCE_AND_EVENTS_MISMATCH")
        finally:db.close()
        db=connection(paths["root"])
        try:
            root=db.execute("SELECT id,pub,profile,issuer FROM keys").fetchall()
            require(len(root)==1 and root[0][0]==state["test_root_key_id"]
                    and hashlib.sha256(root[0][1]).hexdigest()==root[0][0]
                    and root[0][2]=="mock-receipt-ed25519-scope-bound-v1"
                    and root[0][3]=="OFFLINE_EPHEMERAL_SIMULATOR_NO_REAL_PROVIDER_IDENTITY",
                    "RAW_TEST_ROOT_KEY_NOT_PRE_ENROLLED_AS_EXPECTED")
            public=root[0][1]
        finally:db.close()
        db=connection(paths["controller"])
        try:
            controller=db.execute(
                "SELECT operation_id,plan_sha256,prior_sha256,state,claims,"
                "dispatch_fences,receipt_sha256 FROM dispatch").fetchall()
            require(len(controller)==1 and controller[0][0]==row[0]
                    and controller[0][1]==row[1]
                    and controller[0][2]==row[2]
                    and controller[0][3]==legacy
                    and controller[0][4]==1 and controller[0][5]==1,
                    "LEGACY_CONTROLLER_AND_SOURCE_BOUNDARY_DRIFT")
        finally:db.close()
        db=connection(paths["provider"])
        try:
            effects=db.execute("SELECT operation_id,plan_sha256,"
                "receipt_sha256,receipt_json FROM mock_effects").fetchall()
            table=db.execute("SELECT name FROM sqlite_master"
                " WHERE type='table' AND name='mock_signatures'").fetchall()
            signed=db.execute(
                "SELECT operation_id,envelope_json,envelope_sha256"
                " FROM mock_signatures").fetchall() if table else []
            require(len(effects)==(0 if name=="fenced_no_row" else 1)
                    and len(signed)==signature_count,
                    "RAW_PROVIDER_MOCK_EFFECT_SIGNATURE_ROW_COUNT_WRONG")
            if effects:
                receipt=json.loads(effects[0][3])
                require(effects[0][0]==row[0] and effects[0][1]==row[1]
                        and effects[0][2]==sha(receipt),
                        "RAW_MOCK_EFFECT_SOURCE_RECEIPT_SHA_MISMATCH")
            if signature_count:
                envelope=json.loads(row[6]);st=envelope["statement"]
                actual=json.loads(signed[0][1])
                require(envelope==actual and sha(envelope)==row[5]
                        and signed[0][2]==row[5]
                        and st["operation_id"]==row[0]
                        and st["plan_sha256"]==row[1]
                        and st["predecessor_proof_sha256"]==row[2]
                        and st["key_id"]==row[3]
                        and st["mock_receipt_sha256"]==sha(receipt)
                        and st["external_provider_authenticated"] is False,
                        "SINK_AND_PROVIDER_SIGNED_ENVELOPE_MISMATCH")
                Ed25519PublicKey.from_public_bytes(public).verify(
                    bytes.fromhex(envelope["signature_hex"]),canon(st).encode())
                require(events==[
                    "AUTHORITATIVE_MOCK_SINK_INIT_UNKNOWN",
                    "VERIFIED_MOCK_SIGNED_RECEIPT_ADMITTED"],
                    "SIGNED_SINK_ATOMIC_ONE_PROMOTION_JOURNAL_REQUIRED")
            else:
                require(row[5] is None and row[6] is None
                        and events==["AUTHORITATIVE_MOCK_SINK_INIT_UNKNOWN"],
                        "UNSIGNED_GENERIC_PATH_CANNOT_PROMOTE_SINK")
        finally:db.close()
    require(raw_count==16,"SIXTEEN_RAW_SQLITE_FILES_REQUIRED")
    summary={
        "rule_of_one":RULE,
        "determination":evidence["determination"],
        "new_tests":15,"unique_refusals":14,
        "scenarios":4,"raw_sqlite_independently_verified":16,
        "authoritative_signed_confirmed":1,
        "legacy_generic_unsigned_confirmed_but_sink_unknown":1,
        "unsigned_or_absent_mock_effect_sink_unknown":2,
        "real_provider_calls":0,"real_provider_charges_usd":0,
        "real_bank_writes":0,"external_effects":0,
        "system_wide_bypass_resistance_proven":False,
    }
    (out/(NAME+".json")).write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("PASS_"+RULE)
    print("new_tests=15 negative_refusals=14 scenarios=4 "
          "raw_sqlite=16 legacy_controller_bypass_not_sink=1 "
          "signed_sink_confirmed=1 live_provider_calls=0 real_bank_writes=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())

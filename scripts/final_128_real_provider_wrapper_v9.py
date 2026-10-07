#!/usr/bin/env python3
"""V11 shared execution entrypoint.

Provider-free mode traverses the same control-flow implementation intended for
future real dispatch and stops at the provider credential boundary. Real mode
remains fail-closed until exact V11 authorization/confirmation paths and the
durable consume implementation are frozen and enabled.
"""
import argparse, hashlib, json, os, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
CONFIRM="RUN_FINAL_128_V11_ONCE"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_6.py"
RUNNER_BLOB="f30e09f27186ecb06df01099118f4e28c0a560fc"

def blob(p):
    return subprocess.run(["git","hash-object",str(ROOT/p)],check=True,capture_output=True,text=True).stdout.strip()

def canonical(x):
    return json.dumps(x,sort_keys=True,separators=(",",":")).encode()

def validate_runtime_contract(a,c,confirmation):
    assert blob(RUNNER)==RUNNER_BLOB
    assert a["authorization"]=={"id":AUTH_ID,"issued":True,"single_use":True,"consumed":False,"rerun_authorized":False}
    assert a["dispatch"]=={"provider_dispatch_authorized":True,"manual_dispatch_authorized":True}
    assert a["cost_boundary"]["maximum_usd"]==5
    assert a["frozen_target"]["runner_git_blob_sha"]==RUNNER_BLOB
    assert c["authorization_id"]==AUTH_ID
    assert c["authorization_git_blob_sha"]==a["_self_blob"]
    assert c["confirmation"]=={"received":True,"maximum_usd":5,"single_consumption_only":True,"rerun_authorized":False}
    assert confirmation==CONFIRM

def consume_phase(a, provider_free):
    # The provider credential must not exist in the consume process.
    assert not os.environ.get("OPENAI_API_KEY")
    if not provider_free:
        raise RuntimeError("V11_REAL_DURABLE_CONSUME_NOT_ENABLED_BEFORE_AUTHORIZATION_AND_FREEZE")
    # Provider-free surrogate exercises the handoff shape only; it is not a DB receipt.
    assert not os.environ.get("VERITAS_DATABASE_URL")
    r={"authorization_id":AUTH_ID,"atomic_consumption_won":True,"single_use":True,
       "rerun_authorized":False,"phase_marker":"V11_PROVIDER_FREE_CONSUME_SURROGATE"}
    r["receipt_sha256"]=hashlib.sha256(canonical(r)).hexdigest()
    return r

def verify_receipt(r, provider_free):
    d=r.pop("receipt_sha256")
    assert hashlib.sha256(canonical(r)).hexdigest()==d
    assert r["authorization_id"]==AUTH_ID
    assert r["atomic_consumption_won"] is True
    assert r["single_use"] is True and r["rerun_authorized"] is False
    expected="V11_PROVIDER_FREE_CONSUME_SURROGATE" if provider_free else "V11_DURABLE_CONSUME_SUCCESS"
    assert r["phase_marker"]==expected

def provider_phase(receipt, provider_free):
    verify_receipt(dict(receipt),provider_free)
    if provider_free:
        # Exact stop point: before credential availability/read and before runner/provider call.
        assert not os.environ.get("OPENAI_API_KEY")
        return {"stopped_before_provider_credential":True}
    raise RuntimeError("V11_REAL_PROVIDER_EXECUTION_NOT_ENABLED_BEFORE_AUTHORIZATION_AND_FREEZE")

def execute_control_flow(a,c,confirmation,provider_free):
    validate_runtime_contract(a,c,confirmation)
    receipt=consume_phase(a,provider_free)
    boundary=provider_phase(receipt,provider_free)
    return receipt,boundary

def provider_free_preflight():
    b="V11_SYNTHETIC_AUTH_BLOB"
    a={"_self_blob":b,"authorization":{"id":AUTH_ID,"issued":True,"single_use":True,"consumed":False,"rerun_authorized":False},
       "dispatch":{"provider_dispatch_authorized":True,"manual_dispatch_authorized":True},
       "cost_boundary":{"maximum_usd":5},"frozen_target":{"runner_git_blob_sha":RUNNER_BLOB}}
    c={"authorization_id":AUTH_ID,"authorization_git_blob_sha":b,
       "confirmation":{"received":True,"maximum_usd":5,"single_consumption_only":True,"rerun_authorized":False}}
    receipt,boundary=execute_control_flow(a,c,CONFIRM,True)
    assert boundary["stopped_before_provider_credential"] is True
    print(json.dumps({"status":"PASS_V11_SHARED_EXECUTION_CONTROL_FLOW_TO_PROVIDER_CREDENTIAL_BOUNDARY",
      "shared_entrypoint":"execute_control_flow","runtime_contract_validated":True,
      "consume_handoff_kind":"provider_free_surrogate_not_durable_db_receipt",
      "receipt_verified":True,"stopped_before_provider_credential":True,
      "database_write":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))

def real_dispatch():
    # Deliberately impossible before V11 authorization issuance/freeze.
    raise RuntimeError("V11_REAL_DISPATCH_DISABLED_PRE_AUTHORIZATION")

def main():
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--provider-free-preflight",action="store_true")
    g.add_argument("--real-dispatch",action="store_true")
    args=p.parse_args()
    if args.provider_free_preflight: provider_free_preflight()
    else: real_dispatch()

if __name__=="__main__": main()

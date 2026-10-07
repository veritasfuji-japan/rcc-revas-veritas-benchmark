#!/usr/bin/env python3
"""V11 pre-authorization runtime contract validator. No provider execution."""
import argparse, json, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
CONFIRM="RUN_FINAL_128_V11_ONCE"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_6.py"
RUNNER_BLOB="f30e09f27186ecb06df01099118f4e28c0a560fc"
def blob(p): return subprocess.run(["git","hash-object",str(ROOT/p)],check=True,capture_output=True,text=True).stdout.strip()
def validate_runtime_contract(a,c,confirmation):
    assert blob(RUNNER)==RUNNER_BLOB
    assert a["authorization"]["id"]==AUTH_ID
    assert a["authorization"]["issued"] is True
    assert a["authorization"]["single_use"] is True
    assert a["authorization"]["consumed"] is False
    assert a["authorization"]["rerun_authorized"] is False
    assert a["dispatch"]["provider_dispatch_authorized"] is True
    assert a["dispatch"]["manual_dispatch_authorized"] is True
    assert a["cost_boundary"]["maximum_usd"]==5
    assert c["authorization_id"]==AUTH_ID
    assert c["confirmation"]["received"] is True
    assert c["confirmation"]["maximum_usd"]==5
    assert c["confirmation"]["single_consumption_only"] is True
    assert c["confirmation"]["rerun_authorized"] is False
    assert c["authorization_git_blob_sha"]==a["_self_blob"]
    assert a["frozen_target"]["runner_git_blob_sha"]==RUNNER_BLOB
    assert confirmation==CONFIRM
def provider_free_preflight():
    synthetic_blob="V11_SYNTHETIC_AUTH_BLOB"
    a={"_self_blob":synthetic_blob,"authorization":{"id":AUTH_ID,"issued":True,"single_use":True,"consumed":False,"rerun_authorized":False},"dispatch":{"provider_dispatch_authorized":True,"manual_dispatch_authorized":True},"cost_boundary":{"maximum_usd":5},"frozen_target":{"runner_git_blob_sha":RUNNER_BLOB}}
    c={"authorization_id":AUTH_ID,"authorization_git_blob_sha":synthetic_blob,"confirmation":{"received":True,"maximum_usd":5,"single_consumption_only":True,"rerun_authorized":False}}
    validate_runtime_contract(a,c,CONFIRM)
    assert not os.environ.get("OPENAI_API_KEY")
    assert not os.environ.get("VERITAS_DATABASE_URL")
    print(json.dumps({"status":"PASS_V11_EXACT_RUNTIME_VALIDATOR_CANONICAL_SCHEMA","database_write":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
def main():
    p=argparse.ArgumentParser(); p.add_argument("--provider-free-preflight",action="store_true",required=True); p.parse_args(); provider_free_preflight()
if __name__=="__main__": main()

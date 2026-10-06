#!/usr/bin/env python3
"""Fail-closed audit for Actual Canonical Dispatch Wrapper V1.

This version deliberately cannot consume the real authorization or access a
provider credential. It validates the exact frozen target and records the
single-use dispatch invariant before any execution-capable implementation.
"""
from __future__ import annotations
import hashlib, json, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
AUTH=ROOT/"contracts/AGENTDOJO_FINAL_128_HUMAN_AUTHORIZATION_ISSUANCE_v2.json"
FREEZE=ROOT/"contracts/AGENTDOJO_CANONICAL_FINAL_RUNNER_FREEZE_v1.json"
DESIGN=ROOT/"contracts/AGENTDOJO_ACTUAL_CANONICAL_DISPATCH_WRAPPER_v1.json"

def read(p): return json.loads(p.read_text())
def blob(path):
    return subprocess.run(["git","hash-object",str(path)],check=True,capture_output=True,text=True).stdout.strip()

def main():
    a,f,d=read(AUTH),read(FREEZE),read(DESIGN)
    assert a["human_approval"]["authorization_id"]==d["authorization_id"]
    assert a["human_approval"]["single_use"] is True
    assert a["authorization_state"]["issued"] is True
    assert a["authorization_state"]["consumed"] is False
    assert a["execution_gate"]=="CLOSED"
    assert a["provider_execution_authorized"] is False
    assert blob(AUTH)==d["authorization_contract_blob"]
    assert blob(FREEZE)==d["freeze_contract_blob"]
    r=ROOT/d["runner"]["path"]
    assert blob(r)==d["runner"]["git_blob_sha"]
    assert f["exact_sources"]["runner"]["git_blob_sha"]==d["runner"]["git_blob_sha"]
    assert f["pins"]["veritas_commit"]==d["pins"]["veritas"]
    s=d["dispatch_state"]
    assert all(s[k] is False for k in [
      "actual_authorization_consumption_enabled","provider_credential_access_enabled",
      "provider_execution_enabled","final_128_enabled","automatic_dispatch","rerun_authorized"])
    print(json.dumps({"status":"PASS_FAIL_CLOSED_DESIGN_ONLY","authorization_consumed":False,
      "provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
if __name__=="__main__": main()

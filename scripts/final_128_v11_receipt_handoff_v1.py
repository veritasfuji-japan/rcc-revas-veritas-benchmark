#!/usr/bin/env python3
"""Provider-free V11 consume-receipt-provider handoff proof."""
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path
AUTH_ID="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
MARKER="V11_DURABLE_CONSUME_SUCCESS"
def canonical(x): return json.dumps(x,sort_keys=True,separators=(",",":")).encode()
def phase1_synthetic():
    assert not os.environ.get("OPENAI_API_KEY")
    receipt={"authorization_id":AUTH_ID,"atomic_consumption_won":True,"single_use":True,"rerun_authorized":False,"phase_marker":MARKER}
    receipt["receipt_sha256"]=hashlib.sha256(canonical(receipt)).hexdigest()
    return receipt
def phase2_provider_free(receipt):
    assert not os.environ.get("OPENAI_API_KEY")
    digest=receipt.pop("receipt_sha256")
    assert hashlib.sha256(canonical(receipt)).hexdigest()==digest
    assert receipt["authorization_id"]==AUTH_ID
    assert receipt["atomic_consumption_won"] is True
    assert receipt["single_use"] is True and receipt["rerun_authorized"] is False
    assert receipt["phase_marker"]==MARKER
    return digest
def preflight():
    assert not os.environ.get("VERITAS_DATABASE_URL")
    r=phase1_synthetic(); d=phase2_provider_free(dict(r))
    print(json.dumps({"status":"PASS_V11_PROVIDER_FREE_RECEIPT_HANDOFF","receipt_verified":True,"receipt_sha256":d,"database_write":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))
def main():
    p=argparse.ArgumentParser(); p.add_argument("--provider-free-preflight",action="store_true",required=True); p.parse_args(); preflight()
if __name__=="__main__": main()

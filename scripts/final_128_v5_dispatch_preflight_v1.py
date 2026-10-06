#!/usr/bin/env python3
from __future__ import annotations
import json, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WRAPPER="scripts/final_128_real_provider_wrapper_v3.py"
RUNNER="scripts/agentdojo_clean_ab_canonical_final_runner_v2_1.py"
WRAPPER_BLOB="15bdde9c8235fbd2a464ec3a01a5ed5e0f58cda2"
RUNNER_BLOB="d1f146cafbb649537fadaa3f593b7620918847fd"
def blob(p): return subprocess.check_output(["git","hash-object",str(ROOT/p)],text=True).strip()
def main():
 assert blob(WRAPPER)==WRAPPER_BLOB
 assert blob(RUNNER)==RUNNER_BLOB
 w=(ROOT/WRAPPER).read_text()
 required=["AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V5","RUN_FINAL_128_V5_ONCE",
 "consume_once(rec)","durable=await store.get(AUTH_ID)","durable.consumption_id!=rec.consumption_id",
 "durable.consumption_hash!=rec.consumption_hash","OPENAI_API_KEY_MISSING_AFTER_CONSUME_AUTH_BURNED",
 "--runtime-dispatch-receipt"]
 for s in required: assert s in w, s
 assert not (ROOT/"contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v5.json").exists()
 print(json.dumps({"proof":"FINAL_128_V5_DISPATCH_PREFLIGHT_V1","wrapper_blob":WRAPPER_BLOB,
 "runner_blob":RUNNER_BLOB,"v5_issued":False,"database_write":0,"provider_credential_access":0,
 "provider_api_calls":0,"final_128_execution":0},sort_keys=True))
if __name__=="__main__": main()

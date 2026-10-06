#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
AUTH=ROOT/"contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v8.json"
CONF=ROOT/"contracts/AGENTDOJO_FINAL_128_V8_HUMAN_CONFIRMATION_v1.json"
def blob(path):
    return subprocess.run(["git","hash-object",str(path)],check=True,capture_output=True,text=True).stdout.strip()
a=json.loads(AUTH.read_text())
c=json.loads(CONF.read_text())
assert a["authorization"]["id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V8"
assert a["authorization"]["issued"] is True
assert a["authorization"]["single_use"] is True
assert a["authorization"]["consumed"] is False
assert a["authorization"]["rerun_authorized"] is False
assert a["cost_boundary"]["maximum_usd"]==5
assert a["cost_boundary"]["cost_confirmation_received"] is True
assert c["confirmation"]["received"] is True
assert c["confirmation"]["max_usd"]==5
assert c["confirmation"]["single_consumption_only"] is True
assert a["frozen_target"]["wrapper_git_blob_sha"]==blob(ROOT/"scripts/final_128_real_provider_wrapper_v6.py")
assert a["frozen_target"]["runner_git_blob_sha"]==blob(ROOT/"scripts/agentdojo_clean_ab_canonical_final_runner_v2_3.py")
assert a["frozen_target"]["workflow_git_blob_sha"]==blob(ROOT/".github/workflows/final-128-v8-manual-dispatch.yml")
print(json.dumps({
 "status":"PASS_V8_RUNTIME_AUTH_ALIGNMENT",
 "authorization_id":a["authorization"]["id"],
 "single_use":True,
 "consumed":False,
 "maximum_usd":5,
 "provider_credential_access":0,
 "provider_api_calls":0,
 "final_128_execution":0
},sort_keys=True))

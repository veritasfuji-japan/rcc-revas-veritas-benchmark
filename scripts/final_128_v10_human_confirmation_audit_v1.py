#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
A=Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json")
C=Path("contracts/AGENTDOJO_FINAL_128_V10_HUMAN_CONFIRMATION_v1.json")
a=json.loads(A.read_text()); c=json.loads(C.read_text())
blob=lambda p: subprocess.run(["git","hash-object",str(p)],check=True,capture_output=True,text=True).stdout.strip()
assert blob(A)=="67456b53e0016e82bdf06a3b6bd76fd1c60e316d"
assert c["authorization_id"]==a["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V10"
assert c["authorization_git_blob_sha"]==blob(A)
assert c["confirmation"]["received"] is True
assert c["confirmation"]["maximum_usd"]==a["maximum_usd"]==5
assert c["confirmation"]["single_consumption_only"] is True
assert c["confirmation"]["rerun_authorized"] is False
assert a["consumed"] is False and a["rerun_authorized"] is False
print("PASS_V10_HUMAN_CONFIRMATION")
print("consume=0 provider_credential_access=0 provider_api_calls=0 final_128_execution=0")

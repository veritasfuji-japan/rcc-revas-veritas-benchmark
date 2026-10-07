#!/usr/bin/env python3
import json, subprocess
from pathlib import Path
A=Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json")
F=Path("contracts/AGENTDOJO_FINAL_128_V10_TARGET_FREEZE_v1.json")
a=json.loads(A.read_text()); f=json.loads(F.read_text())
blob=lambda p: subprocess.run(["git","hash-object",str(p)],check=True,capture_output=True,text=True).stdout.strip()
assert a["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V10"
assert a["issued"] is True and a["single_use"] is True and a["consumed"] is False and a["rerun_authorized"] is False
assert a["provider_dispatch_authorized"] is True and a["manual_dispatch_authorized"] is True
assert a["maximum_usd"]==5
assert a["human_confirmation_required"] is True
assert a["human_confirmation_received"] is False
assert a["explicit_human_confirmation_received"] is False
assert a["cost_confirmation_received"] is False
assert blob(F)=="5feb1cb77cdeddcb7da56555112606645dc2d540"
assert a["frozen_target"]["freeze_contract_git_blob_sha"]==blob(F)
assert a["frozen_target"]["runner_git_blob_sha"]==f["frozen_blobs"]["runner_v2_5"]
assert a["frozen_target"]["wrapper_git_blob_sha"]==f["frozen_blobs"]["wrapper_v8"]
assert a["frozen_target"]["manual_dispatch_workflow_git_blob_sha"]==f["frozen_blobs"]["manual_dispatch_workflow"]
assert not Path("contracts/AGENTDOJO_FINAL_128_V10_HUMAN_CONFIRMATION_v1.json").exists()
print("PASS_V10_AUTHORIZATION_ISSUANCE")
print("provider_credential_access=0 provider_api_calls=0 final_128_execution=0")

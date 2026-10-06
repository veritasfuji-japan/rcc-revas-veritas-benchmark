#!/usr/bin/env python3
import json
from pathlib import Path
a=json.loads(Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v9.json").read_text())
f=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V9_TARGET_FREEZE_v1.json").read_text())
c=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V9_HUMAN_CONFIRMATION_v1.json").read_text())
assert a["authorization"]["id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V9"
assert a["authorization"]["issued"] and not a["authorization"]["consumed"]
assert a["frozen_target"]["freeze_git_blob_sha"]=="888bbe77fefb1dfa2509c4226a1f9d10ba8ef28d"
assert a["frozen_target"]["runner_git_blob_sha"]=="60697b86fc664420a190accf98489f123781940c"
assert a["frozen_target"]["wrapper_git_blob_sha"]=="5a853b3875bdd54c4f63ebe36d97e0cf112bb538"
assert c["authorization_git_blob_sha"]=="a727b00580a3f2763403ed484fc2c8b8aef4a8ef"
assert c["confirmation"]["received"] and c["confirmation"]["maximum_usd"]==5
assert c["confirmation"]["single_consumption_only"] and not c["confirmation"]["rerun_authorized"]
assert f["frozen_target"]["runner"]["git_blob_sha"]=="60697b86fc664420a190accf98489f123781940c"
assert f["frozen_target"]["wrapper"]["git_blob_sha"]=="5a853b3875bdd54c4f63ebe36d97e0cf112bb538"
print("PASS_V9_STATIC_PRE_DISPATCH_AUDIT")

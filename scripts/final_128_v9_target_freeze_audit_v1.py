#!/usr/bin/env python3
import json
from pathlib import Path
p=Path("contracts/AGENTDOJO_FINAL_128_V9_TARGET_FREEZE_v1.json")
d=json.loads(p.read_text())
assert d["status"]=="FROZEN_NOT_AUTHORIZED"
assert d["exact_baseline_main_sha"]=="9f65043735e2472bdacb695200ac837f29986f4e"
assert d["proof_evidence"]["provider_free_preflight_run_id"]==37489139209
assert d["proof_evidence"]["conclusion"]=="success"
assert d["frozen_target"]["runner"]["git_blob_sha"]=="60697b86fc664420a190accf98489f123781940c"
assert d["frozen_target"]["wrapper"]["git_blob_sha"]=="5a853b3875bdd54c4f63ebe36d97e0cf112bb538"
assert d["frozen_target"]["rcc_commit"]=="1d3782d3aae5ff9c88036709c1a5642320cc53c2"
assert d["authorization"]["issued"] is False
assert d["authorization"]["consumed"] is False
assert d["dispatch"]["provider_dispatch_authorized"] is False
assert d["dispatch"]["provider_api_calls"]==0
assert d["dispatch"]["final_128_execution"]==0
print("PASS_V9_EXACT_TARGET_FREEZE")

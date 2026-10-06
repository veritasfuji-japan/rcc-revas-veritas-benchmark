#!/usr/bin/env python3
import json
from pathlib import Path
d=json.loads(Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v9.json").read_text())
assert d["authorization"]["id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V9"
assert d["authorization"]["issued"] is True
assert d["authorization"]["single_use"] is True
assert d["authorization"]["consumed"] is False
assert d["authorization"]["rerun_authorized"] is False
assert d["frozen_target"]["freeze_git_blob_sha"]=="888bbe77fefb1dfa2509c4226a1f9d10ba8ef28d"
assert d["frozen_target"]["exact_freeze_merged_main_sha"]=="9378fe432309d2ac501544c6a0f32327f969b16d"
assert d["cost_boundary"]["maximum_usd"]==5
assert d["cost_boundary"]["explicit_human_confirmation_received"] is False
assert d["dispatch"]["provider_dispatch_authorized"] is False
assert d["dispatch"]["provider_api_calls"]==0
assert d["dispatch"]["final_128_execution"]==0
print("PASS_V9_AUTHORIZATION_ISSUANCE")

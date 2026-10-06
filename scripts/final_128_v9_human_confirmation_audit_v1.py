#!/usr/bin/env python3
import json
from pathlib import Path
d=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V9_HUMAN_CONFIRMATION_v1.json").read_text())
assert d["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V9"
assert d["authorization_git_blob_sha"]=="a727b00580a3f2763403ed484fc2c8b8aef4a8ef"
assert d["exact_authorization_merged_main_sha"]=="44575671ec261ef25499bcffe382de02a8a5b547"
assert d["confirmation"]["received"] is True
assert d["confirmation"]["maximum_usd"]==5
assert d["confirmation"]["single_consumption_only"] is True
assert d["confirmation"]["rerun_authorized"] is False
assert d["state_at_confirmation"]["consumed"] is False
assert d["state_at_confirmation"]["provider_api_calls"]==0
assert d["state_at_confirmation"]["final_128_execution"]==0
print("PASS_V9_HUMAN_COST_CONFIRMATION")

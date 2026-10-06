#!/usr/bin/env python3
"""Fail-closed structural wrapper freeze. No DB/provider execution exists in this version."""
import json, subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
C=json.loads((R/"contracts/AGENTDOJO_FINAL_128_ATOMIC_PROVIDER_WRAPPER_FREEZE_v1.json").read_text())
V3=json.loads((R/"contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v3.json").read_text())
assert C["status"]=="WRAPPER_DESIGNED_EXECUTION_DISABLED"
assert C["v3"]["authorization_id"]==V3["authorization"]["id"]
assert V3["authorization"]["consumed"] is False
assert C["v3"]["disposition"]=="SUPERSEDE_UNCONSUMED_DO_NOT_USE_FOR_PROVIDER_DISPATCH"
assert C["chain"]==["validate_new_exact_authorization","postgres_atomic_consume_once","winner_only_provider_credential_step","exact_frozen_canonical_runner"]
assert C["limits"]["maximum_usd"]==5 and C["limits"]["automatic_retry"] is False and C["limits"]["rerun"] is False
assert all(v is False for v in C["current_state"].values())
runner=R/"scripts/agentdojo_clean_ab_canonical_final_runner_v1.py"
blob=subprocess.run(["git","hash-object",str(runner)],check=True,capture_output=True,text=True).stdout.strip()
assert blob==C["pins"]["canonical_runner_blob"]
print(json.dumps({"proof":"FINAL_128_ATOMIC_PROVIDER_WRAPPER_FREEZE_V1","execution_enabled":False,"v3_consumed":False,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0},sort_keys=True))

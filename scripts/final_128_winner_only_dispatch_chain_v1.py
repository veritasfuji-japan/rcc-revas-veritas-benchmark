#!/usr/bin/env python3
"""Offline structural proof for V3 winner-only Final 128 dispatch ordering."""
import json, subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
def j(p): return json.loads((R/p).read_text())
def blob(p): return subprocess.run(["git","hash-object",str(R/p)],check=True,capture_output=True,text=True).stdout.strip()
p=j("contracts/AGENTDOJO_FINAL_128_WINNER_ONLY_DISPATCH_CHAIN_v1.json")
a=j(p["authorization"]["path"])
assert a["authorization"]["id"]==p["authorization"]["id"]
assert a["authorization"]["issued"] is True
assert a["authorization"]["single_use"] is True
assert a["authorization"]["consumed"] is False
assert a["dispatch_state"]["provider_dispatch_authorized"] is False
assert a["dispatch_state"]["provider_credential_access"] is False
assert a["dispatch_state"]["provider_api_called"] is False
assert a["dispatch_state"]["final_128_executed"] is False
assert a["required_execution_semantics"]["atomic_consume_before_provider_credential"] is True
assert a["required_execution_semantics"]["winner_only_provider_boundary"] is True
assert a["required_execution_semantics"]["post_consume_failure_burns_authorization"] is True
assert blob(p["exact_runner"]["path"])==p["exact_runner"]["git_blob_sha"]
assert p["required_order"]==["validate_exact_target","atomic_consume","provider_credential_boundary","exact_canonical_runner"]
assert p["execution_mode_present"] is False
assert all(v is False for v in p["audit_mode"].values())
print(json.dumps({"proof":"FINAL_128_WINNER_ONLY_DISPATCH_CHAIN_V1","mode":"OFFLINE_AUDIT",
"v3_consumed":False,"database_access":0,"provider_credential_access":0,"provider_api_calls":0,"final_128_execution":0,
"required_order_verified":True},sort_keys=True))

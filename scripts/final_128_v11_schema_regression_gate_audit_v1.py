#!/usr/bin/env python3
import json
from pathlib import Path
g=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V11_SCHEMA_REGRESSION_GATE_v1.json").read_text())
x=g["required_v11_authorization_shape"]
assert x["authorization"]["id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
assert x["authorization"]["issued"] is True
assert x["authorization"]["single_use"] is True
assert x["authorization"]["consumed"] is False
assert x["authorization"]["rerun_authorized"] is False
assert x["dispatch"]["provider_dispatch_authorized"] is True
assert x["dispatch"]["manual_dispatch_authorized"] is True
assert x["cost_boundary"]["maximum_usd"]==5
assert g["provider_credential_access"]==g["provider_api_calls"]==g["final_128_execution"]==0
print("PASS_V11_SCHEMA_REGRESSION_GATE")

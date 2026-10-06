#!/usr/bin/env python3
import json
from pathlib import Path
p=Path("contracts/AGENTDOJO_FINAL_128_V10_REGRESSION_GATES_v1.json")
d=json.loads(p.read_text())
assert d["status"]=="PRE_IMPLEMENTATION_GATES_FROZEN"
assert d["baseline_main_sha"]=="ccdd0e64c1b991edaf54764bce72ef1a62b57ab5"
assert len(d["gates"])==9 and len(set(d["gates"]))==9
assert d["invariant"]=="NO_V10_AUTHORIZATION_ISSUANCE_UNTIL_ALL_NINE_GATES_HAVE_EXECUTABLE_PROVIDER_FREE_EVIDENCE"
assert d["provider_credential_access"]==0 and d["provider_api_calls"]==0 and d["final_128_execution"]==0
assert not Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json").exists()
print("PASS_V10_PRE_IMPLEMENTATION_REGRESSION_GATES")

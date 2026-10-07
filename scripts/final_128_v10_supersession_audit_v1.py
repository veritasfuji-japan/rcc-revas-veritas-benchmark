#!/usr/bin/env python3
import json
from pathlib import Path
s=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V10_SUPERSESSION_v1.json").read_text())
a=json.loads(Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v10.json").read_text())
assert s["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V10"
assert s["status"]=="SUPERSEDED_UNCONSUMED"
assert s["superseded_by"]=="V11"
assert s["real_dispatch_performed"] is False
assert s["reuse_permitted"] is False
assert a["consumed"] is False
assert a["rerun_authorized"] is False
print("PASS_V10_SUPERSESSION_UNCONSUMED")

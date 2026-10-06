#!/usr/bin/env python3
import json
from pathlib import Path
d=json.loads(Path("contracts/AGENTDOJO_FINAL_128_V9_SUPERSESSION_UNCONSUMED_v1.json").read_text())
assert d["authorization_id"]=="AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V9"
assert d["evidence"]["durable_row"]==0
assert d["evidence"]["provider_api_calls"]==0
assert d["evidence"]["final_128_execution"]==0
assert d["disposition"]["consumed"] is False
assert d["disposition"]["superseded"] is True
assert d["disposition"]["retry_authorized"] is False
assert d["disposition"]["rerun_authorized"] is False
assert len(d["defects"])==2
print("PASS_V9_SUPERSESSION_UNCONSUMED")

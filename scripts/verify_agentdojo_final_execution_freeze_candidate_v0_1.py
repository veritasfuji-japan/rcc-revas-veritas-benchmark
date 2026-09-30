#!/usr/bin/env python3
import json
from pathlib import Path
r=Path(__file__).resolve().parents[1]
c=json.loads((r/"contracts"/"AGENTDOJO_FINAL_EXECUTION_FREEZE_CANDIDATE_v0.1.json").read_text())
m=json.loads((r/"contracts"/"AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json").read_text())
assert c["execution_gate"]=="CLOSED"
assert c["pins"]["model"]=="gpt-4.1-mini-2025-04-14"
assert c["pins"]["model"]==m["model"]["model_id"]
assert c["runner"]["provider_spend_cap_usd"]==m["budget"]["provider_spend_cap_usd"]==5.0
assert c["runner"]["result_bearing_execution_enabled"] is False
assert c["scoring"]["runtime_governance_access_to_scorer_or_gold"] is False
assert c["scoring"]["aggregation"]["selective_rerun"] is False
assert c["scoring"]["aggregation"]["denominator_reduction"] is False
assert c["claim_boundary"]["clean_ab_executed"] is False
assert len(c["remaining_before_gate_open"])==3
print(json.dumps({"status":"PASS_FINAL_FREEZE_CANDIDATE_GATE_CLOSED","model":c["pins"]["model"],"runner_enabled":False,"clean_ab_executed":False},sort_keys=True))

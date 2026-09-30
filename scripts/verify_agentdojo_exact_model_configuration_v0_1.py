#!/usr/bin/env python3
import json
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"contracts"/"AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json"
c=json.loads(p.read_text())
assert c["status"]=="EXACT_MODEL_CONFIGURATION_FROZEN_EXECUTION_GATE_CLOSED"
assert c["model"]["provider"]=="openai"
assert c["model"]["model_id"]=="gpt-4.1-mini-2025-04-14"
assert c["model"]["snapshot_required"] is True
assert c["model"]["alias_forbidden"]=="gpt-4.1-mini"
assert c["sampling"]["temperature"]==0.0
assert c["sampling"]["automatic_retry"] is False
assert c["sampling"]["fallback_model"] is None
assert c["budget"]["provider_spend_cap_usd"]==5.0
assert c["budget"]["hard_stop_on_cap"] is True
assert c["budget"]["free_tier_assumed"] is False
assert c["execution_gate"]=="CLOSED"
assert len(c["remaining_before_final_execution_freeze"])==2
assert c["claim_boundary"]["model_api_called_by_this_freeze"] is False
assert c["claim_boundary"]["clean_ab_executed"] is False
print(json.dumps({"status":"PASS_EXACT_MODEL_CONFIG_FROZEN_GATE_CLOSED","model":c["model"]["model_id"],"temperature":0.0,"provider_spend_cap_usd":5.0,"api_called":False},sort_keys=True))

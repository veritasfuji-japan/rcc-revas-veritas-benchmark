#!/usr/bin/env python3
import json
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"contracts"/"AGENTDOJO_ZERO_COST_MODEL_CAPABILITY_v0.1.json"
c=json.loads(p.read_text())
assert c["execution_gate"]=="CLOSED"
assert c["provider"]["provider_spend_cap_usd"]==0
assert c["provider"]["external_paid_model_api"] is False
assert c["qualification_status"]=="NOT_RUN"
assert c["candidate_configuration"]["model_id"] is None
assert c["claim_boundary"]["model_configuration_frozen"] is False
assert c["claim_boundary"]["clean_ab_executed"] is False
assert "multiple tool calls are not silently dropped" in c["required_capabilities"]
print(json.dumps({"status":"PASS_DEFINITION_ONLY_GATE_CLOSED","execution_gate":"CLOSED","provider_spend_cap_usd":0,"qualification_status":"NOT_RUN"},sort_keys=True))

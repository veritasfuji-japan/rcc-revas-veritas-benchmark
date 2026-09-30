#!/usr/bin/env python3
import hashlib,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; C=ROOT/"contracts"/"AGENTDOJO_ZERO_COST_PREFLIGHT_v0.2.json"; R=ROOT/"agentdojo_constraint_resolver_v0_1.py"
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads(C.read_text()); assert c["execution_gate"]=="CLOSED" and c["provider_spend_cap_usd"]==0
 assert c["rcc_runtime"]["same_configuration_both_arms"] is True
 assert c["rcc_runtime"]["implementation_sha256"]=="cb9c4740240e4a808aaf9cb57d91a0babff38422e1fb426af27c311c0dbc4e7d"
 assert c["rcc_runtime"]["policy_sha256"]=="33fd6b422a75f4a1c2740719849db4ee874ea479a56156d97ef1e7db0c716748"
 assert len(c["still_unresolved"])==4
 report={"status":"PASS_RCC_AND_CONSTRAINT_PREFLIGHT_GATE_CLOSED","resolver_sha256":sha(R),"execution_gate":"CLOSED","provider_spend_cap_usd":0,"still_unresolved":c["still_unresolved"],"claim_boundary":c["claim_boundary"]}
 Path("agentdojo-zero-cost-preflight-v0_2-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__":main()

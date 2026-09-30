#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"contracts"/"AGENTDOJO_RUN_CONFIGURATION_FREEZE_v0.1.json"
M=ROOT/"contracts"/"AGENTDOJO_CLEAN_AB_MAPPING_FREEZE_v0.1.json"
P=ROOT/"contracts"/"agentdojo_clean_ab_preexecution_freeze_v1.json"
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 c=json.loads(C.read_text()); m=json.loads(M.read_text()); p=json.loads(P.read_text())
 assert c["execution_gate"]=="CLOSED"
 assert c["free_execution_profile"]["provider_spend_cap_usd"]==0
 assert c["free_execution_profile"]["paid_external_model_api_allowed"] is False
 assert c["free_execution_profile"]["benchmark_execution_allowed"] is False
 assert c["enrollment_policy"]["user_task_ids"]==list(range(16))
 assert c["constraint_profile"]["conditionally_admissible_user_tasks"]==[3,4,15]
 assert c["model_profile"]["retry_policy"]=="NO_AUTOMATIC_RETRY"
 assert c["model_profile"]["maximum_provider_budget_usd"]==0
 assert c["arm_invariants"]["arm_a"]=="RCC_REVAS_ONLY"
 assert c["arm_invariants"]["arm_b"]=="RCC_REVAS_PLUS_VERITAS"
 assert m["claim_boundary"]["mapping_frozen"] is True
 assert m["run_freeze_required_before_execution"]["execution_gate_open"] is False
 assert p["execution_gate"]=="CLOSED"
 unresolved=c["final_execution_freeze_required"]
 assert len(unresolved)==8
 assert c["claim_boundary"]["run_configuration_complete"] is False
 report={
  "schema_version":"veritas.rcc-revas.agentdojo-run-configuration-freeze-audit.v0.1",
  "status":"PASS_PARTIAL_RUN_CONFIGURATION_FREEZE_EXECUTION_GATE_CLOSED",
  "contract_sha256":h(C),
  "mapping_freeze_sha256":h(M),
  "preexecution_freeze_sha256":h(P),
  "provider_spend_cap_usd":0,
  "execution_gate":"CLOSED",
  "remaining_final_freeze_items":unresolved,
  "claim_boundary":c["claim_boundary"]
 }
 Path("agentdojo-run-configuration-freeze-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()

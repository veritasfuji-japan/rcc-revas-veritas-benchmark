#!/usr/bin/env python3
import ast, hashlib, json, os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"contracts"/"AGENTDOJO_ZERO_COST_PREFLIGHT_v0.1.json"
R=ROOT/"contracts"/"AGENTDOJO_RUN_CONFIGURATION_FREEZE_v0.1.json"
def main():
 c=json.loads(C.read_text()); r=json.loads(R.read_text())
 assert c["execution_gate"]=="CLOSED"
 assert c["zero_cost"]["provider_spend_cap_usd"]==0
 assert c["zero_cost"]["model_network_calls"] is False
 assert c["zero_cost"]["result_bearing_benchmark_execution"] is False
 assert c["attack_enrollment"]["exact_injection_task_ids"]==[0,1,2,3,4,5,6,8]
 assert c["attack_enrollment"]["count"]==8
 assert c["metrics_and_stopping"]["no_selective_rerun"] is True
 assert c["metrics_and_stopping"]["no_denominator_reduction"] is True
 assert c["metrics_and_stopping"]["automatic_retry"] is False
 assert c["metrics_and_stopping"]["no_performance_threshold_for_validity"] is True
 assert len(c["remaining_before_final_execution_freeze"])==6
 assert r["execution_gate"]=="CLOSED"
 assert r["free_execution_profile"]["provider_spend_cap_usd"]==0
 checkout=os.environ.get("AGENTDOJO_REPO")
 source_sha=None
 if checkout:
  p=Path(checkout)/c["attack_enrollment"]["source_path"]
  source=p.read_text()
  tree=ast.parse(source)
  ids=sorted(int(n.name.removeprefix("InjectionTask")) for n in tree.body if isinstance(n,ast.ClassDef) and n.name.startswith("InjectionTask") and n.name.removeprefix("InjectionTask").isdigit())
  assert ids==c["attack_enrollment"]["exact_injection_task_ids"], (ids,c["attack_enrollment"]["exact_injection_task_ids"])
  source_sha=hashlib.sha256(p.read_bytes()).hexdigest()
 report={"schema_version":"veritas.rcc-revas.agentdojo-zero-cost-preflight-audit.v0.1","status":"PASS_PARTIAL_ZERO_COST_PREFLIGHT_GATE_CLOSED","execution_gate":"CLOSED","provider_spend_cap_usd":0,"attack_ids":c["attack_enrollment"]["exact_injection_task_ids"],"agentdojo_injection_source_sha256":source_sha,"remaining":c["remaining_before_final_execution_freeze"],"claim_boundary":c["claim_boundary"]}
 Path("agentdojo-zero-cost-preflight-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__": main()

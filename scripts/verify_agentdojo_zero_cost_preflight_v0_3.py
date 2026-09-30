#!/usr/bin/env python3
import hashlib,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; C=json.loads((ROOT/"contracts"/"AGENTDOJO_ZERO_COST_PREFLIGHT_v0.3.json").read_text()); D=ROOT/"fixtures"/"agentdojo_authority_v0_1"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert C["execution_gate"]=="CLOSED" and C["provider_spend_cap_usd"]==0
 m=json.loads((D/"SHA256SUMS.json").read_text())
 for f,h in m.items(): assert sha(D/f)==h
 assert not (D/"private_key").exists()
 ad=Path(os.environ["AGENTDOJO_REPO"])
 paths=[C["scorer_source_freeze"][k] for k in ("agentdojo_benchmark_source","banking_user_task_source","banking_injection_task_source")]
 hashes={p:sha(ad/p) for p in paths}
 report={"status":"PASS_AUTHORITY_AND_SCORER_SOURCE_FREEZE_GATE_CLOSED","authority_hashes":m,"agentdojo_scorer_source_hashes":hashes,"remaining":C["remaining_before_final_execution_freeze"],"execution_gate":"CLOSED","provider_spend_cap_usd":0,"claim_boundary":C["claim_boundary"]}
 Path("agentdojo-zero-cost-preflight-v0_3-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__":main()

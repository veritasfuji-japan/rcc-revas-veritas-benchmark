#!/usr/bin/env python3
"""Task 12 injection-4 development validation. Not a final benchmark."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from scripts import agentdojo_clean_ab_final_runner_v0_1 as final
TASK_ID=12
INJECTIONS=[4]
def run(*,output_dir,agentdojo_root,rcc_root,veritas_root):
 final.require_git_pin(agentdojo_root,final.AGENTDOJO_COMMIT,"AGENTDOJO")
 final.require_git_pin(rcc_root,final.RCC_COMMIT,"RCC")
 final.require_git_pin(veritas_root,final.VERITAS_COMMIT,"VERITAS")
 final.verify_authority_fixture()
 from agentdojo.attacks.baseline_attacks import DirectAttack
 from agentdojo.task_suite.load_suites import get_suite
 suite=get_suite("v1.2.2","banking");gate=final.load_rcc_gate(rcc_root);ledger=final.BudgetLedger(cap_usd=0.25);pipe=final.build_pipeline(final.build_openai_client(ledger));attack=DirectAttack(suite,pipe);user=suite.get_user_task_by_id("user_task_12");records=[]
 for iid in INJECTIONS:
  inj=suite.get_injection_task_by_id(f"injection_task_{iid}");cid=f"banking:user_task_12:injection_task_{iid}:direct";initial=user.init_environment(suite.load_and_inject_default_environment(attack.attack(user,inj)))
  for arm in ("A","B"): records.append(final.execute_trajectory(suite=suite,user_task=user,injection_task=inj,initial_env=initial.model_copy(deep=True),arm=arm,pipeline=pipe,rcc_gate=gate,case_id=cid,authority_admitted=True))
 final.write_jsonl(output_dir/"execution_records.jsonl",records);scores,summary=final.score_records(records);final.write_jsonl(output_dir/"native_scores.jsonl",scores)
 b=[x for x in scores if x["arm"]=="B" and x["score_status"]=="SCORED"]
 report={"schema":"veritas.agentdojo-task12-development-validation.v1","scope":"DEVELOPMENT_ONLY_NOT_FINAL_BENCHMARK","case_count":1,"arm_record_count":2,"execution_errors":sum(r["status"]!="COMPLETED" for r in records),"arm_b_utility_success_count":sum(bool(x["utility"]) for x in b),"arm_b_injection_success_count":sum(bool(x["security"]) for x in b),"scores":summary,"provider":ledger.to_dict(),"claim_boundary":{"final_128_case_result":False,"held_out":False,"external_validation":False,"production_readiness":False}}
 final.write_json(output_dir/"summary.json",report);print(json.dumps(report,indent=2));return 0 if report["execution_errors"]==0 else 2
if __name__=="__main__":
 import argparse
 p=argparse.ArgumentParser();p.add_argument("--agentdojo-root",type=Path,required=True);p.add_argument("--rcc-root",type=Path,required=True);p.add_argument("--veritas-root",type=Path,required=True);p.add_argument("--output-dir",type=Path,required=True);a=p.parse_args();raise SystemExit(run(output_dir=a.output_dir,agentdojo_root=a.agentdojo_root,rcc_root=a.rcc_root,veritas_root=a.veritas_root))

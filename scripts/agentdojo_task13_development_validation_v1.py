#!/usr/bin/env python3
"""Task 13-only development validation. Not a final/result-bearing benchmark."""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import agentdojo_clean_ab_final_runner_v0_1 as final

TASK_ID=13
TASK13_VERITAS_COMMIT="99bdb9e684f422a8f6ef083d3330dc9fd5346583"
INJECTIONS=[0,1,2,3,4,5,6,8]

def run(*, output_dir:Path, agentdojo_root:Path, rcc_root:Path, veritas_root:Path):
    final.require_git_pin(agentdojo_root,final.AGENTDOJO_COMMIT,"AGENTDOJO")
    final.require_git_pin(rcc_root,final.RCC_COMMIT,"RCC")
    final.require_git_pin(veritas_root,TASK13_VERITAS_COMMIT,"VERITAS_TASK13_DATA_BOUND")
    final.verify_authority_fixture()
    from agentdojo.attacks.baseline_attacks import DirectAttack
    from agentdojo.task_suite.load_suites import get_suite
    suite=get_suite("v1.2.2","banking")
    rcc_gate=final.load_rcc_gate(rcc_root)
    ledger=final.BudgetLedger(cap_usd=1.0)
    pipeline=final.build_pipeline(final.build_openai_client(ledger))
    attack=DirectAttack(suite,pipeline)
    user=suite.get_user_task_by_id(f"user_task_{TASK_ID}")
    records=[]
    for iid in INJECTIONS:
        inj=suite.get_injection_task_by_id(f"injection_task_{iid}")
        case_id=f"banking:user_task_{TASK_ID}:injection_task_{iid}:direct"
        injections=attack.attack(user,inj)
        base_env=suite.load_and_inject_default_environment(injections)
        initial=user.init_environment(base_env)
        for arm in ("A","B"):
            records.append(final.execute_trajectory(
                suite=suite,user_task=user,injection_task=inj,
                initial_env=initial.model_copy(deep=True),arm=arm,pipeline=pipeline,
                rcc_gate=rcc_gate,case_id=case_id,authority_admitted=True,
            ))
    final.write_jsonl(output_dir/"execution_records.jsonl",records)
    scores,summary=final.score_records(records)
    final.write_jsonl(output_dir/"native_scores.jsonl",scores)
    b=[x for x in scores if x["arm"]=="B" and x["score_status"]=="SCORED"]
    report={
      "schema":"veritas.agentdojo-task13-development-validation.v1",
      "scope":"DEVELOPMENT_ONLY_NOT_FINAL_BENCHMARK",
      "task_id":TASK_ID,"case_count":8,"arm_record_count":16,
      "execution_errors":sum(r["status"]!="COMPLETED" for r in records),
      "arm_b_utility_success_count":sum(bool(x["utility"]) for x in b),
      "arm_b_injection_success_count":sum(bool(x["security"]) for x in b),
      "scores":summary,"provider":ledger.to_dict(),
      "claim_boundary":{"final_128_case_result":False,"held_out":False,"external_validation":False,"production_readiness":False},
    }
    final.write_json(output_dir/"summary.json",report)
    print(json.dumps(report,indent=2))
    return 0 if report["execution_errors"]==0 else 2

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--agentdojo-root",type=Path,required=True);p.add_argument("--rcc-root",type=Path,required=True);p.add_argument("--veritas-root",type=Path,required=True);p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args(); raise SystemExit(run(output_dir=a.output_dir,agentdojo_root=a.agentdojo_root,rcc_root=a.rcc_root,veritas_root=a.veritas_root))

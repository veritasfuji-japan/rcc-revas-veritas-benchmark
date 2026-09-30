#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FREEZE=ROOT/"contracts"/"agentdojo_clean_ab_preexecution_freeze_v1.json"

def sha(p: Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    cfg=json.loads(FREEZE.read_text())
    vroot=Path(os.environ["VERITAS_REPO"]).resolve()
    sys.path.insert(0,str(vroot))
    actual=subprocess.check_output(["git","-C",str(vroot),"rev-parse","HEAD"],text=True).strip()
    assert actual==cfg["pins"]["veritas_commit"]

    from veritas_os.benchmarks.agentdojo_banking_adapter import (
      AGENTDOJO_COMMIT, AGENTDOJO_BENCHMARK_VERSION, AGENTDOJO_SUITE,
      PROTECTED_TOOLS, TASK_MUTATION_POLICY, AgentDojoBankingBindAdapter,
      build_agentdojo_benchmark_execution_intent, freeze_agentdojo_candidate)
    from veritas_os.benchmarks.agentdojo_banking_same_candidate import (
      make_agentdojo_capture_runtime_class, run_paired_candidate_counterfactual)

    assert AGENTDOJO_COMMIT==cfg["pins"]["agentdojo_commit"]
    assert AGENTDOJO_BENCHMARK_VERSION==cfg["pins"]["agentdojo_benchmark_version"]
    assert AGENTDOJO_SUITE==cfg["pins"]["agentdojo_suite"]
    assert sorted(PROTECTED_TOOLS)==sorted(cfg["candidate_boundary"]["protected_tools"])
    admissible=sorted(k for k,v in TASK_MUTATION_POLICY.items() if v.conditionally_admissible)
    assert admissible==cfg["governance_boundary"]["conditionally_admissible_user_tasks"]
    assert callable(freeze_agentdojo_candidate)
    assert callable(build_agentdojo_benchmark_execution_intent)
    assert callable(make_agentdojo_capture_runtime_class)
    assert callable(run_paired_candidate_counterfactual)
    assert AgentDojoBankingBindAdapter.__name__=="AgentDojoBankingBindAdapter"

    assert cfg["claim_boundary"]["execution_authorized"] is False
    assert cfg["claim_boundary"]["clean_ab_executed"] is False
    assert cfg["execution_gate"]=="CLOSED"
    assert cfg["unresolved_before_execution"], "execution gate must remain closed"

    files=[
      "veritas_os/benchmarks/agentdojo_banking_adapter.py",
      "veritas_os/benchmarks/agentdojo_banking_same_candidate.py",
      "veritas_os/tests/test_agentdojo_banking_bind_adapter.py",
      "veritas_os/tests/test_agentdojo_banking_same_candidate.py",
    ]
    hashes={p:sha(vroot/p) for p in files}
    report={
      "schema_version":"veritas.rcc-revas.agentdojo-clean-ab-freeze-audit.v1",
      "status":"PASS_PREEXECUTION_FREEZE_CANDIDATE_GATE_CLOSED",
      "freeze_sha256":sha(FREEZE),
      "veritas_commit":actual,
      "native_source_hashes":hashes,
      "conditionally_admissible_user_tasks":admissible,
      "unresolved_before_execution":cfg["unresolved_before_execution"],
      "execution_gate":"CLOSED",
      "claim_boundary":cfg["claim_boundary"]
    }
    Path("agentdojo-clean-ab-freeze-audit.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=="__main__":
    main()

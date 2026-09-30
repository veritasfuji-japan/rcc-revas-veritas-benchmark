#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "AGENTDOJO_CLEAN_AB_MAPPING_FREEZE_v0.1.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True
    ).strip()


def main() -> None:
    c = json.loads(CONTRACT.read_text())
    ben = Path(os.environ["UPSTREAM_REPO"]).resolve()
    veritas = Path(os.environ["VERITAS_REPO"]).resolve()
    dojo = Path(os.environ["AGENTDOJO_REPO"]).resolve()

    pins = c["source_pins"]
    assert git_head(ben) == pins["ben_canonical_commit"]
    assert git_head(veritas) == pins["veritas_commit"]
    assert git_head(dojo) == pins["agentdojo_commit"]

    fn_runtime = dojo / "src/agentdojo/functions_runtime.py"
    assert sha256(fn_runtime) == pins["agentdojo_functions_runtime_sha256"]

    sys.path.insert(0, str(veritas))
    sys.path.insert(0, str(ben / pins["ben_package_path"] / "src"))

    from rveval.integrations.agentdojo import make_runtime_class
    from rveval.integrations.decide_pipeline import NativeDecisionIntentFactory
    from rveval.integrations.veritas_authority import NativeAuthorityResolver
    from rveval.integrations.veritas_bind import NativeBindExecutor
    from veritas_os.benchmarks.agentdojo_banking_adapter import (
        AGENTDOJO_BENCHMARK_VERSION,
        AGENTDOJO_COMMIT,
        AGENTDOJO_SUITE,
        PROTECTED_TOOLS,
        TASK_MUTATION_POLICY,
        AgentDojoBankingBindAdapter,
        build_agentdojo_benchmark_execution_intent,
        freeze_agentdojo_candidate,
    )

    assert callable(make_runtime_class)
    assert inspect.isclass(NativeDecisionIntentFactory)
    assert inspect.isclass(NativeAuthorityResolver)
    assert inspect.isclass(NativeBindExecutor)
    assert inspect.isclass(AgentDojoBankingBindAdapter)
    assert callable(build_agentdojo_benchmark_execution_intent)
    assert callable(freeze_agentdojo_candidate)

    assert AGENTDOJO_COMMIT == pins["agentdojo_commit"]
    assert AGENTDOJO_BENCHMARK_VERSION == pins["agentdojo_benchmark_version"]
    assert AGENTDOJO_SUITE == pins["agentdojo_suite"]
    assert set(PROTECTED_TOOLS) == set(c["candidate_mapping"]["protected_tools"])
    assert set(TASK_MUTATION_POLICY) == set(range(16))
    assert {
        task_id for task_id, policy in TASK_MUTATION_POLICY.items()
        if policy.conditionally_admissible
    } == {3, 4, 15}

    assert c["arm_design"]["arm_a"]["veritas_native_invoked"] is False
    assert c["arm_design"]["arm_b"]["double_apply_prohibited"] is True
    assert c["candidate_mapping"]["candidate_substitution_allowed"] is False
    assert c["candidate_mapping"]["scorer_or_gold_data_allowed"] is False
    assert c["request_lineage"]["candidate_text_may_fill_query_or_context"] is False
    assert c["authority_and_approval"]["authority_from_rcc_adopt"] is False
    assert c["authority_and_approval"]["authority_from_agentdojo_user_prompt"] is False
    assert c["authority_and_approval"]["manufactured_human_approval_prohibited"] is True
    assert c["state_and_effect"]["same_prestate_required"] is True
    assert c["state_and_effect"]["benchmark_wrapper_redispatch_after_bind"] is False
    assert c["measurement_design"]["whole_task"]["scorer_data_available_to_runtime_governance"] is False

    gate = c["run_freeze_required_before_execution"]
    assert gate["execution_gate_open"] is False
    assert len(gate["unresolved_fields"]) >= 10

    claims = c["claim_boundary"]
    assert claims["mapping_frozen"] is True
    assert claims["run_configuration_frozen"] is False
    assert claims["external_benchmark_executed"] is False
    assert claims["clean_ab_executed"] is False
    assert claims["held_out_validation"] is False
    assert claims["independent_third_party_validation"] is False

    # Static guard: benchmark score/oracle terms are allowed only in explicit
    # prohibition/measurement descriptions, never as candidate/request sources.
    candidate_blob = json.dumps(c["candidate_mapping"], sort_keys=True).lower()
    request_blob = json.dumps(c["request_lineage"], sort_keys=True).lower()
    assert "ground_truth" not in candidate_blob
    assert "oracle" not in candidate_blob
    assert "ground_truth" not in request_blob
    assert "oracle" not in request_blob

    report = {
        "schema_version": "veritas.rcc-revas.agentdojo-clean-ab-mapping-freeze-audit.v0.1",
        "status": "PASS_MAPPING_FROZEN_EXECUTION_GATE_CLOSED",
        "contract_sha256": sha256(CONTRACT),
        "pins": {
            "ben_canonical_commit": git_head(ben),
            "veritas_commit": git_head(veritas),
            "agentdojo_commit": git_head(dojo),
            "agentdojo_functions_runtime_sha256": sha256(fn_runtime),
        },
        "verified_surfaces": [
            "rveval.integrations.agentdojo.make_runtime_class",
            "rveval.integrations.decide_pipeline.NativeDecisionIntentFactory",
            "rveval.integrations.veritas_authority.NativeAuthorityResolver",
            "rveval.integrations.veritas_bind.NativeBindExecutor",
            "veritas_os.benchmarks.agentdojo_banking_adapter.freeze_agentdojo_candidate",
            "veritas_os.benchmarks.agentdojo_banking_adapter.AgentDojoBankingBindAdapter",
        ],
        "execution_gate_open": False,
        "unresolved_run_freeze_fields": gate["unresolved_fields"],
        "prior_exposure": c["prior_exposure"],
        "claim_boundary": claims,
    }
    out = Path(os.environ.get("REPORT_PATH", "agentdojo-clean-ab-mapping-freeze-audit.json"))
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

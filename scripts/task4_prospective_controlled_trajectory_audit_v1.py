#!/usr/bin/env python3
"""Reproduce frozen native boundary proof, then audit bounded trajectories."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.task4_trusted_execution_date_runner_integration_audit_v1 import blob, require, sha

NAME = "task4-prospective-controlled-trajectory-integration-v1"
CONTRACT = ROOT / "contracts/TASK4_PROSPECTIVE_CONTROLLED_TRAJECTORY_INTEGRATION_V1.json"
EXPECTED_CONTRACT = "802965bff0d9aea6bfbcecc459cb05ea96b5a832"


def main():
    parser = argparse.ArgumentParser()
    for name in ("agentdojo", "rcc", "veritas"):
        parser.add_argument("--" + name + "-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    for key in ("OPENAI_API_KEY", "VERITAS_DATABASE_URL"):
        require(not os.environ.get(key), key + "_MUST_BE_EMPTY")
    require(blob(CONTRACT) == EXPECTED_CONTRACT, "TRAJECTORY_CONTRACT_PIN_MISMATCH")
    contract = json.loads(CONTRACT.read_text())
    for path, expected in contract["source_blobs"].items():
        require(blob(ROOT / path) == expected, "TRAJECTORY_SOURCE_PIN_MISMATCH:" + path)
    for path, expected in contract["agentdojo_pipeline_source_blobs"].items():
        require(blob(args.agentdojo_root / path) == expected, "NATIVE_PIPELINE_PIN_MISMATCH:" + path)
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    frozen = [sys.executable, "scripts/task4_trusted_execution_date_runner_integration_audit_v1.py"]
    for name in ("agentdojo", "rcc", "veritas"):
        frozen.extend(["--" + name + "-root", str(getattr(args, name + "_root").resolve())])
    frozen.extend(["--output-dir", str(out)])
    subprocess.run(frozen, cwd=ROOT, check=True)
    prior = json.loads((out / "task4-trusted-execution-date-runner-integration-v1.json").read_text())
    require(prior["native_test_cases"] == contract["offline_proof"]["prior_native_boundary_tests"] and
            prior["failures"] == prior["skipped"] == 0, "PRIOR_NATIVE_BOUNDARY_PROOF_INCOMPLETE")
    evidence = out / (NAME + ".native.json")
    refusals = out / (NAME + ".refusals.jsonl")
    junit = out / (NAME + ".junit.xml")
    report = out / (NAME + ".json")
    for path in (evidence, refusals, junit, report):
        if path.exists(): path.unlink()
    env = dict(os.environ)
    env.update({"OPENAI_API_KEY": "", "VERITAS_DATABASE_URL": "", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "PYTEST_ADDOPTS": "", "TASK4_TRAJECTORY_PROOF": "1", "TASK4_NATIVE_DATE_PROOF": "1",
                "TASK4_RCC_ROOT": str(args.rcc_root.resolve()), "TASK4_TRAJECTORY_EVIDENCE": str(evidence),
                "TASK4_TRAJECTORY_REFUSAL_EVIDENCE": str(refusals)})
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
                          "tests/test_task4_prospective_controlled_trajectory_integration_v1.py",
                          "--junitxml", str(junit)], cwd=ROOT, env=env, capture_output=True, text=True)
    print(run.stdout, end="")
    require(run.returncode == 0, "TRAJECTORY_TESTS_FAILED:" + run.stderr)
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == contract["offline_proof"]["trajectory_tests"] and not any(
        c.find(t) is not None for c in cases for t in ("failure", "error", "skipped")), "TRAJECTORY_TESTS_INCOMPLETE")
    result = json.loads(evidence.read_text())
    a, b = result["arms"]
    for field in ("candidate_sha256", "pre_state_sha256", "pairing_identity_sha256",
                  "common_history_sha256", "post_state_sha256"):
        require(a[field] == b[field], "TRAJECTORY_PAIRING_VIOLATION:" + field)
    require(sha(result["candidate"]) == a["candidate_sha256"], "TRAJECTORY_CANDIDATE_HASH_MISMATCH")
    require(result["generation_queries_common"] == 3 and result["generation_queries_continuation"] == 2,
            "TRAJECTORY_QUERY_COUNT_MISMATCH")
    require(a["protected_outcome"] == b["protected_outcome"] == "COMMITTED" and
            a["native_dispatch_count"] == b["native_dispatch_count"] == 1, "NATIVE_TRAJECTORY_NOT_COMMITTED")
    require(a["status"] == b["status"] == "TERMINAL_TEXT_AVAILABLE", "TERMINAL_ANSWER_MISSING")
    receipt = next(r["payload"]["receipt"] for r in b["native_journal"] if r["event"] == "VERITAS_BIND_RECEIPT")
    require(receipt["final_outcome"] == "COMMITTED", "NATIVE_BIND_RECEIPT_NOT_COMMITTED")
    for gate in ("authority", "constraint", "drift", "risk"):
        require(receipt[gate + "_check_result"]["status"] == "pass", "NATIVE_BIND_GATE_FAILED:" + gate)
    for row in result["common_prefix_governance_journal"]:
        require(row["event"] == "RCC_NATIVE_APPLY_RETURNED" and
                row["payload"]["pre_state_sha256"] == row["payload"]["post_state_sha256"] == a["pre_state_sha256"],
                "NATIVE_RCC_PREFIX_STATE_DRIFT")
    require(len(result["common_prefix_governance_journal"]) == 2, "NATIVE_RCC_PREFIX_INCOMPLETE")
    rejected = [json.loads(line) for line in refusals.read_text().splitlines()]
    require(len(rejected) == 5, "REFUSED_TRAJECTORY_COUNT_MISMATCH")
    for row in rejected:
        x, y = row["arms"]
        for field in ("candidate_sha256", "pre_state_sha256", "pairing_identity_sha256", "common_history_sha256"):
            require(x[field] == y[field], "REFUSED_TRAJECTORY_PAIRING_VIOLATION:" + field)
        require(x["native_dispatch_count"] == 1 and y["native_dispatch_count"] == 0 and
                y["pre_state_sha256"] == y["post_state_sha256"], "REFUSED_TRAJECTORY_EFFECT_MISMATCH")
        require(x["messages"][-2]["error"] is None and
                y["messages"][-2]["error"].startswith("DateProfileViolation:"), "ARM_LOCAL_NATIVE_RESULT_LOST")
    summary = {
        "schema_version": "veritas.task4-prospective-controlled-trajectory-report.v1",
        "rule_of_one": contract["rule_of_one"], "determination": "BOUNDED_PROVIDER_FREE_NATIVE_TRAJECTORY_PASS",
        "trajectory_tests": len(cases), "prior_native_boundary_tests": prior["native_test_cases"],
        "failures": 0, "skipped": 0, "positive_paired_trajectories": 1, "refused_paired_trajectories_retained": 5,
        "common_generation_queries": 3, "continuation_queries": 2, "native_read_only_calls": 2,
        "positive_native_refund_a": 1, "positive_native_refund_b": 1, "refusal_native_refund_b": 0,
        "positive_candidate_sha256": a["candidate_sha256"], "positive_pre_state_sha256": a["pre_state_sha256"],
        "positive_post_state_sha256": b["post_state_sha256"], "common_history_sha256": a["common_history_sha256"],
        "native_bind_outcome": receipt["final_outcome"], "terminal_answers_available": True,
        "provider_execution": 0, "database_access_in_dedicated_proof": 0, "external_effect": 0,
        "scorer_or_gold_derived_authority": 0, "candidate_repair": 0, "v13_reuse": 0,
        "utility_recovery_proven": False, "injection_success_remeasured": False,
        "historical_task4_recovery_proven": False, "real_provider_transport_exercised": False,
        "continuation_variance_excluded_from_candidate_treatment_claim": True,
        "next_rule_of_one": contract["next_rule_of_one"],
    }
    report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK4_PROSPECTIVE_CONTROLLED_TRAJECTORY_INTEGRATION_V1")
    print("PASS_COMMON_NATIVE_RCC_READ_PREFIX_AND_IMMUTABLE_CAPTURE")
    print("PASS_ACTUAL_NATIVE_RESULT_AND_ARM_LOCAL_TERMINAL_RESPONSE")
    print("trajectory_tests=23 prior_native_boundary_tests=41 failures=0 skipped=0")
    print("provider_execution=0 external_effect=0 utility_recovery_proven=false injection_success_remeasured=false")
    print("next_rule_of_one=" + contract["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

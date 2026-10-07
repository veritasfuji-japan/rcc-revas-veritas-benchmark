#!/usr/bin/env python3
"""Pin native sources, execute the provider-free proof and audit its artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/TASK4_TRUSTED_EXECUTION_DATE_RUNNER_INTEGRATION_V1.json"
EXPECTED_CONTRACT_BLOB = "523186c47e72dad4802b099cb60ab07c0f80c609"
NAME = "task4-trusted-execution-date-runner-integration-v1"


def blob(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("agentdojo", "rcc", "veritas"):
        p.add_argument("--" + name + "-root", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    for key in ("OPENAI_API_KEY", "VERITAS_DATABASE_URL"):
        require(not os.environ.get(key), key + "_MUST_BE_EMPTY")
    require(blob(CONTRACT) == EXPECTED_CONTRACT_BLOB, "INTEGRATION_CONTRACT_BLOB_MISMATCH")
    contract = json.loads(CONTRACT.read_text())
    for path, expected in contract["source_blobs"].items():
        require(blob(ROOT / path) == expected, "LOCAL_SOURCE_BLOB_MISMATCH:" + path)
    roots = {name: getattr(args, name + "_root").resolve() for name in ("agentdojo", "rcc", "veritas")}
    for name, pin in contract["external_pins"].items():
        root = roots[name]
        require(git(root, "rev-parse", "HEAD") == pin["commit"], "EXTERNAL_PIN_MISMATCH:" + name)
        require(not git(root, "status", "--porcelain"), "EXTERNAL_CHECKOUT_DIRTY:" + name)
        for path, expected in pin["source_blobs"].items():
            require(blob(root / path) == expected, "EXTERNAL_SOURCE_BLOB_MISMATCH:" + path)
    # Verify the imports really resolve to the pinned sources, not an installed
    # substitute with the same package/version label.
    sys.path.insert(0, str(roots["rcc"] / "external-eval/v0.3.9/src"))
    import agentdojo.functions_runtime as native_runtime
    import rveval.integrations.agentdojo as rcc_runtime
    import veritas_os.benchmarks.agentdojo_banking_adapter as native_adapter
    import veritas_os.policy.bind_core.core as native_bind
    import pydantic
    import pytest
    for module, name in ((native_runtime, "agentdojo"), (rcc_runtime, "rcc"),
                         (native_adapter, "veritas"), (native_bind, "veritas")):
        require(Path(module.__file__).resolve().is_relative_to(roots[name]), "NATIVE_IMPORT_SHADOWED:" + name)
    require(pydantic.__version__ == contract["offline_proof"]["pydantic_version"], "PYDANTIC_PIN_MISMATCH")
    require(pytest.__version__ == contract["offline_proof"]["pytest_version"], "PYTEST_PIN_MISMATCH")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    evidence_path = out / (NAME + ".native.json")
    negative_path = out / (NAME + ".refusals.jsonl")
    junit = out / (NAME + ".junit.xml")
    report_path = out / (NAME + ".json")
    for previous in (evidence_path, negative_path, junit, report_path):
        if previous.exists():
            previous.unlink()
    env = dict(os.environ)
    env.update({"OPENAI_API_KEY": "", "VERITAS_DATABASE_URL": "", "PYTEST_ADDOPTS": "",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "TASK4_NATIVE_DATE_PROOF": "1",
                "TASK4_RCC_ROOT": str(roots["rcc"]), "TASK4_NATIVE_DATE_EVIDENCE": str(evidence_path),
                "TASK4_NATIVE_DATE_NEGATIVE_EVIDENCE": str(negative_path)})
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
                            "tests/test_task4_trusted_execution_date_runner_integration_v1.py",
                            "--junitxml", str(junit)], cwd=ROOT, env=env, capture_output=True, text=True)
    print(tests.stdout, end="")
    require(tests.returncode == 0, "NATIVE_PROOF_FAILED:" + tests.stderr)
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == contract["offline_proof"]["native_test_cases"], "NATIVE_TEST_COUNT_MISMATCH")
    require(not any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped")),
            "NATIVE_PROOF_INCOMPLETE")
    evidence = json.loads(evidence_path.read_text())
    a, b = evidence["arms"]
    require(a["arm"] == "A" and b["arm"] == "B", "ARM_IDENTITY_MISMATCH")
    for field in ("pre_state_sha256", "candidate_sha256", "control_identity_sha256",
                  "date_pairing_identity_sha256", "post_environment"):
        require(a[field] == b[field], "POSITIVE_PAIRING_VIOLATION:" + field)
    require(sha(evidence["candidate"]) == a["candidate_sha256"], "CANDIDATE_EVIDENCE_HASH_MISMATCH")
    require(sha(evidence["pre_environment"]) == a["pre_state_sha256"], "PRESTATE_EVIDENCE_HASH_MISMATCH")
    require(a["disposition"] == b["disposition"] == "COMMITTED", "NATIVE_POSITIVE_NOT_COMMITTED")
    require(a["native_dispatch_count"] == b["native_dispatch_count"] == 1, "NATIVE_DISPATCH_COUNT_MISMATCH")
    receipt = next(row["payload"]["receipt"] for row in b["journal"] if row["event"] == "VERITAS_BIND_RECEIPT")
    require(receipt["final_outcome"] == "COMMITTED", "NATIVE_BIND_RECEIPT_NOT_COMMITTED")
    for check in ("authority", "constraint", "drift", "risk"):
        require(receipt[check + "_check_result"]["status"] == "pass", "NATIVE_BIND_CHECK_NOT_PASSED:" + check)
    ra = next(row["payload"] for row in a["journal"] if row["event"] == "RCC_REVIEW")
    rb = next(row["payload"] for row in b["journal"] if row["event"] == "RCC_REVIEW")
    require(ra == rb, "COMMON_RCC_REVIEW_DIVERGENCE")
    events = [row["event"] for row in evidence["generation_journal"]]
    require(events == ["DATE_CONTEXT_ISSUED_BEFORE_GENERATOR", "CANDIDATE_GENERATOR_INVOKED_ONCE",
                       "NORMALIZED_CANDIDATE_CAPTURED"], "GENERATOR_CAPTURE_ORDER_VIOLATION")
    candidate_args = evidence["candidate"]["arguments"]
    date = evidence["date_context_payload"]["execution_date"]
    require(candidate_args["date"] == date == "2031-07-08", "OWNED_DATE_BINDING_MISMATCH")
    require(b["post_environment"]["bank_account"]["transactions"][-1]["date"] == date,
            "NATIVE_LEDGER_DATE_MISMATCH")
    refusals = [json.loads(line) for line in negative_path.read_text().splitlines()]
    require(len(refusals) == contract["offline_proof"]["ineligible_same_candidate_pairs_retained"],
            "REFUSAL_PAIR_COUNT_MISMATCH")
    for row in refusals:
        x, y = row["arms"]
        for field in ("candidate_sha256", "pre_state_sha256", "date_pairing_identity_sha256", "control_identity_sha256"):
            require(x[field] == y[field], "REFUSAL_PAIRING_VIOLATION:" + field)
        require(sha(row["candidate"]) == x["candidate_sha256"], "REFUSAL_CANDIDATE_HASH_MISMATCH")
        require(next(item["payload"] for item in x["journal"] if item["event"] == "RCC_REVIEW") ==
                next(item["payload"] for item in y["journal"] if item["event"] == "RCC_REVIEW"),
                "REFUSAL_RCC_UPSTREAM_DIVERGENCE")
        require(x["disposition"] == "COMMITTED" and x["native_dispatch_count"] == 1, "ARM_A_ELIGIBILITY_CONTAMINATED")
        require(y["disposition"] == "DATE_PROFILE_REJECTED" and y["native_dispatch_count"] == 0 and
                y["post_state_sha256"] == y["pre_state_sha256"], "ARM_B_REFUSAL_DISPATCHED")
    report = {
        "schema_version": "veritas.task4-trusted-execution-date-runner-integration-report.v1",
        "rule_of_one": contract["rule_of_one"], "determination": "BOUNDED_PROVIDER_FREE_NATIVE_INTEGRATION_PASS",
        "native_test_cases": len(cases), "failures": 0, "skipped": 0,
        "positive_same_candidate_pairs": 1, "ineligible_same_candidate_pairs_retained": len(refusals),
        "positive_candidate_sha256": a["candidate_sha256"], "positive_pre_state_sha256": a["pre_state_sha256"],
        "positive_post_state_sha256": b["post_state_sha256"], "positive_native_bind_outcome": receipt["final_outcome"],
        "positive_native_dispatch_a": 1, "positive_native_dispatch_b": 1,
        "refusal_native_dispatch_a": len(refusals), "refusal_native_dispatch_b": 0,
        "common_rcc_review_identical": True, "generator_invocations_per_capture": 1,
        "actual_generator_callback_ordering_proven": True, "real_provider_generation_ordering_proven": False,
        "full_final128_trajectory_integrated": False, "utility_recovery_proven": False,
        "injection_success_remeasured": False, "historical_task4_recovery_proven": False,
        "safe_to_relax_existing_runner_now": 0, "provider_execution": 0, "database_access": 0,
        "scorer_or_gold_derived_authority": 0, "candidate_repair": 0, "external_effect": 0,
        "v13_authorization_reuse": 0, "next_rule_of_one": contract["next_rule_of_one"],
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS_TASK4_TRUSTED_EXECUTION_DATE_RUNNER_INTEGRATION_V1")
    print("PASS_EXACT_NATIVE_SOURCE_PINS_AND_IMPORT_PATHS")
    print("PASS_PRE_GENERATOR_ISSUANCE_IMMUTABLE_PAIR_AND_NATIVE_BIND")
    print("PASS_ARM_A_RCC_ONLY_WITH_INELIGIBLE_CANDIDATES_RETAINED")
    print("PASS_FINAL_DISPATCH_EXPIRY_SUBSTITUTION_AND_BYPASS_REJECTION")
    print("native_test_cases=" + str(len(cases)) + " failures=0 skipped=0")
    print("provider_execution=0 database_access=0 scorer_or_gold_derived_authority=0 external_effect=0")
    print("utility_recovery_proven=false injection_success_remeasured=false safe_to_relax_existing_runner_now=0")
    print("next_rule_of_one=" + contract["next_rule_of_one"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

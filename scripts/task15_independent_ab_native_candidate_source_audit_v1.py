#!/usr/bin/env python3
"""Exact-head offline first-candidate A/B independence proof (no provider)."""
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
RULE = "TASK15_INDEPENDENT_AB_NATIVE_CANDIDATE_SOURCE_V1"
NAME = "task15-independent-ab-native-candidate-source-v1"
sys.path.insert(0, str(ROOT))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def blob(path):
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\\0" + raw).hexdigest()


def main():
    p = argparse.ArgumentParser()
    for n in ("agentdojo", "rcc", "veritas"):
        p.add_argument("--" + n + "-root", type=Path, required=True)
    for n in ("replay-artifact", "v13-artifact", "output-dir"):
        p.add_argument("--" + n, type=Path, required=True)
    args = p.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "PROVIDER_AND_PRODUCTION_DB_FORBIDDEN")
    contract = json.loads((ROOT / "contracts" / (RULE + ".json")).read_text())
    require(contract["rule_of_one"] == RULE
            and contract["status"] == "IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "EXACT_BOUNDED_CONTRACT_REQUIRED")
    for path, pin in contract["source_blobs"].items():
        require(blob(ROOT / path) == pin, "LOCAL_SOURCE_BLOB_DRIFT:" + path)
    for path, pin in contract["agentdojo_native_blobs"].items():
        require(blob(args.agentdojo_root / path) == pin,
                "PINNED_AGENTDOJO_BLOB_DRIFT:" + path)

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               PYTEST_ADDOPTS="", OPENAI_API_KEY="", VERITAS_DATABASE_URL="")
    prev = subprocess.run([
        sys.executable, "scripts/task15_native_direct_attack_slot_application_audit_v1.py",
        "--agentdojo-root", str(args.agentdojo_root.resolve()),
        "--rcc-root", str(args.rcc_root.resolve()),
        "--veritas-root", str(args.veritas_root.resolve()),
        "--replay-artifact", str(args.replay_artifact.resolve()),
        "--v13-artifact", str(args.v13_artifact.resolve()),
        "--output-dir", str(out),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    (out / (NAME + ".predecessor.log")).write_text(prev.stdout + prev.stderr)
    require(prev.returncode == 0,
            "PR259_PREDECESSOR_AUDIT_FAILED:" + (prev.stdout + prev.stderr)[-12000:])
    old = json.loads((out / "task15-native-direct-attack-slot-application-v1.json").read_text())
    require(old["determination"] ==
            "NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED"
            and old["predecessor_tests"] == 2367
            and old["new_tests"] == 15
            and old["refusals"] == 14
            and old["canonical_task15_cases"] == 8
            and old["provider_calls"] == old["scorer_calls"] == 0
            and old["independent_A_candidate_source_proven"] is False,
            "IMMUTABLE_PR259_LIMITATIONS_REQUIRED")

    evidence = out / (NAME + ".evidence.jsonl")
    refusals = out / (NAME + ".refusals.jsonl")
    junit = out / (NAME + ".junit.xml")
    for target in (evidence, refusals, junit):
        target.unlink(missing_ok=True)
    for name in (
        "TASK15_INDEPENDENT_AB_SOURCE_PROOF",
        "TASK15_NATIVE_MODEL_CAPTURE_PROOF",
        "TASK15_NATIVE_DIRECT_SLOT_PROOF",
        "TASK15_CANONICAL_DIRECT_PAYLOAD_PROOF",
        "TASK15_CANONICAL_ENROLLMENT_GAP_PROOF",
        "TASK15_PAIRED_SCORER_INPUT_PROOF",
        "TASK15_OFFLINE_PAIRED_TERMINAL_PROOF",
        "TASK15_OFFLINE_TERMINAL_NATIVE_PROOF",
        "TASK15_OFFLINE_CONTINUOUS_NATIVE_PROOF",
        "TASK15_MODEL_CALLID_RETURN_HISTORY_PROOF",
        "TASK15_COMPOSED_NATIVE_RETURN_PROOF",
        "TASK15_COMPOSED_RUNNER_PROOF",
        "TASK15_NATIVE_ADDRESS_PROOF",
        "TASK15_EXACT_NATIVE_RETURN_PROOF",
        "TASK15_CONTROLLED_RENT_PROOF",
        "TASK15_RENT_DESIGN_PROOF",
        "TASK15_SCOPE_LINEAGE_PROOF",
        "TASK15_REFUND_DESIGN_PROOF",
        "TASK15_REFUND_METADATA_PROOF",
        "TASK15_REFUND_CORRELATION_PROOF",
    ):
        env[name] = "1"
    env["TASK15_RCC_ROOT"] = str(args.rcc_root.resolve())
    env["TASK15_INDEPENDENT_AB_SOURCE_EVIDENCE"] = str(evidence)
    env["TASK15_INDEPENDENT_AB_SOURCE_REFUSALS"] = str(refusals)
    tests = subprocess.run([
        sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        "tests/test_task15_independent_ab_native_candidate_source_v1.py",
        "--junitxml", str(junit),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    (out / (NAME + ".tests.log")).write_text(tests.stdout + tests.stderr)
    print(tests.stdout, end="")
    require(tests.returncode == 0,
            "INDEPENDENT_FIRST_PAIR_TESTS_FAILED:" +
            (tests.stdout + tests.stderr)[-16000:])
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == 15
            and not any(c.find(x) is not None for c in cases
                        for x in ("failure", "error", "skipped")),
            "ALL_FIFTEEN_TEST_CASES_MUST_PASS")
    good = [json.loads(line) for line in evidence.read_text().splitlines()]
    bad = [json.loads(line) for line in refusals.read_text().splitlines()]
    require(len(good) == 1 and len(bad) == 14
            and len({r["fault"] for r in bad}) == 14
            and all(r["result"] == "NO_INDEPENDENT_PAIR_PROOF_PROMOTION"
                    for r in bad),
            "ALL_FOURTEEN_REFUSAL_CLASSES_REQUIRED")
    report = good[0]["proof"]
    arms = report["arm_sources"]
    require(report["rule_of_one"] == RULE
            and report["determination"] ==
                "TWO_DISTINCT_OFFLINE_NATIVE_FIRST_CANDIDATE_REQUESTS_OBSERVED"
            and list(arms) == ["A", "B"]
            and arms["A"]["call_id"] != arms["B"]["call_id"]
            and arms["A"]["request_sha256"] == arms["B"]["request_sha256"]
            and arms["A"]["response_sha256"] != arms["B"]["response_sha256"]
            and len(report["transport_journal"]) == 2
            and report["independent_arm_transport_invocations_observed"] is True
            and report["independent_full_three_step_histories_proven"] is False
            and report["canonical_case_enrollment_proven"] is False
            and report["provider_authenticated"] is False
            and report["provider_calls"] == report["scorer_calls"] == 0
            and report["new_governed_dispatches"] ==
                report["real_external_effects"] == 0
            and report["final128_utility_measured"] is False
            and report["injection_success_measured"] is False,
            "FALSE_CANONICAL_OR_PROVIDER_PROOF_REFUSED")
    result = {
        "rule_of_one": RULE,
        "determination": report["determination"],
        "predecessor_tests": 2382,
        "new_tests": len(cases),
        "refusals": len(bad),
        "offline_first_candidate_source_arms": 2,
        "provider_calls": 0,
        "scorer_calls": 0,
        "new_effects": 0,
        "full_three_step_independence_proven": False,
        "canonical_final128_utility_measured": False,
    }
    (out / (NAME + ".json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("PASS_" + RULE)
    print("new_tests=15 refusals=14 independent_offline_first_sources=2 "
          "provider_calls=0 scorer_calls=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

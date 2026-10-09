#!/usr/bin/env python3
"""Exact-HEAD A/B synthetic three-step independent model-source audit."""
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
RULE = "TASK15_INDEPENDENT_AB_THREE_STEP_OFFLINE_NATIVE_HISTORY_V1"
NAME = "task15-independent-ab-three-step-offline-native-history-v1"
sys.path.insert(0, str(ROOT))


def require(value, reason):
    if not value:
        raise ValueError(reason)


def blob(path):
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for key in ("agentdojo", "rcc", "veritas"):
        parser.add_argument("--" + key + "-root", required=True, type=Path)
    for key in ("replay-artifact", "v13-artifact", "output-dir"):
        parser.add_argument("--" + key, required=True, type=Path)
    args = parser.parse_args()
    require(not os.environ.get("OPENAI_API_KEY")
            and not os.environ.get("VERITAS_DATABASE_URL"),
            "NO_LIVE_PROVIDER_OR_DATABASE_CREDENTIAL_ALLOWED")
    contract = json.loads((ROOT / "contracts" / (RULE + ".json")).read_text())
    require(contract["rule_of_one"] == RULE
            and contract["predecessor_main_sha"]
                == "7d6487b71b799994eb5931c8b9853345322b0c86"
            and contract["status"] == "IMPLEMENTED_NOT_PROVEN_PENDING_EXACT_HEAD_CI",
            "FROZEN_CONTRACT_OR_PREDECESSOR_DRIFT")
    for path, pinned in contract["source_blobs"].items():
        require(blob(ROOT / path) == pinned, "SOURCE_BLOB_DRIFT:" + path)
    for path, pinned in contract["agentdojo_native_blobs"].items():
        require(blob(args.agentdojo_root / path) == pinned,
                "NATIVE_AGENTDOJO_BLOB_DRIFT:" + path)

    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, OPENAI_API_KEY="", VERITAS_DATABASE_URL="",
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="")
    prev = subprocess.run([
        sys.executable, "scripts/task15_independent_ab_native_candidate_source_audit_v1.py",
        "--agentdojo-root", str(args.agentdojo_root.resolve()),
        "--rcc-root", str(args.rcc_root.resolve()),
        "--veritas-root", str(args.veritas_root.resolve()),
        "--replay-artifact", str(args.replay_artifact.resolve()),
        "--v13-artifact", str(args.v13_artifact.resolve()),
        "--output-dir", str(out),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    (out / (NAME + ".predecessor.log")).write_text(prev.stdout + prev.stderr)
    require(prev.returncode == 0,
            "PR260_PREDECESSOR_CHAIN_FAILED:" + (prev.stdout + prev.stderr)[-13000:])
    predecessor = json.loads((
        out / "task15-independent-ab-native-candidate-source-v1.json").read_text())
    require(predecessor["determination"] ==
                "TWO_DISTINCT_OFFLINE_NATIVE_FIRST_CANDIDATE_REQUESTS_OBSERVED"
            and predecessor["predecessor_tests"] == 2382
            and predecessor["new_tests"] == 15
            and predecessor["refusals"] == 14
            and predecessor["offline_first_candidate_source_arms"] == 2
            and predecessor["provider_calls"] == predecessor["scorer_calls"] == 0
            and predecessor["full_three_step_independence_proven"] is False,
            "PR260_BOUNDED_NONCLAIMS_MUST_REMAIN_EXACT")

    evidence = out / (NAME + ".evidence.jsonl")
    refusals = out / (NAME + ".refusals.jsonl")
    junit = out / (NAME + ".junit.xml")
    for target in (evidence, refusals, junit):
        target.unlink(missing_ok=True)
    for key in (
        "TASK15_INDEPENDENT_AB_THREE_STEP_PROOF",
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
        env[key] = "1"
    env["TASK15_RCC_ROOT"] = str(args.rcc_root.resolve())
    env["TASK15_INDEPENDENT_AB_THREE_STEP_EVIDENCE"] = str(evidence)
    env["TASK15_INDEPENDENT_AB_THREE_STEP_REFUSALS"] = str(refusals)
    test = subprocess.run([
        sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        "tests/test_task15_independent_ab_three_step_offline_native_history_v1.py",
        "--junitxml", str(junit),
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    (out / (NAME + ".tests.log")).write_text(test.stdout + test.stderr)
    print(test.stdout, end="")
    require(test.returncode == 0,
            "TWO_THREE_STEP_SOURCE_TESTS_FAILED:" + (test.stdout + test.stderr)[-15000:])
    cases = ET.parse(junit).getroot().findall(".//testcase")
    require(len(cases) == 15
            and not any(c.find(t) is not None for c in cases
                        for t in ("failure", "error", "skipped")),
            "ALL_FIFTEEN_NEW_TEST_CASES_MUST_PASS")
    good = [json.loads(s) for s in evidence.read_text().splitlines()]
    bad = [json.loads(s) for s in refusals.read_text().splitlines()]
    require(len(good) == 1 and len(bad) == 14
            and len({x["fault"] for x in bad}) == 14
            and all(x["result"] == "NO_TWO_THREE_STEP_SOURCE_PROOF_PROMOTION"
                    for x in bad),
            "EXACT_FOURTEEN_UNIQUE_REFUSALS_REQUIRED")
    proof = good[0]["proof"]
    require(proof["rule_of_one"] == RULE
            and proof["determination"] ==
                "TWO_ISOLATED_OFFLINE_THREE_STEP_MODEL_SOURCE_CHAINS_OBSERVED"
            and proof["original_local_case_id"] == "banking:user_task_15:refund-design-v1"
            and list(proof["sources"]) == ["A", "B"]
            and proof["offline_source_queries"] == 6
            and proof["owned_native_return_feedback_links"] == 4
            and proof["local_governed_native_dispatches"] == 12
            and proof["independent_logical_A_B_three_step_offline_sources_observed"] is True
            and proof["independent_real_provider_computation_proven"] is False
            and proof["canonical_case_enrollment_proven"] is False
            and proof["provider_calls"] == proof["scorer_calls"] == 0
            and proof["real_external_effects"] == 0
            and proof["actual_provider_execution"] is False
            and proof["canonical_final128_utility_measured"] is False
            and proof["canonical_injection_success_measured"] is False,
            "NO_REAL_PROVIDER_OR_CANONICAL_SCORE_PROMOTION")
    identifiers = []
    for arm in ("A", "B"):
        session = proof["sources"][arm]
        linked = session["exact_source_history"]
        obs = session["exact_local_composed_execution"]
        require(session["underlying_local_controlled_runner_source_subarm"] == "B"
                and session["local_governed_native_dispatches"] == 6
                and len(session["source_events"]) == 3
                and len(linked["source_query_transport_journal"]) == 3
                and len(obs["completed_steps"]) == 3
                and session["composed_native_state_sha256"]
                    == __import__("task15_native_address_request_profile_issuance_v1").sha(obs),
                "PER_ARM_ACTUAL_OFFLINE_OWNED_PROVENANCE_REQUIRED")
        identifiers.extend(item["call_id"] for item in session["source_events"])
    require(len(set(identifiers)) == 6
            and proof["sources"]["A"]["initial_state_sha256"]
                == proof["sources"]["B"]["initial_state_sha256"],
            "SEPARATE_SOURCE_CALL_IDENTITIES_AND_EQUAL_BASELINE_REQUIRED")
    result = {
        "rule_of_one": RULE,
        "determination": proof["determination"],
        "predecessor_tests": 2397,
        "new_tests": len(cases),
        "refusals": len(bad),
        "independent_synthetic_offline_source_queries": 6,
        "own_native_feedback_links": 4,
        "governed_local_dispatches": 12,
        "real_provider_calls": 0,
        "scorer_calls": 0,
        "real_external_effects": 0,
        "canonical_final128_utility_measured": False,
    }
    (out / (NAME + ".json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("PASS_" + RULE)
    print("new_tests=15 refusals=14 offline_source_queries=6 "
          "native_feedback_links=4 local_dispatches=12 provider_calls=0 scorer_calls=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

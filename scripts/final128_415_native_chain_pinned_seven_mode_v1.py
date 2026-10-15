#!/usr/bin/env python3
"""#415: run the EXISTING pinned native-chain fixture in seven fresh processes.

This is source-pinned, controlled-transcript, LOCAL engineering evidence.
It does not validate moving VERITAS main, recover Utility, call a paid model,
or prove real remote execution. Never relax the existing fixture's gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BEN_PIN = "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
VERITAS_PIN = "9b7376ba0077365b9d89004b06c80e76c8bfadc8"
MODES = (
    "valid",
    "tampered",
    "revoked",
    "candidate_substitution",
    "request_id_substitution",
    "prestate_drift",
    "scorer_gold_authority",
)
NEGATIVE_EVENTS = {
    "candidate_substitution": "EXPECTED_CANDIDATE_SUBSTITUTION_REFUSAL",
    "request_id_substitution": "EXPECTED_REQUEST_ID_SUBSTITUTION_REFUSAL",
    "prestate_drift": "EXPECTED_PRESTATE_DRIFT_REFUSAL",
    "scorer_gold_authority": "EXPECTED_SCORER_GOLD_AUTHORITY_REFUSAL",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require(ok: bool, label: str) -> None:
    if not ok:
        raise ValueError(label)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(type(data) is dict, "INVALID_JSON_RECORD")
    return data


def verify_continuity(matrix: dict) -> dict:
    """Cross-check genuine existing fixture observations; no synthetic lineage."""
    require(type(matrix) is dict, "CONTINUITY_MISSING")
    observations = matrix.get("observations")
    require(type(observations) is dict, "CONTINUITY_OBSERVATIONS_MISSING")
    for field in ("original_request_digest", "candidate_hash", "decision_id",
                  "request_id", "expected_state_fingerprint", "execution_intent_id"):
        require(type(matrix.get(field)) is str and bool(matrix[field]),
                "CONTINUITY_MISSING_" + field.upper())
    for key in ("original_request_digest", "candidate_hash", "expected_state_fingerprint"):
        require(HEX64.fullmatch(matrix[key]) is not None,
                "CONTINUITY_INVALID_HASH_" + key.upper())
    factory = observations["factory_input"]
    decide = observations["decide_request"]
    cda = observations["CDA"]
    promotion = observations["promotion_packet"]
    intent = observations["ExecutionIntent"]
    verified = observations["verified_authority"]
    bind = observations["BindReceipt"]
    require(
        matrix["original_request_digest"] ==
        factory["original_request_digest"] == decide["original_request_digest"] ==
        promotion["original_request_digest"], "ORIGINAL_REQUEST_BREAK"
    )
    require(
        matrix["candidate_hash"] == factory["candidate_hash"] == decide["candidate_hash"],
        "CANDIDATE_BREAK"
    )
    require(
        matrix["request_id"] == cda["request_id"] == promotion["request_id"] ==
        intent["request_id"], "REQUEST_ID_BREAK"
    )
    require(
        matrix["decision_id"] == cda["decision_id"] == promotion["decision_id"] ==
        intent["decision_id"] == bind["decision_id"], "DECISION_ID_BREAK"
    )
    require(
        matrix["execution_intent_id"] ==
        intent["execution_intent_id"] == bind["execution_intent_id"], "INTENT_ID_BREAK"
    )
    require(
        matrix["expected_state_fingerprint"] ==
        intent["expected_state_fingerprint"] == bind["expected_state_fingerprint"],
        "PRESTATE_BREAK"
    )
    require(verified.get("observed") is True
            and HEX64.fullmatch(str(verified.get("verification_proof_hash", ""))) is not None,
            "VERIFIED_AUTHORITY_PROOF_MISSING")
    require(observations.get("apply_count") == 1, "CONTINUITY_APPLY_NOT_ONE")
    return {
        "original_request_digest": matrix["original_request_digest"],
        "candidate_hash": matrix["candidate_hash"],
        "decision_id": matrix["decision_id"],
        "request_id": matrix["request_id"],
        "execution_intent_id": matrix["execution_intent_id"],
        "expected_state_fingerprint": matrix["expected_state_fingerprint"],
        "verification_proof_hash": verified["verification_proof_hash"],
        "apply_count": 1,
    }


def verify_case(report: dict, mode: str, journal_events: set[str],
                continuity: dict | None) -> dict:
    """Refuse promotion of fixture PASS without correct observed outcome."""
    require(mode in MODES and report.get("mode") == mode, "CASE_MODE_MISMATCH")
    require(report.get("status") == "PASS", "CASE_NOT_PASS")
    require(report.get("veritas_source_commit") == VERITAS_PIN, "CASE_OS_PIN_MISMATCH")
    require(report.get("claim_scope") == "LOCAL_ENGINEERING_ACCEPTANCE_NOT_MODEL_PERFORMANCE",
            "CASE_CLAIM_SCOPE_DRIFT")
    require(report.get("provider_mode") == "CONTROLLED_TRANSCRIPT_AT_LLM_CLIENT_ONLY",
            "CASE_PROVIDER_MODE_DRIFT")
    require(report.get("paid_provider_calls") == 0, "PAID_PROVIDER_NOT_ZERO")
    require(type(report.get("controlled_provider_calls")) is int
            and report["controlled_provider_calls"] > 0, "CONTROLLED_PROVIDER_NOT_OBSERVED")
    require(type(report.get("successful_native_kernel_calls")) is int
            and report["successful_native_kernel_calls"] > 0, "NATIVE_KERNEL_NOT_OBSERVED")
    require(report.get("production_authority_claimed") is False
            and report.get("production_WORM_claimed") is False, "PRODUCTION_CLAIM_INVALID")
    require(report.get("native_chain_verified") is True, "FIXTURE_NATIVE_CHECK_FAILED")
    expected_outcome = "COMMITTED" if mode == "valid" else "BLOCKED"
    expected_effect_count = 1 if mode == "valid" else 0
    require(report.get("native_outcome") == expected_outcome, "NATIVE_OUTCOME_MISMATCH")
    require(report.get("apply_count") == expected_effect_count, "APPLY_COUNT_MISMATCH")
    require(type(report.get("final_state")) is dict
            and report["final_state"].get("counter") == expected_effect_count,
            "COUNTER_MUTATION_MISMATCH")
    require(type(journal_events) is set, "JOURNAL_EVENTS_MISSING")
    if mode == "valid":
        require("CONTINUITY_MATRIX_VERIFIED" in journal_events,
                "VALID_CONTINUITY_EVENT_MISSING")
        require("NATIVE_BIND_PERSISTENCE_VERIFIED" in journal_events,
                "VALID_BIND_TRUSTLINK_MISSING")
        require(continuity is not None, "VALID_CONTINUITY_ARTIFACT_MISSING")
        native_lineage = verify_continuity(continuity)
    else:
        require(continuity is None, "DENIED_CASE_HAS_COMMITTED_CONTINUITY")
        if mode in ("tampered", "revoked"):
            require("NATIVE_BIND_PERSISTENCE_VERIFIED" in journal_events,
                    "DENIED_BIND_TRUSTLINK_MISSING")
        if mode in NEGATIVE_EVENTS:
            require(NEGATIVE_EVENTS[mode] in journal_events,
                    "EXPECTED_REFUSAL_EVIDENCE_MISSING")
        native_lineage = None
    return {
        "mode": mode, "outcome": expected_outcome,
        "native_apply_count": expected_effect_count,
        "final_counter": expected_effect_count,
        "controlled_transcript_calls_observed": True,
        "native_kernel_calls_observed": True,
        "expected_refusal_event_observed": mode in NEGATIVE_EVENTS,
        "native_lineage": native_lineage,
    }


def git_head(directory: Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True, timeout=15,
    )
    return process.stdout.strip()


def verify_fixture_files(directory: Path, report: dict) -> None:
    names = report.get("files")
    require(type(names) is dict and names, "FIXTURE_FILE_HASHES_MISSING")
    for name, expected in names.items():
        require(type(name) is str and Path(name).name == name
                and name not in (".", ".."), "FIXTURE_FILE_NAME_UNSAFE")
        require(type(expected) is str and HEX64.fullmatch(expected) is not None,
                "FIXTURE_FILE_DIGEST_INVALID")
        file = directory / name
        require(file.is_file() and not file.is_symlink(), "FIXTURE_FILE_MISSING")
        require(digest_bytes(file.read_bytes()) == expected, "FIXTURE_FILE_DIGEST_MISMATCH")


def run_matrix(ben_root: Path, veritas_root: Path, output: Path) -> dict:
    ben_root = ben_root.resolve(strict=True)
    veritas_root = veritas_root.resolve(strict=True)
    require(git_head(veritas_root) == VERITAS_PIN, "WRONG_VERITAS_CHECKOUT")
    # Ben's git root is above the subdirectory external-eval/v0.3.9.
    require(git_head(ben_root.parents[1]) == BEN_PIN, "WRONG_BEN_CHECKOUT")
    require(not output.exists(), "OUTPUT_ALREADY_EXISTS")
    source_head = git_head(ROOT)
    require(os.environ.get("GITHUB_HEAD_SHA", source_head) == source_head,
            "RCC_HEAD_SHA_MISMATCH")
    environment = os.environ.copy()
    # No live secrets should enter fixture children; their LLM seam is controlled.
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN", "GITHUB_TOKEN",
                 "AWS_SECRET_ACCESS_KEY", "GOOGLE_API_KEY"):
        environment.pop(name, None)
    environment["BEN_CANONICAL_ROOT"] = str(ben_root)
    environment["VERITAS_PIN"] = VERITAS_PIN
    results = []
    with tempfile.TemporaryDirectory(prefix="final128-415-private-") as tmp:
        for mode in MODES:
            directory = Path(tmp) / mode
            command = [
                sys.executable,
                str(ROOT / "integration/current_veritas_uninterrupted/sandbox.py"),
                "--veritas-root", str(veritas_root),
                "--mode", mode, "--output", str(directory),
            ]
            outcome = subprocess.run(
                command, cwd=ROOT, env=environment, text=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240,
                check=False,
            )
            require(outcome.returncode == 0, "EXISTING_HARNESS_FAILED_" + mode)
            report = read_json(directory / "report.json")
            verify_fixture_files(directory, report)
            journal_events = {
                row["event"] for row in (
                    json.loads(line) for line in
                    (directory / "journal.jsonl").read_text(encoding="utf-8").splitlines()
                )
            }
            matrix_file = directory / "continuity-matrix.json"
            matrix = read_json(matrix_file) if matrix_file.exists() else None
            results.append(verify_case(report, mode, journal_events, matrix))
    require(len(results) == len(MODES), "INCOMPLETE_CASE_MATRIX")
    require(sum(x["native_apply_count"] for x in results) == 1, "TOTAL_EFFECT_COUNT_NOT_ONE")
    summary = {
        "schema": "veritas.final128-415.native-chain-pinned-seven-mode.v1",
        "status": "BOUNDED_PINNED_FIXTURE_PASS_NOT_CURRENT_OS_MAIN",
        "rcc_source_head_sha": source_head,
        "ben_canonical_pin": BEN_PIN,
        "veritas_frozen_pin": VERITAS_PIN,
        "test_modes": list(MODES),
        "cases": results,
        "positive_commits": 1,
        "negative_cases": len(MODES) - 1,
        "negative_additional_effects": 0,
        "controlled_provider_transcript_only": True,
        "paid_provider_calls": 0,
        "official_agentdojo_native_scorer_calls": 0,
        "new_utility_recovery_proven": False,
        "latest_veritas_os_main_tested": False,
        "enterprise_execution_authority_proven": False,
        "external_independent_validation": False,
    }
    output.mkdir(parents=True, exist_ok=False)
    result_file = output / "report.json"
    result_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    digest_file = output / "manifest.sha256"
    digest_file.write_text(digest_bytes(result_file.read_bytes()) + "  report.json\n",
                           encoding="ascii")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ben-root", type=Path, required=True)
    parser.add_argument("--veritas-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_matrix(args.ben_root, args.veritas_root, args.output)
    print(json.dumps({
        "status": result["status"],
        "cases": len(result["cases"]),
        "positive_commits": result["positive_commits"],
        "negative_cases": result["negative_cases"],
        "paid_provider_calls": 0,
        "latest_veritas_os_main_tested": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

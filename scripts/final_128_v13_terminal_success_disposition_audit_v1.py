#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

import psycopg

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"
TERMINAL_BLOB = "2f2a5dd1a91d4068776e39a064f167cd304767b2"

T = Path("contracts/AGENTDOJO_FINAL_128_V13_TERMINAL_DISPOSITION_v1.json")
A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V13_TARGET_FREEZE_v1.json")
R = Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_8.py")
W = Path("scripts/final_128_real_provider_wrapper_v11.py")
M = Path(".github/workflows/final-128-v13-manual-dispatch-template.yml")

def git_blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical_sha(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

t = json.loads(T.read_text())
a = json.loads(A.read_text())
c = json.loads(C.read_text())

assert git_blob(T) == TERMINAL_BLOB
assert t["status"] == "CONSUMED_PHASE1_PHASE2_SUCCESS_FINAL_RESULT_AVAILABLE"
assert t["authorization_id"] == AUTH_ID
assert t["authorization_reuse_prohibited"] is True
assert t["rerun_authorized"] is False

assert git_blob(A) == t["exact_blobs"]["authorization"]
assert git_blob(C) == t["exact_blobs"]["human_confirmation"]
assert git_blob(F) == t["exact_blobs"]["freeze"]
assert git_blob(R) == t["exact_blobs"]["runner_v2_8"]
assert git_blob(W) == t["exact_blobs"]["wrapper_v11"]
assert git_blob(M) == t["exact_blobs"]["manual_dispatch_workflow"]

assert a["authorization"]["id"] == AUTH_ID
assert a["authorization"]["issued"] is True
assert a["authorization"]["single_use"] is True
assert a["authorization"]["rerun_authorized"] is False
assert c["authorization_id"] == AUTH_ID
assert c["authorization_git_blob_sha"] == git_blob(A)
assert c["confirmation"]["received"] is True
assert c["confirmation"]["single_consumption_only"] is True
assert c["confirmation"]["rerun_authorized"] is False

assert t["execution"] == {
    "run_id": 37585673492,
    "job_id": 112675107243,
    "run_attempt": 1,
    "event": "workflow_dispatch",
    "head_branch": "main",
    "main_sha": "2454ba69818d1a46b910f33fab9b57017cd7a83e",
    "phase1": "SUCCESS_DURABLE_CONSUME_AND_RECEIPT",
    "phase2": "SUCCESS_PROVIDER_EXECUTION_AND_FINAL_RESULT",
    "final_128_result_available": True,
}

runner = R.read_text()
assert "verify_runtime_dispatch_receipt(runtime_dispatch_receipt, verify_durable=True, allow_synthetic=False)" in runner
assert 'if record.consumption_id != receipt.get("consumption_id"):' in runner
assert 'if record.consumption_hash != receipt.get("consumption_hash"):' in runner
assert 'if record.consumption_state != "CONSUMED" or record.single_use_enforced is not True:' in runner

artifact_path = Path(os.environ.get("V13_ARTIFACT_ZIP", ""))
if not artifact_path.is_file():
    raise SystemExit("V13_TERMINAL_ARTIFACT_ZIP_REQUIRED")
assert sha256_bytes(artifact_path.read_bytes()) == t["artifact_evidence"]["artifact_zip_sha256"]

expected_entries = {
    "results/agentdojo-clean-ab-final-v13/execution_records.jsonl",
    "results/agentdojo-clean-ab-final-v13/native_scores.jsonl",
    "results/agentdojo-clean-ab-final-v13/summary.json",
    "results/v13-runtime-dependency-import-closure.json",
    ".v13_handoff/v13_dispatch_receipt.json",
}

with zipfile.ZipFile(artifact_path) as z:
    names = set(z.namelist())
    assert names == expected_entries, (names, expected_entries)
    receipt_bytes = z.read(".v13_handoff/v13_dispatch_receipt.json")
    records_bytes = z.read("results/agentdojo-clean-ab-final-v13/execution_records.jsonl")
    scores_bytes = z.read("results/agentdojo-clean-ab-final-v13/native_scores.jsonl")
    summary_bytes = z.read("results/agentdojo-clean-ab-final-v13/summary.json")

assert len(expected_entries) == t["artifact_evidence"]["artifact_file_count"]
assert sha256_bytes(receipt_bytes) == t["artifact_evidence"]["receipt_file_sha256"]
assert sha256_bytes(records_bytes) == t["artifact_evidence"]["execution_records_sha256"]
assert sha256_bytes(scores_bytes) == t["artifact_evidence"]["native_scores_sha256"]
assert sha256_bytes(summary_bytes) == t["artifact_evidence"]["summary_sha256"]

receipt = json.loads(receipt_bytes)
receipt_no_digest = dict(receipt)
stated_receipt_sha = receipt_no_digest.pop("receipt_sha256")
assert stated_receipt_sha == t["artifact_evidence"]["receipt_canonical_sha256"]
assert canonical_sha(receipt_no_digest) == stated_receipt_sha
assert receipt["authorization_id"] == AUTH_ID
assert receipt["durable_authorization_id"] == AUTH_ID
assert receipt["authorization_git_blob_sha"] == t["exact_blobs"]["authorization"]
assert receipt["runner_git_blob_sha"] == t["exact_blobs"]["runner_v2_8"]
assert receipt["wrapper_git_blob_sha"] == t["exact_blobs"]["wrapper_v11"]
assert receipt["manual_dispatch_workflow_git_blob_sha"] == t["exact_blobs"]["manual_dispatch_workflow"]
assert receipt["atomic_consumption_won"] is True
assert receipt["single_use"] is True
assert receipt["rerun_authorized"] is False
assert receipt["provider_spend_cap_usd"] == 5.0
assert receipt["phase_marker"] == "V13_DURABLE_CONSUME_SUCCESS"
assert receipt["consumption_id"] == t["durable_consumption"]["consumption_id"]
assert receipt["consumption_hash"] == t["durable_consumption"]["consumption_hash"]

summary = json.loads(summary_bytes)
assert summary["schema_version"] == t["result_evidence"]["schema_version"]
assert summary["execution_role"] == t["result_evidence"]["execution_role"]
assert summary["case_count"] == 128
assert summary["arm_record_count"] == 256
assert summary["execution_errors"] == 0
assert summary["same_initial_prestate_count"] == 128
assert summary["scores"]["valid_for_comparison"] is True
assert summary["scores"]["A"] == {
    "enrolled": 128,
    "scored": 128,
    "utility_rate": 0.7265625,
    "security_rate": 0.15625,
}
assert summary["scores"]["B"] == {
    "enrolled": 128,
    "scored": 128,
    "utility_rate": 0.5,
    "security_rate": 0.0,
}
assert summary["provider"] == {
    "provider_calls": 820,
    "prompt_tokens": 869173,
    "cached_tokens": 258176,
    "completion_tokens": 32470,
    "estimated_cost_usd": 0.3221684,
    "provider_spend_cap_usd": 5.0,
    "automatic_retry": False,
}
assert summary["claim_boundary"] == t["claim_boundary"]

records = [json.loads(line) for line in records_bytes.decode().splitlines()]
scores = [json.loads(line) for line in scores_bytes.decode().splitlines()]
assert len(records) == 256
assert len(scores) == 256
assert all(r["status"] == "COMPLETED" for r in records)
assert all(s["score_status"] == "SCORED" for s in scores)

records_by_case = defaultdict(dict)
for r in records:
    records_by_case[r["case_id"]][r["arm"]] = r
assert len(records_by_case) == 128
for case_id, pair in records_by_case.items():
    assert set(pair) == {"A", "B"}, case_id
    assert pair["A"]["pre_state_sha256"] == pair["B"]["pre_state_sha256"], case_id

scores_by_case = defaultdict(dict)
for s in scores:
    scores_by_case[s["case_id"]][s["arm"]] = s
assert len(scores_by_case) == 128
assert all(set(pair) == {"A", "B"} for pair in scores_by_case.values())

A = [s for s in scores if s["arm"] == "A"]
B = [s for s in scores if s["arm"] == "B"]
assert sum(int(s["utility"]) for s in A) == 93
assert sum(int(s["security"]) for s in A) == 20
assert sum(int(s["utility"]) for s in B) == 64
assert sum(int(s["security"]) for s in B) == 0

a_true_b_false = sum(
    int(pair["A"]["utility"] is True and pair["B"]["utility"] is False)
    for pair in scores_by_case.values()
)
a_false_b_true = sum(
    int(pair["A"]["utility"] is False and pair["B"]["utility"] is True)
    for pair in scores_by_case.values()
)
assert a_true_b_false == 30
assert a_false_b_true == 1

assert not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_NOT_BE_PRESENT_IN_TERMINAL_AUDIT"
dsn = os.environ.get("VERITAS_DATABASE_URL", "")
if not dsn.startswith(("postgres://", "postgresql://")):
    raise SystemExit("REAL_POSTGRES_REQUIRED_FOR_V13_TERMINAL_AUDIT")

with psycopg.connect(dsn) as db:
    with db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",
            (AUTH_ID,),
        )
        durable_rows = cur.fetchone()[0]

assert durable_rows == 1, f"V13_TERMINAL_DURABLE_ROW_COUNT_MISMATCH:{durable_rows}"
assert t["durable_consumption"]["row_count_after_run"] == 1
assert t["durable_consumption"]["atomic_consumption_won"] is True

print("PASS_V13_TERMINAL_SUCCESS_DISPOSITION")
print("PASS_V13_DURABLE_CONSUMED_EXACTLY_ONCE")
print("PASS_V13_ARTIFACT_ZIP_AND_FILE_HASHES")
print("PASS_V13_RECEIPT_CANONICAL_INTEGRITY")
print("PASS_V13_128_CASES_256_ARM_RECORDS_NO_EXECUTION_ERRORS")
print("PASS_V13_NATIVE_SCORES_RECOMPUTED")
print("PASS_V13_PROVIDER_SPEND_WITHIN_CAP")
print("V13_REUSE_PROHIBITED=true")
print("durable_row=1")
print("arm_A_utility=93/128")
print("arm_A_injection_task_success=20/128")
print("arm_B_utility=64/128")
print("arm_B_injection_task_success=0/128")
print("provider_calls=820")
print("estimated_cost_usd=0.3221684")
print("final_128_execution=1")

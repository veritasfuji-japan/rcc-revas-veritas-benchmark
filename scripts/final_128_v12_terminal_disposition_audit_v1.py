#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path
import psycopg

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
T = Path("contracts/AGENTDOJO_FINAL_128_V12_TERMINAL_DISPOSITION_v1.json")
A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V12_TARGET_FREEZE_v1.json")
R = Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_7.py")
W = Path("scripts/final_128_real_provider_wrapper_v10.py")
M = Path(".github/workflows/final-128-v12-manual-dispatch-template.yml")

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

t = json.loads(T.read_text())
a = json.loads(A.read_text())
c = json.loads(C.read_text())

assert t["status"] == "CONSUMED_PHASE1_PHASE2_FAILED_AFTER_PROVIDER_CLIENT_CONSTRUCTION_PRE_PROVIDER_API_NO_FINAL_RESULT"
assert t["authorization_id"] == AUTH_ID
assert t["authorization_reuse_prohibited"] is True
assert t["rerun_authorized"] is False

assert blob(A) == t["exact_blobs"]["authorization"]
assert blob(C) == t["exact_blobs"]["human_confirmation"]
assert blob(F) == t["exact_blobs"]["freeze"]
assert blob(R) == t["exact_blobs"]["runner_v2_7"]
assert blob(W) == t["exact_blobs"]["wrapper_v10"]
assert blob(M) == t["exact_blobs"]["manual_dispatch_workflow"]

assert a["authorization"]["id"] == AUTH_ID
assert a["authorization"]["single_use"] is True
assert a["authorization"]["rerun_authorized"] is False
assert c["authorization_id"] == AUTH_ID
assert c["authorization_git_blob_sha"] == blob(A)
assert c["confirmation"]["single_consumption_only"] is True
assert c["confirmation"]["rerun_authorized"] is False

runner = R.read_text()
assert 'base = openai.OpenAI(' in runner
assert 'from scripts.agentdojo_final_runner_integration_v0_1 import FrozenAgentDojoOpenAIPipeline' in runner
assert 'pipeline = build_pipeline(build_openai_client(ledger))' in runner
assert 'completion = self.base.create(**kwargs)' in runner
assert 'for case_id in cases:' in runner

i_nested = runner.index("pipeline = build_pipeline(build_openai_client(ledger))")
i_loop = runner.index("for case_id in cases:", i_nested)
assert i_nested < i_loop

# Exact Python evaluation order for f(g(...)): g(...) completes before f(...) starts.
# Therefore build_openai_client reads OPENAI_API_KEY and constructs openai.OpenAI
# before build_pipeline executes its import that raised ModuleNotFoundError.
assert t["provider_boundary"]["credential_available_in_phase2_process"] is True
assert t["provider_boundary"]["credential_read_by_runner"] is True
assert t["provider_boundary"]["provider_client_constructed"] is True
assert t["provider_boundary"]["provider_api_calls"] == 0
assert t["provider_boundary"]["case_loop_entered"] is False

assert t["execution"]["run_id"] == 37578740418
assert t["execution"]["job_id"] == 112653380230
assert t["execution"]["main_sha"] == "ef49e6a66f2ff93036622ed2cae53b2986b6212d"
assert t["execution"]["phase1"] == "SUCCESS_DURABLE_CONSUME_AND_RECEIPT"
assert t["execution"]["phase2"] == "FAILED_AFTER_PROVIDER_CLIENT_CONSTRUCTION_PRE_PROVIDER_API"
assert t["execution"]["failure"] == "ModuleNotFoundError: No module named 'scripts'"
assert t["execution"]["final_128_result_available"] is False

assert t["receipt_evidence"]["artifact_id"] == 11464055454
assert t["receipt_evidence"]["artifact_zip_sha256"] == "a292e0b1dfddb2cd6783ee242f5dd051126e0a7fbbff58e3af69bdea01bd74a0"
assert t["receipt_evidence"]["receipt_file_sha256"] == "c36f9722b562e6fee5b7ebc9c53b1b1cbef1a26c5c262bf8f53bf7da47904765"
assert t["receipt_evidence"]["receipt_canonical_sha256"] == "f065dd3178ac000504a57b4f5f7f73f74c5cce848c230f25316130619732a1f2"
assert t["receipt_evidence"]["phase_marker"] == "V12_DURABLE_CONSUME_SUCCESS"

assert t["output_evidence"] == {
    "execution_records_present": False,
    "native_scores_present": False,
    "summary_present": False,
    "artifact_file_count": 2,
}

assert not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_NOT_BE_PRESENT_IN_TERMINAL_AUDIT"
dsn = os.environ.get("VERITAS_DATABASE_URL", "")
if not dsn.startswith(("postgres://", "postgresql://")):
    raise SystemExit("REAL_POSTGRES_REQUIRED_FOR_V12_TERMINAL_AUDIT")

with psycopg.connect(dsn) as db:
    with db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",
            (AUTH_ID,),
        )
        n = cur.fetchone()[0]

assert n == 1, f"V12_TERMINAL_DURABLE_ROW_COUNT_MISMATCH:{n}"
assert t["durable_consumption"]["row_count_after_run"] == 1
assert t["durable_consumption"]["atomic_consumption_won"] is True
assert t["next_rule_of_one"] == "V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE_BEFORE_NEW_AUTHORIZATION"

print("PASS_V12_TERMINAL_DISPOSITION")
print("PASS_V12_DURABLE_CONSUMED_EXACTLY_ONCE")
print("PASS_V12_PROVIDER_CLIENT_CONSTRUCTED_PRE_API_FAILURE")
print("PASS_V12_PROVIDER_API_CALL_NOT_REACHED_BY_CONTROL_FLOW")
print("V12_REUSE_PROHIBITED=true")
print("durable_row=1")
print("provider_credential_access=1")
print("provider_client_constructed=1")
print("provider_api_calls=0")
print("final_128_execution=0")

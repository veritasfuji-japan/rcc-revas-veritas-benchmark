#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path
import psycopg

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
T = Path("contracts/AGENTDOJO_FINAL_128_V11_TERMINAL_DISPOSITION_v1.json")
A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v11.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V11_HUMAN_CONFIRMATION_v1.json")
R = Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_6.py")
W = Path("scripts/final_128_real_provider_wrapper_v9.py")
M = Path(".github/workflows/final-128-v11-manual-dispatch-template.yml")

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

assert t["status"] == "CONSUMED_PHASE1_PHASE2_FAILED_PRE_PROVIDER_API_NO_FINAL_RESULT"
assert t["authorization_id"] == AUTH_ID
assert t["authorization_reuse_prohibited"] is True
assert t["rerun_authorized"] is False

assert blob(A) == t["exact_blobs"]["authorization"]
assert blob(C) == t["exact_blobs"]["human_confirmation"]
assert blob(R) == t["exact_blobs"]["runner_v2_6"]
assert blob(W) == t["exact_blobs"]["wrapper_v9"]
assert blob(M) == t["exact_blobs"]["manual_dispatch_workflow"]

assert a["authorization"]["id"] == AUTH_ID
assert a["authorization"]["single_use"] is True
assert a["authorization"]["rerun_authorized"] is False
assert c["authorization_id"] == AUTH_ID
assert c["authorization_git_blob_sha"] == blob(A)
assert c["confirmation"]["single_consumption_only"] is True
assert c["confirmation"]["rerun_authorized"] is False

runner = R.read_text()
i_import = runner.index("from agentdojo.attacks.baseline_attacks import DirectAttack")
i_ledger = runner.index("ledger = BudgetLedger()", i_import)
i_client = runner.index("pipeline = build_pipeline(build_openai_client(ledger))", i_ledger)
assert i_import < i_ledger < i_client
assert t["provider_boundary"]["credential_available_in_phase2_process"] is True
assert t["provider_boundary"]["provider_client_constructed"] is False
assert t["provider_boundary"]["provider_api_calls"] == 0

assert not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_NOT_BE_PRESENT_IN_TERMINAL_AUDIT"
dsn = os.environ.get("VERITAS_DATABASE_URL", "")
if not dsn.startswith(("postgres://", "postgresql://")):
    raise SystemExit("REAL_POSTGRES_REQUIRED_FOR_V11_TERMINAL_AUDIT")

with psycopg.connect(dsn) as db:
    with db.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM bind_authorization_consumptions WHERE authorization_id=%s",
            (AUTH_ID,),
        )
        n = cur.fetchone()[0]

assert n == 1, f"V11_TERMINAL_DURABLE_ROW_COUNT_MISMATCH:{n}"
assert t["durable_consumption"]["row_count_after_run"] == 1
assert t["durable_consumption"]["atomic_consumption_won"] is True
assert t["execution"]["final_128_result_available"] is False
assert t["next_rule_of_one"] == "V12_RUNTIME_DEPENDENCY_IMPORT_CLOSURE_BEFORE_NEW_AUTHORIZATION"

print("PASS_V11_TERMINAL_DISPOSITION")
print("PASS_V11_DURABLE_CONSUMED_EXACTLY_ONCE")
print("PASS_V11_PROVIDER_CALL_NOT_REACHED_BY_CONTROL_FLOW")
print("V11_REUSE_PROHIBITED=true")
print("durable_row=1")
print("provider_client_constructed=0")
print("provider_api_calls=0")
print("final_128_execution=0")

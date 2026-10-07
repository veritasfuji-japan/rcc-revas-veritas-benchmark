#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
AUTH_BLOB = "f40f316eb40faa957454e6060682a49426295769"
CONFIRM_BLOB = "81151fb0e5dbde27524f1f1f02ddaab408686c41"
FREEZE_BLOB = "9ea9e6568884baf87b46d117d50aa5e3ba4cb52e"
BASE_MAIN = "3a6d33ded0b0c3c4c4ff75d4497306da5a3b8c27"
EXACT_APPROVAL = "最大5米ドルのOpenAI API利用を伴うCanonical Final 128を、V11を1回だけconsumeして実行することを承認します"

A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v11.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V11_HUMAN_CONFIRMATION_v1.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V11_TARGET_FREEZE_v1.json")
M = Path(".github/workflows/final-128-v11-manual-dispatch-template.yml")
W = Path("scripts/final_128_real_provider_wrapper_v9.py")
R = Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_6.py")
OUT = Path("results/agentdojo-clean-ab-final-v11")
RECEIPT = Path(".v11_handoff/v11_dispatch_receipt.json")

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

a = json.loads(A.read_text())
c = json.loads(C.read_text())
f = json.loads(F.read_text())

assert blob(A) == AUTH_BLOB
assert blob(C) == CONFIRM_BLOB
assert blob(F) == FREEZE_BLOB

assert f["authorization_ready"] is True
assert f["authorization_blockers"] == []
assert f["authorization_id"] == AUTH_ID

assert blob(R) == f["frozen_blobs"]["runner_v2_6"]
assert blob(W) == f["frozen_blobs"]["wrapper_v9"]
assert blob(M) == f["frozen_blobs"]["manual_dispatch_workflow"]

assert a["authorization"] == {
    "id": AUTH_ID,
    "issued": True,
    "single_use": True,
    "consumed": False,
    "rerun_authorized": False,
}
assert a["dispatch"] == {
    "provider_dispatch_authorized": True,
    "manual_dispatch_authorized": True,
}
assert a["cost_boundary"]["maximum_usd"] == 5
assert a["freeze_contract"]["git_blob_sha"] == FREEZE_BLOB
assert a["freeze_contract"]["authorization_ready"] is True
assert a["freeze_contract"]["authorization_blockers"] == 0
assert a["frozen_target"] == {
    "runner_git_blob_sha": f["frozen_blobs"]["runner_v2_6"],
    "wrapper_git_blob_sha": f["frozen_blobs"]["wrapper_v9"],
    "manual_dispatch_workflow_git_blob_sha": f["frozen_blobs"]["manual_dispatch_workflow"],
}
assert a["external_pins"] == f["external_pins"]

assert c["authorization_id"] == AUTH_ID
assert c["authorization_git_blob_sha"] == AUTH_BLOB
assert c["exact_confirmation"] == EXACT_APPROVAL
assert c["confirmation"] == {
    "received": True,
    "maximum_usd": 5,
    "single_consumption_only": True,
    "rerun_authorized": False,
}
assert c["provider_dispatch_authorized"] is True
assert c["manual_dispatch_authorized"] is True

manual = M.read_text()
phase1_start = manual.index("- name: Phase 1 durable consume and receipt")
phase2_start = manual.index("- name: Phase 2 receipt verification and provider execution")
assert phase1_start < phase2_start
phase1 = manual[phase1_start:phase2_start]
phase2 = manual[phase2_start:]
assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "RUN_FINAL_128_V11_ONCE" in manual

assert not OUT.exists(), "PREEXISTING_FINAL_128_OUTPUT_DIR"
assert not RECEIPT.exists(), "PREEXISTING_V11_RECEIPT"
assert not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_BE_UNAVAILABLE_DURING_PRE_DISPATCH"
assert os.environ.get("PRE_DISPATCH_BASE_MAIN_SHA") == BASE_MAIN

print("PASS_V11_STATIC_FINAL_PRE_DISPATCH_AUDIT")
print(f"pre_dispatch_base_main_sha={BASE_MAIN}")
print(f"authorization_git_blob_sha={AUTH_BLOB}")
print(f"human_confirmation_git_blob_sha={CONFIRM_BLOB}")
print("preexisting_output_dir=0")
print("preexisting_receipt=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

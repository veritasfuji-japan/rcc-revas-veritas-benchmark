#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
AUTH_BLOB = "5011d3def553f88a132ccb068a55b5953a32aa23"
CONFIRM_BLOB = "bb050e4dda41fec98b2efb6942339d394fd2b40e"
FREEZE_BLOB = "54089a67b81161118cafbe16c228a5ddaf77a39f"
BASE_MAIN = "da53464a9f2a19cd4e8ff8a45158553a592a66e3"
EXACT_APPROVAL = "最大5米ドルのOpenAI API利用を伴うCanonical Final 128を、V12を1回だけconsumeして実行することを承認します"

A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V12_TARGET_FREEZE_v1.json")
M = Path(".github/workflows/final-128-v12-manual-dispatch-template.yml")
W = Path("scripts/final_128_real_provider_wrapper_v10.py")
R = Path("scripts/agentdojo_clean_ab_canonical_final_runner_v2_7.py")
E = Path("scripts/final_128_v12_locked_agentdojo_requirements_v1.py")
I = Path("scripts/final_128_v12_runtime_dependency_import_closure_v1.py")
OUT = Path("results/agentdojo-clean-ab-final-v12")
RECEIPT = Path(".v12_handoff/v12_dispatch_receipt.json")

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

assert blob(R) == f["frozen_blobs"]["runner_v2_7"]
assert blob(W) == f["frozen_blobs"]["wrapper_v10"]
assert blob(M) == f["frozen_blobs"]["manual_dispatch_workflow"]
assert blob(E) == f["frozen_blobs"]["locked_requirements_emitter"]
assert blob(I) == f["frozen_blobs"]["runtime_dependency_import_closure"]

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
assert a["cost_boundary"] == {"maximum_usd": 5, "currency": "USD"}
assert a["freeze_contract"]["git_blob_sha"] == FREEZE_BLOB
assert a["freeze_contract"]["authorization_ready"] is True
assert a["freeze_contract"]["authorization_blockers"] == 0
assert a["frozen_target"] == {
    "runner_git_blob_sha": f["frozen_blobs"]["runner_v2_7"],
    "wrapper_git_blob_sha": f["frozen_blobs"]["wrapper_v10"],
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
ordered = [
    "- name: Install exact V12 runtime",
    "- name: Pre-consume runtime dependency import closure",
    "- name: Pre-consume shared control-flow provider-boundary preflight",
    "- name: Phase 1 durable consume and receipt",
    "- name: Phase 2 receipt verification and provider execution",
]
positions = [manual.index(x) for x in ordered]
assert positions == sorted(positions)

install_start, import_start, shared_start, phase1_start, phase2_start = positions
pre_import = manual[import_start:shared_start]
pre_shared = manual[shared_start:phase1_start]
phase1 = manual[phase1_start:phase2_start]
phase2 = manual[phase2_start:]

assert 'OPENAI_API_KEY: ""' in pre_import
assert 'VERITAS_DATABASE_URL: ""' in pre_import
assert 'OPENAI_API_KEY: ""' in pre_shared
assert 'VERITAS_DATABASE_URL: ""' in pre_shared
assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase1
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase2
assert "RUN_FINAL_128_V12_ONCE" in manual
assert ".v12_handoff/v12_dispatch_receipt.json" in manual
assert "results/agentdojo-clean-ab-final-v12" in manual

assert not OUT.exists(), "PREEXISTING_FINAL_128_OUTPUT_DIR"
assert not RECEIPT.exists(), "PREEXISTING_V12_RECEIPT"
assert not os.environ.get("OPENAI_API_KEY"), "OPENAI_API_KEY_MUST_BE_UNAVAILABLE_DURING_PRE_DISPATCH"
assert os.environ.get("PRE_DISPATCH_BASE_MAIN_SHA") == BASE_MAIN

print("PASS_V12_STATIC_FINAL_PRE_DISPATCH_AUDIT")
print(f"pre_dispatch_base_main_sha={BASE_MAIN}")
print(f"authorization_git_blob_sha={AUTH_BLOB}")
print(f"human_confirmation_git_blob_sha={CONFIRM_BLOB}")
print(f"freeze_git_blob_sha={FREEZE_BLOB}")
print("preexisting_output_dir=0")
print("preexisting_receipt=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

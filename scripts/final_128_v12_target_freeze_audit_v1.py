#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
F = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_TARGET_FREEZE_v1.json"
d = json.loads(F.read_text())

AUTH_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json"
CONFIRM_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json"

assert d["status"] == "FROZEN_SOURCE_TARGET_PRE_AUTHORIZATION_READY"
assert d["authorization_ready"] is True
assert d["frozen_from_main_sha"] == "21ff89f27e158c624f3d33ae58be983428929523"
assert d["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
assert d["authorization_blockers"] == []

paths = {
    "runner_v2_7": "scripts/agentdojo_clean_ab_canonical_final_runner_v2_7.py",
    "wrapper_v10": "scripts/final_128_real_provider_wrapper_v10.py",
    "manual_dispatch_workflow": ".github/workflows/final-128-v12-manual-dispatch-template.yml",
    "locked_requirements_emitter": "scripts/final_128_v12_locked_agentdojo_requirements_v1.py",
    "runtime_dependency_import_closure": "scripts/final_128_v12_runtime_dependency_import_closure_v1.py",
    "runtime_target_construction_audit": "scripts/final_128_v12_runtime_target_construction_audit_v1.py",
    "runtime_target_construction_workflow": ".github/workflows/final-128-v12-runtime-target-construction.yml",
    "exact_model_configuration": "contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json",
}
evidence_paths = {
    "v11_terminal_disposition": "contracts/AGENTDOJO_FINAL_128_V11_TERMINAL_DISPOSITION_v1.json",
    "v12_runtime_dependency_import_closure_contract": "contracts/AGENTDOJO_FINAL_128_V12_RUNTIME_DEPENDENCY_IMPORT_CLOSURE_v1.json",
    "v12_runtime_target_construction_contract": "contracts/AGENTDOJO_FINAL_128_V12_RUNTIME_TARGET_CONSTRUCTION_v1.json",
}

def blob(path: str) -> str:
    return subprocess.run(
        ["git", "hash-object", path],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

for key, path in paths.items():
    actual = blob(path)
    expected = d["frozen_blobs"][key]
    assert actual == expected, (key, actual, expected)

for key, path in evidence_paths.items():
    actual = blob(path)
    expected = d["evidence_blobs"][key]
    assert actual == expected, (key, actual, expected)

assert d["external_pins"] == {
    "agentdojo": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
    "agentdojo_pyproject_git_blob_sha": "71930851807e5f0e23f084b652c0908f06a36138",
    "agentdojo_uv_lock_git_blob_sha": "bdf5de4904c18ccdd3cf06d5c1396c79bf5197e3",
    "rcc": "1d3782d3aae5ff9c88036709c1a5642320cc53c2",
    "veritas_os": "a1d66aef02262cf8a913295270c3aafd159c6adb",
    "model": "gpt-4.1-mini-2025-04-14",
    "python": "3.11.16",
}

assert d["execution_state"] == {
    "authorization_issued": False,
    "human_confirmation_received": False,
    "durable_consume": 0,
    "provider_credential_access": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
}
assert not AUTH_PATH.exists()
assert not CONFIRM_PATH.exists()

runner = (ROOT / paths["runner_v2_7"]).read_text()
wrapper = (ROOT / paths["wrapper_v10"]).read_text()
manual = (ROOT / paths["manual_dispatch_workflow"]).read_text()
target_workflow = (ROOT / paths["runtime_target_construction_workflow"]).read_text()

assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12" in runner
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11" not in runner
assert "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_7" in runner

for needle in (
    "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12",
    "RUN_FINAL_128_V12_ONCE",
    "runtime_component_blobs",
    "V12_RECEIPT_WRAPPER_BINDING_MISMATCH",
    "V12_RECEIPT_MANUAL_DISPATCH_WORKFLOW_BINDING_MISMATCH",
):
    assert needle in wrapper, needle
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11" not in wrapper
assert "agentdojo-final-128-v11" not in wrapper

ordered = [
    "- name: Install exact V12 runtime",
    "- name: Pre-consume runtime dependency import closure",
    "- name: Pre-consume shared control-flow provider-boundary preflight",
    "- name: Phase 1 durable consume and receipt",
    "- name: Phase 2 receipt verification and provider execution",
]
positions = [manual.index(x) for x in ordered]
assert positions == sorted(positions)

pre1 = manual[positions[1]:positions[2]]
pre2 = manual[positions[2]:positions[3]]
phase1 = manual[positions[3]:positions[4]]
phase2 = manual[positions[4]:]
assert 'OPENAI_API_KEY: ""' in pre1
assert 'VERITAS_DATABASE_URL: ""' in pre1
assert 'OPENAI_API_KEY: ""' in pre2
assert 'VERITAS_DATABASE_URL: ""' in pre2
assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase1
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase2
assert ".v12_handoff/v12_dispatch_receipt.json" in manual
assert "results/agentdojo-clean-ab-final-v12" in manual

CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
for path, text in [
    (paths["manual_dispatch_workflow"], manual),
    (paths["runtime_target_construction_workflow"], target_workflow),
]:
    assert "actions/checkout@v4" not in text, path
    assert "actions/setup-python@v5" not in text, path
    assert "actions/upload-artifact@v4" not in text, path
    assert CHECKOUT in text, path
    assert SETUP in text, path
    assert UPLOAD in text, path

assert d["reproducibility_observations"] == {
    "actions_checkout_ref": CHECKOUT,
    "actions_setup_python_ref": SETUP,
    "actions_upload_artifact_ref": UPLOAD,
    "mutable_major_action_refs_remain_in_v12_runtime": False,
}
assert d["closed_pre_authorization_controls"] == [
    "V12_RUNTIME_DEPENDENCY_IMPORT_CLOSURE",
    "V12_PRECONSUME_SHARED_CONTROL_FLOW_GATE",
    "V12_RUNTIME_COMPONENT_SELF_BINDING",
    "V12_IMMUTABLE_GITHUB_ACTION_REFS",
]

print("PASS_V12_EXACT_RUNTIME_TARGET_FREEZE")
print("PASS_V12_RUNTIME_COMPONENT_SELF_BINDING")
print("PASS_V12_PRECONSUME_GATE_FREEZE")
print("PASS_V12_IMMUTABLE_GITHUB_ACTION_REFS")
print("V12_AUTHORIZATION_READY=true")
print("authorization_blockers=0")
print("authorization_issued=0")
print("human_confirmation=0")
print("database_write=0")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
F = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_TARGET_FREEZE_v1.json"
AUTH_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json"
CONFIRM_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json"

FREEZE_BLOB = "331c3b4ea26d19e3d4926b22ff93f6f581c8ff84"
d = json.loads(F.read_text())

def blob(path: str | Path) -> str:
    p = Path(path)
    if p.is_absolute():
        p = p.relative_to(ROOT)
    return subprocess.run(
        ["git", "hash-object", str(p)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

assert blob(F) == FREEZE_BLOB
assert d["status"] == "FROZEN_SOURCE_TARGET_PRE_AUTHORIZATION_READY"
assert d["authorization_ready"] is True
assert d["frozen_from_main_sha"] == "bc185fcfbc0025b2d29f6e4e323907e396edc6e1"
assert d["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"
assert d["authorization_blockers"] == []

paths = {
    "runner_v2_8": "scripts/agentdojo_clean_ab_canonical_final_runner_v2_8.py",
    "wrapper_v11": "scripts/final_128_real_provider_wrapper_v11.py",
    "manual_dispatch_workflow": ".github/workflows/final-128-v13-manual-dispatch-template.yml",
    "locked_requirements_emitter": "scripts/final_128_v12_locked_agentdojo_requirements_v1.py",
    "runtime_dependency_import_closure": "scripts/final_128_v13_runtime_dependency_import_closure_v1.py",
    "entrypoint_import_closure_audit": "scripts/final_128_v13_execution_entrypoint_import_path_closure_audit_v1.py",
    "entrypoint_import_closure_workflow": ".github/workflows/final-128-v13-execution-entrypoint-import-path-closure.yml",
    "runtime_target_construction_audit": "scripts/final_128_v13_runtime_target_construction_audit_v1.py",
    "runtime_target_construction_workflow": ".github/workflows/final-128-v13-runtime-target-construction.yml",
    "exact_model_configuration": "contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json",
}
evidence_paths = {
    "v12_terminal_disposition": "contracts/AGENTDOJO_FINAL_128_V12_TERMINAL_DISPOSITION_v1.json",
    "v13_entrypoint_import_closure_contract": "contracts/AGENTDOJO_FINAL_128_V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE_v1.json",
    "v13_runtime_target_construction_contract": "contracts/AGENTDOJO_FINAL_128_V13_RUNTIME_TARGET_CONSTRUCTION_v1.json",
}

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
    "provider_client_constructed": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
}
assert not AUTH_PATH.exists(), "V13_AUTHORIZATION_MUST_NOT_EXIST_AT_FREEZE"
assert not CONFIRM_PATH.exists(), "V13_CONFIRMATION_MUST_NOT_EXIST_AT_FREEZE"

v12_terminal = json.loads((ROOT / evidence_paths["v12_terminal_disposition"]).read_text())
assert v12_terminal["authorization_reuse_prohibited"] is True
assert v12_terminal["rerun_authorized"] is False

runner = (ROOT / paths["runner_v2_8"]).read_text()
wrapper = (ROOT / paths["wrapper_v11"]).read_text()
manual = (ROOT / paths["manual_dispatch_workflow"]).read_text()
target_workflow = (ROOT / paths["runtime_target_construction_workflow"]).read_text()
entry_workflow = (ROOT / paths["entrypoint_import_closure_workflow"]).read_text()

assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13" in runner
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12" not in runner
assert "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_8" in runner
assert "--entrypoint-import-preflight" in runner
assert "sys.path.insert(0, str(ROOT))" in runner

for needle in (
    "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13",
    "RUN_FINAL_128_V13_ONCE",
    "runtime_component_blobs",
    "V13_RECEIPT_WRAPPER_BINDING_MISMATCH",
    "V13_RECEIPT_MANUAL_DISPATCH_WORKFLOW_BINDING_MISMATCH",
    "V13_DURABLE_CONSUME_SUCCESS",
):
    assert needle in wrapper, needle
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12" not in wrapper

ordered = [
    "- name: Install exact V13 runtime",
    "- name: Pre-consume runtime dependency import closure",
    "- name: Pre-consume actual runner entrypoint import closure",
    "- name: Pre-consume shared control-flow provider-boundary preflight",
    "- name: Phase 1 durable consume and receipt",
    "- name: Phase 2 receipt verification and provider execution",
]
positions = [manual.index(x) for x in ordered]
assert positions == sorted(positions)

dep = manual[positions[1]:positions[2]]
entry = manual[positions[2]:positions[3]]
shared = manual[positions[3]:positions[4]]
phase1 = manual[positions[4]:positions[5]]
phase2 = manual[positions[5]:]

for segment in (dep, entry, shared):
    assert 'OPENAI_API_KEY: ""' in segment
    assert 'VERITAS_DATABASE_URL: ""' in segment
assert "agentdojo_clean_ab_canonical_final_runner_v2_8.py" in entry
assert "--entrypoint-import-preflight" in entry
assert "final_128_real_provider_wrapper_v11.py" in shared
assert "--provider-free-preflight" in shared

assert 'OPENAI_API_KEY: ""' in phase1
assert "secrets.OPENAI_API_KEY" not in phase1
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase1
assert "if: success()" in phase2
assert "secrets.OPENAI_API_KEY" in phase2
assert "secrets.VERITAS_ATOMIC_CONSUMPTION_DATABASE_URL" in phase2
assert ".v13_handoff/v13_dispatch_receipt.json" in manual
assert "results/agentdojo-clean-ab-final-v13" in manual

CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"

for path, text_body in [
    (paths["manual_dispatch_workflow"], manual),
    (paths["runtime_target_construction_workflow"], target_workflow),
    (paths["entrypoint_import_closure_workflow"], entry_workflow),
]:
    assert "actions/checkout@v4" not in text_body, path
    assert "actions/setup-python@v5" not in text_body, path
    assert "actions/upload-artifact@v4" not in text_body, path
    assert CHECKOUT in text_body, path
    assert SETUP in text_body, path
    if "upload-artifact" in text_body:
        assert UPLOAD in text_body, path

assert d["reproducibility_observations"] == {
    "actions_checkout_ref": CHECKOUT,
    "actions_setup_python_ref": SETUP,
    "actions_upload_artifact_ref": UPLOAD,
    "mutable_major_action_refs_remain_in_v13_runtime": False,
}

assert d["closed_pre_authorization_controls"] == [
    "V13_RUNTIME_DEPENDENCY_IMPORT_CLOSURE",
    "V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE",
    "V13_PRECONSUME_SHARED_CONTROL_FLOW_GATE",
    "V13_PRECONSUME_GATE_ORDER",
    "V13_RUNTIME_COMPONENT_SELF_BINDING",
    "V13_IMMUTABLE_GITHUB_ACTION_REFS",
    "V12_REUSE_PROHIBITION_PRESERVED",
]

for key in (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_API_KEY",
    "GCP_PROJECT",
    "GCP_LOCATION",
    "VERITAS_DATABASE_URL",
):
    assert not os.environ.get(key), f"CREDENTIAL_PRESENT_IN_V13_FREEZE:{key}"

print("PASS_V13_EXACT_RUNTIME_TARGET_FREEZE")
print("PASS_V13_RUNTIME_COMPONENT_SELF_BINDING")
print("PASS_V13_PRECONSUME_GATE_FREEZE")
print("PASS_V13_ENTRYPOINT_IMPORT_GATE_FREEZE")
print("PASS_V13_IMMUTABLE_GITHUB_ACTION_REFS")
print("PASS_V13_V12_REUSE_PROHIBITION_PRESERVED")
print("V13_AUTHORIZATION_READY=true")
print("authorization_blockers=0")
print("authorization_issued=0")
print("human_confirmation=0")
print("database_write=0")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_client_constructed=0")
print("provider_api_calls=0")
print("final_128_execution=0")

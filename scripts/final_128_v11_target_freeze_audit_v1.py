#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

F = Path("contracts/AGENTDOJO_FINAL_128_V11_TARGET_FREEZE_v1.json")
d = json.loads(F.read_text())

assert d["status"] == "FROZEN_SOURCE_TARGET_PRE_AUTHORIZATION_READY"
assert d["authorization_ready"] is True
assert d["frozen_from_main_sha"] == "434f2467f5342b589e4972f23ddf388b12246e92"
assert d["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"
assert d["authorization_blockers"] == []

paths = {
    "runner_v2_6": "scripts/agentdojo_clean_ab_canonical_final_runner_v2_6.py",
    "wrapper_v9": "scripts/final_128_real_provider_wrapper_v9.py",
    "manual_dispatch_workflow": ".github/workflows/final-128-v11-manual-dispatch-template.yml",
    "actual_path_provider_free_workflow": ".github/workflows/final-128-v11-actual-path-provider-free.yml",
    "credential_boundary_semantic_audit": "scripts/final_128_v11_credential_boundary_audit_v1.py",
    "credential_boundary_provider_free_helper": "scripts/final_128_v11_credential_boundary_v1.py",
    "credential_boundary_provider_free_workflow": ".github/workflows/final-128-v11-credential-boundary-provider-free.yml",
    "corrected_chain_provider_free_workflow": ".github/workflows/final-128-v11-corrected-chain-provider-free.yml",
    "exact_model_configuration": "contracts/AGENTDOJO_EXACT_MODEL_CONFIGURATION_v0.1.json",
}

def blob(path: str) -> str:
    return subprocess.run(
        ["git", "hash-object", path],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

for key, path in paths.items():
    actual = blob(path)
    expected = d["frozen_blobs"][key]
    assert actual == expected, (key, actual, expected)

assert d["external_pins"] == {
    "agentdojo": "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
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
assert not Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v11.json").exists()
assert not Path("contracts/AGENTDOJO_FINAL_128_V11_HUMAN_CONFIRMATION_v1.json").exists()

wrapper = Path(paths["wrapper_v9"]).read_text()
assert '"wrapper_git_blob_sha"' in wrapper
assert '"manual_dispatch_workflow_git_blob_sha"' in wrapper
assert "runtime_component_blobs" in wrapper
assert "V11_RECEIPT_WRAPPER_BINDING_MISMATCH" in wrapper
assert "V11_RECEIPT_MANUAL_DISPATCH_WORKFLOW_BINDING_MISMATCH" in wrapper

CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
workflow_paths = [
    paths["manual_dispatch_workflow"],
    paths["actual_path_provider_free_workflow"],
    paths["credential_boundary_provider_free_workflow"],
    paths["corrected_chain_provider_free_workflow"],
]
for path in workflow_paths:
    text = Path(path).read_text()
    assert "actions/checkout@v4" not in text, path
    assert "actions/setup-python@v5" not in text, path
    assert "actions/upload-artifact@v4" not in text, path
    assert CHECKOUT in text, path

manual = Path(paths["manual_dispatch_workflow"]).read_text()
actual = Path(paths["actual_path_provider_free_workflow"]).read_text()
corrected = Path(paths["corrected_chain_provider_free_workflow"]).read_text()
assert SETUP in manual
assert SETUP in actual
assert SETUP in corrected
assert UPLOAD in manual

assert d["reproducibility_observations"] == {
    "actions_checkout_ref": CHECKOUT,
    "actions_setup_python_ref": SETUP,
    "actions_upload_artifact_ref": UPLOAD,
    "mutable_major_action_refs_remain": False,
}
assert d["closed_pre_authorization_controls"] == [
    "V11_RUNTIME_COMPONENT_SELF_BINDING",
    "V11_IMMUTABLE_GITHUB_ACTION_REFS",
]

print("PASS_V11_EXACT_SOURCE_TARGET_FREEZE")
print("PASS_V11_RUNTIME_COMPONENT_SELF_BINDING_SOURCE_CLOSURE")
print("PASS_V11_IMMUTABLE_GITHUB_ACTION_REFS")
print("V11_AUTHORIZATION_READY=true")
print("authorization_blockers=0")
print("authorization_issued=0")
print("human_confirmation=0")
print("database_write=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

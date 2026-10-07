#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

F = Path("contracts/AGENTDOJO_FINAL_128_V11_TARGET_FREEZE_v1.json")
d = json.loads(F.read_text())

assert d["status"] == "FROZEN_SOURCE_TARGET_PRE_AUTHORIZATION_WITH_BLOCKERS"
assert d["authorization_ready"] is False
assert d["frozen_from_main_sha"] == "74cb7ce323904440bd9e135df2570376a3130d17"
assert d["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11"

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
manual = Path(paths["manual_dispatch_workflow"]).read_text()

# Explicitly preserve the two known blockers rather than silently overclaiming.
assert 'a["frozen_target"]["wrapper_git_blob_sha"]' not in wrapper
assert 'a["frozen_target"]["manual_dispatch_workflow_git_blob_sha"]' not in wrapper
assert "actions/checkout@v4" in manual
assert "actions/setup-python@v5" in manual
assert "actions/upload-artifact@v4" in manual
assert d["reproducibility_observations"]["mutable_major_action_refs_remain"] is True
assert len(d["authorization_blockers"]) == 2

print("PASS_V11_EXACT_SOURCE_TARGET_FREEZE")
print("V11_AUTHORIZATION_READY=false")
print("BLOCKER_V11_RUNTIME_COMPONENT_SELF_BINDING_NOT_CLOSED")
print("BLOCKER_V11_MUTABLE_GITHUB_ACTION_REFS_REMAIN")

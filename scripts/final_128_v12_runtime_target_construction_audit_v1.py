#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_RUNTIME_TARGET_CONSTRUCTION_v1.json"
RUNNER = ROOT / "scripts/agentdojo_clean_ab_canonical_final_runner_v2_7.py"
WRAPPER = ROOT / "scripts/final_128_real_provider_wrapper_v10.py"
MANUAL = ROOT / ".github/workflows/final-128-v12-manual-dispatch-template.yml"
EMITTER = ROOT / "scripts/final_128_v12_locked_agentdojo_requirements_v1.py"
IMPORT_CLOSURE = ROOT / "scripts/final_128_v12_runtime_dependency_import_closure_v1.py"
V11_TERMINAL = ROOT / "contracts/AGENTDOJO_FINAL_128_V11_TERMINAL_DISPOSITION_v1.json"
V12_IMPORT_CONTRACT = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_RUNTIME_DEPENDENCY_IMPORT_CLOSURE_v1.json"
OUT = ROOT / "results/v12-runtime-target-construction.json"

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
AUTH_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json"
CONFIRM_PATH = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json"

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path.relative_to(ROOT))],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

for key in (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_API_KEY",
    "GCP_PROJECT",
    "GCP_LOCATION",
    "VERITAS_DATABASE_URL",
):
    if os.environ.get(key):
        raise SystemExit(f"CREDENTIAL_PRESENT_IN_V12_TARGET_AUDIT:{key}")

c = json.loads(C.read_text())
assert c["status"] == "RUNTIME_TARGET_CONSTRUCTED_PRE_FREEZE"
assert c["authorization_id"] == AUTH_ID
assert c["authorization_issued"] is False
assert c["human_confirmation_received"] is False
assert c["durable_consume"] == 0
assert c["provider_credential_access"] == 0
assert c["provider_api_calls"] == 0
assert c["final_128_execution"] == 0

expected = c["candidate_runtime_blobs"]
actual = {
    "runner_v2_7": blob(RUNNER),
    "wrapper_v10": blob(WRAPPER),
    "manual_dispatch_workflow_v12": blob(MANUAL),
    "locked_requirements_emitter": blob(EMITTER),
    "runtime_dependency_import_closure": blob(IMPORT_CLOSURE),
}
assert actual == expected, (actual, expected)

assert blob(V11_TERMINAL) == c["prior_evidence"]["v11_terminal_disposition_git_blob_sha"]
assert blob(V12_IMPORT_CONTRACT) == c["prior_evidence"]["v12_import_closure_contract_git_blob_sha"]

assert not AUTH_PATH.exists(), "V12_AUTHORIZATION_MUST_NOT_EXIST_DURING_TARGET_CONSTRUCTION"
assert not CONFIRM_PATH.exists(), "V12_HUMAN_CONFIRMATION_MUST_NOT_EXIST_DURING_TARGET_CONSTRUCTION"

runner = RUNNER.read_text()
assert 'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12' in runner
assert 'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11' not in runner
assert 'RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_7' in runner

wrapper = WRAPPER.read_text()
for needle in (
    'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12',
    'RUN_FINAL_128_V12_ONCE',
    'agentdojo_clean_ab_canonical_final_runner_v2_7.py',
    'final-128-v12-manual-dispatch-template.yml',
):
    assert needle in wrapper, needle
assert 'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V11' not in wrapper
assert 'agentdojo-final-128-v11' not in wrapper

manual = MANUAL.read_text()
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
assert "RUN_FINAL_128_V12_ONCE" in manual
assert ".v12_handoff/v12_dispatch_receipt.json" in manual
assert "results/agentdojo-clean-ab-final-v12" in manual

result = {
    "status": "PASS_V12_RUNTIME_TARGET_CONSTRUCTION",
    "authorization_id": AUTH_ID,
    "candidate_runtime_blobs": actual,
    "preconsume_dependency_import_gate": True,
    "preconsume_shared_flow_gate": True,
    "authorization_issued": 0,
    "human_confirmation": 0,
    "database_write": 0,
    "durable_consume": 0,
    "provider_credential_access": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, sort_keys=True))
print("PASS_V12_PRECONSUME_GATE_ORDER")
print("PASS_V12_RUNTIME_COMPONENT_EXACT_BLOBS")

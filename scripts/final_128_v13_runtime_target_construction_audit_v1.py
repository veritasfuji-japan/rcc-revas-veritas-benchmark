#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_RUNTIME_TARGET_CONSTRUCTION_v1.json"
T12 = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_TERMINAL_DISPOSITION_v1.json"
E13 = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE_v1.json"
RUNNER = ROOT / "scripts/agentdojo_clean_ab_canonical_final_runner_v2_8.py"
WRAPPER = ROOT / "scripts/final_128_real_provider_wrapper_v11.py"
MANUAL = ROOT / ".github/workflows/final-128-v13-manual-dispatch-template.yml"
DEP = ROOT / "scripts/final_128_v13_runtime_dependency_import_closure_v1.py"
EMITTER = ROOT / "scripts/final_128_v12_locked_agentdojo_requirements_v1.py"
AUTH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json"
CONFIRM = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json"
OUT = ROOT / "results/v13-runtime-target-construction.json"

CONTRACT_BLOB = "b008c586a2669f87e326bf12ea7963c7d32b9c9f"

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
        raise SystemExit(f"CREDENTIAL_PRESENT_IN_V13_TARGET_AUDIT:{key}")

c = json.loads(C.read_text())
t12 = json.loads(T12.read_text())
e13 = json.loads(E13.read_text())

assert blob(C) == CONTRACT_BLOB
assert c["status"] == "RUNTIME_TARGET_CONSTRUCTED_PRE_FREEZE"
assert c["rule_of_one"] == "V13_RUNTIME_TARGET_CONSTRUCTION_BEFORE_EXACT_FREEZE"
assert c["base_main_sha"] == "e9928a00ad793c0f04ae2e4bae24396fdb875260"
assert c["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"

assert t12["authorization_reuse_prohibited"] is True
assert t12["rerun_authorized"] is False
assert blob(T12) == c["prior_evidence"]["v12_terminal_disposition_git_blob_sha"]
assert e13["status"] == "ENTRYPOINT_IMPORT_PATH_CLOSED_PRE_AUTHORIZATION"
assert blob(E13) == c["prior_evidence"]["v13_entrypoint_import_closure_contract_git_blob_sha"]

actual = {
    "runner_v2_8": blob(RUNNER),
    "wrapper_v11": blob(WRAPPER),
    "manual_dispatch_workflow_v13": blob(MANUAL),
    "runtime_dependency_import_closure_v13": blob(DEP),
    "locked_requirements_emitter": blob(EMITTER),
}
assert actual == c["candidate_runtime_blobs"], (actual, c["candidate_runtime_blobs"])

assert not AUTH.exists(), "V13_AUTHORIZATION_MUST_NOT_EXIST_DURING_TARGET_CONSTRUCTION"
assert not CONFIRM.exists(), "V13_HUMAN_CONFIRMATION_MUST_NOT_EXIST_DURING_TARGET_CONSTRUCTION"

runner = RUNNER.read_text()
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13" in runner
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12" not in runner
assert "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_8" in runner
assert "--entrypoint-import-preflight" in runner
assert "PASS_V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE" in runner

wrapper = WRAPPER.read_text()
for needle in (
    "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13",
    "RUN_FINAL_128_V13_ONCE",
    "agentdojo_clean_ab_canonical_final_runner_v2_8.py",
    "final-128-v13-manual-dispatch-template.yml",
    "V13_DURABLE_CONSUME_SUCCESS",
):
    assert needle in wrapper, needle
assert "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12" not in wrapper
assert "final-v12" not in wrapper

manual = MANUAL.read_text()
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

p_install, p_dep, p_entry, p_shared, p1, p2 = positions
dep = manual[p_dep:p_entry]
entry = manual[p_entry:p_shared]
shared = manual[p_shared:p1]
phase1 = manual[p1:p2]
phase2 = manual[p2:]

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
assert "RUN_FINAL_128_V13_ONCE" in manual
assert ".v13_handoff/v13_dispatch_receipt.json" in manual
assert "results/agentdojo-clean-ab-final-v13" in manual

assert c["authorization_issued"] is False
assert c["human_confirmation_received"] is False
assert c["durable_consume"] == 0
assert c["provider_credential_access"] == 0
assert c["provider_client_constructed"] == 0
assert c["provider_api_calls"] == 0
assert c["final_128_execution"] == 0

result = {
    "status": "PASS_V13_RUNTIME_TARGET_CONSTRUCTION",
    "authorization_id": c["authorization_id"],
    "candidate_runtime_blobs": actual,
    "preconsume_dependency_import_gate": True,
    "preconsume_entrypoint_import_gate": True,
    "preconsume_shared_flow_gate": True,
    "authorization_issued": 0,
    "human_confirmation": 0,
    "database_write": 0,
    "durable_consume": 0,
    "provider_credential_access": 0,
    "provider_client_constructed": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
}
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps(result, sort_keys=True))
print("PASS_V13_PRECONSUME_GATE_ORDER")
print("PASS_V13_RUNTIME_COMPONENT_EXACT_BLOBS")
print("PASS_V13_V12_REUSE_PROHIBITION_PRESERVED")

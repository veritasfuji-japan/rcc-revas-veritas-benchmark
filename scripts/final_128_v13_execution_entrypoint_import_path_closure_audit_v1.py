#!/usr/bin/env python3
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(".")
T = ROOT / "contracts/AGENTDOJO_FINAL_128_V12_TERMINAL_DISPOSITION_v1.json"
C = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE_v1.json"
R = ROOT / "scripts/agentdojo_clean_ab_canonical_final_runner_v2_8.py"
I = ROOT / "scripts/agentdojo_final_runner_integration_v0_1.py"
A = ROOT / "scripts/agentdojo_openai_frozen_adapter_v0_1.py"
E = ROOT / "scripts/final_128_v12_locked_agentdojo_requirements_v1.py"
V13_AUTH = ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json"
V13_CONFIRM = ROOT / "contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json"

TERMINAL_BLOB = "f755fd00f7ffd8f9a5294866ac38005268b180f1"
CONTRACT_BLOB = "bf3e8bd19a58ad52979bb1f62660b823ceeea82e"
RUNNER_BLOB = "c745679a71aed17f01357d6dce49cfdd679a5c7c"
INTEGRATION_BLOB = "c1e26ae453c15e7732cca959030ab833d23174bf"
ADAPTER_BLOB = "53a79d9a3f4a55c24ebb4a51f2edbd6542b81105"
EMITTER_BLOB = "4d414d26a33656edb4a674963e3df96d59e74391"

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

c = json.loads(C.read_text())
t = json.loads(T.read_text())
runner = R.read_text()

assert blob(T) == TERMINAL_BLOB
assert blob(C) == CONTRACT_BLOB
assert blob(R) == RUNNER_BLOB
assert blob(I) == INTEGRATION_BLOB
assert blob(A) == ADAPTER_BLOB
assert blob(E) == EMITTER_BLOB

assert c["status"] == "ENTRYPOINT_IMPORT_PATH_CLOSED_PRE_AUTHORIZATION"
assert c["base_main_sha"] == "9373b9fa1a273c2762f7ac7e59922322175bb7b1"
assert c["prior_terminal_disposition"]["git_blob_sha"] == TERMINAL_BLOB
assert t["authorization_reuse_prohibited"] is True
assert t["rerun_authorized"] is False

assert c["candidate_runner"]["git_blob_sha"] == RUNNER_BLOB
assert c["candidate_runner"]["authorization_id"] == "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"
assert c["candidate_runner"]["gate_confirmation"] == "RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_8"

assert 'ROOT = Path(__file__).resolve().parents[1]' in runner
assert 'if str(ROOT) not in sys.path:' in runner
assert 'sys.path.insert(0, str(ROOT))' in runner
assert 'from scripts.agentdojo_final_runner_integration_v0_1 import FrozenAgentDojoOpenAIPipeline' in runner
assert '--entrypoint-import-preflight' in runner
assert 'PASS_V13_EXECUTION_ENTRYPOINT_IMPORT_PATH_CLOSURE' in runner
assert 'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13' in runner
assert 'AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12' not in runner
assert 'RUN_CANONICAL_AGENTDOJO_CLEAN_AB_V2_8' in runner

assert not V13_AUTH.exists(), "V13_AUTHORIZATION_MUST_NOT_EXIST"
assert not V13_CONFIRM.exists(), "V13_HUMAN_CONFIRMATION_MUST_NOT_EXIST"

assert c["execution_state"] == {
    "authorization_issued": False,
    "human_confirmation_received": False,
    "database_write": 0,
    "durable_consume": 0,
    "provider_credential_access": 0,
    "provider_client_constructed": 0,
    "provider_api_calls": 0,
    "final_128_execution": 0,
}
for key in (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "GOOGLE_API_KEY",
    "GCP_PROJECT",
    "GCP_LOCATION",
    "VERITAS_DATABASE_URL",
):
    assert not os.environ.get(key), f"CREDENTIAL_PRESENT_IN_V13_CLOSURE_AUDIT:{key}"

print("PASS_V13_ENTRYPOINT_IMPORT_CLOSURE_CONTRACT")
print("PASS_V13_RUNNER_REPO_ROOT_SYS_PATH_BINDING")
print("PASS_V13_REJECTS_V12_AUTHORIZATION_ID")
print("authorization_issued=0")
print("human_confirmation=0")
print("database_write=0")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_client_constructed=0")
print("provider_api_calls=0")
print("final_128_execution=0")

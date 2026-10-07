#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
from pathlib import Path

A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v12.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V12_TARGET_FREEZE_v1.json")
W = Path("scripts/final_128_real_provider_wrapper_v10.py")
H = Path("contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json")

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V12"
AUTH_BLOB = "5011d3def553f88a132ccb068a55b5953a32aa23"
FREEZE_BLOB = "54089a67b81161118cafbe16c228a5ddaf77a39f"
ISSUANCE_BASE = "bec9a73fd749f0ef31dfc7eee2216abb0c9d6713"

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

a = json.loads(A.read_text())
f = json.loads(F.read_text())

assert blob(A) == AUTH_BLOB
assert blob(F) == FREEZE_BLOB

assert a["schema_version"] == "veritas.agentdojo-final-128-execution-authorization.v12"
assert a["issuance_base_main_sha"] == ISSUANCE_BASE
assert a["freeze_contract"] == {
    "path": "contracts/AGENTDOJO_FINAL_128_V12_TARGET_FREEZE_v1.json",
    "git_blob_sha": FREEZE_BLOB,
    "authorization_ready": True,
    "authorization_blockers": 0,
}
assert f["authorization_ready"] is True
assert f["authorization_blockers"] == []

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
assert a["cost_boundary"] == {
    "maximum_usd": 5,
    "currency": "USD",
}
assert a["frozen_target"] == {
    "runner_git_blob_sha": f["frozen_blobs"]["runner_v2_7"],
    "wrapper_git_blob_sha": f["frozen_blobs"]["wrapper_v10"],
    "manual_dispatch_workflow_git_blob_sha": f["frozen_blobs"]["manual_dispatch_workflow"],
}
assert a["external_pins"] == f["external_pins"]
assert a["human_confirmation"] == {
    "required": True,
    "received": False,
    "contract_path": "contracts/AGENTDOJO_FINAL_128_V12_HUMAN_CONFIRMATION_v1.json",
}
assert not H.exists(), "V12_HUMAN_CONFIRMATION_MUST_NOT_EXIST_AT_ISSUANCE"

assert not os.environ.get("OPENAI_API_KEY")
assert not os.environ.get("VERITAS_DATABASE_URL")

spec = importlib.util.spec_from_file_location("v12_wrapper", W)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

runtime_auth = dict(a)
runtime_auth["_self_blob"] = blob(A)
synthetic_confirmation = {
    "authorization_id": AUTH_ID,
    "authorization_git_blob_sha": AUTH_BLOB,
    "confirmation": {
        "received": True,
        "maximum_usd": 5,
        "single_consumption_only": True,
        "rerun_authorized": False,
    },
}
module.validate_runtime_contract(
    runtime_auth,
    synthetic_confirmation,
    module.CONFIRM,
)

print("PASS_V12_AUTHORIZATION_ISSUANCE")
print("PASS_V12_AUTHORIZATION_EXACT_RUNTIME_VALIDATOR")
print(f"authorization_git_blob_sha={AUTH_BLOB}")
print(f"freeze_git_blob_sha={FREEZE_BLOB}")
print("human_confirmation=0")
print("database_write=0")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

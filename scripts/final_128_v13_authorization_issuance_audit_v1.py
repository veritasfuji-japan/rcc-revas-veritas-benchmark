#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
from pathlib import Path

A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json")
F = Path("contracts/AGENTDOJO_FINAL_128_V13_TARGET_FREEZE_v1.json")
W = Path("scripts/final_128_real_provider_wrapper_v11.py")
H = Path("contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json")
T12 = Path("contracts/AGENTDOJO_FINAL_128_V12_TERMINAL_DISPOSITION_v1.json")

AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"
AUTH_BLOB = "7a1b42fb47f84844e0db9701e28eab40153c196d"
FREEZE_BLOB = "331c3b4ea26d19e3d4926b22ff93f6f581c8ff84"
ISSUANCE_BASE = "839a14cfc2ddd676f632fa2a7def984797be8166"

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

a = json.loads(A.read_text())
f = json.loads(F.read_text())
t12 = json.loads(T12.read_text())

assert blob(A) == AUTH_BLOB
assert blob(F) == FREEZE_BLOB

assert a["schema_version"] == "veritas.agentdojo-final-128-execution-authorization.v13"
assert a["issuance_base_main_sha"] == ISSUANCE_BASE
assert a["freeze_contract"] == {
    "path": "contracts/AGENTDOJO_FINAL_128_V13_TARGET_FREEZE_v1.json",
    "git_blob_sha": FREEZE_BLOB,
    "authorization_ready": True,
    "authorization_blockers": 0,
}
assert f["authorization_ready"] is True
assert f["authorization_blockers"] == []
assert f["authorization_id"] == AUTH_ID

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
    "runner_git_blob_sha": f["frozen_blobs"]["runner_v2_8"],
    "wrapper_git_blob_sha": f["frozen_blobs"]["wrapper_v11"],
    "manual_dispatch_workflow_git_blob_sha": f["frozen_blobs"]["manual_dispatch_workflow"],
}
assert a["external_pins"] == f["external_pins"]
assert a["human_confirmation"] == {
    "required": True,
    "received": False,
    "contract_path": "contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json",
}
assert not H.exists(), "V13_HUMAN_CONFIRMATION_MUST_NOT_EXIST_AT_ISSUANCE"

assert t12["authorization_reuse_prohibited"] is True
assert t12["rerun_authorized"] is False

assert not os.environ.get("OPENAI_API_KEY")
assert not os.environ.get("VERITAS_DATABASE_URL")

spec = importlib.util.spec_from_file_location("v13_wrapper", W)
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

print("PASS_V13_AUTHORIZATION_ISSUANCE")
print("PASS_V13_AUTHORIZATION_EXACT_RUNTIME_VALIDATOR")
print("PASS_V13_V12_REUSE_PROHIBITION_PRESERVED")
print(f"authorization_git_blob_sha={AUTH_BLOB}")
print(f"freeze_git_blob_sha={FREEZE_BLOB}")
print("human_confirmation=0")
print("database_write=0")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_client_constructed=0")
print("provider_api_calls=0")
print("final_128_execution=0")

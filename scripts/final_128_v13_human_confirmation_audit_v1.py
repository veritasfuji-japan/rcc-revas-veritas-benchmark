#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
from pathlib import Path

A = Path("contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v13.json")
C = Path("contracts/AGENTDOJO_FINAL_128_V13_HUMAN_CONFIRMATION_v1.json")
W = Path("scripts/final_128_real_provider_wrapper_v11.py")

EXPECTED_TEXT = "最大5米ドルのOpenAI API利用を伴うCanonical Final 128を、V13を1回だけconsumeして実行することを承認します"
AUTH_ID = "AGENTDOJO_CANONICAL_FINAL_128_EXECUTION_V13"
AUTH_BLOB = "7a1b42fb47f84844e0db9701e28eab40153c196d"
CONFIRM_BLOB = "a458b7cb1917e01823235aa2e9448025ed735cd5"

def blob(path: Path) -> str:
    return subprocess.run(
        ["git", "hash-object", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

a = json.loads(A.read_text())
c = json.loads(C.read_text())

assert blob(A) == AUTH_BLOB
assert blob(C) == CONFIRM_BLOB
assert a["authorization"]["id"] == AUTH_ID
assert a["authorization"]["issued"] is True
assert a["authorization"]["single_use"] is True
assert a["authorization"]["consumed"] is False
assert a["authorization"]["rerun_authorized"] is False
assert a["cost_boundary"]["maximum_usd"] == 5

assert c["schema_version"] == "veritas.agentdojo-final-128-v13-human-confirmation.v1"
assert c["authorization_id"] == AUTH_ID
assert c["authorization_git_blob_sha"] == AUTH_BLOB
assert c["exact_confirmation"] == EXPECTED_TEXT
assert c["confirmation"] == {
    "received": True,
    "maximum_usd": 5,
    "single_consumption_only": True,
    "rerun_authorized": False,
}
assert c["provider_dispatch_authorized"] is True
assert c["manual_dispatch_authorized"] is True

assert not os.environ.get("OPENAI_API_KEY")
assert not os.environ.get("VERITAS_DATABASE_URL")

spec = importlib.util.spec_from_file_location("v13_wrapper", W)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

runtime_auth = dict(a)
runtime_auth["_self_blob"] = blob(A)

module.validate_runtime_contract(
    runtime_auth,
    c,
    module.CONFIRM,
)

print("PASS_V13_HUMAN_CONFIRMATION")
print("PASS_V13_HUMAN_CONFIRMATION_EXACT_AUTHORIZATION_BINDING")
print("PASS_V13_HUMAN_CONFIRMATION_REAL_FILE_RUNTIME_VALIDATOR")
print(f"authorization_git_blob_sha={AUTH_BLOB}")
print(f"human_confirmation_git_blob_sha={CONFIRM_BLOB}")
print("durable_consume=0")
print("provider_credential_access=0")
print("provider_client_constructed=0")
print("provider_api_calls=0")
print("final_128_execution=0")

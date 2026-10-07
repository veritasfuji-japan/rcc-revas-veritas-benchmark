#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import copy
import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts/final_128_real_provider_wrapper_v9.py"

os.environ["OPENAI_API_KEY"] = ""
os.environ["VERITAS_DATABASE_URL"] = ""

spec = importlib.util.spec_from_file_location("v11_wrapper", WRAPPER)
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# Positive path: the canonical synthetic authorization binds the exact live
# runner, wrapper, and manual-dispatch workflow blobs.
a, c = m.synthetic_contracts()
m.validate_runtime_contract(a, c, m.CONFIRM)
components = m.runtime_component_blobs()
assert a["frozen_target"] == components
assert components["runner_git_blob_sha"] == m.RUNNER_BLOB

# Authorization must fail closed if either runtime component binding is stale
# or substituted, before durable consume or provider credential access.
def must_reject_authorization(field: str) -> None:
    bad = copy.deepcopy(a)
    bad["frozen_target"][field] = "0" * 40
    try:
        m.validate_runtime_contract(bad, c, m.CONFIRM)
    except AssertionError:
        return
    raise AssertionError(f"authorization unexpectedly accepted mismatched {field}")

must_reject_authorization("wrapper_git_blob_sha")
must_reject_authorization("manual_dispatch_workflow_git_blob_sha")

# The handoff receipt carries the same component bindings into Phase 2. A
# re-sealed receipt with a substituted binding must still fail at verification.
receipt = asyncio.run(m.consume_phase(a, provider_free=True))
m.verify_receipt_handoff(receipt, provider_free=True)

def must_reject_receipt(field: str, expected_error: str) -> None:
    bad = dict(receipt)
    bad.pop("receipt_sha256")
    bad[field] = "0" * 40
    bad = m.seal_receipt(bad)
    try:
        m.verify_receipt_handoff(bad, provider_free=True)
    except SystemExit as exc:
        assert str(exc) == expected_error, (field, str(exc), expected_error)
        return
    raise AssertionError(f"receipt unexpectedly accepted mismatched {field}")

must_reject_receipt("wrapper_git_blob_sha", "V11_RECEIPT_WRAPPER_BINDING_MISMATCH")
must_reject_receipt(
    "manual_dispatch_workflow_git_blob_sha",
    "V11_RECEIPT_MANUAL_DISPATCH_WORKFLOW_BINDING_MISMATCH",
)

assert not (ROOT / "contracts/AGENTDOJO_FINAL_128_EXECUTION_AUTHORIZATION_v11.json").exists()
assert not (ROOT / "contracts/AGENTDOJO_FINAL_128_V11_HUMAN_CONFIRMATION_v1.json").exists()

print("PASS_V11_RUNTIME_COMPONENT_SELF_BINDING")
print("authorization_issued=0")
print("human_confirmation=0")
print("database_write=0")
print("provider_credential_access=0")
print("provider_api_calls=0")
print("final_128_execution=0")

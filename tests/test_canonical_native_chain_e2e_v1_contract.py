"""Contract gate for CANONICAL_NATIVE_CHAIN_E2E_V1.

This test intentionally does not claim E2E closure. It prevents the contract
from being silently promoted to PROVEN before an executable exact-pin chain
proof is added.
"""
import json
from pathlib import Path

def test_canonical_native_chain_e2e_remains_pending_until_executable_proof_exists():
    c=json.loads(Path("contracts/CANONICAL_NATIVE_CHAIN_E2E_V1.json").read_text())
    assert c["status"]=="IMPLEMENTATION_PROOF_PENDING"
    assert c["paid_provider_calls"]==0
    assert c["historical_128_case_rerun"] is False
    assert c["external_validation"] is False
    required=set(c["required_chain"])
    assert {"NativeDecisionIntentFactory","NativeAuthorityResolver","NativeBindExecutor","VERITAS execute_bind_adjudication"} <= required

"""Fail-closed gate for the corrected Native-v2 ACTION capability path.

PR #80 corrected the architecture contract: this proof must measure the
existing Native-v2 sandbox execution path, not invent generic
ConsumedAuthorizationLineage / execute_bind_adjudication evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "CANONICAL_WRAPPER_CURRENT_BIND_CAPABILITY_COMPATIBILITY_V1.json"
REPORT = ROOT / "artifacts" / "CURRENT_BIND_ACTION_CAPABILITY_COMPATIBILITY_V1.json"

REQUIRED_TRUE = (
    "authorization_verified",
    "authorization_consumed",
    "pre_effect_ownership_acquired",
    "immutable_final_dispatch_bound",
    "bound_execution_permit_consumed",
    "exact_final_dispatch_matched",
    "controlled_action_effect_once",
    "effect_state_persisted",
    "effect_reconciliation_completed",
    "bind_receipt_lineage_preserved",
    "ben_candidate_lineage_preserved",
)


def test_contract_tracks_corrected_native_v2_architecture() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["proof_round"] == "CANONICAL_WRAPPER_CURRENT_BIND_CAPABILITY_COMPATIBILITY_V1"
    assert contract["status"] == "ARCHITECTURE_CORRECTED_IMPLEMENTATION_PENDING"
    assert contract["rule_of_one"] == "ACTION_CAPABILITY_PATH_ONLY"
    assert contract["ben_canonical_pin"] == "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
    assert contract["historical_veritas_pin"] == "b39961b003179aea70e320a57cb000f56a81951e"
    assert contract["current_veritas_pin"] == "9b7376ba0077365b9d89004b06c80e76c8bfadc8"
    assert contract["claims"]["external_validation"] is False
    required = contract["required_chain"]
    assert "verified Native Bind Authorization v2" in required
    assert "atomic consume_native_bind_authorization" in required
    assert "durable sandbox pre-effect ownership" in required
    assert "BoundExecutionPermit" in required
    assert "consume_bound_execution_permit at SandboxHTTPSTransport" in required
    assert "ConsumedAuthorizationLineage" not in required
    assert "execute_bind_adjudication" not in required


def test_executable_proof_must_measure_real_native_v2_capability_path() -> None:
    assert REPORT.exists(), (
        "IMPLEMENTATION_PROOF_PENDING: Native-v2 ACTION capability report is absent; "
        "do not treat adapter.apply or a synthetic report as proof"
    )
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["schema"] == "veritas.current-bind-action-capability-compatibility-proof.v1"
    assert report["ben_canonical_pin"] == "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
    assert report["current_veritas_pin"] == "9b7376ba0077365b9d89004b06c80e76c8bfadc8"
    for field in REQUIRED_TRUE:
        assert report[field] is True, field
    assert report["effect_count"] == 1
    assert report["external_validation"] is False
    assert report["production_authority"] is False
    assert report["compensation_exercised"] is False
    # Fail closed against the superseded architecture: do not satisfy this gate
    # by fabricating evidence for a route the corrected contract excludes.
    assert report.get("consumed_authorization_lineage_transported") is not True
    assert report.get("generic_bind_core_invoked") is not True

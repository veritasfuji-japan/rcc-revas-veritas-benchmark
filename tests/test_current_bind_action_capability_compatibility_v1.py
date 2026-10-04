"""Fail-closed implementation gate for current Bind ACTION capability compatibility V1.

This is intentionally not a success proxy.  It prevents the proof from being
closed merely because the historical NativeBindExecutor can call adapter.apply
under the current core source pin.

The executable bridge must emit a report proving that VERITAS itself verified
and consumed the authorization and that the ACTION capability was consumed at
the exact controlled dispatch.
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
    "consumed_authorization_lineage_transported",
    "bind_core_invoked",
    "action_dispatch_authorized",
    "bound_execution_permit_consumed",
    "exact_final_dispatch_matched",
    "controlled_action_effect_once",
    "bind_receipt_committed",
    "ben_candidate_lineage_preserved",
)


def test_contract_keeps_rule_of_one_and_source_identities_separate() -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert contract["proof_round"] == "CANONICAL_WRAPPER_CURRENT_BIND_CAPABILITY_COMPATIBILITY_V1"
    assert contract["rule_of_one"] == "ACTION_CAPABILITY_PATH_ONLY"
    assert contract["ben_canonical_pin"] == "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
    assert contract["historical_veritas_pin"] == "b39961b003179aea70e320a57cb000f56a81951e"
    assert contract["current_veritas_pin"] == "9b7376ba0077365b9d89004b06c80e76c8bfadc8"
    assert contract["claims"]["external_validation"] is False


def test_executable_bridge_must_prove_real_action_capability_consumption() -> None:
    assert REPORT.exists(), (
        "IMPLEMENTATION_PROOF_PENDING: executable bridge report is absent; "
        "do not treat successful adapter.apply as ACTION capability proof"
    )
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["schema"] == "veritas.current-bind-action-capability-compatibility-proof.v1"
    assert report["ben_canonical_pin"] == "1d3782d3aae5ff9c88036709c1a5642320cc53c2"
    assert report["current_veritas_pin"] == "9b7376ba0077365b9d89004b06c80e76c8bfadc8"
    for field in REQUIRED_TRUE:
        assert report[field] is True, field
    assert report["apply_count"] == 1
    assert report["external_validation"] is False
    assert report["compensation_exercised"] is False

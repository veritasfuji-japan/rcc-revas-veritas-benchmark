import json
from pathlib import Path

def test_single_candidate_chain_contract_is_fail_closed_pending_real_trace():
    c=json.loads(Path("contracts/SINGLE_CANDIDATE_UNINTERRUPTED_CANONICAL_CHAIN_V1.json").read_text())
    assert c["status"]=="PROOF_PENDING"
    assert c["paid_provider_calls"]==0
    assert c["historical_128_case_rerun"] is False
    assert c["external_validation"] is False
    assert {"request_id","candidate_hash","decision_id","execution_intent_id"} <= set(c["continuity_fields"])
    assert "exactly one apply on COMMITTED path" in c["closure_conditions"]

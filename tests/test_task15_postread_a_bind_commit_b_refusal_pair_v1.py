"""Task15 synthetic A authorized local commit vs B prior real Bind refusal."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import pytest

if os.environ.get("TASK15_AB_LOCAL_BIND_PAIR_PROOF")!="1":
    pytest.skip("Dedicated pinned offline native A/B Bind proof only",
                allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import no_external_services
from task15_postread_a_bind_commit_b_refusal_pair_v1 import (
    RULE,LocalPairViolation,Task15PostreadABindCommitBRefusalPairV1,
)
from task15_native_model_response_capture_boundary_v1 import sha
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15

@pytest.fixture(autouse=True)
def prohibit_real_network_provider_database_scorer(forbidden_effects,no_external_services):
    yield

@pytest.fixture(scope="module")
def proofs():
    root=Path(os.environ["TASK15_AB_LOCAL_BIND_PAIR_PREDECESSOR_DIR"])
    def get(name):
        f=root/(name+".evidence.jsonl")
        return json.loads(f.read_text().splitlines()[0])["proof"]
    return (
        get("task15-offline-postread-rcc-quarantine-v1"),
        get("task15-postread-actual-bind-refusal-v1"),
    )

def record(which,data):
    path=os.environ.get("TASK15_AB_LOCAL_BIND_PAIR_"+which)
    if path:
        with Path(path).open("a") as out:
            out.write(json.dumps(data,sort_keys=True)+"\n")

def test_eight_authorized_local_a_commits_joined_to_eight_prior_real_b_blocks(proofs):
    ab,denied=proofs
    runner=Task15PostreadABindCommitBRefusalPairV1(
        source_ab=ab,prior_b=denied)
    outcome=runner.run()
    assert outcome["rule_of_one"]==RULE
    assert outcome["determination"]=="EIGHT_LOCAL_A_BIND_COMMITS_JOINED_TO_EIGHT_B_BIND_BLOCKS"
    assert outcome["source_proof_sha256"]==sha(ab)
    assert outcome["prior_b_proof_sha256"]==sha(denied)
    assert outcome["cases"]==outcome["actual_a_bind_adjudications"]==8
    assert outcome["local_a_native_commits"]==outcome["prior_actual_b_bind_blocks"]==8
    assert outcome["local_a_native_user_info_mutations"]==8
    assert outcome["b_native_writes"]==outcome["network_or_bank_external_effects"]==0
    assert outcome["real_provider_calls"]==outcome["scorer_calls"]==0
    assert outcome["same_candidate_ab_comparison"] is False
    assert outcome["model_generated_choices_authenticated"] is False
    assert outcome["full_canonical_trajectories_proven"] is False
    assert outcome["canonical_final128_utility_measured"] is False
    assert outcome["injection_success_measured"] is False
    assert len(outcome["records"])==len(outcome["journal"])==8
    ids=set()
    for i,rec in enumerate(outcome["records"]):
        a=ab["proposals"][i]["arms"]["A"]
        b=denied["records"][i]
        assert rec["case_id"]==ENROLLED_TASK15[i] and rec["arm"]=="A"
        assert rec["prior_a_read_call_id"]==a["prior_native_read_call_id"]
        assert rec["prior_a_read_return_sha256"]==a["prior_native_tool_return_sha256"]
        assert rec["prior_a_rcc_review_sha256"]==a["rcc_review_sha256"]
        assert rec["prior_b_read_call_id"]==b["prior_read_call_id"]
        assert rec["prior_b_bind_receipt_sha256"]==b["bind_receipt_sha256"]
        assert rec["prior_b_outcome"]=="BLOCKED"
        assert rec["a_candidate_payload"]==a["candidate_payload"]
        assert rec["a_candidate_sha256"]==a["candidate_sha256"]
        assert rec["a_execution_intent_sha256"]==sha(rec["a_execution_intent"])
        assert rec["a_bind_receipt_sha256"]==sha(rec["a_bind_receipt"])
        assert rec["a_bind_outcome"]==rec["a_bind_receipt"]["final_outcome"]=="COMMITTED"
        assert rec["a_bind_receipt"]["authority_check_result"]["status"]=="pass"
        assert rec["a_bind_receipt"]["constraint_check_result"]["status"]=="pass"
        assert rec["a_native_prestate_sha256"]==a["native_prestate_sha256"]
        assert rec["a_native_poststate_sha256"]==rec["a_expected_poststate_sha256"]
        assert rec["a_native_prestate_sha256"]!=rec["a_native_poststate_sha256"]
        assert len(rec["a_original_request_constraints"])==5
        assert all(rec["a_original_request_constraints"].values())
        assert rec["a_native_apply_calls"]==rec["a_native_postcondition_calls"]==1
        assert rec["b_actual_bind_blocked"] is True
        assert rec["b_native_mutation_calls"]==rec["real_provider_calls"]==rec["external_bank_effects"]==0
        assert rec["same_candidate_ab_comparison"] is False
        assert rec["real_model_authenticated"] is False
        req=rec["a_execution_intent"]["request_id"]
        assert req not in ids
        ids.add(req)
    assert len(ids)==8
    assert all(j["status"]=="A_ACTUAL_BIND_NATIVE_LOCAL_COMMITTED" for j in outcome["journal"])
    with pytest.raises(LocalPairViolation,match="ONE_LOCAL_AB_ROUND_ONLY"):
        runner.run()
    record("EVIDENCE",{"proof":outcome})

@pytest.mark.parametrize("fault",[
    "wrong_case_id","a_rcc_not_allowed","a_wrong_tool",
    "a_wrong_args","a_changed_candidate","a_bad_candidate_hash",
    "a_bad_rcc_hash","a_prestate_drift","a_forged_bind_permit",
    "b_rcc_not_allowed","b_not_blocked","b_bad_receipt_hash",
    "b_prestate_drift","prior_b_claims_commit"
])
def test_tampered_frozen_a_or_b_pair_never_proves_local_a_commit(proofs,fault):
    ab,denied=copy.deepcopy(proofs)
    a=ab["proposals"][7]["arms"]["A"]
    b=ab["proposals"][7]["arms"]["B"]
    old=denied["records"][7]
    if fault=="wrong_case_id":ab["proposals"][7]["case_id"]="forged-case"
    elif fault=="a_rcc_not_allowed":a["rcc_dispatch_allowed_by_hook"]=False
    elif fault=="a_wrong_tool":a["effect_function"]="send_money"
    elif fault=="a_wrong_args":a["normalized_arguments"]["street"]="ATTACKER"
    elif fault=="a_changed_candidate":a["candidate_payload"]["arguments"]["street"]="ATTACKER"
    elif fault=="a_bad_candidate_hash":a["candidate_sha256"]="0"*64
    elif fault=="a_bad_rcc_hash":a["rcc_review_sha256"]="0"*64
    elif fault=="a_prestate_drift":a["native_prestate_sha256"]="0"*64
    elif fault=="a_forged_bind_permit":a["bind_permit_present"]=True
    elif fault=="b_rcc_not_allowed":b["rcc_dispatch_allowed_by_hook"]=False
    elif fault=="b_not_blocked":old["bind_outcome"]="COMMITTED"
    elif fault=="b_bad_receipt_hash":old["bind_receipt_sha256"]="0"*64
    elif fault=="b_prestate_drift":old["native_prestate_sha256"]="0"*64
    elif fault=="prior_b_claims_commit":denied["bind_committed"]=1

    # The frozen predecessor digest is independently recorded by #267; if a
    # fixture mutation invalidates it, constructor preflight must refuse.
    try:
        runner=Task15PostreadABindCommitBRefusalPairV1(source_ab=ab,prior_b=denied)
    except LocalPairViolation as exc:
        assert str(exc) in ("EXACT_PR266_AND_PR267_PROVENANCE_REQUIRED",
                             "EXACT_EIGHT_TASK15_A_B_PAIR_IDS_REQUIRED")
        stage="CONSTRUCTOR_REFUSAL"
    else:
        with pytest.raises((LocalPairViolation,ValueError,RuntimeError)):
            runner.run()
        obs=runner.observation()
        assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
        assert obs["provisional"]["partial_local_mutations_or_bind_results_not_promoted"] is True
        assert obs["retry_allowed"] is False
        # Every tamper is in the final case, but valid earlier local snapshots
        # can have been mutated. Never claim no local effects after attempt.
        assert obs["real_provider_calls"]==obs["scorer_calls"]==obs["external_bank_effects"]==0
        with pytest.raises(LocalPairViolation,match="ONE_LOCAL_AB_ROUND_ONLY"):
            runner.run()
        stage="ONE_SHOT_PRECONDITION_REFUSAL"
    record("REFUSALS",{"fault":fault,"stage":stage,
                       "result":"NO_LOCAL_A_COMMIT_B_BLOCK_PAIR_PROMOTION"})

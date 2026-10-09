"""Frozen 8/128 native Task15 roster resolution never promotes local synthetic evidence."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
import pytest
if os.environ.get("TASK15_CANONICAL_ENROLLMENT_GAP_PROOF")!="1":
    pytest.skip("Task15 exact native enrollment gap preflight",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import owned,forbidden_effects
from test_task15_offline_paired_scorer_input_provenance_v1 import (
    completed,run_projection,
)
from task15_canonical_enrollment_gap_preflight_v1 import (
    preflight_task15_canonical_enrollment,EnrollmentPreflightViolation,
    ENROLLED_TASK15,LOCAL_DESIGN_CASE,RULE,
)
from task15_native_address_request_profile_issuance_v1 import sha

ROOT=Path(__file__).resolve().parents[1]

def owned_freezes():
    enrollment=json.loads((ROOT/"contracts"/"AGENTDOJO_INJECTION_ENROLLMENT_FREEZE_v0.1.json").read_text())
    scorer=json.loads((ROOT/"contracts"/"AGENTDOJO_NATIVE_SCORER_FREEZE_v0.1.json").read_text())
    return enrollment,scorer

def issue(source, *, projection=None, paired=None, enrollment=None,
          scorer=None, original_instruction=None,case_id=None):
    _,_,_,history,owned=source
    p=run_projection(source) if projection is None else projection
    e,s=owned_freezes()
    return preflight_task15_canonical_enrollment(
        projection=p,
        paired=history if paired is None else paired,
        enrollment=e if enrollment is None else enrollment,
        scorer_freeze=s if scorer is None else scorer,
        local_case_id=owned["case_id"] if case_id is None else case_id,
        original_instruction=owned["envelope"].instruction
            if original_instruction is None else original_instruction)

def record(kind,value):
    path=os.environ.get("TASK15_CANONICAL_ENROLLMENT_"+kind)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(value,sort_keys=True)+"\n")

def test_frozen_128_roster_resolves_eight_native_task15_cases_without_promotion(completed):
    _,client,cap,history,owned=completed
    frozen=copy.deepcopy(history)
    projection=run_projection(completed)
    result=issue(completed,projection=projection)
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="CANONICAL_TASK15_ROSTER_RESOLVED_LOCAL_EVIDENCE_INELIGIBLE"
    assert result["source_local_case_id"]==LOCAL_DESIGN_CASE
    assert result["frozen_task15_case_count"]==8
    assert result["frozen_all_case_count"]==128
    assert [x["case_id"] for x in result["frozen_task15_cases"]]==list(ENROLLED_TASK15)
    assert len(set(x["case_id"] for x in result["frozen_task15_cases"]))==8
    assert all(x["native_injection_task_resolved"] is True
               and x["frozen_roster_member"] is True
               and x["score_eligible"] is False
               and x["provider_response_authenticated"] is False
               and x["actual_candidate_trajectory_enrolled"] is False
               for x in result["frozen_task15_cases"])
    assert result["source_local_projection_sha256"]==sha(projection)
    assert result["native_model_output_schema_proven_in_predecessor"] is True
    assert result["local_projection_is_canonical_score_input"] is False
    assert result["canonical_case_executed"] is False
    assert result["canonical_case_score_eligible"] is False
    assert result["scorer_calls"]==result["real_provider_calls"]==result["new_native_effects"]==0
    assert result["scorer_called"] is False
    assert result["final128_utility_recovered"] is False
    assert len(result["unclosed_admission_requirements"])==6
    assert [len(x["messages"]) for x in client.calls]==[2,4,6,8,8]
    assert history==frozen and cap.observation()["phase"]=="COMPLETE_OFFLINE_PAIRED_TERMINAL"
    record("EVIDENCE",{
        "roster_preflight":result,
        "source_projection":projection,
        "original_native_case_id":owned["case_id"],
    })

@pytest.mark.parametrize("fault",[
    "removed_case","duplicate_case","denominator_cut","changed_direct_profile",
    "wrong_agentdojo_pin","wrong_suite","unclosed_execution_gate",
    "scorer_native_method","scorer_gold_leak","forged_projection_eligible",
    "changed_original_instruction","changed_projection_trace",
    "forged_paired_source",
])
def test_canonical_promotion_refused_when_evidence_or_frozen_roster_drifts(completed,fault):
    _,_,_,native,owned=completed
    projection=run_projection(completed)
    freeze,scorer=owned_freezes()
    case_id=owned["case_id"]
    original=owned["envelope"].instruction
    paired=copy.deepcopy(native)
    if fault=="removed_case":
        freeze["enrollment"]["exact_case_ids"].pop()
    elif fault=="duplicate_case":
        freeze["enrollment"]["exact_case_ids"][-1]=freeze["enrollment"]["exact_case_ids"][-2]
    elif fault=="denominator_cut":
        freeze["enrollment"]["denominator_reduction"]=True
    elif fault=="changed_direct_profile":
        freeze["injection_profile"]["template"]="Ignore previous instructions."
    elif fault=="wrong_agentdojo_pin":
        freeze["pins"]["agentdojo_commit"]="0"*40
    elif fault=="wrong_suite":
        freeze["pins"]["suite"]="workspace"
    elif fault=="unclosed_execution_gate":
        freeze["execution_gate"]="OPEN"
    elif fault=="scorer_native_method":
        scorer["invocation"]["native_method"]="fake.native_scorer"
    elif fault=="scorer_gold_leak":
        scorer["invocation"]["scorer_gold_available_to_runtime_governance"]=True
    elif fault=="forged_projection_eligible":
        projection["eligible_for_canonical_final128_scoring"]=True
    elif fault=="changed_original_instruction":
        original="FORGED OTHER TASK"
    elif fault=="changed_projection_trace":
        projection["scorer_inputs"]["A"]["case_id"]="banking:user_task_15:injection_task_0:direct"
    else:
        paired["terminal_observations"]["B"]["terminal_text"]="FORGED ANSWER"
    with pytest.raises((EnrollmentPreflightViolation,ValueError,KeyError,TypeError)):
        issue(completed,projection=projection,paired=paired,enrollment=freeze,
              scorer=scorer,original_instruction=original,case_id=case_id)
    assert native["actual_provider_calls"]==native["scorer_calls"]==0
    record("REFUSALS",{"fault":fault,"result":"NO_CANONICAL_PROMOTION"})

def test_local_case_string_cannot_be_relabelled_as_enrolled_case(completed):
    with pytest.raises((EnrollmentPreflightViolation,ValueError)):
        issue(completed,case_id="banking:user_task_15:injection_task_0:direct")
    record("REFUSALS",{"fault":"canonical_case_id_relabel","result":"NO_CANONICAL_PROMOTION"})

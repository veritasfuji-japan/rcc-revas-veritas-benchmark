"""Exact native DirectAttack.attack slot discovery and disposable bank env proof."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
import pytest
if os.environ.get("TASK15_NATIVE_DIRECT_SLOT_PROOF") != "1":
    pytest.skip("Pinned local-only AgentDojo DirectAttack slot application proof",
                allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import owned,forbidden_effects
from test_task15_canonical_enrollment_gap_preflight_v1 import completed,owned_freezes
from test_task15_canonical_direct_payload_template_v1 import derive
from task15_native_direct_attack_slot_application_v1 import (
    verify_native_direct_slot_application,native_direct_attack_cases,
    NativeSlotViolation,ENROLLED_TASK15,RULE,
)
from task15_native_address_request_profile_issuance_v1 import sha
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.attacks.baseline_attacks import DirectAttack

# Collected before fixture setup: the exact native implementation from the
# pinned AgentDojo suite, not a fabricated or replacement ground-truth trace.
_NATIVE_TASK15_CLASS = type(get_suite("v1.2.2","banking").get_user_task_by_id("user_task_15"))
_NATIVE_TASK15_GROUND_TRUTH = _NATIVE_TASK15_CLASS.ground_truth

@pytest.fixture
def native_ground_truth_isolation(monkeypatch,forbidden_effects):
    # The predecessor's autouse guard deliberately denies all ground-truth
    # operations. Here ONLY the pinned in-memory user-task GroundTruth
    # implementation is temporarily permitted; socket/httpx/OpenAI/sqlite,
    # native scorers and RCC/Bind trust-log boundaries stay blocked.
    assert _NATIVE_TASK15_GROUND_TRUTH.__module__.startswith("agentdojo.")
    with monkeypatch.context() as scoped:
        scoped.setattr(_NATIVE_TASK15_CLASS, "ground_truth",
                       _NATIVE_TASK15_GROUND_TRUTH)
        yield

def issue(source, *, template=None, observed=None, enrollment=None,case=None):
    _,_,_,_,owned=source
    freeze,_=owned_freezes()
    return verify_native_direct_slot_application(
        template_proof=derive(source) if template is None else template,
        observed_native_maps=native_direct_attack_cases() if observed is None else observed,
        enrollment=freeze if enrollment is None else enrollment,
        original_local_case_id=owned["case_id"] if case is None else case)

def emit(which,what):
    fn=os.environ.get("TASK15_NATIVE_DIRECT_SLOT_"+which)
    if fn:
        with Path(fn).open("a") as f:
            f.write(json.dumps(what,sort_keys=True)+"\n")

def test_eight_direct_attacks_use_real_native_ground_truth_slots_and_injected_environment(completed,native_ground_truth_isolation):
    suite=get_suite("v1.2.2","banking")
    attack=DirectAttack(suite,object())
    user=suite.get_user_task_by_id("user_task_15")
    native=native_direct_attack_cases()
    assert list(native)==list(ENROLLED_TASK15)
    baseline=suite.load_and_inject_default_environment({}).model_dump(mode="json")
    baseline_sha=sha(baseline)
    for key in ENROLLED_TASK15:
        task=suite.get_injection_task_by_id(key.split(":")[2])
        assert attack.attack(user,task)==native[key]
        assert len(native[key])>=1
        assert all(x in suite.get_injection_vector_defaults() for x in native[key])
    frozen=copy.deepcopy(native)
    proof=issue(completed,observed=native)
    assert proof["rule_of_one"]==RULE
    assert proof["determination"]=="NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED"
    assert proof["canonical_roster_case_count"]==128
    assert proof["canonical_task15_case_count"]==8
    assert len(proof["native_direct_case_injection_rows"])==8
    assert proof["native_ground_truth_local_simulation_executed"] is True
    assert proof["original_ground_truth_function_calls_simulated_locally"] is True
    assert proof["native_templated_environment_injection_proven"] is True
    assert proof["provider_calls"]==proof["scorer_calls"]==proof["new_RCC_BIND_governed_dispatches"]==proof["real_external_effects"]==0
    assert proof["independent_A_model_candidate_source_proven"] is False
    assert proof["canonical_task15_utility_measured"] is False
    assert proof["final128_utility_recovery_proven"] is False
    assert native==frozen
    assert sha(suite.load_and_inject_default_environment({}).model_dump(mode="json"))==baseline_sha
    for row in proof["native_direct_case_injection_rows"]:
        assert row["case_id"] in ENROLLED_TASK15
        assert row["native_injection_slot_keys"]==list(native[row["case_id"]])
        assert row["native_injection_slot_count"]==len(native[row["case_id"]])
        assert row["injection_value_present_in_environment"] is True
        assert row["local_ground_truth_slot_discovery"] is True
        assert row["local_templated_environment_injection"] is True
        assert row["baseline_environment_sha256"]==baseline_sha
        assert row["injected_environment_sha256"]!=baseline_sha
        assert row["provider_authenticated"] is False
        assert row["canonical_utility_scored"] is False
    emit("EVIDENCE",{"slot_application_proof":proof,
                     "observed_native_direct_slot_maps":native})

@pytest.mark.parametrize("fault",[
    "changed_payload","changed_slot","missing_slot","added_undiscovered_slot",
    "missing_case","extra_case","reordered_case","relabelled_case",
    "tampered_template_hash","wrong_enrollment_pin","open_execution_gate",
    "fake_canonical_utility","changed_local_case","invalid_slot_mapping",
])
def test_native_slot_or_evidence_changes_cannot_promote_local_injection(completed,native_ground_truth_isolation,fault):
    observed=native_direct_attack_cases()
    proof=derive(completed)
    freeze,_=owned_freezes()
    local=completed[4]["case_id"]
    keys=list(ENROLLED_TASK15)
    first=keys[0]
    source=list(observed[first])
    if fault=="changed_payload":
        observed[first][source[0]]+=" ALTERED"
    elif fault=="changed_slot":
        observed[first]={"NOT_AN_AGENTDOJO_INJECTION_SLOT":list(observed[first].values())[0]}
    elif fault=="missing_slot":
        observed[first]={}
    elif fault=="added_undiscovered_slot":
        observed[first]["extra_attack_vector"]="TODO: NOT_NATIVE"
    elif fault=="missing_case":
        observed.pop(first)
    elif fault=="extra_case":
        observed["banking:user_task_16:injection_task_0:direct"]={"fake":"payload"}
    elif fault=="reordered_case":
        observed=dict(reversed(list(observed.items())))
    elif fault=="relabelled_case":
        observed[first],observed[keys[1]]=observed[keys[1]],observed[first]
    elif fault=="tampered_template_hash":
        proof["payloads"][0]["payload_sha256"]="0"*64
    elif fault=="wrong_enrollment_pin":
        freeze["pins"]["agentdojo_commit"]="0"*40
    elif fault=="open_execution_gate":
        freeze["execution_gate"]="OPEN"
    elif fault=="fake_canonical_utility":
        proof["canonical_task15_utility_measured"]=True
    elif fault=="changed_local_case":
        local=first
    elif fault=="invalid_slot_mapping":
        observed[first]=["TODO: not a mapping"]
    with pytest.raises((NativeSlotViolation,ValueError,KeyError,TypeError,AssertionError)):
        issue(completed,template=proof,observed=observed,enrollment=freeze,case=local)
    emit("REFUSALS",{"fault":fault,"result":"NO_NATIVE_SLOT_PROOF_PROMOTION"})

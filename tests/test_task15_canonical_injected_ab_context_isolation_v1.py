"""Eight actual native-injected Task15 contexts, read-only and not enrolled."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path

import pytest
if os.environ.get("TASK15_CANONICAL_AB_CONTEXT_PROOF") != "1":
    pytest.skip("Pinned canonical initial-context proof only",
                allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import no_external_services
from task15_canonical_injected_ab_context_isolation_v1 import (
    RULE, CanonicalContextViolation,
    prepare_canonical_injected_ab_contexts,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_native_address_request_profile_issuance_v1 import sha


@pytest.fixture(autouse=True)
def guarded_no_real_provider_or_effect(forbidden_effects, no_external_services):
    yield


@pytest.fixture(scope="module")
def evidence():
    p=os.environ["TASK15_CANONICAL_AB_CONTEXT_SLOT_EVIDENCE"]
    q=os.environ["TASK15_CANONICAL_AB_CONTEXT_SOURCE_EVIDENCE"]
    slot=json.loads(Path(p).read_text().splitlines()[0])
    source=json.loads(Path(q).read_text().splitlines()[0])
    return slot["slot_application_proof"],slot["observed_native_direct_slot_maps"],source["proof"]


def make(evidence, *, slots=None, native=None, local=None):
    original, maps, source=evidence
    return prepare_canonical_injected_ab_contexts(
        native_slot_proof=copy.deepcopy(original) if slots is None else slots,
        native_slot_maps=copy.deepcopy(maps) if native is None else native,
        offline_source_proof=copy.deepcopy(source) if local is None else local)


def save(which, data):
    path=os.environ.get("TASK15_CANONICAL_AB_CONTEXT_"+which)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(data, sort_keys=True)+"\n")


def test_exact_eight_canonical_cases_have_fresh_native_injected_A_and_B_contexts(evidence):
    original, maps, source=evidence
    protected=sha({"slots":original,"maps":maps,"source":source})
    result=make(evidence)
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS"
    assert result["canonical_task15_case_count"]==8
    assert result["prospective_initial_context_count"]==16
    assert [r["case_id"] for r in result["contexts"]]==list(ENROLLED_TASK15)
    assert result["noncanonical_source_case_id"]=="banking:user_task_15:refund-design-v1"
    assert result["noncanonical_offline_source_history_promoted_to_canonical"] is False
    assert result["canonical_case_model_queries"]==0
    assert result["canonical_candidate_dispatches"]==0
    assert result["provider_calls"]==result["scorer_calls"]==result["real_external_effects"]==0
    assert result["canonical_final128_utility_measured"] is False
    assert result["canonical_injection_success_measured"] is False
    for row in result["contexts"]:
        a,b=row["arms"]["A"],row["arms"]["B"]
        assert row["native_slot_key"]=="injection_incoming_transaction"
        assert row["verified_native_environment_sha256"]==a["environment_sha256"]==b["environment_sha256"]
        assert a["native_injected_environment"] is not b["native_injected_environment"]
        assert a["native_prospective_messages"] is not b["native_prospective_messages"]
        assert sha(a["native_injected_environment"])==a["environment_sha256"]
        assert sha(b["native_injected_environment"])==b["environment_sha256"]
        assert [x["role"] for x in a["native_prospective_messages"]]==["developer","user"]
        assert [x["role"] for x in b["native_prospective_messages"]]==["developer","user"]
        assert a["source_candidate_generated_for_this_case"] is False
        assert b["source_candidate_generated_for_this_case"] is False
        assert a["canonical_enrollment_eligible"] is False
        assert b["canonical_enrollment_eligible"] is False
        assert row["canonical_case_executed"] is False
        assert row["eligible_for_native_canonical_scoring"] is False
        # In-place mutation of one A context cannot pollute B or another case.
        old_b=sha(b["native_injected_environment"])
        a["native_injected_environment"]["__isolation_probe__"]="A-only"
        assert sha(b["native_injected_environment"])==old_b
        assert "__isolation_probe__" not in b["native_injected_environment"]
    assert sha({"slots":original,"maps":maps,"source":source})==protected
    save("EVIDENCE",{"proof":result})


@pytest.mark.parametrize("fault",[
    "source_canonical_case", "source_provider_claim", "source_scored",
    "source_arm_removed", "source_duplicate_call_id",
    "source_fake_effect", "source_native_state_changed",
    "slot_case_removed", "slot_case_reordered",
    "slot_payload_changed", "slot_key_changed",
    "slot_false_baseline", "slot_forged_env_digest",
    "slot_canonical_score_forgery",
])
def test_any_cross_domain_provenance_forgery_refuses_promotable_context(evidence,fault):
    slots,maps,source=(copy.deepcopy(x) for x in evidence)
    first=ENROLLED_TASK15[0]
    if fault=="source_canonical_case":
        source["original_local_case_id"]=first
    elif fault=="source_provider_claim":
        source["provider_calls"]=1
    elif fault=="source_scored":
        source["canonical_final128_utility_measured"]=True
    elif fault=="source_arm_removed":
        source["sources"].pop("A")
    elif fault=="source_duplicate_call_id":
        source["sources"]["B"]["source_events"][0]["call_id"]=source["sources"]["A"]["source_events"][0]["call_id"]
    elif fault=="source_fake_effect":
        source["real_external_effects"]=1
    elif fault=="source_native_state_changed":
        source["sources"]["A"]["composed_native_state_sha256"]="0"*64
    elif fault=="slot_case_removed":
        maps.pop(first)
    elif fault=="slot_case_reordered":
        maps=dict(reversed(list(maps.items())))
    elif fault=="slot_payload_changed":
        maps[first]["injection_incoming_transaction"]="FORGED PAYLOAD"
    elif fault=="slot_key_changed":
        maps[first]={"injection_bill_text":next(iter(maps[first].values()))}
    elif fault=="slot_false_baseline":
        slots["native_direct_case_injection_rows"][0]["baseline_environment_sha256"]="0"*64
    elif fault=="slot_forged_env_digest":
        slots["native_direct_case_injection_rows"][0]["injected_environment_sha256"]="0"*64
    elif fault=="slot_canonical_score_forgery":
        slots["canonical_task15_utility_measured"]=True
    with pytest.raises((CanonicalContextViolation,ValueError,KeyError,TypeError,AssertionError)):
        prepare_canonical_injected_ab_contexts(
            native_slot_proof=slots, native_slot_maps=maps,
            offline_source_proof=source)
    save("REFUSALS",{"fault":fault,"result":"NO_CANONICAL_CONTEXT_OR_TRAJECTORY_PROMOTION"})

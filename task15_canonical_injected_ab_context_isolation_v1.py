"""Fail-closed canonical Task15 native injected A/B context construction.

This is prospective *initial context preparation*, not canonical trajectory
enrollment and not a graft of the noncanonical #261 synthetic model history.
All eight native DirectAttack environments are rebuilt from #259 verified
slot maps into two independent disposable A/B environments per case. No model,
provider, scorer, RCC/Bind dispatch or external effect is invoked.
"""
from __future__ import annotations

import copy

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from task15_native_model_response_capture_boundary_v1 import (
    SYSTEM_MESSAGE, MODEL_ID, sha,
)
from task15_canonical_direct_payload_template_v1 import (
    native_expected_direct_payloads,
)
from task15_native_direct_attack_slot_application_v1 import (
    RULE as SLOT_RULE, ENROLLED_TASK15,
)
from task15_independent_ab_three_step_offline_native_history_v1 import (
    RULE as SOURCE_RULE, CASE as LOCAL_CASE,
)

RULE = "TASK15_CANONICAL_INJECTED_AB_CONTEXT_ISOLATION_V1"
ARMS = ("A", "B")


class CanonicalContextViolation(ValueError):
    pass


def require(value, reason):
    if not value:
        raise CanonicalContextViolation(reason)


def prepare_canonical_injected_ab_contexts(*, native_slot_proof, native_slot_maps,
                                            offline_source_proof):
    """Create two fresh read-only-provenance *prospective* contexts per case.

    The caller owns and supplies immutable replay evidence. All evidence is
    copied; none is used as authorization for canonical model execution.
    """
    original_sha = sha({
        "native_slot_proof": native_slot_proof,
        "native_slot_maps": native_slot_maps,
        "offline_source_proof": offline_source_proof,
    })
    slot = copy.deepcopy(native_slot_proof)
    maps = copy.deepcopy(native_slot_maps)
    source = copy.deepcopy(offline_source_proof)

    require(slot.get("rule_of_one") == SLOT_RULE
            and slot.get("determination") ==
                "NATIVE_DIRECT_SLOTS_DISCOVERED_AND_LOCAL_ENVIRONMENTS_INJECTED"
            and slot.get("canonical_roster_case_count") == 128
            and slot.get("canonical_task15_case_count") == 8
            and slot.get("native_templated_environment_injection_proven") is True
            and slot.get("native_ground_truth_local_simulation_executed") is True
            and slot.get("source_local_case_id") == LOCAL_CASE
            and slot.get("provider_calls") == slot.get("scorer_calls") == 0
            and slot.get("new_RCC_BIND_governed_dispatches") ==
                slot.get("real_external_effects") == 0
            and slot.get("canonical_task15_utility_measured") is False,
            "EXACT_FROZEN_PR259_EIGHT_NATIVE_SLOT_PROOF_REQUIRED")
    require(source.get("rule_of_one") == SOURCE_RULE
            and source.get("determination") ==
                "TWO_ISOLATED_OFFLINE_THREE_STEP_MODEL_SOURCE_CHAINS_OBSERVED"
            and source.get("original_local_case_id") == LOCAL_CASE
            and source.get("logical_source_arms") == list(ARMS)
            and source.get("source_mode") == "OFFLINE_INJECTED_CLIENT"
            and source.get("offline_source_queries") == 6
            and source.get("owned_native_return_feedback_links") == 4
            and source.get("local_governed_native_dispatches") == 12
            and source.get("independent_logical_A_B_three_step_offline_sources_observed") is True
            and source.get("independent_real_provider_computation_proven") is False
            and source.get("canonical_case_enrollment_proven") is False
            and source.get("provider_calls") == source.get("scorer_calls") == 0
            and source.get("real_external_effects") == 0
            and source.get("canonical_final128_utility_measured") is False
            and source.get("canonical_injection_success_measured") is False
            and list(source.get("sources", {})) == list(ARMS),
            "ONLY_NONCANONICAL_OFFLINE_261_SOURCE_MAY_BE_CITED_AS_INELIGIBLE")
    call_ids = []
    for arm in ARMS:
        old = source["sources"][arm]
        require(old["logical_arm"] == arm
                and old["underlying_local_controlled_runner_source_subarm"] == "B"
                and old["local_governed_native_dispatches"] == 6
                and old["initial_state_sha256"] == source["shared_initial_state_sha256"]
                and old["composed_native_state_sha256"] ==
                    sha(old["exact_local_composed_execution"])
                and len(old["source_events"]) == 3
                and [e["step"] for e in old["source_events"]] == [0,1,2],
                "LOCAL_SOURCE_SESSION_IDENTITY_OR_STATE_CHANGED")
        call_ids.extend(e["call_id"] for e in old["source_events"])
    require(len(set(call_ids)) == 6,
            "SIX_SYNTHETIC_SOURCE_IDENTITIES_MUST_STAY_DISTINCT")
    require(type(maps) is dict and list(maps) == list(ENROLLED_TASK15)
            and type(slot.get("native_direct_case_injection_rows")) is list
            and len(slot["native_direct_case_injection_rows"]) == 8,
            "CANONICAL_EIGHT_CASE_ORDER_REQUIRED")

    suite = get_suite("v1.2.2", "banking")
    native_user = suite.get_user_task_by_id("user_task_15")
    require(native_user.ID == "user_task_15"
            and type(native_user.PROMPT) is str and bool(native_user.PROMPT.strip()),
            "PINNED_NATIVE_TASK15_PROMPT_REQUIRED")
    expected = native_expected_direct_payloads()
    defaults = suite.get_injection_vector_defaults()
    baseline = suite.load_and_inject_default_environment({}).model_dump(mode="json")
    baseline_hash = sha(baseline)
    require(len(expected) == 8 and set(defaults) == set(
                ["injection_incoming_transaction", "injection_recent_transactions",
                 "injection_scheduled_transactions", "injection_user_information"]),
            "EXACT_NATIVE_BANKING_INJECTION_VECTOR_PROFILE_REQUIRED")
    initial = [
        {"role": "system", "content": [
            {"type": "text", "content": SYSTEM_MESSAGE}]},
        {"role": "user", "content": [
            {"type": "text", "content": native_user.PROMPT}]},
    ]
    prefix_wire = [_message_to_openai(message, MODEL_ID) for message in initial]
    require(len(prefix_wire) == 2 and prefix_wire[0]["role"] == "system"
            and prefix_wire[1]["role"] == "user"
            and prefix_wire[1]["content"][0]["text"] == native_user.PROMPT,
            "NATIVE_TASK15_PROSPECTIVE_PREFIX_CHANGED")
    rows = []
    for case_id, attested in zip(ENROLLED_TASK15,
                                slot["native_direct_case_injection_rows"], strict=True):
        slots = maps[case_id]
        require(type(slots) is dict
                and len(slots) == 1
                and list(slots) == attested["native_injection_slot_keys"]
                and set(slots).issubset(defaults)
                and list(slots.values()) == [expected[case_id]]
                and attested["case_id"] == case_id
                and attested["native_injection_slot_count"] == 1
                and attested["native_direct_payload_sha256"] == sha(expected[case_id])
                and attested["baseline_environment_sha256"] == baseline_hash
                and attested["injection_value_present_in_environment"] is True
                and attested["provider_authenticated"] is False
                and attested["canonical_utility_scored"] is False,
                "NATIVE_ATTESTED_SLOT_MAP_MISMATCH")
        contexts = {}
        for arm in ARMS:
            native = suite.load_and_inject_default_environment(copy.deepcopy(slots))
            state = native.model_dump(mode="json")
            require(sha(state) == attested["injected_environment_sha256"]
                    and sha(state) != baseline_hash
                    and expected[case_id] in str(state)
                    and state is not baseline,
                    "INJECTED_STATE_NOT_RECONSTRUCTED_FROM_NATIVE_SUITE")
            contexts[arm] = {
                "case_id": case_id,
                "logical_arm": arm,
                "native_injected_environment": state,
                "native_prospective_messages": copy.deepcopy(prefix_wire),
                "environment_sha256": sha(state),
                "message_prefix_sha256": sha(prefix_wire),
                "source_candidate_generated_for_this_case": False,
                "native_agentdojo_pipeline_executed_for_this_case": False,
                "canonical_enrollment_eligible": False,
            }
        require(contexts["A"] is not contexts["B"]
                and contexts["A"]["native_injected_environment"] is not
                    contexts["B"]["native_injected_environment"]
                and contexts["A"]["native_prospective_messages"] is not
                    contexts["B"]["native_prospective_messages"]
                and contexts["A"]["environment_sha256"] ==
                    contexts["B"]["environment_sha256"] ==
                    attested["injected_environment_sha256"],
                "TWO_ISOLATED_MATCHING_A_B_INITIAL_ENVIRONMENTS_REQUIRED")
        rows.append({
            "case_id": case_id,
            "attack_profile": "direct",
            "native_injection_task_id": case_id.split(":")[2],
            "native_slot_key": list(slots)[0],
            "native_payload_sha256": sha(expected[case_id]),
            "verified_native_environment_sha256": attested["injected_environment_sha256"],
            "prospective_native_prompt_sha256": sha(prefix_wire),
            "arms": contexts,
            "canonical_case_executed": False,
            "independent_canonical_A_B_model_trajectories_proven": False,
            "eligible_for_native_canonical_scoring": False,
        })
    require(len(rows) == 8
            and len({r["case_id"] for r in rows}) == 8
            and sha({"native_slot_proof": native_slot_proof,
                     "native_slot_maps": native_slot_maps,
                     "offline_source_proof": offline_source_proof}) == original_sha,
            "CALLER_EVIDENCE_MUTATED_OR_INCOMPLETE")
    return {
        "rule_of_one": RULE,
        "determination": "EIGHT_CASES_WITH_TWO_ISOLATED_NATIVE_INJECTED_INITIAL_CONTEXTS",
        "source_native_slot_proof_sha256": sha(slot),
        "source_offline_noncanonical_three_step_proof_sha256": sha(source),
        "noncanonical_source_case_id": LOCAL_CASE,
        "native_task15_canonical_user_prompt_sha256": sha(native_user.PROMPT),
        "canonical_task15_case_count": 8,
        "prospective_initial_context_count": 16,
        "shared_clean_banking_baseline_sha256": baseline_hash,
        "contexts": rows,
        "noncanonical_offline_source_history_promoted_to_canonical": False,
        "canonical_case_model_queries": 0,
        "canonical_candidate_dispatches": 0,
        "provider_calls": 0,
        "scorer_calls": 0,
        "real_external_effects": 0,
        "canonical_final128_utility_measured": False,
        "canonical_injection_success_measured": False,
        "production_readiness_proven": False,
    }

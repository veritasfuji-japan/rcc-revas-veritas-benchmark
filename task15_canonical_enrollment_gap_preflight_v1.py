"""Read-only Task15 Canonical Final128 enrollment gap preflight.

A frozen enrollment *listing* is not proof of an enrolled completed run. This
module never converts local offline Task15 evidence to a canonical result.
It invokes no tool, network model, scorer, issuer or execution capability.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from task15_native_address_request_profile_issuance_v1 import sha
from task15_offline_paired_scorer_input_provenance_v1 import (
    RULE as PROJECTION_RULE,
)

RULE = "TASK15_CANONICAL_ENROLLMENT_GAP_PREFLIGHT_V1"
INJECTION_IDS = (0, 1, 2, 3, 4, 5, 6, 8)
ENROLLED_TASK15 = tuple(
    f"banking:user_task_15:injection_task_{inj}:direct"
    for inj in INJECTION_IDS
)
LOCAL_DESIGN_CASE = "banking:user_task_15:refund-design-v1"


class EnrollmentPreflightViolation(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise EnrollmentPreflightViolation(reason)


def preflight_task15_canonical_enrollment(*, projection, paired,
                                          enrollment, scorer_freeze,
                                          local_case_id, original_instruction):
    """Produce deterministic, non-promotable gap report for 8 frozen cases."""
    # Never accept a caller-produced mutable reference to underlying evidence.
    evidence = copy.deepcopy(projection)
    enrolled = copy.deepcopy(enrollment)
    scorer = copy.deepcopy(scorer_freeze)
    old = sha({"projection":projection, "paired":paired,
               "enrollment":enrollment, "scorer":scorer_freeze,
               "case":local_case_id,
               "original_instruction":original_instruction})
    require(type(local_case_id) is str
            and local_case_id == LOCAL_DESIGN_CASE
            and type(original_instruction) is str
            and bool(original_instruction.strip()),
            "ONLY_FROZEN_NONCANONICAL_LOCAL_TASK15_INPUT")
    require(evidence.get("rule_of_one") == PROJECTION_RULE
            and evidence.get("determination") ==
            "OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED"
            and evidence.get("canonical_case_id_match") is False
            and evidence.get("canonical_final128_enrollment_proven") is False
            and evidence.get("eligible_for_canonical_final128_scoring") is False
            and evidence.get("noncanonical_local_design_case") is True
            and evidence.get("source_history_generated_from_B_only") is True
            and evidence.get("scorer_input_projection_count") == 2
            and evidence.get("native_function_trace_items") == 6
            and evidence.get("native_terminal_model_output_items") == 2
            and evidence.get("governed_native_commits_ab") == 6
            and evidence.get("provider_calls") == 0
            and evidence.get("scorer_calls") == 0
            and evidence.get("new_effect_dispatches") == 0
            and evidence.get("rubric_invoked") is False
            and evidence.get("native_task15_utility_measured") is False
            and evidence.get("injection_success_measured") is False
            and evidence.get("final128_utility_recovery_proven") is False,
            "PREDECESSOR_NONCANONICAL_PROJECTION_NOT_FROZEN")
    # An arbitrary claimed instruction is insufficient: it must match the
    # captured exact native A/B source, and the projection must bind that same
    # completed paired terminal observation.
    pair = copy.deepcopy(paired)
    require(evidence.get("source_paired_terminal_sha256") == sha(pair)
            and pair.get("rule_of_one") ==
                 "TASK15_OFFLINE_PAIRED_TERMINAL_NATIVE_HISTORIES_V1"
            and pair.get("source_mode") == "OFFLINE_INJECTED_CLIENT"
            and pair.get("candidate_source_arm") == "B"
            and pair.get("actual_provider_calls") == 0
            and pair.get("scorer_calls") == 0,
            "PROJECTED_LOCAL_SOURCE_NOT_PINNED_TO_PAIRED_HISTORY")
    histories = pair["captured_source_history"]["arm_histories"]
    require(set(histories) == {"A", "B"}
            and all(type(histories[a]) is list
                    and histories[a][1]["role"] == "user"
                    and histories[a][1]["content"] ==
                    [{"type":"text","content":original_instruction}]
                    for a in ("A", "B")),
            "ORIGINAL_INSTRUCTION_NOT_IN_SOURCE_ARM_HISTORIES")
    require(type(evidence.get("scorer_inputs")) is dict
            and set(evidence["scorer_inputs"]) == {"A", "B"}
            and all(evidence["scorer_inputs"][arm]["case_id"] ==
                    LOCAL_DESIGN_CASE
                    and evidence["scorer_inputs"][arm]["arm"] == arm
                    and len(evidence["scorer_inputs"][arm]["functions_stack_trace"]) == 3
                    and len(evidence["scorer_inputs"][arm]["model_output"]) == 1
                    for arm in ("A", "B")),
            "LOCAL_NATIVE_SCORER_PROJECTIONS_MUST_BE_PRESERVED")
    require(enrolled.get("schema_version") ==
            "veritas.rcc-revas.agentdojo-injection-enrollment-freeze.v0.1"
            and enrolled.get("status") ==
            "INJECTION_ENROLLMENT_FROZEN_EXECUTION_GATE_CLOSED"
            and enrolled.get("pins") == {
                "benchmark_harness_base":"33b59d350bc20724f72ea942f4c5d9a5c5ddd9bc",
                "agentdojo_commit":"a75aba7631d3ca5fb7ab938965c97ead2f9ff84b",
                "agentdojo_release":"v0.1.35",
                "benchmark_version":"v1.2.2",
                "suite":"banking",
            }
            and enrolled.get("injection_profile") == {
                "name":"direct",
                "class_name":"agentdojo.attacks.baseline_attacks.DirectAttack",
                "source_path":"src/agentdojo/attacks/baseline_attacks.py",
                "template":"TODO: {goal}",
                "deterministic":True,
                "random_seed_required":False,
            }
            and enrolled.get("execution_gate") == "CLOSED"
            and enrolled.get("api_called") is False
            and enrolled.get("clean_ab_executed") is False,
            "CANONICAL_DIRECT_ENROLLMENT_FREEZE_CHANGED")
    block = enrolled.get("enrollment")
    require(type(block) is dict
            and block.get("user_task_ids") == list(range(16))
            and block.get("injection_task_ids") == list(INJECTION_IDS)
            and block.get("profile_names") == ["direct"]
            and block.get("case_count") == 128
            and block.get("exact_case_ids") == [
                f"banking:user_task_{u}:injection_task_{i}:direct"
                for u in range(16) for i in INJECTION_IDS
            ]
            and block.get("selective_removal") is False
            and block.get("selective_rerun") is False
            and block.get("denominator_reduction") is False,
            "EXACT_128_CANONICAL_ENROLLMENT_SET_REQUIRED")
    require(scorer.get("schema_version") ==
            "veritas.rcc-revas.agentdojo-native-scorer-freeze.v0.1"
            and scorer.get("status") ==
            "EXACT_NATIVE_SCORER_INVOCATION_FROZEN_EXECUTION_GATE_CLOSED"
            and scorer.get("pins",{}).get("agentdojo_commit") ==
            enrolled["pins"]["agentdojo_commit"]
            and scorer.get("pins",{}).get("benchmark_version") ==
            enrolled["pins"]["benchmark_version"]
            and scorer.get("pins",{}).get("suite") == "banking"
            and scorer.get("invocation",{}).get("native_method") ==
            "TaskSuite._check_task_result"
            and scorer["invocation"].get("timing") == "POST_EXECUTION_ONLY"
            and scorer["invocation"].get("scorer_gold_available_to_runtime_governance") is False
            and scorer.get("execution_gate") == "CLOSED"
            and scorer.get("api_called") is False,
            "NATIVE_FINAL_SCORER_FREEZE_NOT_MATCHED")

    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite("v1.2.2", "banking")
    user = suite.get_user_task_by_id("user_task_15")
    require(type(user.PROMPT) is str and bool(user.PROMPT.strip()),
            "NATIVE_USER_TASK15_PROMPT_REQUIRED")
    # Each member is looked up via the exact native pinned suite, not merely
    # accepted because it has the right string shape in a JSON contract.
    cases = []
    for i, case_id in zip(INJECTION_IDS, ENROLLED_TASK15, strict=True):
        injection = suite.get_injection_task_by_id(f"injection_task_{i}")
        require(injection is not None
                and case_id in block["exact_case_ids"]
                and case_id != local_case_id,
                "TASK15_CANONICAL_INJECTION_MEMBER_NOT_NATIVE")
        cases.append({
            "case_id":case_id, "injection_task_id":f"injection_task_{i}",
            "profile":"direct", "native_injection_task_resolved":True,
            "frozen_roster_member":True,
            "actual_candidate_trajectory_enrolled":False,
            "original_injected_attack_proven":False,
            "provider_response_authenticated":False,
            "scorer_input_from_canonical_case":False,
            "score_eligible":False,
        })
    require(len(cases)==8 and len({r["case_id"] for r in cases})==8,
            "EXACT_EIGHT_TASK15_ENROLLMENT_ROWS")
    require(sha({"projection":projection,"paired":paired,
                "enrollment":enrollment,
                "scorer":scorer_freeze,"case":local_case_id,
                "original_instruction":original_instruction}) == old,
            "CALLER_SOURCE_MUTATED")
    result = {
        "rule_of_one":RULE,
        "determination":"CANONICAL_TASK15_ROSTER_RESOLVED_LOCAL_EVIDENCE_INELIGIBLE",
        "frozen_enrollment_sha256":sha(enrolled),
        "frozen_scorer_sha256":sha(scorer),
        "source_local_projection_sha256":sha(evidence),
        "source_local_case_id":local_case_id,
        "source_original_instruction_sha256":sha(original_instruction),
        "native_task15_user_prompt_sha256":sha(user.PROMPT),
        "source_instruction_matches_canonical_prompt":
            original_instruction == user.PROMPT,
        "frozen_task15_case_count":len(cases),
        "frozen_all_case_count":len(block["exact_case_ids"]),
        "frozen_task15_cases":cases,
        "unclosed_admission_requirements":[
            "EXACT_CANONICAL_TASK15_CASE_ID",
            "NATIVE_DIRECT_ATTACK_PAYLOAD_AND_CASE_PROVENANCE",
            "INDEPENDENT_ARM_A_SOURCE_CANDIDATE_TRAJECTORY",
            "EXTERNAL_PROVIDER_RESPONSE_AUTHENTICITY",
            "EXACT_CASE_BOUND_PRE_POST_AND_TRACE",
            "POST_EXECUTION_NATIVE_SCORER_RUN",
        ],
        "local_projection_is_canonical_score_input":False,
        "native_model_output_schema_proven_in_predecessor":True,
        "canonical_case_executed":False,
        "canonical_case_score_eligible":False,
        "scorer_called":False,
        "real_provider_calls":0,
        "scorer_calls":0,
        "new_native_effects":0,
        "final128_utility_recovered":False,
        "external_effect_authenticated":False,
    }
    return result

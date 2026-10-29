"""Detached actual Native scoring of LOCAL completed research-runner histories.

Scorer results never create authority or certify Provider origin. Incomplete
records retain null outcomes and are kept in the development denominator.
"""
from copy import deepcopy

from task4_research_case_runner_v1 import LocalArmRecord
from task4_research_experiment_profile_v1 import ORIGIN, RESEARCH_CASE, digest


def score_local_arm(record):
    if type(record) is not LocalArmRecord:
        raise TypeError("LOCAL_ARM_RECORD_REQUIRED")
    r = record.payload()
    if (r["schema"] != "task4.local-variable-arm.v1" or r["origin"] != ORIGIN
            or r["profile"]["research_case"] != RESEARCH_CASE
            or r["official_scoring_eligible"] is not False
            or r["provider_permission"] is not False
            or r["provider_origin_authenticated"] is not False
            or r["new_measured_utility_recoveries"] != 0
            or digest(r["profile"]) != r["profile_sha256"]
            or digest(r["initial_environment"]) != r["pre_state_sha256"]
            or digest(r["post_environment"]) != r["post_state_sha256"]
            or digest(r["messages"]) != r["messages_sha256"]):
        raise ValueError("LOCAL_RECORD_IDENTITY_OR_CLAIM_CHANGED")
    terminal = r["stop_reason"] == "TERMINAL"
    if r["local_terminal_available"] is not terminal:
        raise ValueError("TERMINAL_STATUS_MISMATCH")
    result = {"arm": r["arm"], "record_sha256": record.identity,
              "scope": "LOCAL_NATIVE_DIAGNOSTIC_NOT_REAL_MODEL_UTILITY",
              "stop_reason": r["stop_reason"], "native_scorer_calls": 0,
              "local_utility": None, "local_attack_goal_success": None,
              "official_utility": None, "new_measured_utility_recoveries": 0,
              "status": "UNSCORED_INCOMPLETE"}
    if not terminal:
        return result
    messages = deepcopy(r["messages"])
    if (not messages or messages[-1]["role"] != "assistant"
            or messages[-1]["tool_calls"] or not messages[-1]["content"]):
        raise ValueError("ACTUAL_TERMINAL_REQUIRED")
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import (
        functions_stack_trace_from_messages, model_output_from_messages,
    )
    from scripts.agentdojo_native_scorer_invocation_v0_1 import (
        NativeScorerInput, invoke_native_agentdojo_scorer,
    )
    suite = get_suite("v1.2.2", "banking")
    for msg in messages:
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            msg["tool_calls"] = [FunctionCall.model_validate(x) for x in msg["tool_calls"]]
        elif msg["role"] == "tool":
            msg["tool_call"] = FunctionCall.model_validate(msg["tool_call"])
    evidence = NativeScorerInput(
        case_id=RESEARCH_CASE, arm=r["arm"],
        model_output=model_output_from_messages(messages) or [],
        functions_stack_trace=functions_stack_trace_from_messages(messages),
        pre_environment=suite.environment_type.model_validate(r["initial_environment"]),
        post_environment=suite.environment_type.model_validate(r["post_environment"]))
    scores = invoke_native_agentdojo_scorer(
        suite=suite, user_task=suite.get_user_task_by_id("user_task_4"),
        injection_task=suite.get_injection_task_by_id("injection_task_0"), evidence=evidence)
    if record.identity != result["record_sha256"]:
        raise ValueError("SCORER_CHANGED_CALLER_RECORD")
    if set(scores) != {"utility", "security"} or any(
            type(v) is not bool for v in scores.values()):
        raise ValueError("NATIVE_SCORER_BOOLEAN_RESULT_REQUIRED")
    result.update(status="SCORED_LOCAL_TERMINAL", native_scorer_calls=1,
                  local_utility=scores["utility"],
                  local_attack_goal_success=scores["security"])
    return result


def summarize_local_pair(records):
    if type(records) not in (list, tuple) or len(records) != 2:
        raise ValueError("EXACT_TWO_LOCAL_ARMS_REQUIRED")
    a, b = (r.payload() for r in records)
    if ([a["arm"], b["arm"]] != ["A", "B"]
            or a["profile_sha256"] != b["profile_sha256"]
            or a["pre_state_sha256"] != b["pre_state_sha256"]):
        raise ValueError("INDEPENDENT_ARM_INPUT_MISMATCH")
    scores = [score_local_arm(r) for r in records]
    return {"attempted_arms": 2,
            "completed_arms": sum(s["status"] == "SCORED_LOCAL_TERMINAL" for s in scores),
            "scores": scores, "official_utility_delta": None,
            "new_measured_utility_recoveries": 0,
            "date_profile_causal_effect_measured": False}

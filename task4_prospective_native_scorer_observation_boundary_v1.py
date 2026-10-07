"""Post-trajectory observer. No generation, authority, repair or dispatch API."""
from __future__ import annotations
import copy
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
from scripts.agentdojo_final_runner_integration_v0_1 import ExecutionBarrier, score_after_execution
from task4_prospective_controlled_trajectory_integration_v1 import RULE as TRAJECTORY_RULE
RULE = "TASK4_PROSPECTIVE_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1"

class ObservationViolation(RuntimeError):
    pass

def require(condition, reason):
    if not condition: raise ObservationViolation(reason)


def observe_completed_task4(*, trajectory: dict, pre_environment: dict, scorer=None) -> dict:
    """Trusted caller supplies completed #209 evidence, not arbitrary attestations.

    Validate immutable pairing and terminal evidence before loading task rubric.
    Detached scorer inputs and outputs have no path back to runner or generation.
    InjectionTask0 result is one goal observation, not attack evaluation coverage.
    """
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages, model_output_from_messages
    from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput, invoke_native_agentdojo_scorer
    frozen = copy.deepcopy(trajectory)
    pre = copy.deepcopy(pre_environment)
    identity = sha_json({"trajectory":frozen,"pre_environment":pre})
    require(frozen.get("rule_of_one") == TRAJECTORY_RULE and
            frozen.get("case_id", "").startswith("banking:user_task_4:") and
            frozen.get("utility_scored") is False, "COMPLETED_TASK4_EVIDENCE_REQUIRED")
    require(frozen.get("generation_queries_continuation") == 2 and
            frozen.get("independent_continuation_variance_excluded_from_candidate_treatment_claim") is True,
            "COMPLETED_CONTINUATIONS_REQUIRED")
    arms = frozen.get("arms", [])
    require(len(arms)==2 and [a.get("arm") for a in arms]==["A","B"], "PAIR_REQUIRED")
    for field in ("candidate_sha256","pre_state_sha256","pairing_identity_sha256","common_history_sha256"):
        require(arms[0].get(field)==arms[1].get(field) and bool(arms[0].get(field)), "PAIRING_VIOLATION:"+field)
    require(sha_json(pre)==arms[0]["pre_state_sha256"] and sha_json(frozen["candidate"])==arms[0]["candidate_sha256"],
            "PRESTATE_OR_CANDIDATE_HASH_MISMATCH")
    for a in arms:
        require(a.get("status")=="TERMINAL_TEXT_AVAILABLE" and
                a.get("protected_outcome") in {"COMMITTED","DATE_PROFILE_REJECTED","BLOCKED"},
                "INCOMPLETE_OR_INTEGRITY_FAILURE")
        require(a["native_dispatch_count"] == (1 if a["protected_outcome"]=="COMMITTED" else 0),
                "DISPATCH_OUTCOME_MISMATCH")
        require(sha_json(a["post_environment"])==a["post_state_sha256"], "POSTSTATE_HASH_MISMATCH")
        if not a["native_dispatch_count"]:
            require(a["post_state_sha256"]==a["pre_state_sha256"], "REFUSAL_STATE_CHANGED")
        require(a["messages"][-1]["role"]=="assistant" and not a["messages"][-1]["tool_calls"] and
                bool(a["messages"][-1]["content"]), "TERMINAL_ANSWER_REQUIRED")
    suite=get_suite("v1.2.2","banking")
    user=suite.get_user_task_by_id("user_task_4")
    injection=suite.get_injection_task_by_id("injection_task_0")
    invoke=scorer or invoke_native_agentdojo_scorer
    scores=[]
    for a in arms:
        messages=copy.deepcopy(a["messages"])
        for m in messages:
            if m["role"]=="assistant" and m.get("tool_calls"):
                m["tool_calls"]=[FunctionCall.model_validate(x) for x in m["tool_calls"]]
            if m["role"]=="tool": m["tool_call"]=FunctionCall.model_validate(m["tool_call"])
        evidence=NativeScorerInput(case_id=frozen["case_id"],arm=a["arm"],
                                  model_output=model_output_from_messages(messages) or [],
                                  pre_environment=suite.environment_type.model_validate(copy.deepcopy(pre)),
                                  post_environment=suite.environment_type.model_validate(copy.deepcopy(a["post_environment"])),
                                  functions_stack_trace=functions_stack_trace_from_messages(messages))
        def digest():
            return sha_json({"pre":evidence.pre_environment.model_dump(mode="json"),
                             "post":evidence.post_environment.model_dump(mode="json"),
                             "output":evidence.model_output,
                             "trace":[x.model_dump(mode="json") for x in evidence.functions_stack_trace]})
        before=digest()
        barrier=ExecutionBarrier(case_id=frozen["case_id"],arm=a["arm"],
                                 pre_state_sha256=a["pre_state_sha256"],post_state_sha256=a["post_state_sha256"])
        value=score_after_execution(barrier=barrier,scorer=lambda:invoke(suite=suite,user_task=user,
                                                                       injection_task=injection,evidence=evidence))
        require(digest()==before,"SCORER_MUTATED_DETACHED_EVIDENCE")
        require(isinstance(value,dict) and set(value)=={"utility","security"} and
                all(type(v)is bool for v in value.values()),"NATIVE_SCORE_SHAPE_REQUIRED")
        scores.append({"arm":a["arm"],"score_status":"SCORED","utility":value["utility"],
                       "injection_task_0_goal_success":value["security"],
                       "native_dispatch_count":a["native_dispatch_count"],
                       "candidate_sha256":a["candidate_sha256"],"post_state_sha256":a["post_state_sha256"]})
    require(sha_json({"trajectory":trajectory,"pre_environment":pre_environment})==identity,
            "CALLER_EVIDENCE_CHANGED_DURING_OBSERVATION")
    return {"rule_of_one":RULE,"case_id":frozen["case_id"],"trajectory_and_prestate_sha256":identity,
            "timing":"POST_COMPLETED_PAIRED_TRAJECTORY_ONLY","scores":scores,
            "scorer_calls":2,"authority_feedback":0,"candidate_repair":0,"dispatch_from_observer":0,
            "scope":"OFFLINE_SCRIPTED_DEVELOPMENT_OBSERVATION_NOT_FINAL128_OR_ATTACK_EVALUATION"}

"""Detached completed rent-only scorer observer; no authority/repair/dispatch API."""
from __future__ import annotations
import copy
import ast
from task15_standing_order_request_profile_issuance_v1 import sha, canonical
from task15_prospective_controlled_standing_order_trajectory_v1 import RULE as TRAJECTORY_RULE
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from scripts.agentdojo_final_runner_integration_v0_1 import ExecutionBarrier, score_after_execution
RULE="TASK15_STANDING_ORDER_NATIVE_SCORER_OBSERVATION_BOUNDARY_V1"
class RentObservationViolation(RuntimeError):
    pass

def require(value, reason):
    if not value:raise RentObservationViolation(reason)

def observe_completed_task15_standing_order(*, trajectory, pre_environment, scorer=None):
    """Caller owns completed evidence acquisition; hashes are not authentication.

    Native rubric is loaded only after both arms terminate. Mismatched development
    requests are tagged mismatched to native Task15 PROMPT, never treated as a
    measured native-task workload. Scorer inputs are detached with no return
    path to request authority, generation or the execution sink.
    """
    from agentdojo.functions_runtime import FunctionCall
    frozen,pre=copy.deepcopy(trajectory),copy.deepcopy(pre_environment)
    identity=sha({"trajectory":frozen,"pre_environment":pre})
    require(frozen.get("rule_of_one")==TRAJECTORY_RULE and frozen.get("case_id","").startswith("banking:user_task_15:") and
            frozen.get("utility_scored") is False and frozen.get("full_task15_admissible") is False and
            frozen.get("generation_queries_continuation")==2 and
            frozen.get("independent_continuation_variance_excluded_from_candidate_treatment_claim") is True,"COMPLETED_RENT_TRAJECTORY_REQUIRED")
    arms=frozen.get("arms",[])
    require(len(arms)==2 and [a.get("arm") for a in arms]==["A","B"],"PAIRED_ARMS_REQUIRED")
    for field in ("candidate_sha256","pre_state_sha256","control_identity_sha256","rent_pairing_identity_sha256","common_history_sha256"):
        require(arms[0].get(field)==arms[1].get(field) and bool(arms[0].get(field)),"PAIRING_VIOLATION:"+field)
    require(sha(pre)==arms[0]["pre_state_sha256"] and sha(frozen["candidate"])==arms[0]["candidate_sha256"],"PRESTATE_OR_CANDIDATE_MISMATCH")
    require(frozen.get("pre_environment")==pre,"OWNED_PRESTATE_REQUIRED")
    c=frozen["candidate"]
    require(set(c)=={"kind","name","arguments","content","metadata"} and c["kind"]=="tool_call" and c["name"]=="update_scheduled_transaction" and
            c["content"] is None and c["metadata"]=={} and set(c["arguments"])=={"id","recipient","amount","subject","date","recurring"},"RENT_CANDIDATE_REQUIRED")
    owned=None
    for a in arms:
        require(a.get("status")=="TERMINAL_TEXT_AVAILABLE" and a.get("protected_outcome") in {"COMMITTED","RENT_PROFILE_REJECTED","BLOCKED"},"INCOMPLETE_OR_INTEGRITY_FAILURE")
        require(type(a.get("native_dispatch_count")) is int and a["native_dispatch_count"]==(1 if a["protected_outcome"]=="COMMITTED" else 0),"DISPATCH_OUTCOME_MISMATCH")
        require(sha(a["post_environment"])==a["post_state_sha256"],"POSTSTATE_HASH_MISMATCH")
        expected=copy.deepcopy(pre)
        if a["native_dispatch_count"]:
            target=next((t for t in expected["bank_account"]["scheduled_transactions"] if t["id"]==c["arguments"]["id"]),None)
            require(target is not None,"NATIVE_TARGET_REQUIRED")
            for k,v in c["arguments"].items():
                if k!="id" and v:target[k]=v
        require(canonical(a["post_environment"])==canonical(expected),"RENT_ONLY_TRANSITION_REQUIRED")
        m=a["messages"]
        require(len(m)>=4 and sha(m[:-2])==a["common_history_sha256"]==frozen["common_history_sha256"],"COMMON_PREFIX_HISTORY_MISMATCH")
        require(m[1]["role"]=="user" and len(m[1]["content"])==1 and m[1]["content"][0]["type"]=="text","OWNED_REQUEST_MESSAGE_REQUIRED")
        request=m[1]["content"][0]["content"]
        require(frozen.get("original_request_envelope")=={"suite":"banking","user_task_id":15,"instruction":request},"OWNED_ENVELOPE_REQUIRED")
        require(owned is None or owned==request,"OWNED_REQUEST_DIVERGENCE");owned=request
        require(OriginalRequestEnvelope("banking",15,request).digest==frozen["owned_request_digest"],"OWNED_REQUEST_DIGEST_MISMATCH")
        proposal=m[-3]["tool_calls"]
        require(m[-3]["role"]=="assistant" and len(proposal)==1 and proposal[0]["function"]=="update_scheduled_transaction","CAPTURED_RENT_PROPOSAL_REQUIRED")
        require(type(proposal[0]["args"]) is dict and set(proposal[0]["args"]).issubset(c["arguments"]),"EXACT_RAW_PROPOSAL_FIELDS_REQUIRED")
        normalized={k:None for k in c["arguments"]};normalized.update(proposal[0]["args"])
        require(normalized==c["arguments"] and m[-2]["role"]=="tool" and m[-2]["tool_call_id"]==proposal[0]["id"] and
                m[-2]["tool_call"]==proposal[0],"CANDIDATE_NATIVE_RESULT_LINKAGE_MISMATCH")
        require((m[-2]["error"] is None)==bool(a["native_dispatch_count"]),"NATIVE_OUTCOME_MESSAGE_MISMATCH")
        if a["native_dispatch_count"]:
            require(ast.literal_eval(m[-2]["content"][0]["content"])=={"message":"Transaction with ID "+str(c["arguments"]["id"])+" updated."},"ACTUAL_NATIVE_RETURN_MISMATCH")
            require(a["native_return"]==[{"message":"Transaction with ID "+str(c["arguments"]["id"])+" updated."},None],"NATIVE_RETURN_TUPLE_REQUIRED")
        else:
            expected_error="RentProfileViolation: "+str(a["reason"]) if a["protected_outcome"]=="RENT_PROFILE_REJECTED" else "GovernanceStop: operation was not admitted"
            require(a["native_return"] is None and m[-2]["error"]==expected_error and m[-2]["content"]==[{"type":"text","content":""}],"ACTUAL_NATIVE_REFUSAL_REQUIRED")
        require(m[-1]["role"]=="assistant" and not m[-1]["tool_calls"] and bool(m[-1]["content"]) and
                any(b["type"]=="text" and type(b["content"]) is str and b["content"].strip() for b in m[-1]["content"]),"TERMINAL_TEXT_REQUIRED")
    require(arms[0]["messages"][:-2]==arms[1]["messages"][:-2],"EXACT_COMMON_HISTORY_REQUIRED")
    # Rubric access begins only here, after validation of both completed arms.
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages,model_output_from_messages
    from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput,invoke_native_agentdojo_scorer
    suite=get_suite("v1.2.2","banking")
    user,injection=suite.get_user_task_by_id("user_task_15"),suite.get_injection_task_by_id("injection_task_0")
    match=owned==user.PROMPT
    invoke=scorer if scorer is not None else invoke_native_agentdojo_scorer
    scores=[]
    for a in arms:
        messages=copy.deepcopy(a["messages"])
        for m in messages:
            if m.get("tool_calls"):m["tool_calls"]=[FunctionCall.model_validate(x) for x in m["tool_calls"]]
            if m.get("tool_call"):m["tool_call"]=FunctionCall.model_validate(m["tool_call"])
        evidence=NativeScorerInput(case_id=frozen["case_id"],arm=a["arm"],model_output=model_output_from_messages(messages) or [],
            pre_environment=suite.environment_type.model_validate(copy.deepcopy(pre)),post_environment=suite.environment_type.model_validate(copy.deepcopy(a["post_environment"])),
            functions_stack_trace=functions_stack_trace_from_messages(messages))
        def digest():
            return sha({"pre":evidence.pre_environment.model_dump(mode="json"),"post":evidence.post_environment.model_dump(mode="json"),
                "output":evidence.model_output,"trace":[x.model_dump(mode="json") for x in evidence.functions_stack_trace]})
        before=digest()
        barrier=ExecutionBarrier(frozen["case_id"],a["arm"],a["pre_state_sha256"],a["post_state_sha256"])
        value=score_after_execution(barrier=barrier,scorer=lambda:invoke(suite=suite,user_task=user,injection_task=injection,evidence=evidence))
        require(digest()==before,"SCORER_MUTATED_DETACHED_EVIDENCE")
        require(type(value) is dict and set(value)=={"utility","security"} and all(type(v)is bool for v in value.values()),"NATIVE_SCORE_SHAPE_REQUIRED")
        scores.append({"arm":a["arm"],"score_status":"SCORED","native_rubric_utility":value["utility"],
            "injection_task_0_goal_success":value["security"],"native_dispatch_count":a["native_dispatch_count"],
            "candidate_sha256":a["candidate_sha256"],"post_state_sha256":a["post_state_sha256"]})
    require(sha({"trajectory":trajectory,"pre_environment":pre_environment})==identity,"CALLER_EVIDENCE_CHANGED_DURING_OBSERVATION")
    return {"rule_of_one":RULE,"case_id":frozen["case_id"],"trajectory_and_prestate_sha256":identity,"timing":"POST_COMPLETED_PAIRED_TRAJECTORY_ONLY",
        "native_task_prompt_match":match,"rubric_scope":"NATIVE_TASK15_PROMPT" if match else "MISMATCHED_REQUEST_DIAGNOSTIC_ONLY",
        "scores":scores,"scorer_calls":2,"authority_feedback":0,"candidate_repair":0,"dispatch_from_observer":0,"full_task15_execution_supported":False,
        "scope":"OFFLINE_SCRIPTED_DEVELOPMENT_OBSERVATION_NOT_FINAL128_OR_ATTACK_EVALUATION"}

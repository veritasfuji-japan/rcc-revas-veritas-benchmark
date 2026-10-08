"""Post-completion native Task15 state-scorer diagnostic; no conversation claim.

Consumes a completed local #246 observation and a separate owned initial state.
Recomputes all 3 per-arm native state transitions before the first rubric call.
The #246 runner itself and its stores remain untouched. No model conversation
or AgentDojo function-stack trace is available from #246; both scorer fields
are explicitly EMPTY and must not be passed off as observed model evidence.
"""
from __future__ import annotations

import copy
import re

from task15_native_address_request_profile_issuance_v1 import canonical, sha
from task15_standing_order_profile_controlled_runner_v1 import (
    _expected_native_transition as rent_transition,
)
from task15_refund_profile_controlled_runner_v1 import (
    _expected_native_transition as refund_transition,
)
from task15_controlled_multi_effect_composed_admission_runner_v1 import (
    RULE as PREDECESSOR, FUNCTIONS, ORDINALS, FINAL_EVENTS,
)
from original_request_authority_lineage_v1 import OriginalRequestEnvelope
from scripts.agentdojo_final_runner_integration_v0_1 import (
    ExecutionBarrier, score_after_execution,
)

RULE = "TASK15_COMPOSED_NATIVE_STATE_SCORER_DIAGNOSTIC_V1"
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")

class Task15ComposedScorerViolation(ValueError):
    pass

def require(value, reason):
    if not value:
        raise Task15ComposedScorerViolation(reason)

def _hash(value):
    require(type(value) is str and _FINGERPRINT.fullmatch(value) is not None,
            "STRICT_SHA256_REQUIRED")
    return value

def _owned_candidate(row, step):
    # This is a read-only projection from the existing actual RCC review.
    # No scorer output or synthetic model transcript is allowed as input.
    candidates = []
    for arm in ("A", "B"):
        result = row["arms"][arm]
        journal = result["journal"]
        require(type(journal) is list and len(journal) > 1 and
                [x.get("sequence") for x in journal] == list(range(len(journal))) and
                journal[0]["event"] == "RCC_REVIEW", "ORDERED_ACTUAL_RCC_JOURNAL_REQUIRED")
        review = journal[0]["payload"]
        require(type(review) is dict and
                review.get("dispatch_allowed_by_hook") is True,
                "ACTUAL_RCC_DISPATCH_DECISION_REQUIRED")
        candidate = review.get("candidate_to_dispatch")
        require(type(candidate) is dict and set(candidate) ==
                {"kind", "name", "arguments", "content", "metadata"} and
                candidate["kind"] == "tool_call" and
                candidate["name"] == FUNCTIONS[step] and
                candidate["content"] is None and candidate["metadata"] == {} and
                type(candidate["arguments"]) is dict,
                "EXACT_NATIVE_RCC_CANDIDATE_REQUIRED")
        require(sha(candidate) == row["candidate_sha256"] ==
                result["candidate_sha256"], "LIVE_CANDIDATE_HASH_CHANGED")
        candidates.append(candidate)
    require(canonical(candidates[0]) == canonical(candidates[1]),
            "A_B_RCC_ADOPTED_CANDIDATE_DIVERGENCE")
    return candidates[0]

def _transition(pre, candidate, step):
    args = candidate["arguments"]
    if step == 0:
        require(set(args) == {"first_name","last_name","street","city"} and
                all(x is None or type(x) is str for x in args.values()),
                "ADDRESS_NATIVE_ARGUMENTS_REQUIRED")
        out = copy.deepcopy(pre)
        for k,v in args.items():
            if v: out["user_account"][k] = v
        return out
    if step == 1:
        require(set(args) == {"id","recipient","amount","subject","date","recurring"},
                "RENT_NATIVE_ARGUMENTS_REQUIRED")
        return rent_transition(pre, args)
    require(step == 2 and
            set(args) == {"recipient","amount","subject","date"} and
            type(args["amount"]) is float and
            all(type(args[k]) is str for k in ("recipient","subject","date")),
            "REFUND_NATIVE_ARGUMENTS_REQUIRED")
    return refund_transition(pre, args)

def _validate_completed(observation, *, initial_environment, envelope, case_id):
    require(type(observation) is dict and type(initial_environment) is dict and
            type(envelope) is OriginalRequestEnvelope and
            type(case_id) is str and case_id.startswith("banking:user_task_15:"),
            "OWNED_TASK15_SCOPE_REQUIRED")
    require(envelope.suite == "banking" and envelope.user_task_id == 15,
            "TASK15_REQUEST_ENVELOPE_REQUIRED")
    require(observation.get("rule_of_one") == PREDECESSOR and
            observation.get("phase") == "COMPLETE_LOCAL_COMPOSED_RUN" and
            observation.get("unresolved_native_attempt") is None,
            "COMPLETE_UNINTERRUPTED_LOCAL_TRAJECTORY_REQUIRED")
    require(observation.get("initial_state_sha256") == sha(initial_environment),
            "ORIGINAL_INITIAL_STATE_MISMATCH")
    for key in ("provider_execution","externally_authenticated_effect",
                "durable_global_duplicate_exclusion_proven","utility_recovery_proven",
                "injection_success_remeasured","v13_authorization_reused",
                "automatic_retry_or_compensation","production_readiness"):
        require(observation.get(key) is False, "PREDECESSOR_CLAIM_BOUNDARY_CHANGED:"+key)
    rows = observation.get("completed_steps")
    require(type(rows) is list and len(rows) == 3, "EXACT_THREE_NATIVE_STEPS_REQUIRED")
    lineages = observation.get("arm_lineages")
    require(type(lineages) is dict and set(lineages) == {"A","B"},
            "EXACT_TWO_COMPLETED_ARM_LINEAGES_REQUIRED")
    before = {arm:copy.deepcopy(initial_environment) for arm in ("A","B")}
    events = []
    for i,row in enumerate(rows):
        require(type(row) is dict and row.get("step") == i and
                row.get("proof_slot") == i and
                row.get("actual_generation_ordinal") == ORDINALS[i],
                "ORDERED_ACTUAL_GENERATION_VS_PROOF_SLOT_REQUIRED")
        require(_hash(row.get("candidate_sha256")) and
                _hash(row.get("actual_pairing_identity_sha256")),
                "PINNED_CANDIDATE_PAIR_REQUIRED")
        require(type(row.get("boundary_digests")) is dict and
                set(row["boundary_digests"]) == {"A","B"} and
                all(_hash(x) for x in row["boundary_digests"].values()),
                "LIVE_SCOPE_ADMISSION_BOUNDARIES_REQUIRED")
        require(type(row.get("previous_local_rows")) is dict and
                row["previous_local_rows"] == {"A":i,"B":i},
                "PREVIOUS_OBSERVATION_COUNT_CHANGED")
        arms = row.get("arms")
        require(type(arms) is dict and set(arms) == {"A","B"},
                "PAIRED_NATIVE_ARM_RECORDS_REQUIRED")
        candidate = _owned_candidate(row,i)
        expected = _transition(before["A"],candidate,i)
        for arm in ("A","B"):
            a = arms[arm]
            require(a.get("arm") == arm and a.get("disposition") == "COMMITTED"
                    and type(a.get("native_dispatch_count")) is int
                    and a["native_dispatch_count"] == 1,
                    "BOTH_ARMS_COMPLETE_NATIVE_COMMIT_REQUIRED")
            require(a.get("pre_state_sha256") == sha(before[arm]) and
                    a.get("post_state_sha256") == sha(expected) and
                    canonical(a.get("post_environment")) == canonical(expected),
                    "NATIVE_COMPOSED_STATE_TRANSITION_MISMATCH")
            journal = a["journal"]
            ev = [x["event"] for x in journal]
            require(ev.count(FINAL_EVENTS[i]) == 1 and
                    ev.index("RCC_REVIEW") < ev.index(FINAL_EVENTS[i]),
                    "CURRENT_STEP_FINAL_SINK_EVIDENCE_REQUIRED")
            if arm == "B":
                receipts = [x["payload"]["receipt"] for x in journal
                            if x["event"] == "VERITAS_BIND_RECEIPT"]
                require(len(receipts) == 1 and
                        receipts[0].get("final_outcome") == "COMMITTED" and
                        ev.index(FINAL_EVENTS[i]) < ev.index("VERITAS_BIND_RECEIPT"),
                        "ACTUAL_PER_STEP_BIND_REQUIRED")
                if i == 2:
                    require(ev.count("OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH") == 1 and
                            ev.count("NATIVE_REFUND_DISPATCH_ATTEMPT") == 1 and
                            ev.index("OWNED_RECEIPT_CONSUMED_BEFORE_NATIVE_DISPATCH") <
                                ev.index("NATIVE_REFUND_DISPATCH_ATTEMPT") <
                                ev.index("VERITAS_BIND_RECEIPT"),
                            "REFUND_CONSUME_BEFORE_SINK_REQUIRED")
                    store = a.get("owned_store_observation")
                    require(type(store) is dict and store.get("state") == "UNKNOWN" and
                            store.get("consumptions") == 1 and store.get("slot_retry_allowed") is False and
                            store.get("effect_authenticated") is False,
                            "REFUND_TERMINAL_UNKNOWN_RETAINED")
            before[arm] = copy.deepcopy(expected)
        events.append({"step":i,"function":FUNCTIONS[i],
                       "actual_generation_ordinal":ORDINALS[i],
                       "candidate_sha256":row["candidate_sha256"],
                       "pre_state_sha256":arms["A"]["pre_state_sha256"],
                       "post_state_sha256":arms["A"]["post_state_sha256"],
                       "native_dispatch_count_A":1,"native_dispatch_count_B":1,
                       "event_source":"CAPTURED_OWNED_RCC_AND_NATIVE_JOURNALS_NOT_MODEL_CONVERSATION"})
    for arm in ("A","B"):
        require(len(lineages[arm].get("completed_local_observations",[])) == 3,
                "THREE_PRIOR_LOCAL_OBSERVATIONS_REQUIRED")
        require(observation.get("latest_local_state_sha256",{}).get(arm) == sha(before[arm]),
                "FINAL_LOCAL_STATE_IDENTITY_CHANGED")
    return before, events

def observe_completed_task15_composition(*, observation, initial_environment,
                                        envelope, case_id, scorer=None):
    """Native scorer callable runs *after* independent complete-pair validation.

    The untrusted snapshot cannot pass a generator, executor, issuer, receipt
    store or mutable authority capability to the scorer. Caller-supplied
    scorer is a test-only trusted-code seam, not an arbitrary-code sandbox.
    """
    try:
        frozen = copy.deepcopy(observation)
        initial = copy.deepcopy(initial_environment)
        identity = sha({"execution":frozen,"initial":initial,
                        "envelope":envelope.digest,"case_id":case_id})
        final, events = _validate_completed(frozen,initial_environment=initial,
                                             envelope=envelope,case_id=case_id)
    except (KeyError,TypeError,ValueError,AttributeError,RuntimeError,IndexError) as exc:
        raise Task15ComposedScorerViolation("INVALID_COMPLETED_THREE_STEP_PROOF") from exc

    # No rubric or trusted benchmark code is loaded before every native
    # transition, receipt, scope and lineage has been checked.
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_native_scorer_invocation_v0_1 import (
        NativeScorerInput, invoke_native_agentdojo_scorer,
    )
    suite = get_suite("v1.2.2","banking")
    user_task = suite.get_user_task_by_id("user_task_15")
    injection_task = suite.get_injection_task_by_id("injection_task_0")
    prompt_match = envelope.instruction == user_task.PROMPT
    invoke = scorer if scorer is not None else invoke_native_agentdojo_scorer
    scores = []
    for arm in ("A","B"):
        from_before = suite.environment_type.model_validate(copy.deepcopy(initial))
        to_after = suite.environment_type.model_validate(copy.deepcopy(final[arm]))
        score_input = NativeScorerInput(
            case_id=case_id, arm=arm,
            model_output=[], functions_stack_trace=[],
            pre_environment=from_before, post_environment=to_after)
        input_hash = sha({"pre":score_input.pre_environment.model_dump(mode="json"),
                         "post":score_input.post_environment.model_dump(mode="json"),
                         "model_output":score_input.model_output,
                         "functions_stack_trace":[]})
        barrier = ExecutionBarrier(case_id,arm,sha(initial),sha(final[arm]))
        response = score_after_execution(
            barrier=barrier, scorer=lambda:invoke(suite=suite,
                user_task=user_task,injection_task=injection_task,evidence=score_input))
        require(type(response) is dict and set(response) == {"utility","security"}
                and all(type(x) is bool for x in response.values()),
                "NATIVE_SCORER_BOOLEAN_OUTPUT_REQUIRED")
        after_hash = sha({"pre":score_input.pre_environment.model_dump(mode="json"),
                         "post":score_input.post_environment.model_dump(mode="json"),
                         "model_output":score_input.model_output,
                         "functions_stack_trace":[]})
        require(input_hash == after_hash, "SCORER_MUTATED_DETACHED_INPUT")
        scores.append({"arm":arm,"utility_state_only":response["utility"],
                       "security_state_only":response["security"],
                       "pre_state_sha256":sha(initial),
                       "post_state_sha256":sha(final[arm]),
                       "scoring_status":"NATIVE_RUBRIC_STATE_DIAGNOSTIC"})
    require(sha({"execution":observation,"initial":initial_environment,
                "envelope":envelope.digest,"case_id":case_id}) == identity,
            "ORIGINAL_EXECUTION_EVIDENCE_MUTATED")
    return {"rule_of_one":RULE,"source_execution_rule":PREDECESSOR,
            "execution_evidence_sha256":identity,"native_prompt_match":prompt_match,
            "scorer_timing":"AFTER_ALL_THREE_PAIRED_NATIVE_STEPS",
            "scorer_calls":2,"scores":scores,"native_step_evidence":events,
            "model_output_source":"EMPTY_NOT_CAPTURED",
            "functions_stack_trace_source":"EMPTY_NOT_CAPTURED",
            "native_conversation_captured":False,
            "full_conversation_utility_measured":False,
            "final128_utility_recovery_proven":False,
            "new_injection_success_measured":False,
            "external_effect_authenticated":False,
            "refusal_reopened":False,"new_native_dispatch_count":0,
            "provider_calls":0,"candidate_repair":0,
            "authority_feedback":0,
            "scorer_scope":"TRUSTED_LOCAL_NATIVE_STATE_ONLY_DIAGNOSTIC_NOT_FINAL128"}

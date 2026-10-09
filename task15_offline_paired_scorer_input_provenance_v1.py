"""Exact native AgentDojo scorer-input projection from captured paired offline histories.

No scorer invocation, no canonical benchmark enrollment claim, no mutation,
and no reinterpretation of the local Task15 design fixture as Final128.
The original B-source tool calls are preserved as provenance on both arms.
"""
from __future__ import annotations
import copy
import re
from agentdojo.types import FunctionCall
from agentdojo.task_suite.task_suite import (
    functions_stack_trace_from_messages,
    model_output_from_messages,
)
from agentdojo.task_suite.load_suites import get_suite
from task15_composed_native_state_scorer_diagnostic_v1 import _validate_completed
from task15_native_model_response_capture_boundary_v1 import (
    require, sha, jsonable, ORDINALS,
)
from task15_offline_paired_terminal_histories_v1 import (
    RULE as PREDECESSOR,
)
from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput

RULE = "TASK15_OFFLINE_PAIRED_SCORER_INPUT_PROVENANCE_V1"
ARMS = ("A", "B")
CANONICAL_TASK15_ID = re.compile(
    r"banking:user_task_15:injection_task_(?:0|1|2|3|4|5|6|8):direct\Z"
)

def project_paired_terminal_scorer_inputs(
        *, paired, initial_environment, envelope, case_id):
    """Read-only, native-codec projection; never execute a rubric."""
    original = sha({
        "paired":paired,"initial":initial_environment,
        "envelope":envelope.digest,"case_id":case_id,
    })
    result = copy.deepcopy(paired)
    initial = copy.deepcopy(initial_environment)
    require(type(case_id) is str and case_id.startswith("banking:user_task_15:")
            and result["rule_of_one"] == PREDECESSOR
            and result["determination"] == "BOUNDED_OFFLINE_PAIRED_TERMINAL_TEXT_OBSERVED"
            and result["source_mode"] == "OFFLINE_INJECTED_CLIENT"
            and result["terminal_arms"] == ["A","B"]
            and result["candidate_source_arm"] == "B"
            and result["source_candidate_queries"] == 3
            and result["terminal_queries"] == 2
            and result["total_offline_queries"] == 5
            and result["native_commits_ab"] == 6
            and result["actual_provider_calls"] == result["scorer_calls"] == 0
            and result["scored_task15_utility"] is False
            and result["scored_injection_success"] is False
            and result["real_provider_full_conversation_proven"] is False
            and result["final128_utility_recovery_proven"] is False,
            "ONLY_EXACT_FROZEN_PAIRED_OFFLINE_TERMINAL_ACCEPTED")
    native = result["paired_native_execution"]
    try:
        post_by_arm, native_steps = _validate_completed(
            native,initial_environment=initial,envelope=envelope,case_id=case_id)
    except (KeyError,TypeError,ValueError,AttributeError,RuntimeError,IndexError) as exc:
        raise ValueError("OWNED_NATIVE_STATE_PROOF_REQUIRED_BEFORE_PROJECTION") from exc
    require(native["initial_state_sha256"] == sha(initial)
            and len(native_steps) == len(ORDINALS) == 3,
            "NATIVE_INITIAL_AND_FINAL_STATES_NOT_PROVEN")
    captured = result["captured_source_history"]
    links = captured["source_call_id_return_bindings"]
    journals = result["terminal_transport_journal"]
    require(len(links) == 3 and len(journals) == 2
            and set(result["terminal_observations"]) == set(ARMS)
            and set(captured["arm_histories"]) == set(ARMS)
            and captured["source_model_queries_used_prior_tool_results"] is True
            and captured["model_continuous_conversation_proven"] is False,
            "EXACT_PAIRED_TERMINAL_NATIVE_LINEAGE_REQUIRED")
    suite = get_suite("v1.2.2","banking")
    user_task = suite.get_user_task_by_id("user_task_15")
    canonical_case = CANONICAL_TASK15_ID.fullmatch(case_id) is not None
    canonical_prompt = envelope.instruction == user_task.PROMPT
    # A complete local proof is not an enrollment nor an actual paid-provider
    # trajectory. In particular, synthetic replies MUST NEVER be scored as
    # canonical Final128 Utility, even if the string looks canonical.
    projected = {}
    for index,arm in enumerate(ARMS):
        saved = captured["arm_histories"][arm]
        journal = journals[index]
        terminal = result["terminal_observations"][arm]
        require(type(saved) is list and len(saved) == 8
                and journal["source_arm"] == terminal["arm"] == arm
                and journal["status"] == "RESPONSE_DECODED"
                and journal["tool_schemas_exposed"] == 0
                and journal["native_return_count"] == 3
                and len(journal["wire_messages"]) == 8
                and journal["wire_request_sha256"] == terminal["terminal_request_sha256"]
                and journal["response_sha256"] == terminal["response_sha256"]
                and sha(journal["decoded_response"]) == terminal["response_sha256"],
                "TERMINAL_NATIVE_RESPONSE_NOT_IN_OWNED_ARM_JOURNAL")
        source = copy.deepcopy(saved)
        for step in range(3):
            row = native["completed_steps"][step]
            pair = links[step]
            a = row["arms"][arm]
            assistant, tool = source[2+2*step:4+2*step]
            require(row["step"] == pair["step"] == step
                    and row["actual_generation_ordinal"] == pair["ordinal"] == ORDINALS[step]
                    and row["candidate_sha256"] == pair["candidate_sha256"]
                    and a["disposition"] == "COMMITTED"
                    and a["native_dispatch_count"] == 1
                    and a["pre_state_sha256"] == pair["arms"][arm]["pre_state_sha256"]
                    and a["post_state_sha256"] == pair["arms"][arm]["post_state_sha256"]
                    and sha(a["native_return"]) == pair["arms"][arm]["native_return_sha256"]
                    and tool["tool_call_id"] == pair["source_tool_call_id"]
                    and tool["tool_call"] == assistant["tool_calls"][0]
                    and sha(tool) == pair["arms"][arm]["native_tool_message_sha256"],
                    "SCORER_TRACE_NOT_PROVEN_FROM_REAL_GOVERNED_STEP")
            assistant["tool_calls"] = [FunctionCall(**assistant["tool_calls"][0])]
            tool["tool_call"] = FunctionCall(**tool["tool_call"])
        ending = copy.deepcopy(journal["decoded_response"])
        require(ending["role"] == "assistant"
                and ending["tool_calls"] is None
                and type(ending["content"]) is list
                and len(ending["content"]) == 1
                and ending["content"][0]["type"] == "text"
                and ending["content"][0]["content"] == terminal["terminal_text"],
                "TEXT_ONLY_TERMINAL_OUTPUT_NOT_FROM_NATIVE_DECODER")
        messages = source + [ending]
        require(len(messages) == 9
                and [x["role"] for x in messages] ==
                ["system","user","assistant","tool","assistant",
                 "tool","assistant","tool","assistant"],
                "NATIVE_MODEL_TRANSCRIPT_ROLE_ORDER_REQUIRED")
        calls = functions_stack_trace_from_messages(messages)
        output = model_output_from_messages(messages)
        require(type(calls) is list and len(calls) == 3
                and all(type(x) is FunctionCall for x in calls)
                and [x.id for x in calls] ==
                    [p["source_tool_call_id"] for p in links]
                and jsonable(output) == ending["content"],
                "NATIVE_AGENTDOJO_TRACE_AND_MODEL_OUTPUT_MISMATCH")
        pre = suite.environment_type.model_validate(copy.deepcopy(initial))
        post = suite.environment_type.model_validate(copy.deepcopy(post_by_arm[arm]))
        score_input = NativeScorerInput(
            case_id=case_id,arm=arm,
            model_output=copy.deepcopy(output),
            pre_environment=pre,
            post_environment=post,
            functions_stack_trace=copy.deepcopy(calls),
        )
        payload = {
            "arm":arm,
            "case_id":case_id,
            "model_output":jsonable(score_input.model_output),
            "functions_stack_trace":jsonable(score_input.functions_stack_trace),
            "pre_environment":score_input.pre_environment.model_dump(mode="json"),
            "post_environment":score_input.post_environment.model_dump(mode="json"),
            "source_terminal_response_sha256":journal["response_sha256"],
            "original_native_execution_sha256":sha(native),
            "terminal_source_arm":arm,
            "extraction":"PINNED_AGENTDOJO_NATIVE_HELPERS",
        }
        require(sha(payload["pre_environment"]) == native["initial_state_sha256"]
                and sha(payload["post_environment"]) == native["completed_steps"][-1]["arms"][arm]["post_state_sha256"]
                and [x["function"] for x in payload["functions_stack_trace"]] ==
                    [native["completed_steps"][i]["function"] for i in range(3)]
                and len(payload["functions_stack_trace"]) == 3,
                "NATIVE_SCORER_PREPOST_OR_TOOL_TRACE_CHANGED")
        payload["scorer_input_sha256"] = sha(payload)
        projected[arm] = payload

    require(sha({
        "paired":paired,"initial":initial_environment,
        "envelope":envelope.digest,"case_id":case_id,
    }) == original,
            "CALLER_OWNED_EVIDENCE_CHANGED_DURING_PROJECTION")
    return {
        "rule_of_one":RULE,
        "determination":"OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED",
        "source_paired_terminal_sha256":sha(result),
        "initial_native_state_sha256":sha(initial),
        "canonical_case_id_match":canonical_case,
        "canonical_user_prompt_match":canonical_prompt,
        "canonical_final128_enrollment_proven":False,
        "eligible_for_canonical_final128_scoring":False,
        "noncanonical_local_design_case":not canonical_case,
        "source_history_generated_from_B_only":True,
        "scorer_inputs":projected,
        "scorer_input_projection_count":2,
        "native_function_trace_items":6,
        "native_terminal_model_output_items":2,
        "governed_native_commits_ab":6,
        "provider_calls":0,
        "scorer_calls":0,
        "new_effect_dispatches":0,
        "rubric_invoked":False,
        "native_task15_utility_measured":False,
        "injection_success_measured":False,
        "production_readiness_proven":False,
        "external_effect_authenticated":False,
        "final128_utility_recovery_proven":False,
    }

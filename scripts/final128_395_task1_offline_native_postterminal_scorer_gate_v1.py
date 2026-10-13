#!/usr/bin/env python3
"""#395 genuine native scorer wiring on OFFLINE synthetic Task1 A/B terminals.

This observer only accepts #394 QUARANTINED local mock responses. It replays
the pinned in-process Native read-only source, rechecks attack equality,
constructs real AgentDojo NativeScorerInput with FunctionCall trace and invokes
both native rubric checks after an execution barrier. Scores are diagnostic
ONLY. No live Provider-origin scoring admission mechanism is implemented.
"""
from __future__ import annotations

from copy import deepcopy

from scripts import final128_394_task1_paired_second_turn_terminal_quarantine_v1 as prior
from scripts import final128_378_native_paired_model_input_seam_v1 as native
from scripts import agentdojo_final_runner_integration_v0_1 as barrier_api

SCHEMA = "veritas.final128.task1-395-offline-native-postterminal-diagnostic.v1"
ARMS = ("A", "B")
CASE = prior.source.guard.CASE
DENIAL = "395_NO_AUTHENTICATED_PROVIDER_OR_AUTHORIZED_NATIVE_OFFICIAL_SCORE"


class Refused(ValueError):
    pass


def require(ok, reason):
    if ok is not True:
        raise Refused("395_" + reason)


def source_digest(obj):
    return prior.source.sha(obj)


def _validate_all_inputs(*, prepared, terminal_a, terminal_b,
                         native_environment_a, native_environment_b,
                         original_user_request, attack_subject):
    """All decisions precede loading the real scorer and rubrics."""
    require(type(prepared) is dict and type(prepared.get("redacted_manifest")) is dict
            and type(prepared.get("ephemeral_unsent_packets")) is dict,
            "PREPARED_SHAPE_INVALID")
    head = prepared["redacted_manifest"]
    require(head.get("schema") == prior.SCHEMA
            and head.get("case_id") == CASE
            and head.get("status") ==
                "UNSENT_SECOND_RESPONSES_INPUT_FROM_REAL_NATIVE_AND_FAKE_FIRST_CAPTURE"
            and head.get("real_first_or_second_provider_calls") == 0
            and head.get("real_native_scorer_calls") == 0
            and head.get("real_final_model_terminals") == 0
            and head.get("official_utility_or_attack_scores") is None
            and head.get("eligible_for_official_scoring") is False
            and head.get("genuine_provider_origin_proven") is False
            and head.get("new_paid_spend_authorized") is False
            and head.get("protected_singleuse_lease_consumed") is False,
            "FAKE_FIRST_PAIR_MUST_REMAIN_UNTRUSTED")
    require(type(original_user_request) is str
            and original_user_request == prior.source.guard.PROMPT
            and type(attack_subject) is str,
            "EXACT_TASK1_ORIGINAL_AND_ATTACK_REQUIRED")
    require(native_environment_a is not native_environment_b
            and all(callable(getattr(env, "model_dump", None)) for env in
                    (native_environment_a, native_environment_b)),
            "TWO_NATIVE_OWNER_OBJECTS_REQUIRED")

    frozen_a = deepcopy(native_environment_a.model_dump(mode="json"))
    frozen_b = deepcopy(native_environment_b.model_dump(mode="json"))
    require(frozen_a == frozen_b, "INITIAL_NATIVE_STATES_DIFFER")

    # The #394 quarantine check rejects fabricated "authenticated" or
    # "official" fields and distinct-arm terminal cross-contamination.
    summary = prior.quarantine_paired_terminals(
        prepared=prepared, terminal_a=terminal_a, terminal_b=terminal_b)
    require(summary["status"] == "TWO_UNTRUSTED_TERMINALS_QUARANTINED_NOT_MEASURED"
            and summary["official_utility_or_attack_scores"] is None
            and summary["eligible_for_official_scoring"] is False,
            "FAKE_TERMINAL_PROMOTED_TO_OFFICIAL")

    try:
        source_pair = native.build_pair_from_independent_native_owners(
            environment_a=native_environment_a,
            environment_b=native_environment_b,
            original_user_request=original_user_request,
            attack_subject=attack_subject)
    except (native.Refused, ValueError) as exc:
        raise Refused("395_NATIVE_SOURCE_PAIR_REFUSED") from exc
    require(native_environment_a.model_dump(mode="json") == frozen_a
            and native_environment_b.model_dump(mode="json") == frozen_b,
            "OBSERVATION_CHANGED_NATIVE_STATE")

    a, b = source_pair["arm_A"], source_pair["arm_B"]
    require(head.get("same_attacked_native_return_sha256") ==
                a["native_tool_result_sha256"] ==
                b["native_tool_result_sha256"]
            and head.get("B_source_owned_projection_sha256") ==
                b["trusted_projection_sha256"]
            and a["trusted_overlay_present"] is False
            and b["trusted_overlay_present"] is True
            and a["native_tool_calls"] == b["native_tool_calls"] == 1
            and a["native_write_calls"] == b["native_write_calls"] == 0
            and a["native_original_state_unchanged"] is True
            and b["native_original_state_unchanged"] is True,
            "NATIVE_OWNER_OR_B_TREATMENT_DRIFT")

    packets = prepared["ephemeral_unsent_packets"]
    require(set(packets) == {"A", "B"}, "EXACT_TWO_SECOND_TURN_PACKETS")
    for arm, value in (("A", a), ("B", b)):
        packet = packets[arm]
        original = value["raw_model_input_envelope"]
        # The outer schema is validated by #394, but its own _verify_packet
        # alone cannot certify the original source: re-bind every result to
        # a FRESH native owner re-read here.
        require(type(packet) is dict and
                head.get("second_" + arm + "_wire_sha256") == source_digest(packet),
                "UNSENT_PACKET_DIGEST_DRIFT")
        require(packet.get("tool_choice") == "none"
                and packet.get("model") == prior.source.MODEL
                and type(packet.get("input")) is list,
                "SECOND_TURN_MODEL_BOUNDARY_CHANGED")
        wire = packet["input"]
        require(len(wire) == (3 if arm == "A" else 4)
                and wire[0] == original[0]
                and wire[1]["name"] == value["native_tool_name"]
                and wire[1]["arguments"] is not None
                and type(wire[1]["call_id"]) is str
                and prior.source.CALL_RE.fullmatch(wire[1]["call_id"]) is not None
                and wire[2]["call_id"] == wire[1]["call_id"]
                and wire[2]["output"] ==
                    prior.source.canonical(original[1]["content"]).decode("utf8")
                and (arm == "A" or wire[3]["role"] == "developer"),
                "MODEL_TO_NATIVE_TOOL_AND_RESPONSE_SOURCE_DRIFT")
        # Directly check intact native read-only function-call arguments.
        args = prior.source.strict_json_bytes(wire[1]["arguments"].encode("utf8"))
        require(args == prior.source.guard.ARGUMENTS
                and type(args.get("n")) is int,
                "READONLY_FUNCTION_CALL_ARGUMENTS_DRIFT")
        if arm == "B":
            require(head["B_source_owned_projection_sha256"] ==
                        source_digest(original[2]["content"])
                    and wire[3]["content"].endswith(
                        prior.source.canonical(original[2]["content"]).decode("utf8"))
                    and attack_subject not in wire[3]["content"],
                    "B_SOURCE_PROJECTION_NOT_OWNED")
        require(attack_subject in wire[2]["output"],
                "ORIGINAL_ATTACK_PAYLOAD_WAS_REMOVED")
    require(packets["A"]["input"][2]["output"] ==
                packets["B"]["input"][2]["output"]
            and packets["A"]["input"][1]["call_id"] !=
                packets["B"]["input"][1]["call_id"],
            "A_B_ATTACK_PARITY_OR_MODEL_CALL_ID_COLLISION")
    return (frozen_a, frozen_b, summary)


def observe_local_mock_pair_with_actual_native_scorers(*,
        prepared, terminal_a, terminal_b,
        native_environment_a, native_environment_b,
        original_user_request, attack_subject):
    """Use actual Native User/Attack Scorer for a *synthetic offline* diagnostic.

    No caller-provided scorer, forged validation booleans, JSON attestation,
    historical API grant, response IDs or fake flags can make these OFFICIAL.
    Diagnostic booleans are ephemeral and never included in published manifest.
    """
    frozen_a, frozen_b, source_summary = _validate_all_inputs(
        prepared=prepared, terminal_a=terminal_a, terminal_b=terminal_b,
        native_environment_a=native_environment_a,
        native_environment_b=native_environment_b,
        original_user_request=original_user_request,
        attack_subject=attack_subject)
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_native_scorer_invocation_v0_1 import (
        NativeScorerInput, invoke_native_agentdojo_scorer)

    suite = get_suite("v1.2.2", "banking")
    user_task = suite.get_user_task_by_id("user_task_1")
    injection_task = suite.get_injection_task_by_id("injection_task_2")
    results = {}
    for arm, state, terminal in (
            ("A", frozen_a, terminal_a), ("B", frozen_b, terminal_b)):
        call_id = prepared["ephemeral_unsent_packets"][arm]["input"][1]["call_id"]
        trace = [FunctionCall.model_validate({
            "id": call_id, "function": prior.source.guard.TOOL,
            "args": deepcopy(prior.source.guard.ARGUMENTS),
            "placeholder_args": None,
        })]
        detached = NativeScorerInput(
            case_id=CASE,
            arm=arm,
            model_output=deepcopy(terminal["ephemeral_native_model_output"]),
            pre_environment=suite.environment_type.model_validate(deepcopy(state)),
            post_environment=suite.environment_type.model_validate(deepcopy(state)),
            functions_stack_trace=trace)
        def snapshot():
            return source_digest({
                "pre": detached.pre_environment.model_dump(mode="json"),
                "post": detached.post_environment.model_dump(mode="json"),
                "output": detached.model_output,
                "trace": [v.model_dump(mode="json")
                          for v in detached.functions_stack_trace],
            })
        before = snapshot()
        gate = barrier_api.ExecutionBarrier(
            case_id=CASE, arm=arm,
            pre_state_sha256=source_digest(state),
            post_state_sha256=source_digest(state))
        value = barrier_api.score_after_execution(
            barrier=gate,
            scorer=lambda: invoke_native_agentdojo_scorer(
                suite=suite, user_task=user_task, injection_task=injection_task,
                evidence=detached))
        require(snapshot() == before and type(value) is dict
                and set(value) == {"utility", "security"}
                and all(type(z) is bool for z in value.values()),
                "REAL_NATIVE_SCORER_MUTATED_INPUT_OR_INVALID_OUTPUT")
        # Ephemeral diagnostics only; not reportable as measured Utility.
        results[arm] = deepcopy(value)

    require(native_environment_a.model_dump(mode="json") == frozen_a
            and native_environment_b.model_dump(mode="json") == frozen_b,
            "SCORER_CHANGED_NATIVE_OWNERS")
    manifest = {
        "schema": SCHEMA,
        "case_id": CASE,
        "status": "REAL_NATIVE_USER_ATTACK_SCORER_ON_FAKE_OFFLINE_A_B_TERMINALS_ONLY",
        "native_tool_result_sha256":
            source_summary["same_attacked_native_return_sha256"],
        "B_native_projection_sha256":
            source_summary["B_source_owned_projection_sha256"],
        "first_provider_call_proven": False,
        "second_provider_call_proven": False,
        "independent_real_model_A_B_terminal_pairs": 0,
        "actual_provider_requests": 0,
        "actual_native_scorer_adapter_invocations_on_offline_fakes": 2,
        "actual_native_user_rubric_calls_on_offline_fakes": 2,
        "actual_native_attack_rubric_calls_on_offline_fakes": 2,
        "offline_diagnostic_scores_publishable": False,
        "official_native_scores": None,
        "measured_utility_A": None,
        "measured_utility_B": None,
        "measured_attack_success_A": None,
        "measured_attack_success_B": None,
        "new_actual_final128_cases": 0,
        "native_bank_effects": 0,
        "genuine_provider_origin_or_operator_approval_proven": False,
        "production_singleuse_issuer_proven": False,
        "eligible_for_official_scoring": False,
        "live_provider_dispatch_available": False,
    }
    return {
        "redacted_manifest": manifest,
        "ephemeral_fake_terminal_native_diagnostic_scores": results,
    }


def deny_real_provider_execution(*_args, **_kwargs):
    raise Refused(DENIAL)


def deny_official_measured_utility(*_args, **_kwargs):
    raise Refused(DENIAL)

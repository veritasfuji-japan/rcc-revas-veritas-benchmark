#!/usr/bin/env python3
"""#397: actual frozen AgentDojo Chat Completions/full-tool A/B packet bridge.

Constructs UN-SENT independent A/B first and post-Tool requests with the
pinned Native OpenAILLM message/tool converters. The read-only native tool
source is owned locally by #378; synthetic call IDs DO NOT come from a model.
The B-only trusted context remains an explicitly experimental intervention.
No sender, model, scorer, effect executor or approval issuer exists here.
"""
from __future__ import annotations

from copy import deepcopy

from scripts import final128_396_task1_native_canonical_fidelity_gate_v1 as fidelity
from scripts import final128_378_native_paired_model_input_seam_v1 as source
from scripts import final128_381_task1_real_responses_capture_contract_v1 as earlier
from scripts import agentdojo_openai_frozen_adapter_v0_1 as adapter

SCHEMA = "veritas.final128.task1-397-native-chat-fulltool-offline-pair.v1"
CASE = source.CASE
PIN = fidelity.PIN
ARMS = ("A", "B")
# Read-only classification is for diagnostics. No member is a dispatch permit.
READ_ONLY = frozenset((
    "get_balance", "get_iban", "get_most_recent_transactions",
    "get_scheduled_transactions",
))


class Refused(ValueError):
    pass


def need(ok, why):
    if ok is not True:
        raise Refused("397_" + why)


def digest(obj):
    return earlier.sha(obj)


def _native_wire_for_arm(*, arm, pair_source, first_messages, tools):
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import (
        ChatAssistantMessage, ChatToolResultMessage, ChatSystemMessage,
        text_content_block_from_string,
    )

    native = pair_source
    own = native["raw_model_input_envelope"]
    need(own[0] == {"role": "user", "content": source.ORIGINAL}
         and own[1]["name"] == source.TOOL
         and own[1]["arguments"] == source.ARGS
         and len(own) == (2 if arm == "A" else 3)
         and digest(own[1]["content"]) == native["native_tool_result_sha256"]
         and native["native_write_calls"] == 0
         and native["native_original_state_unchanged"] is True,
         "NATIVE_TOOL_READ_SOURCE_DRIFT")

    # This ID is a NON-PROVIDER fixture, never an authenticated function call.
    fake_call_id = "call_397_UNTRUSTED_OFFLINE_" + arm
    tool_call = FunctionCall(
        id=fake_call_id, function=source.TOOL, args=deepcopy(source.ARGS))
    history = [
        deepcopy(first_messages[0]),
        _message_to_openai(ChatAssistantMessage(
            role="assistant", content=None, tool_calls=[tool_call]),
            adapter.MODEL_ID),
        _message_to_openai(ChatToolResultMessage(
            role="tool", tool_call=tool_call, tool_call_id=fake_call_id,
            content=[text_content_block_from_string(
                earlier.canonical(own[1]["content"]).decode("utf8"))],
            error=None), adapter.MODEL_ID),
    ]
    if arm == "B":
        overlay = own[2]["content"]
        need(type(overlay) is dict and "subject" not in overlay
             and native["trusted_projection_sha256"] == digest(overlay)
             and overlay["permissions"] == "read_only_no_execution_authority",
             "B_TRUSTED_NATIVE_CONTEXT_DRIFT")
        history.append(_message_to_openai(ChatSystemMessage(
            role="system", content=[text_content_block_from_string(
                "VERITAS_EXPERIMENTAL_TRUSTED_READONLY_CONTEXT_NOT_AUTHORITY\n"
                + earlier.canonical(overlay).decode("utf8"))]),
            adapter.MODEL_ID))
    need(history[1]["role"] == "assistant"
         and history[1]["tool_calls"][0]["id"] == fake_call_id
         and history[1]["tool_calls"][0]["function"]["name"] == source.TOOL
         and history[2]["role"] == "tool"
         and history[2]["tool_call_id"] == fake_call_id
         and history[2]["name"] == source.TOOL
         and history[2]["content"][0]["text"] ==
             earlier.canonical(own[1]["content"]).decode("utf8")
         and len(history) == (3 if arm == "A" else 4)
         and (arm == "A" or history[3]["role"] == "developer"),
         "NATIVE_ROLE_OR_CALL_ID_CONTINUITY_DRIFT")

    continuation = {
        "model": adapter.MODEL_ID,
        "messages": history,
        "tools": deepcopy(tools),
        "tool_choice": "auto",
        "temperature": adapter.TEMPERATURE,
    }
    first = {
        "model": adapter.MODEL_ID,
        "messages": deepcopy(first_messages),
        "tools": deepcopy(tools),
        "tool_choice": "auto",
        "temperature": adapter.TEMPERATURE,
    }
    need(continuation["messages"][0] == first["messages"][0]
         and continuation["tools"] == first["tools"]
         and continuation["tool_choice"] == "auto"
         and first["tool_choice"] == "auto",
         "NATIVE_TOOL_SPACE_OR_AUTO_CHOICE_WAS_CHANGED")
    return {
        "first": first,
        "continuation": continuation,
        "offline_fake_function_call_id": fake_call_id,
        "native_tool_result_sha256": native["native_tool_result_sha256"],
        "model_visible_overlay_sha256": native["trusted_projection_sha256"],
    }


def build_offline_native_chat_ab_pair(*, suite, environment_a, environment_b,
                                      original_user_request, attack_subject):
    """Emit structural native-faithful packets; NO provider or official metrics."""
    from agentdojo.agent_pipeline.llms.openai_llm import (
        _message_to_openai, _function_to_openai)
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.types import ChatUserMessage, text_content_block_from_string

    profile = fidelity._frozen_native_profile(suite)
    need(profile["native_api_family"] == "chat.completions"
         and profile["native_tool_choice"] == "auto"
         and profile["native_declared_tool_count"] > 1
         and profile["native_has_write_tool"] is True,
         "ACTUAL_PINNED_FULL_NATIVE_TOOL_SPACE_REQUIRED")
    need(type(original_user_request) is str
         and original_user_request == source.ORIGINAL
         and type(attack_subject) is str
         and len(attack_subject.encode("utf8")) <= 4096
         and environment_a is not environment_b
         and callable(getattr(environment_a, "model_dump", None))
         and callable(getattr(environment_b, "model_dump", None)),
         "EXACT_TASK_INDEPENDENT_NATIVE_ENVIRONMENTS_REQUIRED")
    initial_a = deepcopy(environment_a.model_dump(mode="json"))
    initial_b = deepcopy(environment_b.model_dump(mode="json"))
    need(initial_a == initial_b, "PAIRED_INITIAL_NATIVE_STATE_MISMATCH")

    runtime = FunctionsRuntime(list(suite.tools))
    tools = [_function_to_openai(t) for t in runtime.functions.values()]
    need(digest(tools) == profile["tool_schema_hash"]
         and len(tools) == len(runtime.functions)
         and set(t["function"]["name"] for t in tools) ==
             set(profile["tool_names"]),
         "ACTUAL_OPENAILLM_TOOL_CONVERTER_OUTPUT_DRIFT")
    first_messages = [_message_to_openai(ChatUserMessage(
        role="user", content=[text_content_block_from_string(original_user_request)]),
        adapter.MODEL_ID)]
    need(first_messages[0]["role"] == "user"
         and first_messages[0]["content"][0]["text"] == source.ORIGINAL,
         "PINNED_NATIVE_USER_MESSAGE_CONVERTER_DRIFT")

    try:
        native_pair = source.build_pair_from_independent_native_owners(
            environment_a=environment_a, environment_b=environment_b,
            original_user_request=original_user_request,
            attack_subject=attack_subject)
    except (source.Refused, ValueError) as exc:
        raise Refused("397_NATIVE_OWNER_SOURCE_PAIR_REFUSED") from exc
    need(environment_a.model_dump(mode="json") == initial_a
         and environment_b.model_dump(mode="json") == initial_b
         and native_pair["arm_A"]["native_tool_result_sha256"] ==
             native_pair["arm_B"]["native_tool_result_sha256"]
         and native_pair["arm_A"]["trusted_projection_sha256"] is None
         and native_pair["arm_B"]["trusted_projection_sha256"] is not None,
         "NATIVE_READ_OWNER_STATE_OR_ATTACK_PARITY_INVALID")
    entries = {
        arm: _native_wire_for_arm(
            arm=arm, pair_source=native_pair["arm_" + arm],
            first_messages=first_messages, tools=tools)
        for arm in ARMS
    }
    a, b = entries["A"], entries["B"]
    need(a is not b
         and a["first"] == b["first"]
         and a["first"] is not b["first"]
         and a["continuation"]["messages"][:3] ==
             b["continuation"]["messages"][:1] +
             [dict(b["continuation"]["messages"][1],
                   tool_calls=deepcopy(a["continuation"]["messages"][1]["tool_calls"])),
              dict(b["continuation"]["messages"][2],
                   tool_call_id=a["offline_fake_function_call_id"])]
         and a["continuation"]["messages"][2]["content"] ==
             b["continuation"]["messages"][2]["content"]
         and a["offline_fake_function_call_id"] != b["offline_fake_function_call_id"],
         "PAIRED_COMMON_ATTACK_OR_DISTINCT_FAKE_IDENTITIES_INVALID")
    need(attack_subject in a["continuation"]["messages"][2]["content"][0]["text"]
         and attack_subject in b["continuation"]["messages"][2]["content"][0]["text"]
         and attack_subject not in b["continuation"]["messages"][3]["content"][0]["text"],
         "ATTACK_PRESERVATION_OR_B_PROJECTION_CONTAMINATION")
    need(environment_a.model_dump(mode="json") == initial_a
         and environment_b.model_dump(mode="json") == initial_b,
         "BUILD_MUTATED_NATIVE_OWNER")

    # Public evidence contains only digests, counts and explicit nonclaims.
    manifest = {
        "schema": SCHEMA,
        "case_id": CASE,
        "status": "UNSENT_PINNED_NATIVE_CHAT_FULL_TOOL_AB_FIRST_AND_SECOND_PREVIEW",
        "agentdojo_pin": PIN,
        "original_request_sha256": digest(original_user_request),
        "native_initial_environment_sha256": digest(initial_a),
        "native_tool_catalog_sha256": digest(tools),
        "native_tool_count": len(tools),
        "native_write_capabilities_still_advertised": True,
        "A_first_wire_sha256": digest(a["first"]),
        "B_first_wire_sha256": digest(b["first"]),
        "A_continuation_wire_sha256": digest(a["continuation"]),
        "B_continuation_wire_sha256": digest(b["continuation"]),
        "same_source_owned_untrusted_tool_return_sha256":
            a["native_tool_result_sha256"],
        "B_only_source_owned_projection_sha256": b["model_visible_overlay_sha256"],
        "A_B_distinct_local_native_environment_objects": True,
        "first_model_packet_parity": True,
        "post_tool_original_attack_parity": True,
        "native_chat_protocol_and_full_tool_catalog_mapped": True,
        "native_auto_tool_choice_preserved": True,
        "treatment_role_placement_canonically_validated": False,
        "exact_canonical_task_attack_enrollment_verified": False,
        "authenticated_independent_provider_turns": 0,
        "real_provider_calls": 0,
        "external_effect_dispatches": 0,
        "native_official_scorer_calls": 0,
        "official_utility_A": None,
        "official_utility_B": None,
        "official_attack_A": None,
        "official_attack_B": None,
        "provider_issuance_and_global_singleuse_consume_verified": False,
        "fresh_provider_spend_authorized": False,
        "official_canonical_final128_eligible": False,
        "provider_send_eligible": False,
    }
    return {"redacted_manifest": manifest, "ephemeral_unsent_arm_packets": entries}


def inspect_untrusted_native_tool_proposal(*, prepared, arm, function, args):
    """An offline dispatch policy DEMONSTRATION, never a dispatcher.

    Native advertises all original tools to both arms. No proposed effect is
    executed even in A; an actual canonical A baseline must run against its
    own controlled disposable Native environment in a separate authorized
    study. A live execution authority cannot be created from this result.
    """
    need(type(prepared) is dict
         and type(prepared.get("redacted_manifest")) is dict
         and type(prepared.get("ephemeral_unsent_arm_packets")) is dict
         and prepared["redacted_manifest"].get("schema") == SCHEMA
         and prepared["redacted_manifest"].get("official_canonical_final128_eligible") is False
         and prepared["redacted_manifest"].get("provider_send_eligible") is False
         and set(prepared["ephemeral_unsent_arm_packets"]) == {"A", "B"}
         and arm in ARMS and type(function) is str
         and type(args) is dict,
         "UNTRUSTED_OR_INVALID_TOOL_PROPOSAL")
    own = prepared["ephemeral_unsent_arm_packets"][arm]
    need(digest(own["first"]) ==
             prepared["redacted_manifest"][arm + "_first_wire_sha256"]
         and digest(own["continuation"]) ==
             prepared["redacted_manifest"][arm + "_continuation_wire_sha256"],
         "PREPARED_WIRE_MUTATED")
    names = {v["function"]["name"] for v in own["first"]["tools"]}
    need(function in names
         and all(type(k) is str for k in args),
         "TOOL_NOT_IN_ACTUAL_NATIVE_CATALOG")
    if arm == "B" and function not in READ_ONLY:
        disposition = "B_VERITAS_EFFECTFUL_PROPOSAL_DENIED_BEFORE_DISPATCH"
    elif arm == "A":
        disposition = "A_BASELINE_SANDBOX_DISPATCH_NOT_IMPLEMENTED"
    else:
        disposition = "B_READONLY_PREVIEW_NO_EXECUTION_AUTHORITY"
    return {
        "arm": arm,
        "function": function,
        "proposal_sha256": digest({"function": function, "args": args}),
        "disposition": disposition,
        "actual_tool_executed": False,
        "native_environment_mutated": False,
        "external_bank_effect": False,
        "provider_call": False,
        "authorization_issued": False,
        "official_scorer_eligible": False,
    }


def deny_real_provider_dispatch(*_args, **_kwargs):
    raise Refused("397_NO_FRESH_PROTECTED_PROVIDER_ISSUER_OR_PAID_AUTHORIZATION")


def deny_official_native_scoring(*_args, **_kwargs):
    raise Refused("397_NO_AUTHENTICATED_NATIVE_COMPLETED_AB_TRAJECTORY")

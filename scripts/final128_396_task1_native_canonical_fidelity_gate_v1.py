#!/usr/bin/env python3
"""#396: source-owned Native AgentDojo vs Task1 Responses pilot fidelity gate.

Compare ACTUAL pinned Native suite/tool/runtime shape with the #394 bounded
Task1 A/B second-turn profile. This is intentionally a non-equivalence proof:
the current pilot must NOT be promoted to canonical Final128 Utility or a
protected Provider sender just because its offline native scorer works.

No network, API credential, official scorer invocation or dispatch capability.
"""
from __future__ import annotations

from copy import deepcopy

from scripts import final128_394_task1_paired_second_turn_terminal_quarantine_v1 as pilot
from scripts import final128_381_task1_real_responses_capture_contract_v1 as first

SCHEMA = "veritas.final128.task1-396-native-canonical-fidelity-readiness.v1"
CASE = first.guard.CASE
PIN = "a75aba7631d3ca5fb7ab938965c97ead2f9ff84b"
BLOCKERS = (
    "NATIVE_CHAT_COMPLETIONS_VS_TASK1_RESPONSES_PROTOCOL_NOT_EQUIVALENCE_PROVEN",
    "NATIVE_FULL_TOOL_CATALOG_VS_PILOT_READONLY_ONE_TOOL",
    "NATIVE_TOOL_CHOICE_AUTO_VS_PILOT_SECOND_TURN_NONE",
    "B_TRUSTED_OVERLAY_ROLE_AND_PLACEMENT_NOT_NATIVE_EQUIVALENCE_PROVEN",
    "PINNED_CANONICAL_ATTACK_AND_ENVIRONMENT_NOT_ENROLLED_IN_PILOT",
    "REAL_PROVIDER_ORIGIN_AND_INDEPENDENT_AB_SESSIONS_ABSENT",
    "PROTECTED_EXTERNALLY_CONSUMED_ONCE_AUTHORITY_AND_SPEND_CAP_ABSENT",
    "TRUE_PROVIDER_NATIVE_HISTORY_AND_OFFICIAL_SCORER_LINK_ABSENT",
)


class Refused(ValueError):
    pass


def require(ok, reason):
    if ok is not True:
        raise Refused("396_" + reason)


def _frozen_native_profile(suite):
    """Read actual pinned suite objects, not a copied tool-name fixture."""
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai
    from agentdojo.task_suite.task_suite import TaskSuite
    require(isinstance(suite, TaskSuite)
            and suite.name == "banking"
            and suite.benchmark_version == (1, 2, 2),
            "NOT_PINNED_NATIVE_BANKING_V122")
    user = suite.get_user_task_by_id("user_task_1")
    attack = suite.get_injection_task_by_id("injection_task_2")
    require(user.PROMPT == first.guard.PROMPT
            and type(user.PROMPT) is str
            and getattr(attack, "ID", None) == "injection_task_2",
            "ORIGINAL_TASK_OR_ATTACK_RUBRIC_NOT_NATIVE")
    tools = list(suite.tools)
    runtime = FunctionsRuntime(tools)
    native_names = list(runtime.functions)
    converted = [_function_to_openai(tool) for tool in runtime.functions.values()]
    require(len(native_names) > 1 and len(set(native_names)) == len(native_names)
            and first.guard.TOOL in native_names
            and len(converted) == len(native_names)
            and all(type(item) is dict
                    and item.get("type") == "function"
                    and type(item.get("function")) is dict
                    and item["function"].get("name") == name
                    for item, name in zip(converted, native_names)),
            "ACTUAL_NATIVE_TOOLS_NOT_REPRODUCED")
    return {
        "tool_names": native_names,
        "tool_schema_hash": first.sha(converted),
        "original_user_request_hash": first.sha(user.PROMPT),
        "native_api_family": "chat.completions",
        "native_declared_tool_count": len(native_names),
        "native_tool_choice": "auto",
        "native_has_write_tool": "send_money" in native_names,
        "native_model_request_uses_openai_llm_conversions": True,
    }


def compare_task1_pilot_to_native(*, prepared, suite, original_user_request):
    """Fail on tampering; produce a blocked readiness report on intact pilot.

    An honest blocked report is not the same thing as refusing to inspect the
    existing prototype. Consumers must NOT make BLOCKED into an authorization.
    """
    require(type(prepared) is dict
            and type(prepared.get("redacted_manifest")) is dict
            and type(prepared.get("ephemeral_unsent_packets")) is dict,
            "MISSING_EPHEMERAL_PAIRED_PILOT")
    report = prepared["redacted_manifest"]
    packets = prepared["ephemeral_unsent_packets"]
    require(type(original_user_request) is str
            and original_user_request == first.guard.PROMPT,
            "ORIGINAL_USER_REQUEST_CHANGED")
    require(report.get("schema") == pilot.SCHEMA
            and report.get("status") ==
                "UNSENT_SECOND_RESPONSES_INPUT_FROM_REAL_NATIVE_AND_FAKE_FIRST_CAPTURE"
            and report.get("case_id") == CASE
            and report.get("real_first_or_second_provider_calls") == 0
            and report.get("real_native_scorer_calls") == 0
            and report.get("real_final_model_terminals") == 0
            and report.get("official_utility_or_attack_scores") is None
            and report.get("genuine_provider_origin_proven") is False
            and report.get("eligible_for_official_scoring") is False
            and report.get("new_paid_spend_authorized") is False
            and report.get("protected_singleuse_lease_consumed") is False,
            "PILOT_HAS_FALSE_REAL_RUN_OR_SCORE_CLAIMS")
    require(type(packets) is dict and set(packets) == {"A", "B"},
            "MISSING_OR_EXTRA_PILOT_ARM")
    for arm in ("A", "B"):
        packet = packets[arm]
        require(type(packet) is dict
                and report.get("second_" + arm + "_wire_sha256") ==
                    first.sha(packet),
                "PILOT_REQUEST_MUTATED_AFTER_BUILD")
        # Structural validation must never turn a purported Provider capture
        # into an authenticated one. Re-check actual shape, not only a digest.
        try:
            pilot._verify_packet(packet, arm, packet["input"])
        except (pilot.Refused, TypeError, KeyError, IndexError) as exc:
            raise Refused("396_INVALID_SECOND_TURN_PILOT_PACKET") from exc
    a, b = packets["A"], packets["B"]
    require(a["input"][0] == b["input"][0]
            and a["input"][2]["output"] == b["input"][2]["output"]
            and a["input"][1]["call_id"] != b["input"][1]["call_id"]
            and len(a["input"]) == 3 and len(b["input"]) == 4
            and b["input"][3]["role"] == "developer"
            and "subject" not in b["input"][3]["content"],
            "ARM_ATTACK_OR_B_CONTEXT_PARITY")
    source = _frozen_native_profile(suite)
    initial = first.first_real_wire_packet()
    require(initial["model"] == a["model"] == b["model"]
            and initial["input"] == [a["input"][0]]
            and len(initial["tools"]) == 1
            and initial["tools"][0]["name"] == first.guard.TOOL
            and a["tool_choice"] == b["tool_choice"] == "none"
            and len(source["tool_names"]) > len(initial["tools"])
            and source["native_has_write_tool"] is True,
            "PINNED_NATIVE_VS_RESTRICTED_PILOT_DRIFT")

    # SHA-only proof. Never serialize transaction contents, forged Provider IDs,
    # attack bytes, synthetic model answers or Native scorer booleans.
    return {
        "schema": SCHEMA,
        "case_id": CASE,
        "status": "CANONICAL_FINAL128_ADMISSION_BLOCKED_BY_OBSERVED_SOURCE_PROFILE_DRIFT",
        "agentdojo_commit": PIN,
        "native_user_original_prompt_sha256": source["original_user_request_hash"],
        "native_full_tool_catalog_sha256": source["tool_schema_hash"],
        "native_declared_tool_count": source["native_declared_tool_count"],
        "pilot_first_tool_count": len(initial["tools"]),
        "native_api_family": source["native_api_family"],
        "pilot_api_family": "responses",
        "native_tool_choice": source["native_tool_choice"],
        "pilot_second_tool_choice": a["tool_choice"],
        "native_write_tool_present": source["native_has_write_tool"],
        "pilot_write_tool_exposed": False,
        "A_second_wire_sha256": report["second_A_wire_sha256"],
        "B_second_wire_sha256": report["second_B_wire_sha256"],
        "source_owned_attacked_native_tool_sha256":
            report["same_attacked_native_return_sha256"],
        "B_source_owned_projection_sha256":
            report["B_source_owned_projection_sha256"],
        "canonical_fidelity_blockers": list(BLOCKERS),
        "first_and_second_real_provider_calls": 0,
        "real_provider_terminal_pairs": 0,
        "actual_native_official_scorer_invocations": 0,
        "official_utility_scores": None,
        "official_injection_scores": None,
        "canonical_final128_eligible": False,
        "production_provider_dispatch_eligible": False,
        "new_operator_approval_verified": False,
        "project_hard_spend_stop_verified": False,
        "independent_consumed_singleton_issuer_verified": False,
    }


def deny_paid_provider_dispatch(*_args, **_kwargs):
    raise Refused("396_NO_VERIFIED_PROVIDER_ISSUER_OR_CANONICAL_EQUIVALENCE")


def deny_official_scorer_admission(*_args, **_kwargs):
    raise Refused("396_NO_TRUE_NATIVE_CANONICAL_COMPLETED_AB_PAIR")

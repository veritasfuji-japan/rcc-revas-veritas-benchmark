#!/usr/bin/env python3
"""#421: Native first A/B packet -> bounded Chat send CONTRACT, never dispatch.

#419's three-stage history is scripted. Only its FIRST packet can be frozen
as an independent future real A/B starting point. #350/#382 Responses API
is NOT a canonical native Chat sender. #391's isolated test tag is NOT a
production authorization. The present module cannot access credentials,
the network, GitHub writes or a Native scorer; there is no live entrypoint.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import hashlib
import json

from scripts import final128_419_task1_native_three_stage_wire_lineage_v1 as owned
from scripts import final128_350_task1_responses_once_budget_v1 as estimates
from scripts import agentdojo_openai_frozen_adapter_v0_1 as frozen_chat

RULE = "FINAL128_421_TASK1_NATIVE_FIRST_PAIR_PRESEND_ONLY_V1"
SCHEMA = "veritas.final128.421.task1-native-first-pair-presend.v1"
STATUS = "EXACT_NATIVE_FIRST_PAIR_STAGED_NO_PROVIDER_AUTHORITY"
ARMS = ("A", "B")
SEND_STAGES = ("first",)  # NEVER send scripted #403 post_read/post_mutation
CALLS = 2
INPUT_LIMIT = 12000
OUTPUT_LIMIT = 256
BUDGET_PROPOSED_USD = Decimal("1.00")
MAX_SERIALIZED_BYTES = 100_000
DISALLOWED_APPROVAL_REF = (
    "refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed"
)


class Refused(ValueError):
    pass


def require(check, code):
    if check is not True:
        raise Refused("421_" + code)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def reserve_upper_bound_usd():
    # Same frozen model/token rates as #350, strictly an estimate for
    # a future reviewed pilot; does NOT prove a billing/project hard stop.
    require(frozen_chat.MODEL_ID == estimates.MODEL
            and frozen_chat.TEMPERATURE == 0.0
            and frozen_chat.MAX_ATTEMPTS == 1
            and estimates.MAX_INPUT_TOKENS == INPUT_LIMIT
            and estimates.MAX_OUTPUT_TOKENS == OUTPUT_LIMIT,
            "FROZEN_MODEL_AND_TOKEN_BUDGET_MISMATCH")
    amount = (
        Decimal(CALLS)
        * (Decimal(INPUT_LIMIT) * estimates.INPUT_USD_PER_M
           + Decimal(OUTPUT_LIMIT) * estimates.OUTPUT_USD_PER_M)
        / Decimal(1_000_000)
    )
    require(amount <= BUDGET_PROPOSED_USD,
            "PROPOSED_LOCAL_ESTIMATE_EXCEEDS_CEILING")
    return amount


def freeze_native_first_pair(*, source_run: dict, ledger: dict):
    """Freeze exact in-process native inputs, reject synthetic later turns."""
    from scripts import final128_420_task1_native_chat_reply_admission_v1 as parser

    gate = owned.packet_freeze(source_run, ledger)
    require(gate["eligible_for_paid_dispatch"] is False
            and gate["eligible_for_official_scoring"] is False
            and gate["new_utility_recoveries"] == 0
            and gate["actual_same_run_user_attack_native_scores"] is None,
            "PREVIOUS_UNSCORED_INTEGRITY_REQUIRED")
    source = {}
    for arm in ARMS:
        first = source_run["ephemeral_" + arm.lower()]["first"]
        require(type(first) is dict
                and set(first) == {"model", "messages", "tools",
                                   "tool_choice", "temperature"}
                and digest(first) == gate["owned_stage_packet_sha256"][arm]["first"]
                and first["model"] == frozen_chat.MODEL_ID
                and first["temperature"] == frozen_chat.TEMPERATURE
                and first["tool_choice"] == "auto"
                and [v.get("role") for v in first["messages"]]
                    == ["developer", "user"]
                and all(type(v) is dict for v in first["tools"])
                and len(first["tools"]) == source_run["redacted_manifest"]["native_full_tool_count"],
                "EXACT_PINNED_NATIVE_CHAT_FIRST_WIRE_REQUIRED")
        # The model must see the entire unpruned native tool catalog.
        # No original request/payload rewrite, no imported synthetic call IDs.
        require(all("tool_calls" not in item and "tool_call_id" not in item
                    for item in first["messages"]),
                "NO_SCRIPTED_NATIVE_TOOL_CALL_IDS_IN_INITIAL_WIRE")
        payload = deepcopy(first)
        payload.update({
            "n": 1, "max_completion_tokens": OUTPUT_LIMIT,
            "store": False, "stream": False,
        })
        require(len(canonical(payload)) <= MAX_SERIALIZED_BYTES,
                "FULL_NATIVE_FIRST_PACKET_TOO_LARGE")
        source[arm] = payload
    require(source["A"] == source["B"]
            and source["A"] is not source["B"]
            and source["A"]["messages"] is not source["B"]["messages"]
            and source["A"]["tools"] is not source["B"]["tools"]
            and digest(source["A"]["tools"]) ==
                 gate["full_native_tool_catalog_sha256"],
            "INDEPENDENT_ARM_INPUT_COPY_AND_NATIVE_CATALOG_PARITY")
    upper = reserve_upper_bound_usd()
    summary = {
        "schema": SCHEMA,
        "rule_of_one": RULE,
        "status": STATUS,
        "case_id": gate["case_id"],
        "agentdojo_pin": gate["agentdojo_pin"],
        "veritas_pin": gate["veritas_pin"],
        "native_source_419_sha256": digest(gate),
        "original_native_initial_input_sha256":
            gate["owned_stage_packet_sha256"]["A"]["first"],
        "native_full_tool_catalog_sha256":
            gate["full_native_tool_catalog_sha256"],
        "native_original_attacked_result_sha256":
            gate["native_original_attacked_tool_result_sha256"],
        "first_packet_SHA256_by_arm": {arm: digest(source[arm]) for arm in ARMS},
        "number_of_proposed_first_chat_calls": CALLS,
        "native_first_inputs_exactly_equal_but_distinct_objects": True,
        "native_full_catalog_preserved": True,
        "native_later_scripted_stages_sendable": False,
        "max_completion_tokens_per_call": OUTPUT_LIMIT,
        "estimated_input_token_bound_per_call": INPUT_LIMIT,
        "budget_upper_estimate_usd": str(upper),
        "proposed_budget_ceiling_usd": str(BUDGET_PROPOSED_USD),
        "provider_enforced_spend_stop_verified": False,
        "authenticated_operator_approval": False,
        "protected_production_single_use_lease_consumed": False,
        "old_test_only_tag_is_valid_production_lease": False,
        "provider_request_count": 0,
        "independently_authenticated_provider_responses": 0,
        "native_tool_calls_after_provider": 0,
        "native_official_scorer_calls": 0,
        "eligible_for_live_dispatch": False,
        "eligible_for_official_scoring": False,
        "new_utility_recoveries": 0,
        "no_customer_or_production_effect": True,
    }
    # Do not publish the ephemeral native request with original user data.
    return {"redacted_manifest": summary, "ephemeral_unsent_packets": source}


def validate_owned_presend_payload(*, prepared: dict, arm: str,
                                    proposed_payload: dict):
    """Future protected caller can pin bytes; this is NOT permission to send."""
    require(type(prepared) is dict
            and set(prepared) == {"redacted_manifest", "ephemeral_unsent_packets"}
            and type(prepared["redacted_manifest"]) is dict
            and type(prepared["ephemeral_unsent_packets"]) is dict
            and arm in ARMS, "EXACT_PREPARED_NATIVE_PAIR_ONLY")
    manifest = prepared["redacted_manifest"]
    require(manifest.get("schema") == SCHEMA
            and manifest.get("status") == STATUS
            and manifest.get("eligible_for_live_dispatch") is False
            and manifest.get("provider_request_count") == 0
            and manifest.get("authenticated_operator_approval") is False
            and manifest.get("protected_production_single_use_lease_consumed") is False,
            "CANNOT_MINT_PROVIDER_AUTHORITY")
    owned_payload = prepared["ephemeral_unsent_packets"].get(arm)
    require(type(owned_payload) is dict and type(proposed_payload) is dict
            and proposed_payload == owned_payload
            and digest(proposed_payload) ==
                manifest.get("first_packet_SHA256_by_arm", {}).get(arm)
            and proposed_payload.get("n") == 1
            and proposed_payload.get("max_completion_tokens") == OUTPUT_LIMIT
            and proposed_payload.get("store") is False
            and proposed_payload.get("stream") is False
            and len(canonical(proposed_payload)) <= MAX_SERIALIZED_BYTES,
            "MODIFIED_OR_UNBOUNDED_NATIVE_SEND_PACKET")
    return {
        "arm": arm,
        "request_sha256": digest(proposed_payload),
        "original_task1_first_native_request_sha256":
            manifest["original_native_initial_input_sha256"],
        "status": "VERIFIED_PRESEND_BYTES_NOT_PERMISSION",
        "eligible_to_send": False,
    }


def deny_provider_send_or_model_scoring(*_args, **_kwargs):
    raise Refused("421_NO_PROTECTED_LIVE_CHAT_SENDER_OR_PROVIDER_AUTHORITY")

#!/usr/bin/env python3
"""#420 native Chat Completions reply admission, deliberately UNAUTHENTICATED.

The already merged #419 has the actual pinned AgentDojo Chat Completions
full-tool request packets. #381/#382 are a different Responses API pilot.
This module parses an UNTRUSTED reply against one original in-process #419
packet and DOES NOT send, authenticate, execute, authorize or score anything.
Only a future independent TLS/protected caller could attest origin.
"""
from __future__ import annotations

import hashlib
import json
import re

from scripts import final128_419_task1_native_three_stage_wire_lineage_v1 as native

RULE = "FINAL128_420_NATIVE_CHAT_UNTRUSTED_REPLY_ADMISSION_V1"
SCHEMA = "veritas.final128.420.task1-native-chat-reply-admission.v1"
MAX_REPLY_BYTES = 96000
MAX_MODEL_TEXT_BYTES = 8192
MAX_ARGUMENT_BYTES = 4096
MAX_CALLS_PER_REPLY = 20
RESPONSE_ID = re.compile(r"^chatcmpl-[A-Za-z0-9_-]{6,150}$")
CALL_ID = re.compile(r"^call_[A-Za-z0-9_-]{4,152}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class Refused(ValueError):
    pass


def need(ok, reason):
    if ok is not True:
        raise Refused("420_" + reason)


def sha(value):
    return hashlib.sha256(native.previous.canonical(value)).hexdigest()


def _unique_keys(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def _bad_constant(_):
    raise Refused("420_NONFINITE_JSON")


def _strict_obj(data, max_bytes, reason):
    need(type(data) is bytes and 0 < len(data) <= max_bytes, reason)
    try:
        value = json.loads(data.decode("utf8"), object_pairs_hook=_unique_keys,
                           parse_constant=_bad_constant)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise Refused("420_NOT_STRICT_UTF8_JSON") from exc
    need(type(value) is dict, "TOP_LEVEL_OBJECT_REQUIRED")
    return value


def _content_ok(content):
    return content is None or (
        type(content) is str and
        len(content.encode("utf8")) <= MAX_MODEL_TEXT_BYTES
    )


def inspect_untrusted_native_chat_reply(*, source_run, frozen_ledger,
                                         arm, stage, raw_response):
    """Parse one locally supplied Chat reply after independently reading #419.

    An attacker can construct a JSON body, model name or response ID.
    None of these proves HTTPS/TLS, account custody or Provider origin.
    """
    need(arm in native.ARMS and stage in native.STAGES,
         "EXACT_ARM_AND_STAGE_REQUIRED")
    frozen = native.packet_freeze(source_run, frozen_ledger)
    packet = source_run["ephemeral_" + arm.lower()][stage]
    need(sha(packet) == frozen["owned_stage_packet_sha256"][arm][stage],
         "SOURCE_OWNED_EXACT_NATIVE_REQUEST_MISSING")

    reply = _strict_obj(raw_response, MAX_REPLY_BYTES, "BOUNDED_RAW_REPLY_REQUIRED")
    need(set(reply) == {"id", "model", "choices", "usage"},
         "UNTRUSTED_RESPONSE_SHAPE_OR_CLAIM_FIELD")
    need(type(reply["id"]) is str
         and RESPONSE_ID.fullmatch(reply["id"]) is not None
         and reply["model"] == packet["model"]
         and type(reply["choices"]) is list
         and len(reply["choices"]) == 1,
         "MODEL_OR_RESPONSE_ID_OR_EXACTLY_ONE_CHOICE")
    choice = reply["choices"][0]
    need(type(choice) is dict
         and set(choice) == {"index", "finish_reason", "message"}
         and type(choice["index"]) is int and choice["index"] == 0
         and type(choice["message"]) is dict,
         "ONE_NATIVE_CHAT_ASSISTANT_CHOICE_REQUIRED")
    message = choice["message"]
    need(set(message) == {"role", "content", "tool_calls"}
         and message["role"] == "assistant"
         and _content_ok(message["content"]),
         "EXACT_ASSISTANT_CONTENT_SCHEMA_REQUIRED")
    usage = reply["usage"]
    need(type(usage) is dict
         and set(usage) == {"prompt_tokens", "completion_tokens"}
         and type(usage["prompt_tokens"]) is int
         and type(usage["completion_tokens"]) is int
         and 0 <= usage["prompt_tokens"] <= 12000
         and 0 <= usage["completion_tokens"] <= 256,
         "EXPLICIT_BOUNDED_PROVIDER_USAGE_REQUIRED")

    calls = message["tool_calls"]
    tool_names = set()
    for entry in packet["tools"]:
        need(type(entry) is dict and type(entry.get("function")) is dict
             and type(entry["function"].get("name")) is str,
             "NATIVE_FULL_CATALOG_INVALID")
        tool_names.add(entry["function"]["name"])
    ids = set()
    parsed = []
    if calls is None:
        need(choice["finish_reason"] == "stop"
             and type(message["content"]) is str
             and bool(message["content"].strip()),
             "GENUINE_TERMINAL_SHAPE_REQUIRED_NOT_ORIGIN")
        disposition = "UNTRUSTED_TERMINAL_NOT_SCOREABLE"
    else:
        need(type(calls) is list
             and 1 <= len(calls) <= MAX_CALLS_PER_REPLY
             and choice["finish_reason"] == "tool_calls",
             "TOOL_CALLS_FINISH_REASON_OR_CARDINALITY")
        for item in calls:
            need(type(item) is dict
                 and set(item) == {"id", "type", "function"}
                 and item["type"] == "function"
                 and type(item["id"]) is str
                 and CALL_ID.fullmatch(item["id"]) is not None
                 and item["id"] not in ids
                 and type(item["function"]) is dict
                 and set(item["function"]) == {"name", "arguments"},
                 "NATIVE_FUNCTION_CALL_ID_OR_SHAPE_INVALID")
            ids.add(item["id"])
            fn = item["function"]
            need(type(fn["name"]) is str
                 and fn["name"] in tool_names
                 and type(fn["arguments"]) is str
                 and 0 < len(fn["arguments"].encode("utf8")) <= MAX_ARGUMENT_BYTES,
                 "FUNCTION_NOT_IN_UNPRUNED_NATIVE_CATALOG")
            args = _strict_obj(fn["arguments"].encode("utf8"),
                               MAX_ARGUMENT_BYTES,
                               "BOUNDED_NATIVE_FUNCTION_ARGUMENTS_REQUIRED")
            need(not any(key.startswith("_") for key in args),
                 "FORBID_RESERVED_TOOL_ARGUMENT_FIELDS")
            # Here arguments are UNTRUSTED proposals only: Bind must still
            # decide before any protected Native tool can be dispatched.
            parsed.append({"id": item["id"], "function": fn["name"],
                           "arguments": args})
        disposition = "UNTRUSTED_NATIVE_TOOL_PROPOSAL_PRE_BIND"

    # Raw completion content, call IDs, account details, original lower
    # trust text and spoofable Provider ID stay strictly ephemeral.
    return {
        "schema": SCHEMA,
        "rule_of_one": RULE,
        "status": disposition,
        "case_id": frozen["case_id"],
        "arm": arm,
        "stage": stage,
        "source_owned_request_sha256": frozen["owned_stage_packet_sha256"][arm][stage],
        "source_owned_full_tool_catalog_sha256":
            frozen["full_native_tool_catalog_sha256"],
        "untrusted_reply_sha256": hashlib.sha256(raw_response).hexdigest(),
        "untrusted_response_id_sha256": sha(reply["id"]),
        "native_tool_call_count": len(parsed),
        "native_tool_call_names": [entry["function"] for entry in parsed],
        "native_tool_id_ownership_digest": sha([entry["id"] for entry in parsed]),
        "native_tool_arguments_sha256": [sha(entry["arguments"]) for entry in parsed],
        "untrusted_local_content_shape_checked": True,
        "independent_tls_provider_origin_verified": False,
        "externally_consumed_global_oneuse_lease": False,
        "fresh_operator_approval_observed": False,
        "native_tool_executed": False,
        "actual_model_terminal_proven": False,
        "same_run_native_user_attack_scored": False,
        "eligible_for_provider_dispatch": False,
        "eligible_for_official_utility": False,
        "official_utility": None,
        "official_attack_success": None,
        "new_utility_recoveries": 0,
        "model_submitted_to_provider": False,
    }


def deny_live_provider_and_native_effect(*_args, **_kwargs):
    raise Refused("420_NO_PROTECTED_SENDER_OR_NATIVE_EXECUTION_AUTHORITY")


def deny_official_native_scoring(*_args, **_kwargs):
    raise Refused("420_UNTRUSTED_REPLY_NOT_AUTHENTICATED_NATIVE_TERMINAL")

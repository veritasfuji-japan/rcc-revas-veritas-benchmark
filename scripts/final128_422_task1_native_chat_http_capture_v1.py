#!/usr/bin/env python3
"""#422: full native Chat Completions HTTP capture -> existing #420 parser.

This is deliberately a NON-LIVE CAPTURE ADAPTER. The future protected
sender must supply authenticated TLS bytes and true independent issuance.
Nothing here sends requests, consumes permissions or executes model tools.
Header fields / response IDs supplied by a caller remain forgeable.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import re

from scripts import final128_420_task1_native_chat_reply_admission_v1 as reply
from scripts import final128_421_task1_native_first_pair_presend_v1 as first

RULE = "FINAL128_422_TASK1_FULL_CHAT_CAPTURE_SOURCE_BOUND_UNAUTHENTICATED_V1"
SCHEMA = "veritas.final128.422.task1-native-chat-full-http-capture.v1"
ARMS = ("A", "B")
MAX_BODY_BYTES = reply.MAX_REPLY_BYTES
MAX_HTTP_REQUEST_ID = 160
CLIENT_ID = re.compile(r"^task1-422-([AB])-([1-9][0-9]{5,19})$")
SERVER_ID = re.compile(r"^[A-Za-z0-9_-]{6,160}$")
TOP_FIELDS = frozenset({
    "id", "object", "created", "model", "choices", "usage",
    "system_fingerprint", "service_tier"
})
CHOICE_FIELDS = frozenset({"index", "finish_reason", "message", "logprobs"})
MESSAGE_FIELDS = frozenset({
    "role", "content", "tool_calls", "refusal", "annotations",
    "audio", "function_call"
})
USAGE_FIELDS = frozenset({
    "prompt_tokens", "completion_tokens", "total_tokens",
    "prompt_tokens_details", "completion_tokens_details"
})


class Refused(ValueError):
    pass


def need(condition, why):
    if condition is not True:
        raise Refused("422_" + why)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _sanitize_real_chat(raw_response: bytes):
    """Retain only fields the merged #420 Native assistant parser understands.

    A Chat Completions HTTP response has extra server metadata and usage
    details that were intentionally absent from #420's local shape fixtures.
    Ignore ONLY recognized passive metadata; refuse any unknown live field,
    actual refusal content, logprobs, audio or deprecated function calls.
    """
    raw = reply._strict_obj(raw_response, MAX_BODY_BYTES,
                            "BOUNDED_CHAT_HTTP_BODY_REQUIRED")
    need(set(raw) >= {"id", "object", "created", "model", "choices", "usage"}
         and set(raw) <= TOP_FIELDS
         and raw["object"] == "chat.completion"
         and type(raw["created"]) is int and raw["created"] > 0,
         "NATIVE_CHAT_HTTP_TOP_LEVEL_PROTOCOL_ORIGIN_UNVERIFIED")
    choices = raw["choices"]
    need(type(choices) is list and len(choices) == 1
         and type(choices[0]) is dict
         and {"index", "finish_reason", "message"} <= set(choices[0])
         and set(choices[0]) <= CHOICE_FIELDS
         and choices[0].get("logprobs") is None,
         "ONE_CHAT_CHOICE_NO_UNSUPPORTED_LOGPROBS")
    choice = choices[0]
    message = choice["message"]
    need(type(message) is dict
         and {"role", "content"} <= set(message) <= MESSAGE_FIELDS
         and message.get("refusal") is None
         and message.get("audio") is None
         and message.get("function_call") is None
         and message.get("annotations") in (None, []),
         "NO_UNSUPPORTED_NATIVE_MESSAGE_CONTENT_OR_REFUSAL")
    usage = raw["usage"]
    need(type(usage) is dict
         and {"prompt_tokens", "completion_tokens", "total_tokens"} <= set(usage)
         and set(usage) <= USAGE_FIELDS
         and all(type(usage[k]) is int and usage[k] >= 0
                 for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
         and usage["total_tokens"] ==
             usage["prompt_tokens"] + usage["completion_tokens"],
         "TRUE_TOKEN_USAGE_SHAPE_AND_TOTAL_REQUIRED")
    normalized = {
        "id": raw["id"],
        "model": raw["model"],
        "usage": {k: usage[k] for k in ("prompt_tokens", "completion_tokens")},
        "choices": [{
            "index": choice["index"],
            "finish_reason": choice["finish_reason"],
            "message": {
                "role": message["role"],
                "content": message["content"],
                "tool_calls": message.get("tool_calls"),
            },
        }],
    }
    need(len(first.canonical(normalized)) <= reply.MAX_REPLY_BYTES,
         "NORMALIZED_BOUND_REQUIRED")
    return normalized, usage


def capture_one(*, native_run, ledger, prepared, arm, client_request_id,
                response_status, response_headers, raw_response):
    """Source-bound *externally supplied* HTTP observations. Never authenticates."""
    need(arm in ARMS and type(client_request_id) is str
         and len(client_request_id) <= MAX_HTTP_REQUEST_ID
         and CLIENT_ID.fullmatch(client_request_id) is not None
         and CLIENT_ID.fullmatch(client_request_id).group(1) == arm,
         "EXACT_ARM_CLIENT_REQUEST_ID")
    need(type(response_status) is int and response_status == 200,
         "HTTP_NON_SUCCESS_UNKNOWN_NO_RETRY")
    need(type(response_headers) is dict and
         set(response_headers) == {"x-request-id"} and
         type(response_headers["x-request-id"]) is str and
         SERVER_ID.fullmatch(response_headers["x-request-id"]) is not None,
         "EXACT_SERVER_REQUEST_ID_HEADER_ORIGIN_UNVERIFIED")
    freeze = first.freeze_native_first_pair(source_run=native_run, ledger=ledger)
    need(type(prepared) is dict
         and set(prepared) == {"redacted_manifest", "ephemeral_unsent_packets"}
         and prepared["redacted_manifest"] == freeze["redacted_manifest"]
         and prepared["ephemeral_unsent_packets"] == freeze["ephemeral_unsent_packets"]
         and prepared is not freeze, "EXACT_LOCAL_NATIVE_FIRST_PAIR_REQUIRED")
    first.validate_owned_presend_payload(
        prepared=prepared, arm=arm,
        proposed_payload=prepared["ephemeral_unsent_packets"][arm])
    normalized, usage = _sanitize_real_chat(raw_response)
    # Existing parser owns exact original Native tool schema and arguments.
    untrusted = reply.inspect_untrusted_native_chat_reply(
        source_run=native_run, frozen_ledger=ledger, arm=arm,
        stage="first", raw_response=first.canonical(normalized))
    need(untrusted["source_owned_request_sha256"] ==
         freeze["redacted_manifest"]["original_native_initial_input_sha256"],
         "PROVIDER_BODY_NOT_BOUND_TO_NATIVE_FIRST_REQUEST")
    # Post-call count is NOT a pre-call account/project hard spend cap.
    need(usage["prompt_tokens"] <= first.INPUT_LIMIT
         and usage["completion_tokens"] <= first.OUTPUT_LIMIT,
         "POSTCALL_TOKEN_USAGE_TOO_HIGH_NO_RETRY")
    cost = (
        Decimal(usage["prompt_tokens"]) * first.estimates.INPUT_USD_PER_M
        + Decimal(usage["completion_tokens"]) * first.estimates.OUTPUT_USD_PER_M
    ) / Decimal(1_000_000)
    return {
        "schema": SCHEMA, "rule_of_one": RULE,
        "status": "EXTERNALLY_SUPPLIED_CHAT_HTTP_FIRST_RESPONSE_UNAUTHENTICATED",
        "case_id": freeze["redacted_manifest"]["case_id"],
        "arm": arm, "request_sha256":
            freeze["redacted_manifest"]["first_packet_SHA256_by_arm"][arm],
        "raw_response_sha256": sha_bytes(raw_response),
        "normalized_chat_body_sha256": first.digest(normalized),
        "client_request_id_sha256": first.digest(client_request_id),
        "server_request_id_sha256":
            first.digest(response_headers["x-request-id"]),
        "model_response_id_sha256": untrusted["untrusted_response_id_sha256"],
        "native_full_tool_catalog_sha256":
            freeze["redacted_manifest"]["native_full_tool_catalog_sha256"],
        "native_tool_call_count": untrusted["native_tool_call_count"],
        "native_tool_call_names": untrusted["native_tool_call_names"],
        "model_proposed_tool_arguments_sha256":
            untrusted["native_tool_arguments_sha256"],
        "estimated_cost_usd_not_invoice": str(cost),
        "provider_origin_independently_attested": False,
        "trusted_tls_sender_verified": False,
        "production_once_issuer_verified": False,
        "operator_consent_verified": False,
        "project_spend_hard_limit_verified": False,
        "native_tool_dispatches": 0,
        "native_final_model_terminal_proven": False,
        "official_native_scores": None,
        "eligible_for_native_effect": False,
        "eligible_for_official_scoring": False,
        "new_utility_recoveries": 0,
    }


def quarantine_pair(*, native_run, ledger, prepared, capture_a, capture_b):
    """Pair two untrusted HTTP captures; NEVER join them to a scored run."""
    need(type(capture_a) is dict and type(capture_b) is dict
         and set(capture_a) == {
             "client_request_id", "response_status", "response_headers",
             "raw_response"
         } and set(capture_b) == set(capture_a),
         "EXACT_RAW_HTTP_PAIR_REQUIRED")
    a = capture_one(native_run=native_run, ledger=ledger, prepared=prepared,
                    arm="A", **capture_a)
    b = capture_one(native_run=native_run, ledger=ledger, prepared=prepared,
                    arm="B", **capture_b)
    # Reject replay/arm mislabelling even when model tool calls are valid.
    for field in ("client_request_id_sha256", "server_request_id_sha256",
                  "model_response_id_sha256"):
        need(a[field] != b[field],
             "INDEPENDENT_A_B_HTTP_RESPONSE_IDENTITIES_REQUIRED")
    need(a["request_sha256"] == b["request_sha256"]
         and a["native_full_tool_catalog_sha256"] ==
             b["native_full_tool_catalog_sha256"],
         "FIRST_NATIVE_AB_PARITY")
    aggregate = Decimal(a["estimated_cost_usd_not_invoice"]) +                 Decimal(b["estimated_cost_usd_not_invoice"])
    need(aggregate <= first.BUDGET_PROPOSED_USD,
         "LOCAL_SOFT_ESTIMATE_EXCEEDS_PROPOSED_TARGET")
    return {
        "schema": SCHEMA,
        "status": "TWO_UNTRUSTED_NATIVE_CHAT_HTTP_FIRST_CAPTURES_QUARANTINED",
        "case_id": a["case_id"],
        "A": a, "B": b,
        "total_estimated_cost_usd_not_invoice": str(aggregate),
        "genuine_provider_origin_verified": False,
        "provider_calls_performed_by_this_module": 0,
        "native_tools_dispatched": 0,
        "first_A_B_actual_model_generation_proven": False,
        "eligible_for_official_scoring": False,
        "new_utility_recoveries": 0,
    }


def deny_paid_send_and_auth(*_args, **_kwargs):
    raise Refused("422_NO_PROTECTED_TLS_SENDER_OR_TRUSTED_ISSUER")

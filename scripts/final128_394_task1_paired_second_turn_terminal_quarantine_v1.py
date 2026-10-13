#!/usr/bin/env python3
"""#394 Task1 paired native second-turn packets and untrusted final quarantine.

Only real pinned AgentDojo local read-only tools and OFFLINE fabricated Responses
captured bytes are accepted. This cannot dispatch a Provider request or issue a
native score. The resulting second-turn packets are UNSENT proposals; the
terminal adapter is not evidence of real LLM provenance or Utility recovery.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from scripts import final128_381_task1_real_responses_capture_contract_v1 as source

SCHEMA = "veritas.final128.task1-394-paired-second-turn-untrusted-final.v1"
ARMS = ("A", "B")
MAX_SECOND_BYTES = 56000
MAX_TERMINAL_TEXT_BYTES = 8192


class Refused(ValueError):
    pass


def need(condition, reason):
    if condition is not True:
        raise Refused("394_" + reason)


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _verify_packet(packet, arm, original):
    first = source.first_real_wire_packet()
    need(arm in ARMS and type(packet) is dict
         and set(packet) == set(first) and packet["model"] == first["model"]
         and packet["tools"] == first["tools"]
         and packet["tool_choice"] == "none"
         and packet["parallel_tool_calls"] is False
         and packet["store"] is False and packet["stream"] is False
         and packet["max_output_tokens"] == first["max_output_tokens"],
         "SECOND_WIRE_SETTING_OR_TOOL_DRIFT")
    rows = packet["input"]
    need(type(rows) is list and len(rows) == (3 if arm == "A" else 4)
         and rows[0] == {"role": "user", "content": source.guard.PROMPT}
         and type(rows[1]) is dict and rows[1]["type"] == "function_call"
         and rows[1]["name"] == source.guard.TOOL
         and type(rows[1]["call_id"]) is str
         and source.CALL_RE.fullmatch(rows[1]["call_id"]) is not None
         and rows[2]["type"] == "function_call_output"
         and rows[2]["call_id"] == rows[1]["call_id"]
         and type(rows[2]["output"]) is str,
         "MODEL_FUNCTION_CALL_TO_NATIVE_RETURN_BROKEN")
    need(rows[1] == original[1]
         and rows[2] == original[2]
         and len(rows[2]["output"].encode("utf8")) <= source.MAX_NATIVE_ROWS_BYTES,
         "EXACT_ORIGINAL_ATTACKED_NATIVE_RETURN_CHANGED")
    if arm == "B":
        need(rows[3] == original[3]
             and rows[3]["role"] == "developer"
             and "subject" not in rows[3]["content"],
             "B_SOURCE_OWNED_CONTEXT_CHANGED")
    else:
        need(len(rows) == 3, "A_MUST_HAVE_NO_TREATMENT")
    need(len(source.canonical(packet)) <= MAX_SECOND_BYTES,
         "SECOND_PACKET_TOO_LARGE")
    return True


def prepare_paired_unsent_second_turns(*, capture_a, capture_b,
                                       native_environment_a, native_environment_b,
                                       original_user_request, attack_subject):
    """Re-read each real native source, then bind untrusted first call IDs.

    The identity checks concern CONTENT SHAPE only; a supplied capture may be
    fabricated. Calling this function never authenticates a Provider session.
    """
    res = source.prepare_untrusted_continuation_candidates(
        capture_a=capture_a, capture_b=capture_b,
        native_environment_a=native_environment_a,
        native_environment_b=native_environment_b,
        original_user_request=original_user_request,
        attack_subject=attack_subject,
    )
    upstream = res["redacted_manifest"]
    previews = res["ephemeral_untrusted_continuation_previews"]
    need(upstream["status"] ==
         "RAW_RESPONSES_SHAPE_NATIVE_CONTINUATION_PREVIEW_DENY_SEND"
         and upstream["ready_for_live_dispatch"] is False
         and upstream["eligible_for_official_scoring"] is False
         and upstream["observed_provider_ids_genuine"] is False
         and upstream["actual_live_provider_calls"] == 0,
         "UPSTREAM_PREVIEW_CANNOT_MINT_TRUST")
    packets = {}
    for arm in ARMS:
        packet = source.first_real_wire_packet()
        packet["input"] = deepcopy(previews[arm])
        packet["tool_choice"] = "none"
        _verify_packet(packet, arm, previews[arm])
        packets[arm] = packet
    need(packets["A"]["input"][0] == packets["B"]["input"][0]
         and packets["A"]["input"][2]["output"] ==
             packets["B"]["input"][2]["output"]
         and packets["A"]["input"][1]["call_id"] !=
             packets["B"]["input"][1]["call_id"]
         and attack_subject in packets["A"]["input"][2]["output"]
         and attack_subject in packets["B"]["input"][2]["output"]
         and attack_subject not in packets["B"]["input"][3]["content"],
         "CROSS_ARM_PARITY_OR_ATTACK_TRUST_DRIFT")
    report = {
        "schema": SCHEMA,
        "case_id": source.guard.CASE,
        "status": "UNSENT_SECOND_RESPONSES_INPUT_FROM_REAL_NATIVE_AND_FAKE_FIRST_CAPTURE",
        "first_wire_sha256": upstream["first_wire_sha256"],
        "second_A_wire_sha256": source.sha(packets["A"]),
        "second_B_wire_sha256": source.sha(packets["B"]),
        "same_attacked_native_return_sha256":
            upstream["A_B_native_tool_response_sha256"],
        "B_source_owned_projection_sha256":
            upstream["B_source_owned_spending_projection_sha256"],
        "distinct_claimed_first_function_call_ids": True,
        "real_native_readonly_source_used": True,
        "genuine_provider_origin_proven": False,
        "real_first_or_second_provider_calls": 0,
        "real_final_model_terminals": 0,
        "real_native_scorer_calls": 0,
        "official_utility_or_attack_scores": None,
        "eligible_for_official_scoring": False,
        "protected_singleuse_lease_consumed": False,
        "new_paid_spend_authorized": False,
    }
    return {"redacted_manifest": report, "ephemeral_unsent_packets": packets}


def parse_untrusted_second_terminal(*, prepared, arm, submitted_packet,
                                    raw_http_response_body,
                                    asserted_http_status, asserted_x_request_id,
                                    claimed_capture_source):
    """Validate one *fake* terminal's shape, return quarantined native text.

    The output is an in-memory potential AgentDojo model_output shape. It is
    NEVER scorer-admissible without separately established Provider provenance,
    authenticated lineage, completed native trace and permission.
    """
    need(type(prepared) is dict and arm in ARMS
         and type(prepared.get("redacted_manifest")) is dict
         and prepared["redacted_manifest"].get("schema") == SCHEMA
         and prepared["redacted_manifest"].get("eligible_for_official_scoring")
             is False
         and prepared["redacted_manifest"].get("genuine_provider_origin_proven")
             is False
         and prepared["redacted_manifest"].get("real_first_or_second_provider_calls")
             == 0,
         "ONLY_QUARANTINED_LOCAL_PREVIEW")
    packet = prepared["ephemeral_unsent_packets"][arm]
    need(type(submitted_packet) is dict and submitted_packet == packet
         and source.sha(packet) ==
             prepared["redacted_manifest"]["second_" + arm + "_wire_sha256"],
         "SECOND_REQUEST_TAMPERED")
    _verify_packet(packet, arm, packet["input"])
    need(type(asserted_http_status) is int and asserted_http_status == 200
         and type(asserted_x_request_id) is str
         and source.ID_RE.fullmatch(asserted_x_request_id) is not None
         and claimed_capture_source == "UNTRUSTED_OFFLINE_FIXTURE",
         "UNAUTHENTICATED_OR_NON_200_FINAL")
    data = source.strict_json_bytes(raw_http_response_body)
    need(type(data) is dict and data.get("object") == "response"
         and data.get("model") == source.MODEL
         and data.get("status") == "completed"
         and type(data.get("id")) is str
         and data["id"].startswith("resp_")
         and source.ID_RE.fullmatch(data["id"]) is not None,
         "FINAL_MODEL_ID_STATUS_INVALID")
    outputs = data.get("output")
    need(type(outputs) is list and len(outputs) == 1
         and type(outputs[0]) is dict,
         "FINAL_ONLY_ONE_ASSISTANT_MESSAGE")
    msg = outputs[0]
    need(msg.get("type") == "message" and msg.get("role") == "assistant"
         and (msg.get("status") is None or msg.get("status") == "completed")
         and type(msg.get("content")) is list and len(msg["content"]) == 1,
         "FINAL_MESSAGE_SHAPE_INVALID")
    piece = msg["content"][0]
    need(type(piece) is dict and set(piece) == {"type", "text"}
         and piece["type"] == "output_text"
         and type(piece["text"]) is str and bool(piece["text"].strip())
         and len(piece["text"].encode("utf8")) <= MAX_TERMINAL_TEXT_BYTES,
         "FINAL_TEXT_EMPTY_UNBOUNDED_OR_REFUSAL")
    usage = data.get("usage")
    need(type(usage) is dict
         and all(type(usage.get(k)) is int
             and 0 <= usage[k] <= source.transport.MAX_INPUT_TOKENS +
                                    source.transport.MAX_OUTPUT_TOKENS
             for k in ("input_tokens", "output_tokens", "total_tokens"))
         and usage["total_tokens"] == usage["input_tokens"] + usage["output_tokens"]
         and usage["input_tokens"] <= source.transport.MAX_INPUT_TOKENS
         and usage["output_tokens"] <= source.transport.MAX_OUTPUT_TOKENS,
         "FINAL_TOKEN_USAGE_INVALID")
    output = [{"type": "text", "content": piece["text"]}]
    return {
        "arm": arm,
        "status": "QUARANTINED_UNTRUSTED_TERMINAL_NO_OFFICIAL_SCORE",
        "claimed_response_id": data["id"],
        "claimed_http_request_id_sha256": source.sha(asserted_x_request_id),
        "raw_terminal_sha256": sha_bytes(raw_http_response_body),
        "model_output_sha256": source.sha(output),
        "ephemeral_native_model_output": output,
        "provider_origin_authenticated": False,
        "official_native_scorer_eligible": False,
        "official_utility_or_attack_scores": None,
    }


def quarantine_paired_terminals(*, prepared, terminal_a, terminal_b):
    need(type(prepared) is dict and type(terminal_a) is dict
         and type(terminal_b) is dict
         and [terminal_a.get("arm"), terminal_b.get("arm")] == ["A", "B"]
         and all(t.get("status") ==
           "QUARANTINED_UNTRUSTED_TERMINAL_NO_OFFICIAL_SCORE"
           and t.get("provider_origin_authenticated") is False
           and t.get("official_native_scorer_eligible") is False
           and t.get("official_utility_or_attack_scores") is None
           and source.sha(t["ephemeral_native_model_output"]) ==
               t["model_output_sha256"]
           for t in (terminal_a, terminal_b))
         and terminal_a["claimed_response_id"] != terminal_b["claimed_response_id"]
         and terminal_a["claimed_http_request_id_sha256"] !=
             terminal_b["claimed_http_request_id_sha256"],
         "TERMINAL_PAIR_UNTRUSTED_LINEAGE_INVALID")
    report = deepcopy(prepared["redacted_manifest"])
    need(report["eligible_for_official_scoring"] is False
         and report["real_first_or_second_provider_calls"] == 0,
         "FALSE_SCORER_ELIGIBILITY")
    report.update({
        "status": "TWO_UNTRUSTED_TERMINALS_QUARANTINED_NOT_MEASURED",
        "A_untrusted_terminal_sha256": terminal_a["raw_terminal_sha256"],
        "B_untrusted_terminal_sha256": terminal_b["raw_terminal_sha256"],
        "A_untrusted_model_output_sha256": terminal_a["model_output_sha256"],
        "B_untrusted_model_output_sha256": terminal_b["model_output_sha256"],
        "untrusted_terminal_count": 2,
        "real_final_model_terminals": 0,
        "real_native_scorer_calls": 0,
        "official_utility_or_attack_scores": None,
        "eligible_for_official_scoring": False,
    })
    return report


def deny_real_provider_dispatch(*_args, **_kwargs):
    raise Refused("394_NO_FRESH_APPROVAL_ISSUER_TRUSTED_TLS_OR_BUDGET")


def deny_official_native_scoring(*_args, **_kwargs):
    raise Refused("394_NO_AUTHENTICATED_COMPLETED_NATIVE_PROVIDER_PAIR")

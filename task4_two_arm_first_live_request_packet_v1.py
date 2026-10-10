"""#292: immutable two-arm FIRST real-model request payload PACKET, no transport.

Constructs complete model-input JSON payloads from the exact native attacked
Task4 A/B synthetic provenance. No model responses are imported, synthesized,
or claimed real. Separate package IDs are *local evidence labels* only; they
are not actual Provider request IDs or authorizations.

This module has no network, no API client and no execution method.
"""
from __future__ import annotations
import copy
import hashlib
import json

from task4_first_provider_request_origin_no_promotion_v1 import (
    RULE as FIRST_RULE, frozen_first_request_handoff,
    digest as sha, FirstOriginDenied,
)
from task4_native_injected_read_exposure_v1 import CASE
from task4_trusted_execution_date_profile_v1 import REQUEST

RULE="TASK4_TWO_ARM_FIRST_LIVE_REQUEST_PACKET_V1"
MODEL="gpt-4.1-mini-2025-04-14"
ARMS=("A","B")
MAX_OUTPUT_TOKENS=256
PROPOSED_PER_CALL_MAX_MICRO_USD=250000  # $0.25 (NOT spend permission)
PROPOSED_TWO_CALL_MAX_MICRO_USD=500000  # $0.50 (NOT spend permission)
MAX_REQUEST_BYTES=32768

class PacketDenied(ValueError): pass

def need(x,why):
    if not x: raise PacketDenied(why)

def canon(x):
    return json.dumps(x,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf-8")

def digest(x):
    return hashlib.sha256(canon(x)).hexdigest()

def make_two_arm_packets(history,*,provider_client=None,api_key=None,
                         operator_approval=None,previous_response=None):
    need(provider_client is None and api_key is None
         and operator_approval is None and previous_response is None,
         "NO_REAL_CLIENT_APPROVAL_OR_FAKE_PROVIDER_HISTORY_IN_PACKET_PROOF")
    try:
        origin=frozen_first_request_handoff(history)
    except (FirstOriginDenied,ValueError,TypeError,KeyError) as e:
        raise PacketDenied("SOURCE_FIRST_QUERY_ORIGIN_INVALID:"+str(e)) from e
    need(origin["rule_of_one"]==FIRST_RULE and
         origin["allowed_live_provider_calls"]==0
         and origin["allowed_real_spend_micro_usd"]==0
         and origin["model_transport_status"]=="NOT_CONSTRUCTED",
         "FROZEN_SOURCE_NO_PROVIDER_AUTHORITY_REQUIRED")
    source=history["sources"]
    packets={}
    for arm in ARMS:
        start=source[arm]["requests"][0]
        origin_arm=origin["arms"][arm]
        need(set(start)=={"model","messages","tools","tool_choice","temperature"}
             and digest(start)==origin_arm["first_request_sha256"]
             and digest(start["messages"])==origin_arm["first_model_messages_sha256"]
             and digest(start["tools"])==origin_arm["first_native_tool_schemas_sha256"],
             "MODEL_START_SOURCE_HASH_DRIFT")
        need(start["model"]==MODEL
             and [m["role"] for m in start["messages"]]==["developer","user"]
             and type(start["temperature"]) is float
             and start["temperature"]==0.0
             and start["tool_choice"]=="auto"
             and "send_money" in [t["function"]["name"] for t in start["tools"]],
             "EXACT_NATIVE_FIRST_SOURCE_PROFILE_REQUIRED")
        need(start["messages"][1]["content"]==[
             {"type":"text","text":REQUEST}],
             "ORIGINAL_REQUEST_WAS_MUTATED")
        payload={
            "model": MODEL,
            "messages": copy.deepcopy(start["messages"]),
            "tools": copy.deepcopy(start["tools"]),
            "tool_choice":"auto",
            "temperature":0.0,
            "max_completion_tokens":MAX_OUTPUT_TOKENS,
            "n":1,
            "stream":False,
            "store":False,
        }
        need(len(canon(payload))<=MAX_REQUEST_BYTES,
             "MODEL_FIRST_REQUEST_EXCEEDS_BYTE_CEILING")
        # This is only the FIRST call. The first call has NOT YET
        # encountered a malicious tool result; a subsequent genuine
        # Provider-generated tool read is required for full exposure.
        packets[arm]={
            "logical_arm":arm,
            "case_id":CASE,
            "source_synthetic_only":True,
            "synthetic_source_sha256":origin_arm["synthetic_source_sha256"],
            "synthetic_source_nonce":origin_arm["synthetic_source_session_nonce"],
            "first_request_sha256":origin_arm["first_request_sha256"],
            "complete_first_request":payload,
            "complete_first_request_sha256":digest(payload),
            "complete_first_request_bytes":len(canon(payload)),
            "request_sent_to_provider":False,
            "provider_response_authenticity_proven":False,
            "provider_request_id":None,
            "provider_response_id":None,
            "actual_model_response_available":False,
            "model_tool_result_from_real_model":False,
            "same_bytes_allow_distinct_owner":True,
            "provider_use_authorized":False,
            "bank_effect_execution_authorized":False,
            "proposed_per_call_max_spend_micro_usd":PROPOSED_PER_CALL_MAX_MICRO_USD,
        }
    need(packets["A"]["first_request_sha256"]==
         packets["B"]["first_request_sha256"] and
         packets["A"]["complete_first_request_sha256"]==
         packets["B"]["complete_first_request_sha256"] and
         packets["A"]["synthetic_source_sha256"]!=
         packets["B"]["synthetic_source_sha256"] and
         packets["A"]["synthetic_source_nonce"]!=
         packets["B"]["synthetic_source_nonce"],
         "EXACT_SAME_FIRST_REQUEST_DIFFERENT_LOGICAL_OWNER_REQUIRED")
    return {
        "rule_of_one":RULE,
        "case_id":CASE,
        "entrypoint":"PREPARED_OFFLINE_ONLY_NOT_EXECUTABLE",
        "provider_api_operation":"POST /v1/chat/completions",
        "proposed_exact_model_snapshot":MODEL,
        "model_snapshot_currently_usable_by_ACCOUNT":"NOT_CHECKED",
        "source_observation":"TWO_SYNTHETIC_LOCAL_GENERATORS_NOT_LIVE_LLMS",
        "native_attack_payload_seen_by_first_model_call":False,
        "real_attack_exposure_requires_genuine_tool_read_after_model_response":True,
        "first_request_count_proposed":2,
        "approved_request_count":0,
        "model_max_output_tokens_per_request":MAX_OUTPUT_TOKENS,
        "proposed_total_cost_micro_usd":PROPOSED_TWO_CALL_MAX_MICRO_USD,
        "approved_cost_micro_usd":0,
        "max_cost_is_hard_provider_billing_cap":False,
        "fresh_human_approval_present":False,
        "operator_trust_root_enrolled":False,
        "durable_live_single_use_claim_performed":False,
        "actual_provider_calls":0,
        "actual_spend_micro_usd":0,
        "real_external_effects":0,
        "new_canonical_final128_scores":0,
        "new_v13_utility_recoveries":0,
        "independent_real_model_sources_proven":False,
        "packets":packets,
    }

def provider_dispatch_from_packet(_packet,*args,**kwargs):
    """An attempted model request by this module must ALWAYS be denied."""
    raise PacketDenied("FIRST_REQUEST_PACKET_HAS_NO_TRANSPORT_OR_SPEND_AUTHORITY")

#!/usr/bin/env python3
"""#306: prospective Task4 SDK *mock-transport* pre-dispatch preflight.

A real installed OpenAI Python SDK serializes the #303 issuer-frozen wire,
but httpx.MockTransport terminates it locally. Nothing reaches OpenAI.
No API credentials, live authorization, response authentication, actual
RCC/Bind or bank mutation. A locally fabricated completion is NOT a model reply.

This validates only an offline transport boundary; it cannot confer human
consent, enforce account billing limits, or attest host time.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
if str(ROOT/"scripts") not in sys.path:
    sys.path.insert(0,str(ROOT/"scripts"))

from task4_prospective_model_wire_date_boundary_v1 import (
    ProspectiveWireBoundary, BoundaryViolation, MODEL, REQUEST, canonical,
    date_session, local_stub_candidate, sha,
)
from task4_prospective_offline_completion_envelope_bridge_v1 import (
    FIXTURE_ID, FIXTURE_TOOL_ID, local_completion_fixture, exact_json,
)

RULE="TASK4_FUTURE_PROVIDER_SDK_PREDISPATCH_MOCK_V1"
SOURCE_MAIN="92291f6bce099637a8c4d44ef7e5669e88e46d69"
SDK_VERSION="1.109.1"
MOCK_ONLY_KEY="offline-test-key-never-real"
API_HOST="api.openai.com"
MAX_INPUT_TOKENS_FIXTURE=10_000
MAX_OUTPUT_TOKENS=256
# Historical #299 frozen estimation profile, NOT current rates or a billing cap.
ESTIMATE_INPUT_PER_MILLION=Decimal("0.40")
ESTIMATE_OUTPUT_PER_MILLION=Decimal("1.60")
# This is a local preflight threshold. No ability to spend exists.
LOCAL_ESTIMATE_THRESHOLD=Decimal("0.005")
EXPECTED_CONSUMED_TAG="95ff6be8c5875ed3827a00fe71fb54bd9de48130"

class PreDispatchRefused(ValueError):
    pass

def require(ok,code):
    if not ok:
        raise PreDispatchRefused(code)

def strict_estimated_cost(input_token_ceiling, output_token_ceiling):
    require(type(input_token_ceiling) is int and
            0 < input_token_ceiling <= MAX_INPUT_TOKENS_FIXTURE,
            "INPUT_TOKEN_CEILING_NOT_ADMITTED")
    require(type(output_token_ceiling) is int and
            output_token_ceiling == MAX_OUTPUT_TOKENS,
            "OUTPUT_TOKEN_CEILING_NOT_FROZEN")
    estimate=(
        Decimal(input_token_ceiling)*ESTIMATE_INPUT_PER_MILLION+
        Decimal(output_token_ceiling)*ESTIMATE_OUTPUT_PER_MILLION
    )/Decimal(1_000_000)
    require(estimate <= LOCAL_ESTIMATE_THRESHOLD,
            "HISTORICAL_RATE_ESTIMATE_OVER_OFFLINE_THRESHOLD")
    return estimate

def build_local_response(boundary):
    """Fake completion, generated only inside a local MockTransport."""
    response=local_completion_fixture(boundary)["response"]
    return deepcopy(response)

def verify_local_sdk_reply(completion, frozen_wire):
    """Never infer real Provider origin from an SDK-parsed JSON object."""
    require(type(completion.id) is str and completion.id==FIXTURE_ID and
            completion.model==MODEL and
            len(completion.choices)==1 and
            completion.choices[0].finish_reason=="tool_calls" and
            completion.choices[0].message.role=="assistant" and
            completion.choices[0].message.content is None and
            completion.choices[0].message.refusal is None,
            "LOCAL_ONLY_COMPLETION_SCHEMA_OR_SOURCE_CHANGED")
    usage=completion.usage
    require(usage is not None and
            usage.prompt_tokens==0 and
            usage.completion_tokens==0 and
            usage.total_tokens==0,
            "LOCAL_COMPLETION_CANNOT_IMPERSONATE_BILLABLE_USAGE")
    calls=completion.choices[0].message.tool_calls
    require(calls is not None and len(calls)==1 and
            calls[0].id==FIXTURE_TOOL_ID and
            calls[0].type=="function" and
            calls[0].function.name=="send_money",
            "LOCAL_ONLY_ONE_KNOWN_TOOL_CALL_REQUIRED")
    args=exact_json(calls[0].function.arguments)
    expected=local_stub_candidate(frozen_wire)
    require(type(args) is dict and args==expected["arguments"],
            "LOCAL_REPLY_CANDIDATE_MISMATCH")
    return {"kind":"tool_call","name":"send_money","arguments":args,
            "content":None,"metadata":{}}

@dataclass(frozen=True)
class OfflineOutcome:
    wire_sha256:str
    context_sha256:str
    parsed_candidate_sha256:str
    bind_facing_pairing_sha256:str
    sdk_local_intercepts:int
    estimated_local_budget:str
    request_id:str

class OfflineSDKPreflight:
    """One attempt; SDK always uses a non-networked MockTransport."""
    def __init__(self,*,clock=None):
        self.boundary=ProspectiveWireBoundary(date_session(clock))
        self.wire=self.boundary.issue_and_freeze()
        self.wire_bytes=canonical(self.wire)
        self.request_id="offline-sdk-306-"+sha({
            "wire_sha256":sha(self.wire),
            "context_digest":self.boundary.context.digest})[:28]
        self.attempted=False
        self.intercepts=0
        self.events=["ISSUER_CONTEXT_BEFORE_FROZEN_WIRE","OFFLINE_DISPATCH_DENY_BY_CONSTRUCTION"]
        self.captured_json=None
        self.response_fixture=None
        self.outcome=None

    def run_once(self,*,supplied_wire=None,input_token_ceiling=MAX_INPUT_TOKENS_FIXTURE,
                 estimated_threshold=LOCAL_ESTIMATE_THRESHOLD,
                 local_response_mutator=None):
        require(not self.attempted,"LOCAL_SDK_SINGLE_ATTEMPT_ALREADY_CONSUMED")
        self.attempted=True  # failure permanently consumes the local slot
        wire=deepcopy(self.wire if supplied_wire is None else supplied_wire)
        self.boundary._verify_wire(wire)
        require(canonical(wire)==self.wire_bytes and
                wire["model"]==MODEL and
                wire["max_completion_tokens"]==MAX_OUTPUT_TOKENS and
                wire["n"]==1 and wire["store"] is False and
                wire["stream"] is False and wire["tool_choice"]=="auto",
                "SDK_WIRE_EXACT_POLICY_DRIFT")
        estimate=strict_estimated_cost(input_token_ceiling,wire["max_completion_tokens"])
        require(type(estimated_threshold) is Decimal and
                estimated_threshold==LOCAL_ESTIMATE_THRESHOLD and
                estimate <= estimated_threshold,
                "BUDGET_APPROVAL_PROFILE_CANNOT_BE_OVERRIDDEN")
        require(not any(os.environ.get(k) for k in (
            "OPENAI_API_KEY","TASK4_OPENAI_API_KEY","ANTHROPIC_API_KEY",
            "VERITAS_DATABASE_URL","OPENAI_BASE_URL")),
            "REAL_CREDENTIAL_OR_CUSTOM_BASE_URL_PRESENT")
        import httpx
        import openai
        from importlib.metadata import version
        require(version("openai")==SDK_VERSION,"REAL_SDK_VERSION_NOT_PINNED")
        def intercept(request):
            self.intercepts+=1
            require(self.intercepts==1,"SDK_RETRY_OR_SECOND_POST_FORBIDDEN")
            require(request.method=="POST" and request.url.scheme=="https" and
                    request.url.host==API_HOST and
                    request.url.path=="/v1/chat/completions" and
                    not request.url.query,
                    "SDK_REQUEST_TARGET_DRIFT "+
                    "method="+repr(request.method)+
                    " scheme="+repr(request.url.scheme)+
                    " host="+repr(request.url.host)+
                    " path="+repr(request.url.path)+
                    " query_len="+str(len(request.url.query)))
            # Observe exactly the real SDK's serialized JSON body.
            data=exact_json(request.content.decode("utf8"))
            require(type(data) is dict and canonical(data)==self.wire_bytes,
                    "REAL_SDK_SERIALIZED_WIRE_DIFFERS_FROM_FROZEN_AUTHORIZED_WIRE")
            require(request.headers.get("authorization")=="Bearer "+MOCK_ONLY_KEY and
                    request.headers.get("content-type","").startswith("application/json"),
                    "SDK_LOCAL_DUMMY_CREDENTIAL_DRIFT")
            self.captured_json=data
            self.events.append("REAL_SDK_SERIALIZATION_CAPTURED_IN_LOCAL_MOCK_TRANSPORT")
            response=build_local_response(self.boundary)
            if local_response_mutator is not None:
                local_response_mutator(response)
            self.response_fixture=deepcopy(response)
            # Response belongs ONLY to this in-process fixture.
            return httpx.Response(200,json=response,request=request)

        # The SDK has no path to the real network: client transport is wholly
        # replaced by a local MockTransport. No user-supplied transport/client.
        transport=httpx.MockTransport(intercept)
        with httpx.Client(transport=transport,trust_env=False) as http_client:
            with openai.OpenAI(api_key=MOCK_ONLY_KEY,http_client=http_client,
                               max_retries=0,timeout=3.0) as client:
                completion=client.chat.completions.create(**wire)
        require(self.intercepts==1 and self.captured_json is not None,
                "ZERO_OR_MULTI_LOCAL_SDK_INTERCEPTS")
        candidate=verify_local_sdk_reply(completion,wire)
        self.boundary.capture_stub_response(
            supplied_wire=wire,proposed_candidate=candidate)
        pairing=self.boundary.verify_before_bind(
            supplied_wire=wire,candidate=deepcopy(candidate))
        self.events.append("LOCAL_REPLY_DATE_CANDIDATE_CHECKED_BEFORE_BIND")
        self.outcome=OfflineOutcome(
            wire_sha256=sha(wire),
            context_sha256=self.boundary.context.digest,
            parsed_candidate_sha256=sha(candidate),
            bind_facing_pairing_sha256=pairing,
            sdk_local_intercepts=self.intercepts,
            estimated_local_budget=str(estimate),
            request_id=self.request_id)
        return self.outcome

def audit():
    p=OfflineSDKPreflight()
    result=p.run_once()
    require(p.events==[
        "ISSUER_CONTEXT_BEFORE_FROZEN_WIRE",
        "OFFLINE_DISPATCH_DENY_BY_CONSTRUCTION",
        "REAL_SDK_SERIALIZATION_CAPTURED_IN_LOCAL_MOCK_TRANSPORT",
        "LOCAL_REPLY_DATE_CANDIDATE_CHECKED_BEFORE_BIND",
    ] and result.sdk_local_intercepts==1 and len(result.bind_facing_pairing_sha256)==64,
    "MODEL_SDK_MOCK_TRANSPORT_PREFLIGHT_EVIDENCE_INVALID")
    return {
      "rule_of_one":RULE,
      "determination":"REAL_SDK_SERIALIZATION_EXACTLY_MATCHED_OFFLINE_FROZEN_WIRE_WITHOUT_NETWORK",
      "parent_main_sha":SOURCE_MAIN,
      "sdk_package_version_exact":SDK_VERSION,
      "model_id_configuration_only":MODEL,
      "original_request":REQUEST,
      "issuer_context_before_sdk_request":True,
      "sdk_httpx_mock_transport_intercepts":result.sdk_local_intercepts,
      "real_provider_posts":0,"network_to_openai":False,
      "frozen_request_sha256":result.wire_sha256,
      "date_context_sha256":result.context_sha256,
      "local_stub_candidate_sha256":result.parsed_candidate_sha256,
      "bind_facing_date_pairing_sha256":result.bind_facing_pairing_sha256,
      "local_correlation_id":result.request_id,
      "single_mock_attempt_consumed":True,
      "max_completion_tokens":MAX_OUTPUT_TOKENS,
      "input_token_ceiling_hypothetical":MAX_INPUT_TOKENS_FIXTURE,
      "historical_rate_estimate_usd_not_current_quote":result.estimated_local_budget,
      "offline_estimate_threshold_usd_not_billing_cap":str(LOCAL_ESTIMATE_THRESHOLD),
      "prior_third_provider_approval_reusable":False,
      "additional_human_approval_issued":False,
      "new_provider_authorization_or_durable_consumption":False,
      "sdk_model_reply_is_locally_fabricated_not_authenticated":True,
      "actual_native_veritas_bind_adjudications":0,
      "native_bank_dispatches":0,
      "real_bank_effects":0,
      "official_agentdojo_scoring":0,"final128_calls":0,
      "real_model_utility_proven":False,
      "production_authority_proven":False,
      "events":p.events,
      "limits":"This proof constructs an SDK request and intercepts it with httpx.MockTransport, entirely in-process. Local SDK mock invocation is NOT a network Provider POST, budget cap, human approval, signed Provider receipt, real-model inference, actual Bind authorization, or financial effect. Cost uses historical frozen hypothetical rates only.",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    report=audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("TASK4_REAL_OPENAI_SDK_MOCK_TRANSPORT_EXACT_WIRE_PREFLIGHT_PASS_ZERO_PROVIDER_CALLS")

if __name__=="__main__":
    main()

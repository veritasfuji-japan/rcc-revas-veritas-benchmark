#!/usr/bin/env python3
"""#455 actual Native -> OpenAI SDK wire seam, with NO possible Provider transport.

This is a research SENDER STAGING implementation, not a live Sender.
It constructs genuine native request messages via the original frozen Task4
trajectory, serializes with the actual OpenAI SDK, then unconditionally denies
the first outbound request at httpx.BaseTransport. There is NO delegation
to any network transport, no secret reads, no live switch, no retries and
no fabricated Provider response / native terminal / Utility score.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

RULE = "TASK4_455_NATIVE_SDK_RESEARCH_SENDER_WIRE_HARD_NO_GO_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
PRESTATE = "8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
ATTACK = "0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
ROOT = Path(__file__).resolve().parents[1]
ARMS = ("A", "B")
MAX_ATTEMPTS_PER_ARM = 5
MAX_BODY_BYTES = 10_000
MAX_LOCAL_BPE = 10_000  # Not a Provider-billed-token bound.
MAX_COMPLETION_TOKENS = 256
REAL_PROVIDER_DISPATCH = "DENY"
# There is deliberately NO real/send flag, provider key, approval or network
# transport path in this module. Do not convert this to ALLOW via configuration.
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_455_LIVE_APPROVAL",
)
ALLOWED_JSON = frozenset((
    "model", "messages", "tools", "tool_choice", "temperature",
    "max_completion_tokens",
))
DATE_PREFIX = "Task4 trusted runtime metadata: UTC execution date "
# Legacy native date exists ONLY inside the pinned offline AgentDojo fixture.
OFFLINE_DATE = "2031-07-08"
LOWER_SHA = re.compile(r"[0-9a-f]{64}\Z")


class Refused(RuntimeError):
    """No data-bearing exception string or secret value may reach CI logs."""


def require(ok: bool, reason: str):
    if not ok:
        raise Refused(reason)


def deny_real_context():
    require(not any(os.environ.get(k) for k in SENSITIVE),
            "455_PROVIDER_SECRET_OR_LIVE_CONTEXT_DENIED")


def unique_json(pairs):
    row = {}
    for key, value in pairs:
        require(key not in row, "455_DUPLICATE_JSON_FIELDS")
        row[key] = value
    return row


def inspect_sdk_request(request: Any) -> dict:
    """Inspect actual SDK-produced bytes, never authorizing transmission."""
    from task4_trusted_execution_date_profile_v1 import REQUEST
    from scripts import task4_325_exact_sdk_wire_offline_v1 as prior

    require(request.method == "POST" and
            request.url.scheme == "https" and
            request.url.host == "api.openai.com" and
            request.url.path == "/v1/chat/completions" and
            not request.url.query, "455_EXACT_SDK_ENDPOINT_REQUIRED")
    body = request.content
    require(type(body) is bytes and 0 < len(body) <= MAX_BODY_BYTES,
            "455_FULL_SDK_BODY_BYTE_LIMIT")
    try:
        payload = json.loads(body.decode("utf-8", "strict"),
                             object_pairs_hook=unique_json)
    except (ValueError, UnicodeError) as exc:
        raise Refused("455_CANONICAL_UTF8_JSON_REQUIRED") from exc
    require(type(payload) is dict and set(payload) == ALLOWED_JSON and
            payload["model"] == MODEL and
            type(payload["max_completion_tokens"]) is int and
            payload["max_completion_tokens"] == MAX_COMPLETION_TOKENS and
            type(payload["temperature"]) in (int, float) and
            payload["temperature"] == 0 and
            payload["tool_choice"] == "auto",
            "455_MODEL_WIRE_PROFILE_AND_COMPLETION_CAP_REQUIRED")
    messages = payload["messages"]
    tools = payload["tools"]
    require(type(messages) is list and len(messages) == 2 and
            type(tools) is list and len(tools) >= 5,
            "455_ONLY_INITIAL_OWNED_NATIVE_REQUEST")
    require(messages[0] == {
                "role": "developer",
                "content": [{"type": "text",
                             "text": DATE_PREFIX + OFFLINE_DATE + "."}]
            } and
            messages[1] == {"role": "user", "content": [{
                "type": "text", "text": REQUEST
            }]},
            "455_EXACT_FROZEN_TRUSTED_ORIGINAL_REQUEST_REQUIRED")
    require(any(type(tool) is dict and
                type(tool.get("function")) is dict and
                tool["function"].get("name") == "send_money"
                for tool in tools),
            "455_NATIVE_SEND_MONEY_SCHEMA_REQUIRED")
    # Existing #326 pinned BPE mapping; this remains a LOCAL estimate and a
    # request-size policy, NOT Provider billing attestation.
    from scripts.task4_326_offline_bpe_wire_gate_v1 import tiktoken_encoder
    encoding = tiktoken_encoder()
    local_tokens = len(encoding.encode(body.decode("utf8"),
                                       disallowed_special=()))
    require(0 < local_tokens <= MAX_LOCAL_BPE,
            "455_LOCAL_BPE_PROFILE_EXCEEDED")
    return {
        "sdk_body_sha256": hashlib.sha256(body).hexdigest(),
        "sdk_body_bytes": len(body),
        "local_bpe_not_provider_usage": local_tokens,
        "model": MODEL,
        "case_id": CASE,
        "pinned_native_prestate_sha256": PRESTATE,
        "pinned_native_lower_trust_attack_sha256": ATTACK,
        "output_tokens_max_per_call": MAX_COMPLETION_TOKENS,
        "first_own_date": OFFLINE_DATE,
        "date_trust": "OFFLINE_FIXTURE_NOT_REAL_ISSUER",
        "source_class": "REAL_SDK_WIRE_NO_REAL_MODEL",
        "actual_provider_posts": 0,
        "provider_post_allowed": False,
    }


class RejectingResearchWire:
    """SDK-compatible httpx transport: it CANNOT forward a request anywhere."""

    def __init__(self, arm: str):
        require(arm in ARMS, "455_EXACT_ARM_REQUIRED")
        self.arm = arm
        self.calls = 0
        self.sealed = False
        self.last: dict | None = None

    def __enter__(self):
        return self

    def __exit__(self, *_unused):
        self.close()

    def close(self):
        # No underlying socket or transport to close.
        pass

    def handle_request(self, request):
        # No network constructor, .send(), proxy, request factory or fallback.
        require(not self.sealed and self.calls == 0,
                "455_SINGLE_REFUSAL_NO_REPEAT_OR_RETRY")
        self.sealed = True
        self.calls += 1
        try:
            self.last = inspect_sdk_request(request)
        finally:
            # Even an invalid/oversized request permanently freezes the arm.
            self.sealed = True
        raise Refused("455_HARD_NO_GO_EXTERNAL_PROVIDER_TRANSPORT_ABSENT")


def stage_native_first_request(arm: str) -> dict:
    """Execute actual pinned Native setup to first SDK wire and stop at egress.

    The result is a read-only report of attempted *local* request preparation.
    It intentionally does not simulate a real Provider response or run a scorer.
    """
    deny_real_context()
    require(arm in ARMS, "455_EXACT_ARM_REQUIRED")
    import httpx
    import openai
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import (
        load_rcc_gate, sha_json, verify_authority_fixture)
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_319_injected_scripted_wire_native_terminal_audit_v1 import injected_environment
    from task4_trusted_execution_date_profile_v1 import Task4DateProfileSession
    from task4_trusted_execution_date_runner_integration_v1 import Task4ControlledDateRunner
    from task4_frozen_provider_transport_date_context_binding_v1 import Task4FrozenTransportElement
    from task4_323_single_arm_trajectory_v1 import Task4OneArmProspectiveTrajectory

    # Read-only assertion; no paid Provider permission can be inferred.
    base.reject_live_context()
    suite = get_suite("v1.2.2", "banking")
    env, pre = injected_environment(suite)
    require(sha_json(pre) == PRESTATE, "455_FROZEN_INJECTED_NATIVE_PRESTATE_REQUIRED")
    original = sha_json(env.model_dump(mode="json"))
    session = Task4DateProfileSession(
        source_id="task4-455-offline-fixture-only-" + arm,
        signing_key=os.urandom(32),
        clock=lambda: datetime(2031, 7, 8, 12, tzinfo=timezone.utc))
    runner = Task4ControlledDateRunner(
        environment_type=suite.environment_type, tools=suite.tools,
        rcc_gate=load_rcc_gate(Path(os.environ["TASK4_RCC_ROOT"])),
        date_session=session, authority_admitted=verify_authority_fixture())
    gateway = RejectingResearchWire(arm)
    with httpx.Client(transport=gateway, trust_env=False) as http_client:
        # Static test-local sentinel: never read or reuse an actual Project key.
        with openai.OpenAI(api_key=base.LOCAL_KEY, base_url="https://api.openai.com/v1",
                           http_client=http_client, max_retries=0, timeout=3.0) as sdk:
            generator = Task4FrozenTransportElement(client=cap.CapOnlyOfflineSDKProxy(sdk))
            trajectory = Task4OneArmProspectiveTrajectory(
                controlled_runner=runner, generation_element=generator)
            try:
                trajectory.run(case_id=base.SOURCE_CASE + ":dev-stage-455",
                               proposal_ordinal=0, trusted_env=env,
                               selected_arm=arm)
            except Exception as exc:
                # The SDK wraps transport exceptions. Refuse all outcomes unless
                # exactly one strict SDK request was observed and denied.
                if not (gateway.sealed and gateway.calls == 1 and
                        gateway.last is not None):
                    raise Refused("455_UNEXPECTED_NATIVE_OR_SDK_FAILURE") from exc
            else:
                raise Refused("455_NATIVE_MUST_NEVER_REACH_A_MODEL_RESPONSE")
    require(sha_json(env.model_dump(mode="json")) == original and
            gateway.last is not None and gateway.calls == 1,
            "455_PRESTATE_OR_ONE_REFUSAL_INTEGRITY_FAILURE")
    return {
        "rule_of_one": RULE,
        "arm": arm,
        "actual_native_frozen_request_prepared": True,
        "source_native_prestate_sha256": original,
        "native_source_prestate_frozen": True,
        "sdk_request": gateway.last,
        "first_model_query_attempts": gateway.calls,
        "provider_calls": 0,
        "genuine_model_completions": 0,
        "native_tool_effects": 0,
        "native_terminal_responses": 0,
        "native_scorer_calls": 0,
        "new_authentic_utility_recoveries": 0,
        "real_issuer_date_attested": False,
        "real_provider_send_enabled": False,
        "status": "REAL_NATIVE_FIRST_SDK_REQUEST_CONSTRUCTED_PROVIDER_HARD_DENIED",
    }


def stage_paired_native_ab() -> dict:
    """Two independent SDK first-request sources; both hard-denied."""
    deny_real_context()
    arms = [stage_native_first_request(a) for a in ARMS]
    require([x["arm"] for x in arms] == list(ARMS) and
            all(x["provider_calls"] == 0 for x in arms) and
            arms[0]["sdk_request"]["sdk_body_sha256"] ==
            arms[1]["sdk_request"]["sdk_body_sha256"] and
            arms[0]["source_native_prestate_sha256"] ==
            arms[1]["source_native_prestate_sha256"],
            "455_A_B_FROZEN_SOURCE_OR_EGRESS_DENIAL_MISMATCH")
    return {
        "rule_of_one": RULE,
        "case_id": CASE,
        "research_environment_not_accessed": "task4-provider-protected",
        "model": MODEL,
        "arms": arms,
        "actual_provider_calls": 0,
        "new_true_model_utility_recoveries": 0,
        "fresh_paid_permission": False,
        "future_credential_isolation": "NOT_PROVEN",
        "future_cross_runner_one_use": "NOT_IMPLEMENTED",
        "new_live_provider_dispatch": "DENY",
        "status": "OFFLINE_NATIVE_SDK_PREWIRE_READY_LIVE_UNAUTHORIZED",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["offline-native-prewire"], required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    deny_real_context()
    path = (ROOT / args.output).resolve()
    require(path.is_relative_to(ROOT) and not path.exists(),
            "455_EXCLUSIVE_OUTPUT_WITHIN_REPOSITORY_ONLY")
    report = stage_paired_native_ab()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print("TASK4_455_NATIVE_FIRST_OPENAI_SDK_WIRE_BOTH_ARMS_HARD_NO_GO")


if __name__ == "__main__":
    main()

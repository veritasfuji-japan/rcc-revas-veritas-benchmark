#!/usr/bin/env python3
"""#304: strictly offline prospective Task4 response-envelope-to-candidate bridge.

Consumes only a conspicuously synthetic, local, never-networked completion-like
fixture. Reuses #303 issuer-owned date-before-wire, its immutable wire hash,
its single candidate capture, and its Bind-facing integrity recheck.

This is NOT a Provider adapter, Provider authentication, native Bind adjudication,
bank effect, production execution authority, official score, or new API consent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from task4_prospective_model_wire_date_boundary_v1 import (
    ATTACKER, BoundaryViolation, CASE, MODEL, ProspectiveWireBoundary,
    RECIPIENT, STANDIN_ID, SUBJECT, canonical, date_session,
    local_stub_candidate, require, sha,
)

RULE = "TASK4_PROSPECTIVE_LOCAL_COMPLETION_ENVELOPE_TO_CAPTURE_V1"
SOURCE = "OFFLINE_SYNTHETIC_COMPLETION_NOT_PROVIDER"
FIXTURE_ID = "offline-only-response-304-never-provider"
FIXTURE_TOOL_ID = "offline-only-tool-304"
MAX_LOCAL_ENVELOPE_BYTES = 16_384


def wire_hash(boundary):
    require(type(boundary) is ProspectiveWireBoundary and
            boundary.wire_bytes is not None, "ISSUER_FROZEN_WIRE_REQUIRED")
    return hashlib.sha256(boundary.wire_bytes).hexdigest()


def client_correlation(boundary):
    """Session-scoped local correlation, NOT a cryptographic Provider attestation."""
    require(type(boundary) is ProspectiveWireBoundary and
            boundary.context is not None, "ISSUED_SESSION_CONTEXT_REQUIRED")
    context_scoped = sha({
        "wire_sha256": wire_hash(boundary),
        "issuer_context_digest": boundary.context.digest,
    })
    return "offline-304-" + context_scoped[:24]


def exact_json(raw):
    """Strict JSON for a single tool argument object; reject duplicate keys."""
    require(type(raw) is str and 0 < len(raw.encode("utf8")) <= 4096,
            "TOOL_ARGUMENT_BYTES_BOUNDARY")
    def reject_duplicate(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "DUPLICATE_TOOL_ARGUMENT_KEY")
            out[key] = value
        return out
    def reject_constant(value):
        raise BoundaryViolation("NONFINITE_JSON_CONSTANT")
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate,
                          parse_constant=reject_constant)
    except (ValueError, TypeError, UnicodeError) as exc:
        if isinstance(exc, BoundaryViolation):
            raise
        raise BoundaryViolation("MALFORMED_TOOL_ARGUMENTS") from exc


def local_completion_fixture(boundary):
    """Explicitly fabricated locally; no network, real IDs, or billed tokens."""
    require(boundary.phase == "FROZEN_NOT_DISPATCHABLE",
            "ISSUER_FROZEN_WIRE_REQUIRED")
    wire = json.loads(boundary.wire_bytes)
    candidate = local_stub_candidate(wire)
    response = {
        "id": FIXTURE_ID,
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{
            "index": 0, "finish_reason": "tool_calls",
            "message": {
                "role": "assistant", "content": None, "refusal": None,
                "tool_calls": [{
                    "id": FIXTURE_TOOL_ID, "type": "function",
                    "function": {
                        "name": "send_money",
                        "arguments": canonical(candidate["arguments"]).decode("utf8"),
                    },
                }],
            },
        }],
        "usage": {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        },
    }
    return {
        "source": SOURCE,
        "local_wire_sha256": wire_hash(boundary),
        "local_client_correlation": client_correlation(boundary),
        "response": response,
    }


class OfflineCompletionBridge:
    def __init__(self, boundary):
        require(type(boundary) is ProspectiveWireBoundary and
                boundary.phase == "FROZEN_NOT_DISPATCHABLE",
                "FROZEN_ISSUER_WIRE_REQUIRED")
        self.boundary = boundary
        self.attempted = False
        self.events = []
        self.proposed_candidate = None
        self.response_sha256 = None
        self.pairing_identity = None

    def receive_once(self, *, supplied_wire, local_packet):
        """Consume slot on entry, including all rejects. No retry or repair."""
        require(not self.attempted, "SINGLE_OFFLINE_COMPLETION_ATTEMPT_ONLY")
        self.attempted = True
        self.events.append("OFFLINE_LOCAL_COMPLETION_ATTEMPT_CONSUMED")
        b = self.boundary
        b._verify_wire(supplied_wire)
        require(type(local_packet) is dict and
                set(local_packet) == {
                    "source", "local_wire_sha256",
                    "local_client_correlation", "response"},
                "EXACT_LOCAL_ENVELOPE_SHAPE_REQUIRED")
        require(local_packet["source"] == SOURCE and
                local_packet["local_wire_sha256"] == wire_hash(b) and
                local_packet["local_client_correlation"] == client_correlation(b),
                "UNAUTHENTICATED_OR_CROSS_WIRE_LOCAL_STUB")
        require(len(canonical(local_packet)) <= MAX_LOCAL_ENVELOPE_BYTES,
                "LOCAL_RESPONSE_ENVELOPE_TOO_LARGE")
        response = local_packet["response"]
        require(type(response) is dict and
                set(response) == {"id", "object", "model", "choices", "usage"} and
                response["id"] == FIXTURE_ID and
                response["object"] == "chat.completion" and
                response["model"] == MODEL,
                "LOCAL_ONLY_RESPONSE_SCHEMA_OR_ORIGIN_DRIFT")
        usage = response["usage"]
        require(type(usage) is dict and
                usage == {"prompt_tokens": 0, "completion_tokens": 0,
                          "total_tokens": 0},
                "SIMULATED_USAGE_MUST_NOT_IMPERSONATE_PAID_PROVIDER_USAGE")
        choices = response["choices"]
        require(type(choices) is list and len(choices) == 1 and
                type(choices[0]) is dict and
                set(choices[0]) == {"index", "finish_reason", "message"} and
                type(choices[0]["index"]) is int and
                choices[0]["index"] == 0 and
                choices[0]["finish_reason"] == "tool_calls",
                "EXACT_ONE_TOOL_CHOICE_REQUIRED")
        message = choices[0]["message"]
        require(type(message) is dict and
                set(message) == {"role", "content", "refusal", "tool_calls"} and
                message["role"] == "assistant" and
                message["content"] is None and message["refusal"] is None,
                "NO_TEXT_REFUSAL_OR_EXTRA_ASSISTANT_OUTPUT")
        calls = message["tool_calls"]
        require(type(calls) is list and len(calls) == 1 and
                type(calls[0]) is dict and
                set(calls[0]) == {"id", "type", "function"} and
                calls[0]["id"] == FIXTURE_TOOL_ID and
                calls[0]["type"] == "function",
                "EXACT_ONE_OFFLINE_TOOL_CALL_REQUIRED")
        fn = calls[0]["function"]
        require(type(fn) is dict and set(fn) == {"name", "arguments"} and
                fn["name"] == "send_money", "UNEXPECTED_PROTECTED_TOOL_FUNCTION")
        args = exact_json(fn["arguments"])
        require(type(args) is dict and
                set(args) == {"recipient", "amount", "subject", "date"} and
                type(args["recipient"]) is str and
                type(args["amount"]) in (int, float) and
                type(args["subject"]) is str and
                type(args["date"]) is str,
                "STRICT_TYPED_SEND_MONEY_ARGUMENTS_REQUIRED")
        # Minimal envelope adapter policy: protected amount/recipient/date are
        # additionally rechecked by the unmodified issuer-owned #303 profile.
        self.proposed_candidate = {
            "kind": "tool_call", "name": "send_money",
            "arguments": args, "content": None, "metadata": {},
        }
        self.response_sha256 = sha(response)
        b.capture_stub_response(
            supplied_wire=supplied_wire,
            proposed_candidate=self.proposed_candidate,
            local_stub_id=STANDIN_ID)
        self.events.append("ONE_LOCAL_UNTRUSTED_TOOL_PROPOSAL_CAPTURED")
        return b.frozen_digest

    def verify_before_bind(self, *, supplied_wire, candidate=None, prestate=None):
        """No native Bind or bank dispatch. Only #303 Bind-facing preflight."""
        require(self.attempted and self.boundary.phase == "CANDIDATE_CAPTURED",
                "UNTRUSTED_LOCAL_CANDIDATE_NOT_CAPTURED")
        proposed = self.proposed_candidate if candidate is None else candidate
        pair = self.boundary.verify_before_bind(
            supplied_wire=supplied_wire, candidate=proposed, prestate=prestate)
        self.pairing_identity = pair
        self.events.append("BIND_FACING_DATE_WIRE_AND_CANDIDATE_RECHECK_PASSED")
        return pair


def audit():
    require(not any(os.getenv(k) for k in (
        "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY", "VERITAS_DATABASE_URL")),
        "NO_PROVIDER_OR_DATABASE_SECRET_IN_OFFLINE_AUDIT")
    boundary = ProspectiveWireBoundary(date_session())
    wire = boundary.issue_and_freeze()
    bridge = OfflineCompletionBridge(boundary)
    packet = local_completion_fixture(boundary)
    frozen = bridge.receive_once(supplied_wire=wire, local_packet=packet)
    pair = bridge.verify_before_bind(supplied_wire=wire)
    require(bridge.events == [
        "OFFLINE_LOCAL_COMPLETION_ATTEMPT_CONSUMED",
        "ONE_LOCAL_UNTRUSTED_TOOL_PROPOSAL_CAPTURED",
        "BIND_FACING_DATE_WIRE_AND_CANDIDATE_RECHECK_PASSED",
    ] and bridge.proposed_candidate["arguments"]["recipient"] == RECIPIENT and
       bridge.proposed_candidate["arguments"]["date"] ==
       boundary.context.payload()["execution_date"] and
       len(pair) == 64 and frozen == sha(bridge.proposed_candidate),
       "PROSPECTIVE_OFFLINE_STUB_CORRELATION_OR_BIND_FACING_DRIFT")
    return {
        "rule_of_one": RULE,
        "determination": "LOCAL_COMPLETION_ENVELOPE_CORRELATED_AND_CAPTURED_BEFORE_BIND_ONLY",
        "parent_merge": "ad930d2344322d4e8a067ec170ad75c6f6c5b0dc",
        "date_issued_before_model_wire": True,
        "frozen_wire_sha256": wire_hash(boundary),
        "client_correlation_local_only": client_correlation(boundary),
        "stub_response_sha256": bridge.response_sha256,
        "captured_candidate_sha256": frozen,
        "candidate_pairing_identity_sha256": pair,
        "one_local_completion_attempt": True,
        "synthetic_local_fixture_not_real_model": True,
        "response_identity_not_authenticated_by_provider": True,
        "historical_third_responses_reused": False,
        "human_api_consent_reused": False,
        "actual_provider_posts": 0,
        "actual_native_bind_adjudications": 0,
        "native_bank_dispatches": 0,
        "external_bank_effects": 0,
        "official_agentdojo_scores": 0,
        "new_canonical_final128_scores": 0,
        "production_authority_proven": False,
        "events": bridge.events,
        "limitations": "Only a synthetic, local Chat Completions-like response envelope. The frozen wire is NEVER transmitted; no real Provider invocation, actual Bind adjudication, authenticated server response, production date source or bank effect.",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("TASK4_LOCAL_COMPLETION_ENVELOPE_CAPTURE_OFFLINE_SUCCESS_NO_PROVIDER")


if __name__ == "__main__":
    main()

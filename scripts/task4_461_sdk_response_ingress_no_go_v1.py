#!/usr/bin/env python3
"""Source-neutral Task4 SDK request/response ingress contract, with NO sender.

The caller owns and supplies the original httpx Request and already-obtained
Response; this module MUST NOT create either or contact the Provider. A receipt
from a separate consumer must precede response observation; an archival
callback must attest local sealing of the same raw bytes before any response
JSON is parsed. Ingress observations never attest Provider origin/Utility.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

CASE = "banking:user_task_4:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
RULE = "TASK4_461_OPAQUE_SDK_RESPONSE_INGRESS_NO_PROVIDER_V1"
MAX_PER_ARM = 5
MAX_REQUEST_BYTES = 10000
MAX_RESPONSE_BYTES = 2_000_000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ENDPOINT = "https://api.openai.com/v1/chat/completions"


class IngressRefused(RuntimeError):
    """Only fixed reason codes; do not surface untrusted response data."""


def require(value, reason):
    if value is not True:
        raise IngressRefused(reason)


def sha(blob):
    return sha256(blob).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "461_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def strict_json(data):
    require(type(data) is bytes and len(data) > 0, "461_NONEMPTY_JSON_BYTES_REQUIRED")
    try:
        return json.loads(data.decode("utf-8", "strict"),
                          object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              IngressRefused("461_NONFINITE_JSON_DENIED")))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise IngressRefused("461_MALFORMED_JSON_DENIED") from exc


class SDKResponseIngress:
    """One trial/arm state machine; no network, secrets, response generation or key handling.

    `claim` and `seal` are separately supplied functions. An actual sender
    requires its OWN reviewed code, owner consent, IAM and provider evidence.
    This class intentionally returns an UNSCORED local ingress observation.
    """

    def __init__(self, *, arm, trial_id):
        require(arm in ("A", "B"), "461_ARM_REQUIRED")
        require(type(trial_id) is str and bool(HEX64.fullmatch(trial_id)),
                "461_FROZEN_TRIAL_SHA_REQUIRED")
        self.arm = arm
        self.trial_id = trial_id
        self.attempts = 0
        self.pending = None
        self.poisoned = False
        self.initial_two = None
        self.previous_messages = None
        self.response_ids = set()
        self.receipts = []

    def _outbound_shape(self, request, ordinal):
        require(request.method == "POST" and str(request.url) == ENDPOINT,
                "461_ONLY_EXACT_CHAT_COMPLETIONS_ENDPOINT")
        raw = request.content
        require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST_BYTES,
                "461_BOUNDED_ORIGINAL_WIRE_REQUEST")
        payload = strict_json(raw)
        require(type(payload) is dict and
                payload.get("model") == MODEL and
                type(payload.get("messages")) is list and
                type(payload.get("tools")) is list and
                len(payload["tools"]) > 0 and
                type(payload.get("max_completion_tokens")) is int and
                payload["max_completion_tokens"] == 256 and
                payload.get("tool_choice") == "auto" and
                type(payload.get("temperature")) in (int, float) and
                payload["temperature"] == 0,
                "461_SDK_WIRE_MODEL_BUDGET_OR_TOOLS_DRIFT")
        msgs = payload["messages"]
        require(len(msgs) >= 2 and type(msgs[0]) is dict and
                type(msgs[1]) is dict and
                msgs[0].get("role") == "developer" and
                msgs[1].get("role") == "user" and
                type(msgs[0].get("content")) is list and
                type(msgs[1].get("content")) is list,
                "461_NATIVE_OWNED_FIRST_TWO_MESSAGES_REQUIRED")
        if ordinal == 0:
            require(len(msgs) == 2, "461_INITIAL_QUERY_MUST_BE_FIRST")
            self.initial_two = json.dumps(msgs[:2], sort_keys=True)
        else:
            require(self.initial_two == json.dumps(msgs[:2], sort_keys=True) and
                    self.previous_messages is not None and
                    len(msgs) > len(self.previous_messages) and
                    msgs[:len(self.previous_messages)] == self.previous_messages,
                    "461_CANNOT_REWRITE_PREVIOUS_NATIVE_HISTORY")
        return raw, msgs

    def before_response(self, *, ordinal, request, claim):
        """Consume attempt before ANY response is produced/observed; failure is final."""
        require(not self.poisoned and self.pending is None,
                "461_PENDING_OR_POISONED_SESSION_DENY")
        if not (type(ordinal) is int and ordinal == self.attempts and
                0 <= ordinal < MAX_PER_ARM):
            self.poisoned = True
            raise IngressRefused("461_STRICT_FIVE_ATTEMPT_SEQUENCE")
        self.attempts += 1  # irreversible even if claim or inspection fails
        self.poisoned = True
        raw, messages = self._outbound_shape(request, ordinal)
        require(callable(claim), "461_LOCAL_CONSUMER_REQUIRED")
        # No source of permission comes from the model or the HTTP response.
        outcome = claim(trial=self.trial_id, arm=self.arm,
                        ordinal=ordinal, request_sha=sha(raw))
        require(type(outcome) is dict and
                outcome.get("decision") == "LOCAL_CONSUMED_NO_SEND" and
                outcome.get("live_post") is False and
                type(outcome.get("receipt_sha")) is str and
                bool(HEX64.fullmatch(outcome["receipt_sha"])),
                "461_ONLY_LOCAL_CONSUME_RECEIPT_NO_SEND")
        self.pending = {"ordinal": ordinal, "request": request,
                        "request_sha": sha(raw), "receipt_sha": outcome["receipt_sha"],
                        "messages": messages}
        self.poisoned = False
        return {"arm": self.arm, "ordinal": ordinal,
                "request_sha256": sha(raw), "local_consumed": True,
                "provider_send_permission": False}

    def after_response(self, *, response, seal):
        """Seal raw bytes BEFORE validating/parsing the untrusted response."""
        require(not self.poisoned and self.pending is not None,
                "461_NO_AUTHORIZED_PENDING_SOURCE")
        p = self.pending
        self.pending = None
        self.poisoned = True  # sealed after success only; any error blocks replay
        require(response.request is p["request"], "461_REQUEST_RESPONSE_OBJECT_IDENTITY")
        raw = response.content
        require(type(raw) is bytes and 0 <= len(raw) <= MAX_RESPONSE_BYTES,
                "461_RAW_RESPONSE_TOO_LARGE")
        require(callable(seal), "461_SEAL_CALLBACK_REQUIRED")
        digest = sha(raw)
        sealed = seal(trial=self.trial_id, arm=self.arm, ordinal=p["ordinal"],
                      request=p["request"], response=response,
                      receipt_sha=p["receipt_sha"])
        # Callback may come from a future reviewed external archive. Its fields
        # remain claims only, not verified Provider or custody attestation.
        require(type(sealed) is dict and sealed.get("request_sha256") == p["request_sha"]
                and sealed.get("response_sha256") == digest and
                sealed.get("arm") == self.arm and
                sealed.get("ordinal") == p["ordinal"] and
                sealed.get("local_fsync_completed") is True and
                sealed.get("external_provider_authenticated") is False,
                "461_PREPARSE_ORIGIN_PRESERVING_SEAL_REQUIRED")
        require(sha(response.content) == digest,
                "461_SEAL_MUTATED_SDK_RESPONSE")
        require(response.status_code == 200,
                "461_NON_200_SEALED_BUT_UNSCORABLE")
        body = strict_json(raw)
        require(type(body) is dict and body.get("object") == "chat.completion" and
                body.get("model") == MODEL and
                type(body.get("id")) is str and len(body["id"]) > 0 and
                body["id"] not in self.response_ids and
                type(body.get("choices")) is list and len(body["choices"]) == 1,
                "461_RESPONSE_IS_NOT_ONE_MODEL_SHAPED_CHOICE")
        choice = body["choices"][0]
        require(type(choice) is dict and choice.get("index") == 0 and
                type(choice.get("message")) is dict and
                choice["message"].get("role") == "assistant" and
                choice.get("finish_reason") in ("tool_calls", "stop"),
                "461_ASSISTANT_CHOICE_OR_FINISH_REASON_INVALID")
        self.response_ids.add(body["id"])
        self.previous_messages = p["messages"]
        self.receipts.append({"arm": self.arm, "ordinal": p["ordinal"],
                              "request_sha256": p["request_sha"],
                              "response_sha256": digest,
                              "local_receipt_sha256": p["receipt_sha"],
                              "response_bytes": len(raw),
                              "provenance": "UNVERIFIED_RESPONSE_SUPPLIED_BY_CALLER"})
        self.poisoned = False
        return response  # The SDK parser receives the identical Response object.

    def unknown(self):
        """Any timeout, process uncertainty or failure burns this entire arm."""
        self.pending = None
        self.poisoned = True

    def report(self):
        require(self.pending is None, "461_PENDING_RESPONSE_UNSCORED")
        return {"rule_of_one": RULE, "case_id": CASE, "arm": self.arm,
                "request_attempts_reserved": self.attempts,
                "response_receipts": list(self.receipts),
                "real_provider_posts_proven": False,
                "provider_authenticated": False,
                "remote_custody_proven": False,
                "genuine_model_utility": None,
                "score_status": "UNSCORED",
                "real_provider_dispatch": "DENY",
                "poisoned": self.poisoned}

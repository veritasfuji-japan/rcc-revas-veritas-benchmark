#!/usr/bin/env python3
"""Task4 #456: preserve the ACTUAL SDK-visible raw local response bytes through
one full pinned Native A/B arm and scorer, without Provider POST or raw CI leak.

This is a capture-seam integration proof using the original #323 scripted
httpx.MockTransport. It neither accepts external 'genuine' response files nor
produces new genuine Utility evidence. No sender, production API key, or
general network transport is constructed here.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_456_RAW_SDK_HTTP_RESPONSE_TO_ORIGINAL_NATIVE_SCORER_LINEAGE_OFFLINE_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
ARMS = ("A", "B")
MAX_PER_ARM = 4
MAX_BYTES = 64_000
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL",
    "TASK4_456_LIVE_APPROVAL",
)


class Refused(ValueError):
    pass


def require(valid, reason):
    if valid is not True:
        raise Refused(reason)


def digest(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def unique_pairs(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "456_DUPLICATE_JSON_FIELD_DENY")
        out[k] = v
    return out


def exact_json(raw: bytes):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES,
            "456_RESPONSE_BYTES_BOUNDED")
    try:
        return json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              Refused("456_NONFINITE_JSON_DENY")))
    except (UnicodeError, ValueError) as exc:
        raise Refused("456_RAW_RESPONSE_JSON_INVALID") from exc


def deny_live_environment():
    require(not any(os.environ.get(name) for name in SENSITIVE),
            "456_LIVE_SECRET_OR_PROVIDER_ENV_DENIED")


class RawResponseJournal:
    """Volatile, source-bound, immutable-by-contract HTTP response recorder.

    May ONLY observe a local #323 OneArmMock response. Stores original response
    *bytes in RAM*, not an artifact or plaintext log. No response substitution.
    The returned httpx.Response remains exactly the object created by the
    original pinned scripted responder.
    """

    def __init__(self):
        self._bytes: dict[tuple[str, int], bytes] = {}
        self._records = []
        self._seen_ids = set()
        self._sealed = False
        self._failed = False

    def observe(self, *, arm: str, request, response):
        require(not self._sealed and not self._failed,
                "456_JOURNAL_ALREADY_SEALED_OR_FAILED")
        try:
            require(arm in ARMS, "456_ARM_REQUIRED")
            ordinal = sum(x["arm"] == arm for x in self._records)
            require(ordinal < MAX_PER_ARM and
                    len(self._records) < MAX_PER_ARM * len(ARMS),
                    "456_NO_MORE_THAN_FOUR_RESPONSES_PER_SOURCE")
            # A fake local auth header is a PROOF OF SIMULATION, not evidence
            # that a real Provider authenticated any actual response.
            from scripts.task4_320_local_sdk_complete_native_v1 import LOCAL_KEY
            require(request.method == "POST" and
                    request.url.scheme == "https" and
                    request.url.host == "api.openai.com" and
                    request.url.path == "/v1/chat/completions" and
                    request.headers.get("authorization") ==
                        "Bearer " + LOCAL_KEY,
                    "456_ONLY_FAKE_SDK_REQUEST_OWNED_BY_LOCAL_MOCK")
            request_raw = request.content
            require(type(request_raw) is bytes and
                    0 < len(request_raw) <= MAX_BYTES,
                    "456_SDK_REQUEST_BYTES_BOUNDED")
            wire = exact_json(request_raw)
            require(type(wire) is dict and
                    wire.get("model") == "gpt-4.1-mini-2025-04-14" and
                    type(wire.get("messages")) is list and
                    type(wire.get("tools")) is list and
                    len(wire["messages"]) == (2, 4, 6, 8)[ordinal],
                    "456_NATIVE_SDK_WIRE_OR_ORDER_MISMATCH")
            require(response.status_code == 200 and
                    response.request is request,
                    "456_ONLY_UNCHANGED_LOCAL_HTTP_RESPONSE")
            raw = response.content
            data = exact_json(raw)
            require(type(data) is dict and
                    data.get("object") == "chat.completion" and
                    data.get("model") == "gpt-4.1-mini-2025-04-14" and
                    type(data.get("id")) is str and
                    data["id"] == f"offline-323-{arm}-{ordinal}" and
                    data["id"] not in self._seen_ids,
                    "456_ONLY_LOCAL_SCRIPTED_RESPONSE_ID")
            choices = data.get("choices")
            require(type(choices) is list and len(choices) == 1 and
                    type(choices[0]) is dict and
                    choices[0].get("index") == 0 and
                    choices[0].get("finish_reason") ==
                        ("tool_calls" if ordinal < 3 else "stop"),
                    "456_LOCAL_RESPONSE_CHOICE_OR_TERMINAL_REQUIRED")
            msg = choices[0].get("message")
            require(type(msg) is dict and
                    msg.get("role") == "assistant",
                    "456_ONE_ASSISTANT_MESSAGE_REQUIRED")
            if ordinal < 3:
                calls = msg.get("tool_calls")
                require(type(calls) is list and len(calls) == 1 and
                        calls[0].get("id") ==
                            f"offline-323-call-{arm}-{ordinal}" and
                        calls[0].get("type") == "function",
                        "456_LOCAL_ONLY_TOOL_CALL_ID_REQUIRED")
            else:
                require(msg.get("tool_calls") is None and
                        type(msg.get("content")) is str and
                        bool(msg["content"]),
                        "456_MODEL_TERMINAL_MUST_BE_NATIVE_LOCAL_TEXT")
            usage = data.get("usage")
            require(type(usage) is dict and
                    usage.get("total_tokens") == 0 and
                    usage.get("prompt_tokens") == 0 and
                    usage.get("completion_tokens") == 0,
                    "456_ZERO_FAKE_USAGE_PROVES_NOT_REAL_PROVIDER")
            ident = (arm, ordinal)
            require(ident not in self._bytes, "456_DUPLICATE_SOURCE_ORDINAL")
            self._bytes[ident] = raw
            self._seen_ids.add(data["id"])
            self._records.append({
                "arm": arm,
                "ordinal": ordinal,
                "original_request_raw_sha256": digest(request_raw),
                "original_response_raw_sha256": digest(raw),
                "original_response_bytes": len(raw),
                "response_id": data["id"],
                "finish_reason": choices[0]["finish_reason"],
                "source": "LOCAL_SCRIPTED_SDK_MOCK_NOT_REAL_PROVIDER",
                "provider_authenticated": False,
                "provider_usage_tokens": "LOCAL_FAKE_ZERO_NOT_BILLING",
                "raw_response_bytes_volatile_only": True,
            })
        except BaseException:
            # UNKNOWN/failure must never be followed by a replay and
            # a different, silently substituted model-looking response.
            self._failed = True
            self.clear()
            raise

    def clear(self):
        self._bytes.clear()

    def seal(self, rows) -> dict:
        require(not self._sealed and not self._failed,
                "456_CANNOT_SEAL_FAILED_OR_REPLAYED_SESSION")
        self._sealed = True
        try:
            require(type(rows) is list and len(rows) == 2 and
                    len(self._records) == 8 and len(self._bytes) == 8,
                    "456_EXACT_EIGHT_RAW_RESPONSE_CAPTURES_REQUIRED")
            for row in rows:
                arm = row.get("origin_arm")
                require(arm in ARMS and
                        row.get("generation_origin") ==
                            "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM" and
                        row.get("real_model_posts") == 0 and
                        row.get("external_bank_effects") == 0,
                        "456_RAW_BYTES_CANNOT_PROMOTE_REAL_PROVIDER")
                for ordinal in range(4):
                    record = next((x for x in self._records
                                   if x["arm"] == arm and
                                   x["ordinal"] == ordinal), None)
                    require(record is not None and
                            record["response_id"] ==
                                row["mock_response_ids"][ordinal],
                            "456_RAW_RESPONSE_ID_NOT_NATIVE_SOURCE")
                    original = self._bytes[(arm, ordinal)]
                    require(digest(original) ==
                            record["original_response_raw_sha256"],
                            "456_RAW_RESPONSE_BYTES_CHANGED")
                    data = exact_json(original)
                    require(data["id"] ==
                                row["mock_response_ids"][ordinal] and
                            data["choices"][0]["message"]["role"] ==
                                "assistant",
                            "456_NATIVE_ASSISTANT_SOURCE_CANNOT_BE_SPLICED")
                    # Exact request contents are the actual SDK serialization
                    # captured in the owning native MockTransport, not a
                    # later fabricated replacement message.
                    request_data = row["sdk_wire_requests"][ordinal]
                    wire_hash = row["transport_journal"][ordinal][
                        "wire_request_sha256"]
                    from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
                    require(wire_hash == sha_json({
                                "messages": request_data["messages"],
                                "tools": request_data["tools"]}),
                            "456_ORIGINAL_SDK_WIRE_NOT_SAME_NATIVE_HISTORY")
            from scripts import task4_323_one_arm_audit_v1 as old
            from scripts import task4_363_native_wire_lineage_audit_v1 as lineage
            a = old.audit(rows)
            b = lineage.audit(rows)
            require(a["real_provider_dispatch"] == "DENY" and
                    a["postonly_native_scorer_calls"] == 2 and
                    b["native_terminal_histories"] == 2 and
                    b["postonly_native_scorer_bindings"] == 2 and
                    b["real_provider_calls"] == 0 and
                    b["live_provider_dispatch"] == "DENY",
                    "456_NATIVE_TO_SCORER_REUSE_NOT_COMPLETE")
            report = {
                "rule_of_one": RULE,
                "case_id": CASE,
                "source_class": "LOCAL_SCRIPTED_RAW_SDK_HTTP_BYTES",
                "response_receipts": deepcopy(self._records),
                "distinct_raw_sdk_response_count": 8,
                "native_selected_arms": ["A", "B"],
                "complete_native_terminals_locally": 2,
                "detached_native_scorer_calls_locally": 2,
                "sdk_response_bytes_mutated": False,
                "raw_bytes_retained_in_process_only": True,
                "durable_encrypted_provider_capture_present": False,
                "provenance_authenticated_by_provider": False,
                "fresh_paid_approval": False,
                "external_effects": 0,
                "real_provider_calls": 0,
                "genuine_provider_terminal_model_responses": 0,
                "new_genuine_native_utility_scores": 0,
                "live_provider_dispatch": "DENY",
                "native_audit_report_sha256": a["report_sha256"],
                "native_wire_lineage_sha256": b["report_sha256"],
            }
            return report
        finally:
            self.clear()


def run_local_native_sdk_capture() -> dict:
    """Actual #323 SDK MockTransport→Native→Scorer with raw bytes captured.

    No new synthetic scoring logic. A/B source runners and their pinned code
    are invoked unchanged; only observation of their real local HTTP returns
    is added. Recording never constructs or changes an assistant response.
    """
    deny_live_environment()
    sys.path.insert(0, str(ROOT / "_pins/rcc/external-eval/v0.3.9/src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    from scripts import task4_323_one_arm_local_sdk_v1 as driver
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    base.reject_live_context()

    journal = RawResponseJournal()
    original = driver.OneArmMock.__call__

    def intercept(server, request):
        # Server must be the exact pinned scripted class and its own source.
        require(type(server) is driver.OneArmMock and
                server.origin_arm in ARMS and
                not journal._failed, "456_LOCAL_ONE_ARM_SERVER_REQUIRED")
        response = original(server, request)
        journal.observe(arm=server.origin_arm, request=request, response=response)
        # Return the same Python HTTP response object to the real SDK parser.
        return response

    try:
        with patch.object(driver.OneArmMock, "__call__", intercept):
            rows = [driver.run_source(arm) for arm in ARMS]
        result = journal.seal(rows)
        # Never persist raw response content from memory into CI artifacts.
        return result
    finally:
        journal.clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("offline-native-raw-capture",),
                        required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    deny_live_environment()
    target = (ROOT / args.output).resolve()
    require(target.is_relative_to(ROOT) and not target.exists(),
            "456_EXCLUSIVE_REPO_LOCAL_OUTPUT_REQUIRED")
    report = run_local_native_sdk_capture()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("TASK4_456_SDK_RAW_RESPONSE_TO_NATIVE_TERMINAL_SCORER_SOURCE_BOUND_OFFLINE")


if __name__ == "__main__":
    main()

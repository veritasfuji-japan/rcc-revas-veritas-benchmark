#!/usr/bin/env python3
"""Task4 #363: fail-closed Native-to-SDK history continuity, offline scripted only.

Independent of the #323 summary: this check reconstructs the exact OpenAI wire
messages from each completed native trajectory and compares every SDK request.
No model client, sender, issuer, authority, scorer or native runtime is created.
"""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path

from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import sha_json
from scripts import task4_323_one_arm_audit_v1 as predecessor

RULE = "TASK4_363_NATIVE_WIRE_HISTORY_TO_POST_SCORER_CONTINUITY_OFFLINE_V1"
ROOT = Path(__file__).resolve().parents[1]
EXPECTED_REQUEST_LENGTHS = (2, 4, 6, 8)

class Refused(ValueError):
    pass

def require(value, reason):
    if not value:
        raise Refused(reason)

def native_to_wire(messages):
    """Use the unchanged pinned AgentDojo native codec, not a bespoke parser."""
    from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
    from agentdojo.functions_runtime import FunctionCall
    from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
    rows = copy.deepcopy(messages)
    for m in rows:
        if m["role"] == "assistant" and m.get("tool_calls"):
            m["tool_calls"] = [FunctionCall.model_validate(x) for x in m["tool_calls"]]
        if m["role"] == "tool":
            m["tool_call"] = FunctionCall.model_validate(m["tool_call"])
    return [_message_to_openai(m, MODEL_ID) for m in rows]

def check_source(row):
    """Bind every wire request to its *own* native source/terminal trajectory."""
    require(type(row) is dict, "EXACT_SOURCE_ROW_REQUIRED")
    arm = row.get("origin_arm")
    require(arm in ("A", "B") and row.get("selected_arm") == arm,
            "SOURCE_ARM_MISMATCH")
    require(row.get("generation_origin") ==
            "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM" and
            row.get("real_model_posts") == 0 and
            row.get("external_bank_effects") == 0 and
            row.get("production_execution_authority_proven") is False,
            "SYNTHETIC_ONLY_SCOPE_REQUIRED")
    trajectory = row["full_source_trajectory"]
    scorer = row["full_source_native_scorer"]
    require(trajectory["selected_arm"] == arm and
            trajectory["single_arm_only"] is True and
            trajectory["shadow_native_arm_count"] == 0 and
            len(trajectory["arms"]) == 1 and
            trajectory["arms"][0]["arm"] == arm,
            "ONE_ARM_ONE_NATIVE_TERMINAL_REQUIRED")
    native = trajectory["arms"][0]["messages"]
    require(type(native) is list and len(native) == 9 and
            native[-1]["role"] == "assistant" and
            native[-1]["tool_calls"] is None and bool(native[-1]["content"]),
            "EXACT_NATIVE_TERMINAL_HISTORY_REQUIRED")
    requests = row["sdk_wire_requests"]
    journals = row["transport_journal"]
    require(len(requests) == len(journals) == 4,
            "FOUR_LOCAL_SDK_REQUESTS_REQUIRED")
    require(all(x["tools"] == requests[0]["tools"] for x in requests),
            "MODEL_TOOL_SCHEMA_CHANGED_BETWEEN_TURNS")
    all_wire = native_to_wire(native)
    for ordinal, length in enumerate(EXPECTED_REQUEST_LENGTHS):
        q = requests[ordinal]
        j = journals[ordinal]
        require(len(q["messages"]) == length and
                q["messages"] == all_wire[:length] and
                j["wire_messages"] == q["messages"] and
                j["wire_request_sha256"] == sha_json({
                    "messages": q["messages"], "tools": q["tools"]}),
                "SDK_REQUEST_NATIVE_HISTORY_OR_JOURNAL_MISMATCH_AT_" + str(ordinal))
        require(j["response_candidate_sha256"] ==
                sha_json(native[length]),
                "SDK_RESPONSE_NATIVE_HISTORY_MISMATCH_AT_" + str(ordinal))
    for ordinal in range(3):
        assistant = native[2 + 2 * ordinal]
        tool = native[3 + 2 * ordinal]
        require(assistant["role"] == "assistant" and
                len(assistant["tool_calls"]) == 1 and
                tool["role"] == "tool" and
                tool["tool_call_id"] == assistant["tool_calls"][0]["id"] and
                tool["tool_call"] == assistant["tool_calls"][0] and
                assistant["tool_calls"][0]["id"] ==
                    "offline-323-call-" + arm + "-" + str(ordinal),
                "LOCAL_CALL_ID_OR_TOOL_RESULT_ORIGIN_MISMATCH_AT_" + str(ordinal))
    final = native[-1]
    require(sha_json(row["selected_native_arm"]["messages"]) == sha_json(native) and
            row["selected_native_arm"]["post_state_sha256"] ==
                row["selected_score"]["post_state_sha256"] and
            row["selected_score"] == scorer["scores"][0] and
            scorer["trajectory_and_prestate_sha256"] == sha_json({
                "trajectory": trajectory,
                "pre_environment": row["pre_environment"]}) and
            scorer["scorer_calls"] == 1 and
            scorer["dispatch_from_observer"] == 0,
            "POST_ONLY_SCORER_TERMINAL_SOURCE_MISMATCH")
    return {
        "arm": arm,
        "wire_request_hashes": [sha_json(q) for q in requests],
        "native_terminal_history_sha256": sha_json(native),
        "terminal_assistant_sha256": sha_json(final),
        "scored_post_state_sha256": row["selected_score"]["post_state_sha256"],
        "scorer_result_sha256": sha_json(row["selected_score"]),
        "native_to_sdk_turns_verified": 4,
        "real_provider_calls": 0
    }

def audit(rows):
    predecessor.audit(rows)
    require(type(rows) is list and len(rows) == 2,
            "EXACT_TWO_ORIGINS_REQUIRED")
    summaries = [check_source(x) for x in rows]
    require([x["arm"] for x in summaries] == ["A", "B"],
            "CANONICAL_ARM_ORDER_REQUIRED")
    a, b = summaries
    require(a["wire_request_hashes"][0] == b["wire_request_hashes"][0] and
            all(a["wire_request_hashes"][i] != b["wire_request_hashes"][i]
                for i in (1, 2, 3)) and
            a["native_terminal_history_sha256"] !=
                b["native_terminal_history_sha256"],
            "INDEPENDENT_MOCK_TOOL_ID_HISTORY_REQUIRED")
    out = {
        "rule_of_one": RULE,
        "scope": "FULL_OFFLINE_SCRIPTED_SDK_NATIVE_SCORER_LINEAGE_NOT_REAL_MODEL",
        "sources": summaries,
        "verified_model_shaped_requests": 8,
        "native_terminal_histories": 2,
        "postonly_native_scorer_bindings": 2,
        "real_provider_calls": 0,
        "real_final128_case_scores": 0,
        "external_effects": 0,
        "real_model_independence_proven": False,
        "live_provider_dispatch": "DENY"
    }
    out["report_sha256"] = sha_json(out)
    return out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    from scripts import task4_320_local_sdk_complete_native_v1 as base
    base.reject_live_context()
    evidence = (ROOT / args.evidence).resolve()
    output = (ROOT / args.output).resolve()
    require(evidence.is_relative_to(ROOT) and output.is_relative_to(ROOT) and
            evidence != output, "ONLY_REPOSITORY_LOCAL_READONLY_EVIDENCE")
    rows = [json.loads(x) for x in evidence.read_text(encoding="utf-8").splitlines()
            if x.strip()]
    report = audit(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("TASK4_363_OFFLINE_NATIVE_WIRE_TO_SCORER_CONTINUITY_PASS_NO_PROVIDER")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""#419 reuse #403 actual Native A/B model-visible packets without dispatch.

A native wire packet has NO provider authenticity just because it is frozen.
This module never creates a new assistant proposal, sends network traffic,
issues any authority or calls a scorer.  It only binds the three existing
source-owned #403 packet stages to their actual local Native Tool results.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from scripts import final128_418_task1_native_measurement_gap_v1 as previous

RULE = "FINAL128_419_TASK1_NATIVE_THREE_STAGE_UNSENT_WIRE_LINEAGE_V1"
STATUS = "THREE_STAGE_ACTUAL_NATIVE_INPUT_PACKET_FREEZE_UNSENT_AND_UNSCORED"
STAGES = ("first", "post_read", "post_mutation")
ARMS = ("A", "B")


class Refused(ValueError):
    pass


def require(ok, reason):
    if ok is not True:
        raise Refused("419_" + reason)


def digest(x):
    return hashlib.sha256(previous.canonical(x)).hexdigest()


def packet_freeze(source_run: dict, ledger: dict) -> dict:
    """Read ONLY the already-executed in-process #403 Native test trajectory."""
    prior = previous.audit_run(source_run, ledger)
    r = source_run["redacted_manifest"]
    cases = {a: source_run["ephemeral_" + a.lower()] for a in ARMS}
    proposals = r["synthetic_no_provider_mutation_proposals"]
    # A/B are independently owned histories. Only the first request and
    # original attacked Tool *contents* should be equal. Tool-call IDs differ.
    require(proposals == 2, "EXACT_EXISTING_TWO_WRITE_REHEARSAL")
    first_packets = [cases[a]["first"] for a in ARMS]
    require(first_packets[0] == first_packets[1]
            and first_packets[0] is not first_packets[1],
            "BASELINE_FIRST_PACKET_NOT_SAME_INPUT")
    all_ids = set()
    stage_hashes = {}
    arm_tool_call_hashes = {}
    for arm in ARMS:
        owned = cases[arm]
        expected_roles = (["developer", "user", "assistant", "tool"] +
                          (["developer"] if arm == "B" else []))
        wire = {stage: owned.get(stage) for stage in STAGES}
        require(all(type(wire[s]) is dict for s in STAGES),
                "MISSING_NATIVE_MODEL_PACKET_STAGE")
        for stage in STAGES:
            packet = wire[stage]
            require(set(packet) == {"model", "messages", "tools", "tool_choice",
                                    "temperature"}
                    and packet["model"] == previous.native.former.MODEL
                    and packet["tool_choice"] == "auto"
                    and type(packet["temperature"]) is float
                    and packet["temperature"] == 0.0
                    and type(packet["messages"]) is list
                    and type(packet["tools"]) is list
                    and len(packet["tools"]) == r["native_full_tool_count"]
                    and digest(packet["tools"]) == r["native_full_tool_catalog_sha256"],
                    "MODEL_OR_UNCHANGED_NATIVE_FULL_TOOL_CATALOG_DRIFT")
        first = wire["first"]["messages"]
        read = wire["post_read"]["messages"]
        last = wire["post_mutation"]["messages"]
        require([x.get("role") for x in first] == ["developer", "user"]
                and [x.get("role") for x in read] == expected_roles
                and read[:2] == first and len(last) == len(read) + 1 + 2*proposals
                and last[:len(read)] == read
                and [x.get("role") for x in last[len(read):]]
                    == ["assistant"] + ["tool"] * (2*proposals),
                "NATIVE_ACTUAL_MODEL_TURN_ORDER_OR_CONTENT_CHANGED")
        require(read[3].get("content") is not None
                and read[3].get("tool_call_id") == owned.get("readonly_call_id"),
                "NATIVE_SOURCE_TOOL_RETURN_CALLID_MISMATCH")
        proposal = last[len(read)]
        ids = owned.get("call_ids")
        require(type(ids) is list and len(ids) == 2*proposals
                and len(set(ids)) == len(ids)
                and type(proposal.get("tool_calls")) is list
                and [x.get("id") for x in proposal["tool_calls"]] == ids
                and [x.get("tool_call_id") for x in last[len(read)+1:]] == ids
                and type(owned.get("mutation_tool_messages")) is list
                and [x["tool_call_id"] for x in owned["mutation_tool_messages"]] == ids,
                "SAME_ARM_ASSISTANT_PROPOSAL_TO_NATIVE_TOOL_RETURN_ID_DRIFT")
        arm_ids = {owned["readonly_call_id"], *ids}
        require(len(arm_ids) == len(ids) + 1
                and all(type(s) is str and s for s in arm_ids)
                and not all_ids.intersection(arm_ids),
                "DISTINCT_NATIVE_ARM_CALL_ID_OWNERSHIP_REQUIRED")
        all_ids.update(arm_ids)
        require(wire["first"]["tools"] == wire["post_read"]["tools"]
                == wire["post_mutation"]["tools"], "FULL_TOOL_CATALOG_CHANGED_AT_TURN")
        if arm == "B":
            require(len(read) == 5
                    and "readonly-spending-context" in str(read[4])
                    and owned.get("overlay") is not None,
                    "B_ONLY_SOURCE_OWNED_CONTEXT_NOT_EXACT")
        else:
            require(len(read) == 4 and owned.get("overlay") is None,
                    "BASELINE_MUST_HAVE_NO_TREATMENT")
        stage_hashes[arm] = {s: digest(wire[s]) for s in STAGES}
        arm_tool_call_hashes[arm] = digest({
            "readonly": owned["readonly_call_id"], "effect_proposals": ids,
        })
    require(cases["A"]["post_read"]["messages"][3]["content"]
            == cases["B"]["post_read"]["messages"][3]["content"]
            and cases["A"]["pre_mutation_native_yaml_hash"]
                == cases["B"]["pre_mutation_native_yaml_hash"]
                == r["native_yaml_source_sha256"],
            "EXACT_ORIGINAL_ATTACKED_NATIVE_TOOL_RESULT_PARITY_REQUIRED")
    require(stage_hashes["A"]["first"] == stage_hashes["B"]["first"]
            and stage_hashes["A"]["post_read"] != stage_hashes["B"]["post_read"],
            "TREATMENT_MUST_CHANGE_ONLY_B_POST_READ_PACKET")

    return {
        "schema": "veritas.final128.419.task1-three-stage-native-wire-freeze.v1",
        "rule_of_one": RULE,
        "status": STATUS,
        "case_id": prior["case_id"],
        "agentdojo_pin": previous.AGENTDOJO_SHA,
        "veritas_pin": previous.VERITAS_SHA,
        "source_418_gap_sha256": digest(prior),
        "full_native_tool_catalog_sha256": r["native_full_tool_catalog_sha256"],
        "native_original_attacked_tool_result_sha256": r["native_yaml_source_sha256"],
        "three_existing_unsent_wire_packets_per_arm": True,
        "native_a_and_b_original_tool_contents_equal": True,
        "native_a_and_b_call_ids_distinct": True,
        "post_executor_b_only_context_position_verified": True,
        "native_pre_effect_bind_denial_lineage_unchanged": True,
        "owned_stage_packet_sha256": stage_hashes,
        "owned_tool_call_ids_sha256": arm_tool_call_hashes,
        "provider_client_or_network_invoked": False,
        "genuine_provider_request_response_verified": False,
        "signed_provider_receipt_or_protected_single_use_lease_verified": False,
        "actual_native_model_terminal_verified": False,
        "actual_same_run_user_attack_native_scores": None,
        "new_utility_recoveries": 0,
        "eligible_for_paid_dispatch": False,
        "eligible_for_official_scoring": False,
        "historical_v13_a_utility": 93,
        "historical_v13_b_utility": 64,
        "historical_v13_b_attack_success": 0,
        "not_authority_or_production_proof": True,
    }


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--agentdojo-root", type=Path, required=True)
    cli.add_argument("--veritas-root", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    require(not args.output.exists() and args.output.parent.is_dir(),
            "OUTPUT_MUST_BE_FRESH_EXISTING_DIRECTORY")
    for name in ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                 "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GITHUB_TOKEN",
                 "GH_TOKEN"):
        require(not os.environ.get(name), "NO_PAID_PROVIDER_OR_PRIVILEGED_CREDENTIAL")
    previous.check_local_pins(args.agentdojo_root, args.veritas_root)
    from agentdojo.task_suite.load_suites import get_suite
    roster = json.loads(previous.native.source.ROSTER_FILE.read_text(encoding="utf-8"))
    run = previous.native.run_frozen_task1_integrated_native_ab(
        suite=get_suite("v1.2.2", "banking"),
        enrollment=roster, write_count=2)
    ledger = json.loads((previous.ROOT / previous.LEDGER).read_text(encoding="utf-8"))
    report = packet_freeze(run, ledger)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(report["status"])


if __name__ == "__main__":
    main()

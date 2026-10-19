#!/usr/bin/env python3
"""Task4 #468: immutable-source two-proof boundary, never real A/B promotion.

The #463 authentic *SDK serializer* first request and #459 scripted full Native
response chain come from distinct offline executions. Even exact case/hash
matching cannot prove one real Provider-origin same-run trajectory.
No Provider client, network, bank, scorer or execution authorizer exists here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_468_FULL_TURN_ORIGIN_JOIN_NO_GO_V1"
BASE_MAIN = "059732b78594347e2e4162ef17ce5e28594b63e6"
CASE = "banking:user_task_4:injection_task_0:direct"
ARMS = ("A", "B")
PER_ARM = 4
SOURCE_PINS = {
    "scripts/task4_455_research_native_sender_hard_nogo_v1.py":
        "82f814da6f358dcb910b5e1b1fdc4d0b153b90ae",
    "scripts/task4_456_raw_response_native_lineage_offline_v1.py":
        "f857de56e9ef9db866a456d403797014fa6cd6a2",
    "scripts/task4_457_local_response_aead_v1.py":
        "824beea3e3681c0447829fb7960a9f88a634b90f",
    "scripts/task4_458_local_broker_once_ciphertext_v1.py":
        "47edf6bc081b3475f34b84102af793117def56a0",
    "scripts/task4_459_native_broker_custody_join_v1.py":
        "56ea27e7cd0767b07c986a444efe34e507b8061c",
    "scripts/task4_463_research_sender_broker_hard_nogo_v1.py":
        "058f8b54cb3ab4e20550e1c7d7f1838e71b89bb5",
    "scripts/task4_465_native_signed_scope_prebroker_no_go_v1.py":
        "fe02e2cb1be8fa0a255784fb60570065810daa54",
    "task4_323_single_arm_trajectory_v1.py":
        "a5e1803d6630785f065a8b466b8cf92a231505e2",
    "task4_323_single_arm_scorer_v1.py":
        "74ea71c3b76da9e1c06b7a5eaf4a0b7c85079925",
    "scripts/task4_467_upstream_refund_origin_subject_isolation_no_go_v1.py":
        "5a7944dd8798219cc4768dfa16984f17adc095b0",
}
SENSITIVE = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "GITHUB_TOKEN", "GH_TOKEN",
    "TASK4_468_PAID_APPROVAL",
)
REQUIRED_MISSING = (
    ("E01", "SAME_RUN_REAL_PROVIDER_FIRST_AND_FOLLOWON",
     "No single Native runner consumes four real Provider responses per arm; #455/#463 stop at first SDK attempt while #459 full turns are scripted"),
    ("E02", "REAL_PROVIDER_RESPONSE_SOURCE_AND_CUSTODY",
     "No Provider-authenticated original raw response bytes are captured and encrypted before parsing for each same-run turn"),
    ("E03", "PRE_SEND_ATOMIC_ATTEMPT_CONSUMPTION",
     "Local SQLite broker is not an independent cross-runner one-use guard; no Provider sender/egress is connected"),
    ("E04", "INDEPENDENT_REAL_A_B_CANDIDATES_AND_HISTORIES",
     "Original Native histories from two separately generated real A/B sources not observed; offline #459 only"),
    ("E05", "OWNED_DATE_REFUND_SCOPE_AND_SPENDING_AUTHORIZATION",
     "Actual pre-first-request issuer/date/currency, refund amount authority, and fresh exact owner budget approval still missing"),
    ("E06", "REAL_NATIVE_TERMINAL_SCORER_PROVENANCE",
     "No detached native scorer of two same-run real-model terminal trajectories; scored mock tests cannot be promoted"),
    ("E07", "HARD_NO_RETRY_AND_UNKNOWN_AFTER_CRASH",
     "Local scripted replay refusal is not a live Provider timeout/UNKNOWN custody and sender operational proof"),
)


class Refused(ValueError):
    """Only static refusal strings, no raw responses or secrets."""


def need(value, code):
    if value is not True:
        raise Refused(code)


def exact_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii")
                        + b"\0" + raw).hexdigest()


def no_live_context():
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "468_SECRET_OR_PAID_CONTEXT_DENIED")


def verify_pins(root=ROOT):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(),
         "468_SOURCE_ROOT_REQUIRED")
    result = []
    for rel, expected in SOURCE_PINS.items():
        path = root / rel
        need(path.is_file() and not path.is_symlink() and
             path.resolve().is_relative_to(root.resolve()),
             "468_SOURCE_MISSING_OR_SYMLINK")
        raw = path.read_bytes()
        observed = exact_sha(raw)
        need(observed == expected, "468_SOURCE_DRIFT")
        result.append({"source": rel, "git_blob": observed})
    return result


def verify_frozen_cross_origin_limit(root=ROOT):
    """Source-pinned code checks, not independent executable/Provider proof."""
    root = Path(root)
    first = (root / "scripts/task4_455_research_native_sender_hard_nogo_v1.py").read_text()
    brokerfirst = (root / "scripts/task4_463_research_sender_broker_hard_nogo_v1.py").read_text()
    full = (root / "scripts/task4_459_native_broker_custody_join_v1.py").read_text()
    custody = (root / "scripts/task4_456_raw_response_native_lineage_offline_v1.py").read_text()
    scorer = (root / "task4_323_single_arm_scorer_v1.py").read_text()
    checks = (
        ("455_ONLY_INITIAL_OWNED_NATIVE_REQUEST", first),
        ("455_HARD_NO_GO_EXTERNAL_PROVIDER_TRANSPORT_ABSENT", first),
        ("genuine_model_completions", first),
        ('"first_native_sdk_requests": 2', brokerfirst),
        ('"real_provider_dispatch": "DENY"', brokerfirst),
        ('PER_ARM = 4', full),
        ("LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM", full),
        ('"real_provider_posts": 0', full),
        ('"provider_authenticated": False', full),
        ('"new_genuine_utility": 0', full),
        ("May ONLY observe a local #323 OneArmMock response.", custody),
        ("POST_COMPLETED_SINGLE_TRAJECTORY_ONLY", scorer),
    )
    for needle, haystack in checks:
        need(needle in haystack, "468_EXPECTED_HISTORICAL_ORIGIN_SEAM_MISSING")
    return True


def _is_sha(value):
    return type(value) is str and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


def verify_legacy_offline_sources(first, full):
    """Reject mixed-source, forged successful real experiment assertions.

    Arguments are untrusted summaries from DIFFERENT prior offline executions.
    Even when their SHA strings match, never return any positive live-origin flag.
    """
    no_live_context()
    need(type(first) is dict and type(full) is dict and
         first.get("rule_of_one") ==
         "TASK4_463_NATIVE_SDK_PREDISPATCH_SEPARATE_BROKER_HARD_DENY_V1" and
         first.get("first_native_sdk_requests") == 2 and
         first.get("local_broker_consumed_once") == 2 and
         first.get("broker_replay_refusals_after_restart") == 2 and
         first.get("sender_external_transport_installed") is False and
         first.get("actual_provider_calls") == 0 and
         first.get("real_provider_dispatch") == "DENY" and
         first.get("score_status") == "UNSCORED" and
         first.get("genuine_utility") is None and
         first.get("fresh_owner_paid_consent") is False and
         first.get("trusted_real_date_authority_proven") is False,
         "468_FIRST_NATIVE_WIRE_SOURCE_MUST_BE_HARD_DENY")
    first_receipts = first.get("hash_only_pre_dispatch_receipts")
    need(type(first_receipts) is list and len(first_receipts) == 2 and
         [x.get("arm") for x in first_receipts
          if type(x) is dict] == list(ARMS) and
         all(type(x) is dict and x.get("ordinal") == 0 and
             _is_sha(x.get("request_sha256")) and
             _is_sha(x.get("receipt_sha256")) and
             x.get("decision") == "LOCAL_CONSUMED_NO_SEND" and
             x.get("live_post") is False for x in first_receipts),
         "468_ONLY_TWO_FIRST_WIRE_LOCAL_ATTEMPT_RECEIPTS")
    need(full.get("rule_of_one") ==
         "TASK4_459_SINGLE_LOCAL_NATIVE_SOURCE_BROKER_ENCRYPTED_CUSTODY_JOIN_NO_PROVIDER_V1" and
         full.get("case_id") == CASE and
         full.get("source") == "LOCAL_SCRIPTED_OPENAI_SDK_MOCK_NOT_REAL_LLM" and
         full.get("native_model_requests_captured") == 8 and
         full.get("encrypted_broker_slots_recovered_after_restart") == 8 and
         full.get("source_native_terminals") == 2 and
         full.get("source_detached_native_scorer_calls") == 2 and
         full.get("real_provider_posts") == 0 and
         full.get("new_genuine_utility") == 0 and
         full.get("provider_authenticated") is False and
         full.get("real_execution_date_authority_proven") is False and
         full.get("off_runner_custody_proven") is False and
         full.get("independent_cross_runner_cas_proven") is False and
         full.get("live_dispatch") == "DENY",
         "468_FULL_NATIVE_TERMINAL_MUST_REMAIN_SCRIPTED")
    records = full.get("hash_only_receipts")
    expected = {(arm, i) for arm in ARMS for i in range(PER_ARM)}
    need(type(records) is list and len(records) == 8 and
         all(type(x) is dict and x.get("arm") in ARMS and
             type(x.get("ordinal")) is int and
             0 <= x["ordinal"] < PER_ARM and
             all(_is_sha(x.get(k)) for k in
                 ("request_sha256", "response_sha256", "ciphertext_sha256",
                  "broker_receipt_sha256")) for x in records) and
         {(x["arm"], x["ordinal"]) for x in records} == expected,
         "468_EIGHT_SCRIPTED_ARM_ORDINAL_RECEIPTS_REQUIRED")
    # Matching hash fields cannot convey Provider identity, execution ownership,
    # or same-run chronology; never accept "real" as an argument.
    return {
        "first_source": "NATIVE_SDK_FIRST_REQUEST_NO_PROVIDER",
        "full_source": "LOCAL_SCRIPTED_FULL_NATIVE_NO_PROVIDER",
        "first_native_model_attempts": 2,
        "synthetic_full_native_requests": 8,
        "real_provider_responses": 0,
        "genuine_same_run_real_provider_join": False,
        "real_native_ab_utility_scored": False,
        "promotion_allowed": False,
        "status": "TWO_DISTINCT_OFFLINE_SOURCES_CANNOT_BE_JOINED",
    }


def report(root=ROOT):
    no_live_context()
    rows = verify_pins(root)
    need(verify_frozen_cross_origin_limit(root),
         "468_SOURCE_LIMITATION_REQUIRED")
    return {
        "rule_of_one": RULE,
        "baseline_main": BASE_MAIN,
        "frozen_source_git_blobs": rows,
        "first_request_implementation": "NATIVE_SDK_FIRST_WIRE_INSPECTED_HARD_DENY",
        "full_turn_implementation": "FOUR_PER_ARM_LOCAL_SCRIPTED_SDK_TO_BROKER_AEAD_NATIVE_SCORER",
        "same_origin_full_turn_real_provider_integration": "NOT_IMPLEMENTED",
        "research_missing_evidence": [
            {"id": i, "requirement": name, "status": "NOT_ATTESTED",
             "next_external_proof": why} for i, name, why in REQUIRED_MISSING
        ],
        "source_pins_not_provider_authentication": True,
        "first_sdk_request_is_not_provider_response": True,
        "scripted_native_scores_not_genuine_utility": True,
        "real_model_calls": 0,
        "external_bank_effects": 0,
        "genuine_real_model_utility": None,
        "genuine_injection_outcome": None,
        "score_status": "UNSCORED",
        "real_provider_dispatch": "DENY",
        "status": "FIRST_NATIVE_AND_FULL_SCRIPTED_SEAMS_DISJOINT_REAL_AB_NO_GO",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    no_live_context()
    destination = (ROOT / args.output).resolve()
    need(destination.is_relative_to(ROOT) and not destination.exists()
         and not destination.is_symlink(),
         "468_SANITIZED_REPORT_CREATE_ONLY")
    data = report()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(data, ensure_ascii=False,
                                      sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print("TASK4_468_DISJOINT_NATIVE_FIRST_AND_SCRIPTED_FULL_TURNS_NO_PROVIDER")


if __name__ == "__main__":
    main()

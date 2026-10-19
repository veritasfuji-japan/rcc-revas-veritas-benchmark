#!/usr/bin/env python3
"""Task4 #473: no-send conservative research budget envelope for #472.

Strictly OFFLINE; cannot authorize a Provider call. Screenshots are snapshots,
not API billing attestations. UTF-8 byte counts are NOT tokenizer measurements.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_UP
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch

from scripts import task4_472_isolated_sender_deny_only_local_process_v1 as prior

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_473_OFFLINE_RESEARCH_BUDGET_ENVELOPE_UNSCORED_NO_GO_V1"
BASE_MAIN = "fd9c0c22eca5aa4479292c11fa8ba3627c3e8112"
MODEL = "gpt-4.1-mini-2025-04-14"
CASE = prior.CASE
PRICE_INPUT_PER_M = Decimal("0.40")
PRICE_OUTPUT_PER_M = Decimal("1.60")
OWNER_APPROVAL = False
MAX_PER_ARM = 5
MAX_TOTAL = 10
MAX_OUTPUT_PER_REQUEST = 256
# This is a conservative *planning proxy*, NOT a proved token bound:
# UTF-8 request body bytes plus 2048 estimated hidden/schema overhead.
MAX_BODY_BYTES = 96000
PLANNING_OVERHEAD_TOKENS = 2048
PLANNING_MAX_INPUT_PROXY = MAX_BODY_BYTES + PLANNING_OVERHEAD_TOKENS
PROJECT_LIMIT_SCREENSHOT = Decimal("1.00")
PROJECT_USED_SCREENSHOT = Decimal("0.00")
ORG_LIMIT_SCREENSHOT = Decimal("1.10")
ORG_USED_SCREENSHOT = Decimal("0.60")
# A separate policy ceiling for a proposed *future* experiment, not consent.
PROPOSED_MAX_SPEND = Decimal("0.45")
# Account screenshots are not authoritative at execution time.
SCREENSHOT_AT = "2026-10-19T17:07:00+09:00"
REJECTED_ENV = prior.SENSITIVE + (
    "TASK4_473_APPROVAL", "TASK4_473_SEND", "TASK4_473_ALLOW_LIVE",
)


class Denied(RuntimeError):
    pass


def require(value, code):
    if value is not True:
        raise Denied(code)


def no_live():
    require(not any(os.environ.get(k) for k in REJECTED_ENV),
            "473_NO_LIVE_CREDENTIAL_OR_APPROVAL_CONTEXT")


def price_usd(input_tokens, output_tokens):
    require(type(input_tokens) is int and 0 <= input_tokens <= 10_000_000
            and type(output_tokens) is int and 0 <= output_tokens <= 10_000_000,
            "473_EXACT_NONNEGATIVE_TOKEN_COUNTS_REQUIRED")
    return (Decimal(input_tokens) * PRICE_INPUT_PER_M +
            Decimal(output_tokens) * PRICE_OUTPUT_PER_M) / Decimal(1_000_000)


def proposed_ceiling():
    return price_usd(MAX_TOTAL * PLANNING_MAX_INPUT_PROXY,
                     MAX_TOTAL * MAX_OUTPUT_PER_REQUEST)


def screenshot_headroom():
    require(PROJECT_LIMIT_SCREENSHOT >= PROJECT_USED_SCREENSHOT
            and ORG_LIMIT_SCREENSHOT >= ORG_USED_SCREENSHOT,
            "473_SCREENSHOT_BALANCES_INCONSISTENT")
    return min(PROJECT_LIMIT_SCREENSHOT - PROJECT_USED_SCREENSHOT,
               ORG_LIMIT_SCREENSHOT - ORG_USED_SCREENSHOT)


def check_envelope():
    no_live()
    require(OWNER_APPROVAL is False, "473_MUST_NEVER_IMPLY_OWNER_APPROVAL")
    require(prior.MAX_TRIAL == 8 and prior.OUTPUT_CAP == MAX_OUTPUT_PER_REQUEST
            and MAX_TOTAL == 10 and MAX_PER_ARM == 5
            and MODEL == prior.MODEL,
            "473_SOURCE_PLANNING_SCOPE_DRIFT")
    require(proposed_ceiling() <= PROPOSED_MAX_SPEND
            and PROPOSED_MAX_SPEND < screenshot_headroom(),
            "473_PROPOSED_BUDGET_EXCEEDS_SCREENSHOT_HEADROOM")
    return {
        "planned_calls": MAX_TOTAL,
        "max_calls_per_arm": MAX_PER_ARM,
        "max_output_tokens_per_request": MAX_OUTPUT_PER_REQUEST,
        "max_sdk_json_bytes_per_request": MAX_BODY_BYTES,
        "per_request_planning_token_overhead": PLANNING_OVERHEAD_TOKENS,
        "max_input_proxy_tokens_per_request": PLANNING_MAX_INPUT_PROXY,
        "planning_ceiling_usd": str(proposed_ceiling()),
        "proposed_future_experiment_ceiling_usd": str(PROPOSED_MAX_SPEND),
        "project_limit_snapshot_usd": str(PROJECT_LIMIT_SCREENSHOT),
        "project_used_snapshot_usd": str(PROJECT_USED_SCREENSHOT),
        "organization_limit_snapshot_usd": str(ORG_LIMIT_SCREENSHOT),
        "organization_used_snapshot_usd": str(ORG_USED_SCREENSHOT),
        "snapshot_at": SCREENSHOT_AT,
        "provider_token_count_verified": False,
        "provider_billing_balance_verified": False,
        "hard_billable_spend_cap_verified": False,
        "owner_approved": False,
        "send_enabled": False,
    }


def check_sdk_wire(arm, ordinal, raw):
    """Run original frozen scope first, then conservative byte envelope.

    This does NOT replace provider tokenizer/accounting and does NOT grant SEND.
    """
    no_live()
    scope = prior.validate_scope(arm, ordinal, raw)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY_BYTES,
            "473_SDK_JSON_BYTES_OVER_PLANNING_ENVELOPE")
    require(scope["sdk_bytes"] == len(raw)
            and scope["request_sha256"] == hashlib.sha256(raw).hexdigest(),
            "473_SCOPE_AND_ORIGINAL_SDK_WIRE_MISMATCH")
    check_envelope()
    return {
        "arm": arm,
        "ordinal": ordinal,
        "original_sdk_wire_sha256": scope["request_sha256"],
        "sdk_json_bytes": len(raw),
        "planning_max_input_proxy_tokens": PLANNING_MAX_INPUT_PROXY,
        "output_token_cap": MAX_OUTPUT_PER_REQUEST,
        "real_provider_send_allowed": False,
    }


def run_offline_native_budget_join():
    """Prove original #472 real SDK wires enter budget guard before claim.

    The original worker, local Broker, AEAD and scripted Native scorer still
    run; NO paid Provider transport exists in this call graph.
    """
    check_envelope()
    verified = []
    original = prior.claim_packet

    def guarded(arm, ordinal, raw):
        # Called in the Native parent before each local Unix socket claim.
        # The isolated worker independently checks the same SDK bytes.
        # Restart replays also call this helper, but are not new claims.
        if len(verified) < 8:
            record = check_sdk_wire(arm, ordinal, raw)
            verified.append(record)
        return original(arm, ordinal, raw)

    with patch.object(prior, "claim_packet", guarded):
        result = prior.run_native_with_isolated_deny_worker()
    require(len(verified) == 8
            and [(x["arm"], x["ordinal"]) for x in verified] ==
                [(a, i) for a in prior.ARMS for i in range(prior.MAX_TURNS)]
            and result["real_provider_posts"] == 0
            and result["score_status"] == "UNSCORED"
            and result["restart_worker_refused_all_replays"] == 8,
            "473_FULL_OFFLINE_NATIVE_BUDGET_JOIN_FAILED")
    source_hashes = result["hash_only_worker_attempt_receipts"]
    require(all(x["original_sdk_wire_sha256"] ==
                y["sdk_wire_sha256"] and x["arm"] == y["arm"]
                and x["ordinal"] == y["ordinal"]
                for x, y in zip(verified, source_hashes)),
            "473_BUDGET_AND_WORKER_ORIGINAL_WIRE_JOIN_FAILED")
    return {
        "rule": RULE,
        "base_main": BASE_MAIN,
        "case": CASE,
        "model": MODEL,
        "envelope": check_envelope(),
        "offline_sdk_requests_budget_checked": len(verified),
        "same_run_worker_once_claims": result["independent_local_worker_attempts"],
        "same_run_preparse_aead_scripted_responses":
            result["same_run_native_aeAD_preparse_responses"],
        "same_run_scripted_terminal_arms":
            result["same_run_local_scripted_terminal_arms"],
        "same_run_local_scripted_scorers":
            result["same_run_local_scripted_scorer_calls"],
        "restart_replays_denied": result["restart_worker_refused_all_replays"],
        "hash_only_budget_preflight_receipts": verified,
        "real_provider_posts": 0,
        "external_bank_effects": 0,
        "genuine_native_utility": None,
        "score_status": "UNSCORED",
        "owner_authorization": "ABSENT",
        "sender": "NOT_IMPLEMENTED",
        "provider_input_tokens": "NOT_ATTESTED",
        "provider_billing": "NOT_ATTESTED",
        "no_go": True,
    }


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    no_live()
    dest = (ROOT / args.output).resolve()
    require(dest.is_relative_to(ROOT) and not dest.exists()
            and not dest.is_symlink(),
            "473_REPORT_MUST_BE_CREATE_ONLY_INSIDE_REPOSITORY")
    result = run_offline_native_budget_join()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("TASK4_473_REAL_SDK_WIRE_OFFLINE_BUDGET_PREFLIGHT_NO_PROVIDER")


if __name__ == "__main__":
    main()

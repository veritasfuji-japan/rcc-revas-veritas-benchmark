#!/usr/bin/env python3
"""Task4 #324: OFFLINE ONLY, fail-closed prospective request-budget simulation.

Pure Python. No Provider client, sender, credentials, real approvals, effects,
GitHub access, external ledger, trusted production clock or network imports.
Passing this preflight NEVER authorizes a Provider POST.

Rule-of-One: bounded attempt *reservation* and simulated UNKNOWN no-resend.
An in-process journal is NOT a cross-job atomic consumption ledger.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
import hashlib
import json
import os
import re
from threading import Lock

RULE = "TASK4_324_OFFLINE_PREDISPATCH_BUDGET_AND_UNKNOWN_DENY_V1"
PARENT_MAIN = "6554d0faaef979038ec8b300b7dca759a2f274d7"
MODEL = "gpt-4.1-mini-2025-04-14"
CASE = "banking:user_task_4:injection_task_0:direct"
PRESTATE = "8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
ATTACK_SUBJECT = "0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
MAX_PER_ARM = 5
MAX_TOTAL = 10
MAX_INPUT_EACH = 10_000
MAX_OUTPUT_EACH = 256
MAX_INPUT_TOTAL = 100_000
MAX_OUTPUT_TOTAL = 2_560
INPUT_PRICE_M = Decimal("0.40")
OUTPUT_PRICE_M = Decimal("1.60")
SIMULATED_BUDGET_USD = Decimal("0.10")
ARMS = ("A", "B")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SENSITIVE = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
             "OPENAI_BASE_URL", "VERITAS_DATABASE_URL")

class Denied(ValueError):
    pass

def demand(valid: bool, reason: str) -> None:
    if not valid:
        raise Denied(reason)

def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def usd(input_tokens: int, max_output_tokens: int) -> Decimal:
    return ((Decimal(input_tokens) * INPUT_PRICE_M) +
            (Decimal(max_output_tokens) * OUTPUT_PRICE_M)) / Decimal(1_000_000)

@dataclass(frozen=True)
class SimulatedContext:
    branch: str = "main"
    ref: str = "refs/heads/main"
    main_sha: str = PARENT_MAIN
    event: str = "workflow_dispatch"
    run_attempt: int = 1
    environment: str = "task4-provider-protected"
    model: str = MODEL
    case: str = CASE
    prestate_sha256: str = PRESTATE
    attack_subject_sha256: str = ATTACK_SUBJECT
    bank_destination: str = "in_memory_agentdojo_only"
    execution_class: str = "RESEARCH_ONLY_OFFLINE"
    test_fixture_marker: str = "TEST_ONLY_NOT_REAL_HUMAN_APPROVAL"
    user_live_approval: bool = False
    external_spend_cap_verified: bool = False
    secret_available: bool = False
    real_provider_send_enabled: bool = False

def verify_test_context(ctx: SimulatedContext) -> None:
    demand(type(ctx) is SimulatedContext, "EXACT_TEST_CONTEXT_REQUIRED")
    demand(ctx.branch == "main" and ctx.ref == "refs/heads/main" and
           ctx.main_sha == PARENT_MAIN and ctx.event == "workflow_dispatch" and
           type(ctx.run_attempt) is int and ctx.run_attempt == 1 and
           ctx.environment == "task4-provider-protected",
           "PINNED_TEST_RUN_IDENTITY_REQUIRED")
    demand(ctx.model == MODEL and ctx.case == CASE and
           ctx.prestate_sha256 == PRESTATE and
           ctx.attack_subject_sha256 == ATTACK_SUBJECT,
           "PINNED_MODEL_CASE_OR_NATIVE_INJECTION_REQUIRED")
    demand(ctx.bank_destination == "in_memory_agentdojo_only" and
           ctx.execution_class == "RESEARCH_ONLY_OFFLINE" and
           ctx.test_fixture_marker == "TEST_ONLY_NOT_REAL_HUMAN_APPROVAL" and
           ctx.user_live_approval is False and
           ctx.external_spend_cap_verified is False and
           ctx.secret_available is False and
           ctx.real_provider_send_enabled is False,
           "ANY_LIVE_APPROVAL_SECRET_OR_PRODUCTION_EFFECT_DENIED")
    demand(not any(os.environ.get(key) for key in SENSITIVE),
           "REAL_CREDENTIAL_OR_ENDPOINT_IN_ENV_DENIED")

@dataclass(frozen=True)
class Attempt:
    arm: str
    ordinal: int
    input_tokens: int
    max_output_tokens: int
    request_sha256: str

class OfflineReservationJournal:
    """Test-only process-local record. NEVER a sender permission or durable ledger."""
    def __init__(self, ctx: SimulatedContext):
        verify_test_context(ctx)
        self.ctx = ctx
        self._lock = Lock()
        self._seen: set[tuple[str,int]] = set()
        self._per_arm: dict[str,int] = {"A":0,"B":0}
        self._input = 0
        self._output = 0
        self._reserved = Decimal("0")
        self._frozen = False
        self._rows: list[dict] = []
        self._previous = "0" * 64

    @property
    def real_provider_post_allowed(self) -> bool:
        return False

    def reserve_local_only(self, attempt: Attempt) -> dict:
        """Consume in-process uniqueness BEFORE any fake transport response.

        Success means LOCAL_DRY_RUN_RESERVED, never LIVE_POST_APPROVED.
        Expected usage is a caller-provided planning input, not measured tokens.
        """
        with self._lock:
            verify_test_context(self.ctx)
            demand(not self._frozen, "UNKNOWN_OR_CLOSED_NO_RESEND")
            demand(type(attempt) is Attempt and attempt.arm in ARMS and
                   type(attempt.ordinal) is int and attempt.ordinal >= 0 and
                   type(attempt.input_tokens) is int and
                   1 <= attempt.input_tokens <= MAX_INPUT_EACH and
                   type(attempt.max_output_tokens) is int and
                   1 <= attempt.max_output_tokens <= MAX_OUTPUT_EACH and
                   type(attempt.request_sha256) is str and
                   SHA256.fullmatch(attempt.request_sha256) is not None,
                   "EXACT_REQUEST_AND_TOKEN_PROFILE_REQUIRED")
            key = (attempt.arm, attempt.ordinal)
            demand(key not in self._seen and
                   attempt.ordinal == self._per_arm[attempt.arm] and
                   self._per_arm[attempt.arm] < MAX_PER_ARM and
                   len(self._seen) < MAX_TOTAL,
                   "DUPLICATE_NONMONOTONIC_OR_CALL_COUNT_LIMIT")
            next_in = self._input + attempt.input_tokens
            next_out = self._output + attempt.max_output_tokens
            next_cost = self._reserved + usd(attempt.input_tokens,
                                              attempt.max_output_tokens)
            demand(next_in <= MAX_INPUT_TOTAL and next_out <= MAX_OUTPUT_TOTAL and
                   next_cost <= SIMULATED_BUDGET_USD,
                   "AGGREGATE_TOKEN_OR_PLANNING_COST_EXCEEDED")
            self._seen.add(key)
            self._per_arm[attempt.arm] += 1
            self._input, self._output, self._reserved = next_in, next_out, next_cost
            row = {"index": len(self._rows), "arm": attempt.arm,
                   "ordinal": attempt.ordinal,
                   "request_sha256": attempt.request_sha256,
                   "input_tokens_estimated_not_verified": attempt.input_tokens,
                   "output_tokens_reserved_not_used": attempt.max_output_tokens,
                   "reserved_estimated_usd": format(next_cost,"f"),
                   "decision": "LOCAL_DRY_RUN_RESERVED_NO_SEND",
                   "previous_receipt_sha256": self._previous,
                   "real_provider_post_allowed": False}
            row["receipt_sha256"] = digest(row)
            self._previous = row["receipt_sha256"]
            self._rows.append(row)
            return dict(row)

    def mark_simulated_unknown(self, key: tuple[str,int]) -> None:
        with self._lock:
            demand(key in self._seen, "UNKNOWN_MUST_FOLLOW_LOCAL_RESERVATION")
            self._frozen = True

    def close(self) -> None:
        with self._lock:
            self._frozen = True

    def snapshot(self) -> dict:
        with self._lock:
            return {"rule_of_one": RULE, "parent_main_sha": PARENT_MAIN,
                    "provider_sender_present": False,
                    "human_live_approval_available": False,
                    "hard_provider_billing_cap_proven": False,
                    "persistent_cross_job_ledger_proven": False,
                    "external_egress_enforcement_proven": False,
                    "true_tokenizer_before_send_proven": False,
                    "real_provider_post_allowed": False,
                    "simulated_local_reservation_count": len(self._seen),
                    "per_arm": dict(self._per_arm),
                    "estimated_input_tokens": self._input,
                    "reserved_output_tokens": self._output,
                    "worst_case_planning_usd_not_invoice":format(self._reserved,"f"),
                    "simulated_unknown_or_closed": self._frozen,
                    "receipt_chain_head": self._previous,
                    "receipts": [dict(row) for row in self._rows]}

def exact_offline_example() -> dict:
    ctx = SimulatedContext()
    journal = OfflineReservationJournal(ctx)
    for arm in ARMS:
        for n in range(MAX_PER_ARM):
            request_hash = digest({"case": CASE, "arm": arm, "ordinal": n,
                                   "synthetic": True})
            journal.reserve_local_only(Attempt(arm=arm, ordinal=n,
                                               input_tokens=MAX_INPUT_EACH,
                                               max_output_tokens=MAX_OUTPUT_EACH,
                                               request_sha256=request_hash))
    journal.mark_simulated_unknown(("B",MAX_PER_ARM-1))
    result = journal.snapshot()
    demand(result["simulated_local_reservation_count"] == MAX_TOTAL and
           result["worst_case_planning_usd_not_invoice"] == "0.044096" and
           result["simulated_unknown_or_closed"] and
           result["real_provider_post_allowed"] is False,
           "OFFLINE_EXAMPLE_NOT_FAIL_CLOSED")
    result["report_sha256"] = digest(result)
    return result

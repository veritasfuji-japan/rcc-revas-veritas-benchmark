#!/usr/bin/env python3
"""Task1 research ref-CAS: IN-MEMORY MOCK ONLY; NEVER live issuance.

Models a hypothetical GitHub create-ref endpoint's single-winner behavior.
No GitHub client, network, token, subprocess, workflow, paid Provider or tag
write exists here. A simulated 201+readback is NOT permission to send.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
import re
from typing import Callable

SCHEMA = "veritas.task1.research.tag-cas.memory-mock.v1"
REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
RESEARCH_REF = "refs/tags/final128-task1-research-first-two-once-v1"
PRODUCTION_REF = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
MODEL = "gpt-4.1-mini-2025-04-14"
CASE = "banking:user_task_1:injection_task_2:direct"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
RUN = re.compile(r"[1-9][0-9]{5,19}\Z")


class Refused(ValueError):
    """Mock claim rejected; never a signal to dispatch an API call."""


def need(condition: bool, why: str) -> None:
    if condition is not True:
        raise Refused("TASK1_RESEARCH_REF_CAS_MOCK_" + why)


@dataclass(frozen=True)
class MockPlan:
    run_id: str
    main_sha: str
    first_a_sha256: str
    first_b_sha256: str
    proposed_ref: str = RESEARCH_REF

    def validate(self) -> None:
        need(type(self.run_id) is str and RUN.fullmatch(self.run_id) is not None,
             "RUN_FORMAT")
        need(type(self.main_sha) is str
             and SHA40.fullmatch(self.main_sha) is not None,
             "EXACT_MAIN_SHA_FORMAT")
        need(type(self.first_a_sha256) is str
             and SHA256.fullmatch(self.first_a_sha256) is not None
             and type(self.first_b_sha256) is str
             and SHA256.fullmatch(self.first_b_sha256) is not None
             and self.first_a_sha256 == self.first_b_sha256,
             "FIRST_NATIVE_A_B_IDENTICAL_SHA_REQUIRED")
        need(type(self.proposed_ref) is str
             and self.proposed_ref == RESEARCH_REF
             and self.proposed_ref != PRODUCTION_REF,
             "EXACT_RESEARCH_REF_ONLY")


@dataclass(frozen=True)
class MockDecision:
    status: str
    created_ref_post_attempted: bool
    origin_authenticated: bool = False
    live_provider_dispatch_authorized: bool = False
    real_tag_issued: bool = False
    official_native_scoring_eligible: bool = False


class InMemoryFakeGitRefs:
    """Linearizable fake POST for two competing threads; NOT GitHub evidence.

    Fault injection is intentionally only for the exact hardcoded RESEARCH_REF.
    Deletion is a TEST-ONLY simulated administrator attack, showing why a
    mutable/unprotected real ref cannot itself ensure lifetime uniqueness.
    """

    def __init__(self) -> None:
        self._refs: dict[str, str] = {}
        self._lock = Lock()
        self.post_attempts = 0
        self.read_attempts = 0

    def read(self, ref: str, *, fault: str = "normal") -> tuple[int, dict]:
        need(ref == RESEARCH_REF, "ONLY_FAKE_RESEARCH_REF_READ")
        need(fault in ("normal", "http_403", "http_500", "stale_404",
                       "wrong_sha", "malformed_200"), "READ_FAULT_ALLOWLIST")
        with self._lock:
            self.read_attempts += 1
            if fault == "http_403":
                return 403, {}
            if fault == "http_500":
                return 500, {}
            if fault == "stale_404":
                return 404, {}
            actual = self._refs.get(ref)
            if actual is None:
                return 404, {}
            if fault == "malformed_200":
                return 200, {"ref": ref}
            if fault == "wrong_sha":
                return 200, {"ref": ref, "object": {"sha": "f" * 40}}
            return 200, {"ref": ref, "object": {"sha": actual}}

    def post(self, ref: str, sha: str, *, fault: str = "normal") -> tuple[int, dict]:
        need(ref == RESEARCH_REF and type(sha) is str
             and SHA40.fullmatch(sha) is not None,
             "ONLY_FAKE_RESEARCH_REF_CREATE")
        need(fault in (
            "normal", "timeout_before_commit", "timeout_after_commit",
            "http_500_before_commit", "http_500_after_commit",
            "http_409_before_commit", "http_403", "http_429",
            "malformed_201_after_commit", "wrong_sha_201_after_commit",
            "false_success_201_without_commit", "conflict_422_without_ref",
        ), "CREATE_FAULT_ALLOWLIST")
        with self._lock:
            self.post_attempts += 1
            if fault == "timeout_before_commit":
                raise TimeoutError("MOCK_TIMEOUT_BEFORE_COMMIT")
            if fault in ("http_403", "http_429", "http_409_before_commit",
                         "http_500_before_commit", "conflict_422_without_ref"):
                return ({
                    "http_403": 403, "http_429": 429,
                    "http_409_before_commit": 409,
                    "http_500_before_commit": 500,
                    "conflict_422_without_ref": 422,
                }[fault], {})
            if ref in self._refs:
                return 422, {"message": "MOCK_DUPLICATE_REF"}
            if fault == "false_success_201_without_commit":
                return 201, {"ref": ref, "object": {"sha": sha}}
            self._refs[ref] = sha
            if fault == "timeout_after_commit":
                raise TimeoutError("MOCK_TIMEOUT_AFTER_COMMIT")
            if fault == "http_500_after_commit":
                return 500, {}
            if fault == "malformed_201_after_commit":
                return 201, {"ref": ref}
            if fault == "wrong_sha_201_after_commit":
                return 201, {"ref": ref, "object": {"sha": "e" * 40}}
            return 201, {"ref": ref, "object": {"sha": sha}}

    def admin_deletes_mock_ref(self) -> None:
        """ADVERSARIAL FAKE only; reveals missing ref immutability assumptions."""
        with self._lock:
            self._refs.pop(RESEARCH_REF, None)


def decide_mock_claim(
    server: InMemoryFakeGitRefs,
    plan: MockPlan,
    *,
    pre_read_fault: str = "normal",
    post_fault: str = "normal",
    readback_fault: str = "normal",
    after_pre_read: Callable[[], None] | None = None,
) -> MockDecision:
    """One pretend GET -> at most one pretend POST -> one pretend GET.

    Never promote a timeout, HTTP error, redacted response, or stale read to
    a successful claim. Even success is tagged SIMULATION_NOT_AUTHORITY.
    """
    need(type(server) is InMemoryFakeGitRefs, "IN_MEMORY_FAKE_ONLY")
    need(type(plan) is MockPlan, "MOCK_PLAN_REQUIRED")
    plan.validate()
    code, _ = server.read(plan.proposed_ref, fault=pre_read_fault)
    if code == 200:
        return MockDecision("DENY_MOCK_REF_ALREADY_PRESENT", False)
    if code != 404:
        return MockDecision("STOP_MOCK_PREFLIGHT_UNKNOWN", False)

    if after_pre_read is not None:
        need(callable(after_pre_read), "TEST_BARRIER_ONLY")
        after_pre_read()

    try:
        status, made = server.post(plan.proposed_ref, plan.main_sha,
                                   fault=post_fault)
    except TimeoutError:
        # Do not retry or even interpret a later read as permission to send.
        return MockDecision("STOP_MOCK_POST_OUTCOME_UNKNOWN_NO_RETRY", True)

    if status in (409, 422):
        return MockDecision("STOP_MOCK_REF_CREATE_CONFLICT_NO_RETRY", True)
    if status != 201:
        return MockDecision("STOP_MOCK_CREATE_HTTP_UNCERTAIN_NO_RETRY", True)
    if not (type(made) is dict
            and made.get("ref") == plan.proposed_ref
            and type(made.get("object")) is dict
            and made["object"].get("sha") == plan.main_sha):
        return MockDecision("STOP_MOCK_POST_BODY_UNTRUSTED_NO_RETRY", True)

    status, observed = server.read(plan.proposed_ref, fault=readback_fault)
    if not (status == 200 and type(observed) is dict
            and observed.get("ref") == plan.proposed_ref
            and type(observed.get("object")) is dict
            and observed["object"].get("sha") == plan.main_sha):
        return MockDecision("STOP_MOCK_READBACK_MISMATCH_NO_RETRY", True)

    return MockDecision("SIMULATED_CAS_OBSERVED_NOT_LIVE_AUTHORITY", True)

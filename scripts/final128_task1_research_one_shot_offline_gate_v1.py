#!/usr/bin/env python3
"""Task1 research one-shot FSM: LOCAL MOCK REHEARSAL ONLY, NEVER an issuer.

This code has NO Provider client, secrets, GitHub API, network, production tag,
Actions workflow, shell command, or real dispatch function. It cannot approve
real paid execution. A per-directory O_EXCL journal models a claim and two
mock arm intents; private runner disk is NOT a global cross-run lease.

An intent is burned BEFORE the mock response is captured. An uncertain phase
after crash may NEVER be resumed into another arm/model call. The mock capture
is AES-256-GCM sealed BEFORE injected parser validation (PR #434 primitive).
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from scripts import final128_task1_research_capture_first_offline_v1 as capture

SCHEMA = "veritas.task1.research.one-shot.local-mock-gate.v1"
MODE = "OFFLINE_SIMULATION_NO_LIVE_AUTHORITY"
RUN_RE = re.compile(r"[1-9][0-9]{5,19}\Z")
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
FILES = frozenset({
    "00-claim.json", "01-A-intent.json", "02-A-result.json",
    "01-B-intent.json", "02-B-result.json", "03-mock-pair-complete.json",
})


class Refused(RuntimeError):
    """A closed mock gate, NOT an actual authority decision."""


def need(ok: bool, code: str) -> None:
    if ok is not True:
        raise Refused("TASK1_RESEARCH_ONESHOT_MOCK_" + code)


def canonical(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(data: dict) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()


@dataclass(frozen=True)
class MockPlan:
    """Caller assertion, not an authenticated source pin or consent."""
    run_id: str
    main_sha: str
    native_first_a_sha256: str
    native_first_b_sha256: str

    def checked(self) -> None:
        need(type(self.run_id) is str and RUN_RE.fullmatch(self.run_id) is not None,
             "RUN_ID")
        need(type(self.main_sha) is str and SHA40.fullmatch(self.main_sha) is not None,
             "MAIN_SHA")
        need(type(self.native_first_a_sha256) is str
             and SHA256.fullmatch(self.native_first_a_sha256) is not None
             and type(self.native_first_b_sha256) is str
             and SHA256.fullmatch(self.native_first_b_sha256) is not None
             and self.native_first_a_sha256 == self.native_first_b_sha256,
             "EXACT_IDENTICAL_INITIAL_AB_PACKET_SHA")
    
    def claims(self) -> dict:
        self.checked()
        return {
            "schema": SCHEMA,
            "mode": MODE,
            "repository": capture.REPO,
            "case": capture.CASE,
            "model": capture.MODEL,
            "run_id": self.run_id,
            "main_sha": self.main_sha,
            "initial_a_sha256": self.native_first_a_sha256,
            "initial_b_sha256": self.native_first_b_sha256,
            "max_mock_arm_intents": 2,
            "live_calls_authorized": 0,
            "provider_calls_performed": 0,
            "production_tag_ref_mutated": False,
            "official_scoring_eligible": False,
        }


def _private_dir_fd(root: Path) -> int:
    need(isinstance(root, Path), "PRIVATE_PATH_REQUIRED")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        need(stat.S_ISDIR(st.st_mode)
             and stat.S_IMODE(st.st_mode) & 0o077 == 0,
             "PRIVATE_DIRECTORY_0700_REQUIRED")
    except BaseException:
        os.close(fd)
        raise
    return fd


class OfflineMockGate:
    """Fail-closed local FSM, NON-dispatchable by construction.

    Each instance may capture an arm only if THIS SAME instance recorded its
    intent. Re-opening after an uncertain intent cannot resume it. This is a
    teaching/rehearsal property and NOT a durable global execution guard.
    """

    def __init__(self, root: Path, plan: MockPlan):
        need(type(plan) is MockPlan, "MOCK_PLAN_REQUIRED")
        plan.checked()
        self.root, self.plan = root, plan
        self.plan_sha = digest(plan.claims())
        self._armed = None
        fd = _private_dir_fd(root)
        os.close(fd)

    def _entries(self) -> set[str]:
        fd = _private_dir_fd(self.root)
        try:
            return set(os.listdir(fd))
        finally:
            os.close(fd)

    def _create(self, name: str, value: dict) -> None:
        need(name in {
            "00-claim.json", "01-A-intent.json", "02-A-result.json",
            "01-B-intent.json", "02-B-result.json",
            "03-mock-pair-complete.json",
        }, "FIXED_JOURNAL_NAME_ONLY")
        fd = _private_dir_fd(self.root)
        try:
            handle = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=fd,
            )
            try:
                with os.fdopen(handle, "wb") as out:
                    out.write(canonical(value) + b"\n")
                    out.flush()
                    os.fsync(out.fileno())
            finally:
                # fdopen owns the descriptor after successful entry.
                pass
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self, name: str) -> dict:
        fd = _private_dir_fd(self.root)
        try:
            f = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=fd)
            try:
                with os.fdopen(f, "rb") as inp:
                    raw = inp.read(4096 + 1)
            finally:
                pass
        finally:
            os.close(fd)
        need(len(raw) <= 4096, "BOUNDED_JOURNAL")
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Refused("TASK1_RESEARCH_ONESHOT_MOCK_CORRUPTED_JOURNAL") from None
        need(type(parsed) is dict, "JOURNAL_SHAPE")
        return parsed

    def state(self) -> str:
        entries = self._entries()
        a_encrypted = "task1-research-A-" + self.plan.run_id + "-mock.enc.json"
        b_encrypted = "task1-research-B-" + self.plan.run_id + "-mock.enc.json"
        allowed = FILES | {
            a_encrypted, b_encrypted,
        }
        need(entries <= allowed, "UNEXPECTED_OR_PARTIAL_FILE_STOP")
        if not entries:
            return "UNCLAIMED"
        need("00-claim.json" in entries, "NO_PRIOR_CLAIM_STOP")
        claim = self._read("00-claim.json")
        need(claim.get("schema") == SCHEMA
             and claim.get("plan_sha256") == self.plan_sha
             and claim.get("status") == "LOCAL_MOCK_CLAIMED_NOT_AUTHORIZED",
             "WRONG_CLAIM_PLAN_STOP")
        has = lambda n: n in entries
        if not has("01-A-intent.json"):
            need(entries == {"00-claim.json"}, "CLAIM_SEQUENCE_STOP")
            return "CLAIMED"
        need(self._read("01-A-intent.json") == {
            "arm": "A", "plan_sha256": self.plan_sha,
            "status": "BEFORE_UNTRUSTED_MOCK_A_NO_RETRY",
        }, "A_INTENT_MISMATCH")
        if not has("02-A-result.json"):
            need(entries == {"00-claim.json", "01-A-intent.json"},
                 "A_UNCERTAIN_SEQUENCE_STOP")
            return "A_INTENT_UNKNOWN_STOP"
        a = self._read("02-A-result.json")
        need(a.get("arm") == "A" and a.get("plan_sha256") == self.plan_sha
             and a.get("raw_sha256") is not None
             and type(a.get("validated_mock")) is bool
             and has(a_encrypted), "A_EVIDENCE_UNKNOWN_STOP")
        if a["validated_mock"] is False:
            need(not ({"01-B-intent.json", "02-B-result.json",
                      "03-mock-pair-complete.json", b_encrypted} & entries),
                 "A_REJECTED_B_MUST_NEVER_START")
            return "A_VALIDATION_REFUSED_STOP"
        if not has("01-B-intent.json"):
            need(entries == {
                "00-claim.json", "01-A-intent.json",
                "02-A-result.json", a_encrypted,
            }, "A_CAPTURE_SEQUENCE_STOP")
            return "A_MOCK_CAPTURED"
        need(self._read("01-B-intent.json") == {
            "arm": "B", "plan_sha256": self.plan_sha,
            "status": "BEFORE_UNTRUSTED_MOCK_B_NO_RETRY",
        }, "B_INTENT_MISMATCH")
        if not has("02-B-result.json"):
            need(entries == {
                "00-claim.json", "01-A-intent.json",
                "02-A-result.json", a_encrypted, "01-B-intent.json",
            }, "B_UNCERTAIN_SEQUENCE_STOP")
            return "B_INTENT_UNKNOWN_STOP"
        b = self._read("02-B-result.json")
        need(b.get("arm") == "B" and b.get("plan_sha256") == self.plan_sha
             and b.get("raw_sha256") is not None
             and type(b.get("validated_mock")) is bool
             and has(b_encrypted), "B_EVIDENCE_UNKNOWN_STOP")
        if b["validated_mock"] is False:
            need(not has("03-mock-pair-complete.json"),
                 "REJECTED_B_CANNOT_CLOSE")
            return "B_VALIDATION_REFUSED_STOP"
        need(has("03-mock-pair-complete.json"),
             "B_CAPTURED_BUT_CLOSURE_UNKNOWN_STOP")
        need(self._read("03-mock-pair-complete.json") == {
            "status": "MOCK_PAIR_COMPLETE_NOT_PAID_AUTHORITY",
            "plan_sha256": self.plan_sha, "provider_calls": 0,
        }, "INVALID_FINAL_MARKER")
        need(entries == {
            "00-claim.json", "01-A-intent.json", "02-A-result.json",
            a_encrypted, "01-B-intent.json", "02-B-result.json",
            b_encrypted, "03-mock-pair-complete.json",
        }, "EXTRA_FILES_FINAL_STOP")
        return "MOCK_PAIR_COMPLETE_NO_REAL_AUTHORITY"

    def claim(self) -> None:
        need(self.state() == "UNCLAIMED", "CLAIM_NOT_FRESH")
        self._create("00-claim.json", {
            "schema": SCHEMA, "plan_sha256": self.plan_sha,
            "status": "LOCAL_MOCK_CLAIMED_NOT_AUTHORIZED",
        })

    def begin_arm(self, arm: str) -> None:
        need(type(arm) is str and arm in ("A", "B"), "EXACT_ARM")
        need(self._armed is None, "PRIOR_INTENT_UNRESOLVED")
        expected = "CLAIMED" if arm == "A" else "A_MOCK_CAPTURED"
        need(self.state() == expected, "STAGE_NOT_ELIGIBLE_NO_RETRY")
        self._create("01-" + arm + "-intent.json", {
            "arm": arm, "plan_sha256": self.plan_sha,
            "status": "BEFORE_UNTRUSTED_MOCK_" + arm + "_NO_RETRY",
        })
        self._armed = arm

    def seal_mock_then_validate(self, *, arm: str, raw: bytes,
                                fake_test_key: bytes, validator) -> dict:
        need(self._armed == arm and arm in ("A", "B"),
             "SAME_INSTANCE_INTENT_REQUIRED_NO_RESUME")
        need(self.state() == arm + "_INTENT_UNKNOWN_STOP",
             "INTENT_NOT_EXACT_OR_ALREADY_USED")
        # This assignment occurs before any capture attempt. Disk/validator
        # errors mean UNKNOWN and NO second attempt in this instance.
        self._armed = None
        receipt = capture.rehearse_mock_then_validate(
            raw=raw, aes256_key=fake_test_key, output_dir=self.root,
            arm=arm, run_id=self.plan.run_id,
            main_sha=self.plan.main_sha,
            request_sha256=self.plan.native_first_a_sha256,
            validator=validator,
        )
        self._create("02-" + arm + "-result.json", {
            "arm": arm, "plan_sha256": self.plan_sha,
            "raw_sha256": receipt["raw_sha256"],
            "validated_mock": receipt["validated_mock"],
        })
        if arm == "B" and receipt["validated_mock"] is True:
            self._create("03-mock-pair-complete.json", {
                "status": "MOCK_PAIR_COMPLETE_NOT_PAID_AUTHORITY",
                "plan_sha256": self.plan_sha,
                "provider_calls": 0,
            })
        return {
            "state": self.state(),
            "provider_calls": 0,
            "tag_writes": 0,
            "authorized_for_live_provider": False,
            "eligible_for_official_scoring": False,
        }

    @property
    def live_dispatch_allowed(self) -> bool:
        return False

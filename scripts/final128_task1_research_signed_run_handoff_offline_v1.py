#!/usr/bin/env python3
"""OFFLINE MOCK ONLY: signed Task1 first-pair run handoff, NOT authority.

No GitHub client, network, Provider client, token loader, real tag creation,
workflow, or paid dispatch. Synthetic signatures and ephemeral in-memory replay
claims demonstrate data integrity only; never permission to execute a model.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import re
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

REPO = "veritasfuji-japan/rcc-revas-veritas-benchmark"
CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
RESEARCH_REF = "refs/tags/final128-task1-research-first-two-once-v1"
SCHEMA = "veritas.task1.research.signed-run-handoff.offline.v1"
PURPOSE = "SYNTHETIC_EVIDENCE_ONLY_NO_PROVIDER_AUTHORITY"
SIGNER_LABEL = "OFFLINE_TEST_EPHEMERAL_KEY_NOT_ENROLLED"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
RUN = re.compile(r"[1-9][0-9]{5,19}\Z")
FIELDS = frozenset((
    "schema", "purpose", "signer_label", "repository", "case", "model",
    "research_ref", "research_ref_target_sha", "main_sha", "run_id",
    "run_attempt", "issuer_job_id", "sender_job_id",
    "first_request_sha256_by_arm", "max_first_model_posts", "no_retry",
    "synthetic_only", "paid_consent", "ruleset_enrolled",
    "provider_secret_access", "production_tag_consumed",
))


class Refused(ValueError):
    """Ineligible mock evidence; cannot upgrade to real execution approval."""


def need(ok: bool, reason: str) -> None:
    if ok is not True:
        raise Refused("TASK1_SIGNED_HANDOFF_OFFLINE_" + reason)


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class MockJobContext:
    """Untrusted caller-supplied fixture, NOT GitHub authenticated identity."""
    main_sha: str
    run_id: str
    issuer_job_id: str
    sender_job_id: str
    request_sha256: str
    run_attempt: int = 1

    def check(self) -> None:
        need(type(self.main_sha) is str and SHA40.fullmatch(self.main_sha) is not None,
             "MAIN_SHA")
        for value in (self.run_id, self.issuer_job_id, self.sender_job_id):
            need(type(value) is str and RUN.fullmatch(value) is not None,
                 "RUN_OR_JOB_ID")
        need(self.issuer_job_id != self.sender_job_id, "SEPARATE_JOBS")
        need(type(self.request_sha256) is str
             and SHA256.fullmatch(self.request_sha256) is not None,
             "FIRST_NATIVE_REQUEST_HASH")
        need(type(self.run_attempt) is int and self.run_attempt == 1,
             "NO_RERUN_ATTEMPTS")


def mock_payload(context: MockJobContext) -> dict:
    """Construct untrusted mock request; no issuer or approval is contacted."""
    need(type(context) is MockJobContext, "EXACT_CONTEXT")
    context.check()
    return {
        "schema": SCHEMA, "purpose": PURPOSE, "signer_label": SIGNER_LABEL,
        "repository": REPO, "case": CASE, "model": MODEL,
        "research_ref": RESEARCH_REF,
        "research_ref_target_sha": context.main_sha,
        "main_sha": context.main_sha,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "issuer_job_id": context.issuer_job_id,
        "sender_job_id": context.sender_job_id,
        "first_request_sha256_by_arm": {
            "A": context.request_sha256, "B": context.request_sha256,
        },
        "max_first_model_posts": 2, "no_retry": True,
        "synthetic_only": True, "paid_consent": False,
        "ruleset_enrolled": False, "provider_secret_access": False,
        "production_tag_consumed": False,
    }


def validate_mock_payload(payload: dict, expected: MockJobContext) -> None:
    need(type(payload) is dict and set(payload) == FIELDS,
         "EXACT_SIGNED_PAYLOAD_FIELDS")
    need(type(expected) is MockJobContext, "EXACT_CONTEXT")
    expected.check()
    # Exact comparison closes scope, type, claim-target, bound destination,
    # model, digest, rerun, and synthetic flag drift together.
    need(payload == mock_payload(expected)
         and all(type(payload[k]) is type(mock_payload(expected)[k])
                 for k in FIELDS), "SCOPE_OR_JOB_CONTEXT_MISMATCH")
    first = payload["first_request_sha256_by_arm"]
    need(type(first) is dict and set(first) == {"A", "B"}
         and all(type(x) is str for x in first.values()), "INITIAL_A_B_SHAPE")
    need(type(payload["run_attempt"]) is int
         and type(payload["max_first_model_posts"]) is int,
         "STRICT_INTEGER_FIELDS")


def mock_sign(payload: dict, ephemeral_test_private: Ed25519PrivateKey,
              context: MockJobContext) -> dict:
    """Only sign a *synthetic* payload with a supplied in-memory test key.

    Never loads a key, GitHub token, environment or actual Provider credential.
    """
    need(isinstance(ephemeral_test_private, Ed25519PrivateKey),
         "EPHEMERAL_TEST_SIGNING_KEY_REQUIRED")
    validate_mock_payload(payload, context)
    signature = ephemeral_test_private.sign(canonical(payload))
    return {
        "payload": payload,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "algorithm": "ED25519_OFFLINE_TEST_ONLY",
    }


@dataclass(frozen=True)
class MockReview:
    status: str
    mock_integrity_ok: bool = False
    provider_dispatch_authorized: bool = False
    claim_origin_authenticated: bool = False
    github_identity_authenticated: bool = False
    real_ref_created: bool = False
    real_ruleset_installed: bool = False
    cost_approved: bool = False
    official_scoring_eligible: bool = False


class EphemeralReplayLedger:
    """Thread-safe single-process mock; NOT durable across Actions runners."""
    def __init__(self) -> None:
        self._lock = Lock()
        self._seen: set[str] = set()

    def mark_once(self, fingerprint: str) -> bool:
        need(type(fingerprint) is str and SHA256.fullmatch(fingerprint) is not None,
             "LEDGER_FINGERPRINT")
        with self._lock:
            if fingerprint in self._seen:
                return False
            self._seen.add(fingerprint)
            return True


def verify_and_mark_mock(
    signed: object, *, expected: MockJobContext,
    pinned_test_public_key: Ed25519PublicKey,
    replay_ledger: EphemeralReplayLedger,
) -> MockReview:
    """Verify exact fake contract, signature, context, and ephemeral replay.

    No path through this function grants model execution. A signer's key and
    a 'trusted' GitHub context must be enrolled by a separate future authority;
    these are user-supplied mock values here, so source identity is UNPROVEN.
    """
    need(type(signed) is dict and set(signed) == {
        "payload", "signature_base64", "algorithm",
    } and signed.get("algorithm") == "ED25519_OFFLINE_TEST_ONLY",
         "SIGNED_ENVELOPE_SHAPE")
    need(isinstance(pinned_test_public_key, Ed25519PublicKey),
         "EXPLICIT_TEST_PUBLIC_KEY_REQUIRED")
    need(type(replay_ledger) is EphemeralReplayLedger,
         "EPHEMERAL_LEDGER_ONLY")
    payload = signed["payload"]
    validate_mock_payload(payload, expected)
    encoded = signed["signature_base64"]
    need(type(encoded) is str and len(encoded) <= 128,
         "SIGNATURE_FORMAT")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise Refused("TASK1_SIGNED_HANDOFF_OFFLINE_INVALID_SIGNATURE_ENCODING") from None
    need(len(signature) == 64 and base64.b64encode(signature).decode("ascii") == encoded,
         "CANONICAL_SIGNATURE")
    data = canonical(payload)
    try:
        pinned_test_public_key.verify(signature, data)
    except InvalidSignature:
        raise Refused("TASK1_SIGNED_HANDOFF_OFFLINE_SIGNATURE_MISMATCH") from None
    # Reservation is AFTER verification and context checking. Same-process
    # claim is one-winner, but a new ledger instance can accept a replay.
    fingerprint = hashlib.sha256(data + signature).hexdigest()
    need(replay_ledger.mark_once(fingerprint), "DUPLICATE_HANDOFF_STOP")
    return MockReview("SIGNED_OFFLINE_MOCK_MATCH_NO_LIVE_AUTHORITY", True)

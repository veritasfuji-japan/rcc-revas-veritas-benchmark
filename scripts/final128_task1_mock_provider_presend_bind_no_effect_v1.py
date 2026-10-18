#!/usr/bin/env python3
"""OFFLINE Task1: mock Provider send boundary with a source-owned fake issuer.

Only the pre-existing #441 frozen GitHub observation checker is reused.
All positive permissions are freshly generated synthetic SAME-PROCESS fixtures,
never real GitHub / OIDC / human / Provider authority. No Provider SDK,
HTTP client, network, secrets, subprocess, CLI, workflow or real Bind adapter.
This code is NOT installed on the live #423 Provider egress path.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from threading import Lock

from scripts import final128_task1_live_ref_run_authority_gap_offline_v1 as evidence

SCHEMA = "veritas.final128.task1.mock-provider-presend-bind-no-effect.v1"
PURPOSE = "IN_PROCESS_SYNTHETIC_FIXTURE_NEVER_LIVE_AUTHORITY"
REPO = evidence.REPO
REF = evidence.RESEARCH_REF
SHA = evidence.FROZEN_SHA
PRODUCTION_REF = evidence.PRODUCTION_REF
CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
FAKE_RUN = "OFFLINE_FIXTURE_RUN_NOT_GITHUB"
FAKE_ISSUER = "OFFLINE_FIXTURE_ISSUER_NOT_ENROLLED"
FAKE_SENDER = "OFFLINE_FIXTURE_SENDER_NOT_AUTHENTICATED"
PACKET = b'{"offline_test_only":true,"synthetic_native_first_packet":"A_B_EQUAL"}'
PACKET_SHA256 = hashlib.sha256(PACKET).hexdigest()
MAX_PACKET_BYTES = 2048
ARMS = ("A", "B")
ALLOWLIST = frozenset((
    "schema", "purpose", "repository", "research_ref", "research_sha",
    "case_id", "model", "run_id", "run_attempt", "issuer", "sender",
    "arm", "packet_sha256", "expires_at_fake_tick", "max_fake_attempts",
    "no_retry", "production_tag_consumed", "paid_approved",
))
FAKE_ACK = "OFFLINE_LOCAL_FAKE_RESPONSE_NOT_PROVIDER"


class Refused(ValueError):
    """No fake sending was admitted."""


class UnknownAfterAttempt(Refused):
    """Fake send was attempted; remain stopped, do not retry."""


def need(ok: bool, reason: str) -> None:
    if ok is not True:
        raise Refused("TASK1_MOCK_PROVIDER_BIND_" + reason)


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def claims_for(arm: str) -> dict:
    need(type(arm) is str and arm in ARMS, "ARM")
    return {
        "schema": SCHEMA,
        "purpose": PURPOSE,
        "repository": REPO,
        "research_ref": REF,
        "research_sha": SHA,
        "case_id": CASE,
        "model": MODEL,
        "run_id": FAKE_RUN,
        "run_attempt": 1,
        "issuer": FAKE_ISSUER,
        "sender": FAKE_SENDER,
        "arm": arm,
        "packet_sha256": PACKET_SHA256,
        "expires_at_fake_tick": 2,
        "max_fake_attempts": 2,
        "no_retry": True,
        "production_tag_consumed": False,
        "paid_approved": False,
    }


@dataclass(frozen=True)
class MockPermit:
    """Signed test fixture, NOT independently enrolled execution authority."""
    claims: object
    mac_sha256: str


class InProcessFixtureIssuer:
    """Ephemeral mock HMAC key; never persisted or trusted by any real sender."""

    def __init__(self) -> None:
        self._mock_key = secrets.token_bytes(32)

    def issue(self, arm: str) -> MockPermit:
        payload = claims_for(arm)
        mac = hmac.new(self._mock_key, canonical(payload), hashlib.sha256)
        return MockPermit(payload, mac.hexdigest())

    def check(self, permit: object, arm: str) -> None:
        need(type(permit) is MockPermit
             and type(permit.claims) is dict
             and set(permit.claims) == ALLOWLIST,
             "MISSING_OR_AMBIGUOUS_MOCK_PERMIT")
        expected = claims_for(arm)
        # Exact value AND exact type: bool must not masquerade as int.
        need(set(expected) == set(permit.claims)
             and all(type(permit.claims[k]) is type(expected[k])
                     and permit.claims[k] == expected[k] for k in expected),
             "FAKE_RUN_OR_SCOPE_DRIFT")
        need(type(permit.mac_sha256) is str
             and len(permit.mac_sha256) == 64,
             "MALFORMED_SYNTHETIC_MAC")
        expected_mac = hmac.new(
            self._mock_key, canonical(expected), hashlib.sha256
        ).hexdigest()
        need(hmac.compare_digest(permit.mac_sha256, expected_mac),
             "WRONG_SYNTHETIC_ISSUER")


class InMemoryFakeProviderPort:
    """Local-only fake sink, no HTTP or socket imports; not access-controlled.

    Callers in the same process can invoke this object directly. This demo
    is NOT an OS/network/IAM non-bypassability demonstration.
    """

    def __init__(self, failure: str = "none") -> None:
        need(type(failure) is str and failure in (
            "none", "A_TIMEOUT", "B_TIMEOUT", "A_BAD_ACK", "B_BAD_ACK",
        ), "FAKE_FAILURE_MODE")
        self.failure = failure
        self.attempts: list[str] = []

    def deliver(self, arm: str, raw: bytes) -> dict:
        need(type(arm) is str and arm in ARMS
             and type(raw) is bytes and raw == PACKET,
             "FAKE_PORT_EXACT_PACKET_ONLY")
        self.attempts.append(arm)
        if self.failure == arm + "_TIMEOUT":
            raise TimeoutError("OFFLINE_UNKNOWN_AFTER_FAKE_ATTEMPT")
        response = {
            "marker": FAKE_ACK,
            "arm": arm,
            "packet_sha256": PACKET_SHA256,
            "ordinal": len(self.attempts),
        }
        if self.failure == arm + "_BAD_ACK":
            response["packet_sha256"] = "f" * 64
        return response


class MockPreSendBoundary:
    """Source-owned mock gate: validate immediately before local fake send.

    Consumed/unknown phase is sink-instance-owned, shared by mock workers
    referring to this *same* object. Creating a fresh object resets state.
    """

    def __init__(self, fixture_issuer: InProcessFixtureIssuer,
                 fake_port: InMemoryFakeProviderPort) -> None:
        need(type(fixture_issuer) is InProcessFixtureIssuer,
             "ONLY_SYNTHETIC_ISSUER_ALLOWED")
        need(type(fake_port) is InMemoryFakeProviderPort,
             "ONLY_LOCAL_FAKE_PORT_ALLOWED")
        self._issuer = fixture_issuer
        self._port = fake_port
        self._lock = Lock()
        self._phase = "FRESH"
        self._receipts: list[dict] = []

    def attempt(self, *, arm: str, raw: bytes, permit: object,
                frozen_snapshot: object, fake_tick: int = 1,
                caller_run_claim: object = None) -> dict:
        # The #441 snapshot validator always says live dispatch is NO-GO.
        # Its PASS means only historical evidence consistency; the positive
        # path below depends on a separate *synthetic test fixture*.
        try:
            review = evidence.review_frozen_snapshot(
                frozen_snapshot, caller_run_claim=caller_run_claim
            )
        except (evidence.Refused, TypeError, KeyError) as exc:
            raise Refused("TASK1_MOCK_PROVIDER_BIND_FROZEN_EVIDENCE_DENIED") from exc
        need(review.authorized_to_send_provider is False
             and review.run_job_origin_authenticated is False
             and review.decision == "PAID_TASK1_NO_GO",
             "SNAPSHOT_MUST_NOT_GRANT_LIVE_AUTHORITY")
        need(type(arm) is str and arm in ARMS, "EXACT_ARM")
        need(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET_BYTES
             and raw == PACKET
             and hashlib.sha256(raw).hexdigest() == PACKET_SHA256,
             "EXACT_SYNTHETIC_PACKET")
        need(type(fake_tick) is int and 0 <= fake_tick <= 2,
             "FAKE_EXPIRY_OR_TYPE")
        self._issuer.check(permit, arm)
        with self._lock:
            expected_arm = "A" if self._phase == "FRESH" else (
                "B" if self._phase == "A_ACK" else None
            )
            need(expected_arm == arm, "REPLAY_WRONG_ORDER_OR_UNKNOWN_STOP")
            # Record an irreversible ATTEMPT / UNKNOWN before fake transport.
            self._phase = "UNKNOWN_AFTER_" + arm
            try:
                response = self._port.deliver(arm, raw)
                expected = {
                    "marker": FAKE_ACK,
                    "arm": arm,
                    "packet_sha256": PACKET_SHA256,
                    "ordinal": 1 if arm == "A" else 2,
                }
                if (type(response) is not dict or set(response) != set(expected)
                        or any(type(response[k]) is not type(expected[k])
                               or response[k] != expected[k] for k in expected)):
                    raise ValueError("MALFORMED_FAKE_ACK")
            except Exception as exc:
                # The fake effect may have happened; never repeat this arm.
                raise UnknownAfterAttempt(
                    "TASK1_MOCK_PROVIDER_BIND_UNKNOWN_AFTER_FAKE_ATTEMPT_NO_RETRY"
                ) from exc
            receipt = {
                "arm": arm,
                "fake_packet_sha256": PACKET_SHA256,
                "mock_only": True,
                "provider_calls": 0,
                "paid_authority": False,
                "run_authenticated": False,
            }
            self._receipts.append(receipt)
            self._phase = "A_ACK" if arm == "A" else "PAIR_ACK"
            return dict(receipt)

    def summary(self) -> dict:
        with self._lock:
            return {
                "phase": self._phase,
                "fake_attempts": tuple(self._port.attempts),
                "fake_receipts": len(self._receipts),
                "real_provider_calls": 0,
                "live_execution_authorized": False,
                "global_durable_single_use_proven": False,
                "independent_issuer_authenticated": False,
                "real_veritas_bind_called": False,
                "native_utility_scored": False,
            }

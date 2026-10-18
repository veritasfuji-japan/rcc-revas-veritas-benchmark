#!/usr/bin/env python3
"""Task1 independent Provider-executor acceptance contract (OFFLINE, NO EFFECT).

Pure-data architecture audit, not a runtime gate. No GitHub/API/Provider access,
secrets, workflows or shared remote store. Neither JSON nor green CI grants
paid Provider authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

SCHEMA = "veritas.final128.task1.independent-executor-acceptance.offline.v1"
CASE = "banking:user_task_1:injection_task_2:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
REPOSITORY = "veritasfuji-japan/rcc-revas-veritas-benchmark"
CONTRACT_FILE = (Path(__file__).resolve().parents[1] / "docs/optimization/"
                 "FINAL128_TASK1_INDEPENDENT_EXECUTOR_ACCEPTANCE_OFFLINE_V1.json")
BLOCKERS = (
    "EXTERNALLY_AUTHENTICATED_ISSUER_AND_RECIPIENT_NOT_PROVEN",
    "ISSUER_AND_RUNNER_PROVIDER_CREDENTIAL_DENIAL_NOT_PROVEN",
    "EXECUTOR_ONLY_PROVIDER_EGRESS_NOT_PROVEN",
    "EXECUTOR_OWNED_REMOTE_ATOMIC_MULTI_RUNNER_LEDGER_NOT_PROVEN",
    "PROVIDER_DISPATCH_BOUND_TO_REAL_BIND_AND_LEDGER_NOT_PROVEN",
    "LIVE_423_SENDER_STILL_OUTSIDE_INDEPENDENT_GATE",
    "PROVIDER_BILLING_HARD_STOP_NOT_PROVEN",
    "FRESH_PAID_TASK1_CONSENT_NOT_GRANTED",
)


class Refused(ValueError):
    """Tampered or improperly promoted offline design input."""


@dataclass(frozen=True)
class Review:
    status: str
    blockers: tuple[str, ...]
    design_integrity_only: bool = True
    real_iam_installed: bool = False
    remote_global_single_use_proven: bool = False
    real_provider_non_bypassability_proven: bool = False
    paid_dispatch_authorized: bool = False
    can_execute_provider: bool = False


def _exact(got: object, expected: object) -> bool:
    """Closed-world JSON equality with strict bool/int separation."""
    if type(got) is not type(expected):
        return False
    if type(expected) is dict:
        return set(got) == set(expected) and all(
            _exact(got[k], v) for k, v in expected.items()
        )
    if type(expected) is list:
        return len(got) == len(expected) and all(
            _exact(a, b) for a, b in zip(got, expected)
        )
    return got == expected


def expected_contract() -> dict:
    """Source-owned REQUIREMENTS, never an assertion they are installed."""
    return {
        "schema": SCHEMA,
        "purpose": "INERT_EXTERNAL_EXECUTOR_ACCEPTANCE_DESIGN_ONLY",
        "repository": REPOSITORY,
        "case": CASE,
        "model": MODEL,
        "source_prs": [405, 410, 411, 412, 423, 437, 442, 445, 446],
        "trust_domains": {
            "issuer": {
                "principal": "INDEPENDENT_ENROLLED_ISSUER_REQUIRED",
                "provider_credentials": "DENIED",
                "remote_ledger_mutation": "DENIED",
            },
            "github_runner": {
                "principal": "UNTRUSTED_ORCHESTRATION_ONLY",
                "provider_credentials": "DENIED",
                "issuer_signing_credentials": "DENIED",
                "provider_network_egress": "DENIED",
            },
            "executor": {
                "principal": "INDEPENDENT_SENDER_REQUIRED",
                "provider_credentials": "EXECUTOR_ONLY",
                "issuer_signing_credentials": "DENIED",
                "permit_verification": "ENROLLED_IDENTITY_AND_AUDIENCE_REQUIRED",
                "bind_at_last_boundary": "REAL_VERITAS_BIND_REQUIRED",
                "provider_network_egress": "EXECUTOR_ONLY",
            },
            "ledger": {
                "principal": "EXECUTOR_CONTROLLED_SHARED_REMOTE_STORE_REQUIRED",
                "owner": "NOT_THE_CALLER_OR_EPHEMERAL_RUNNER",
                "atomic_reserve": "COMMIT_BEFORE_POSSIBLE_PROVIDER_POST",
                "cross_runner_scope": "GLOBALLY_SHARED_ACROSS_ALL_TASK1_ATTEMPTS",
                "delete_reset_replay": "DENIED",
            },
        },
        "lease": {
            "binding": ["repository", "commit_sha", "case", "model",
                        "run_id", "run_attempt", "recipient_principal",
                        "arm", "request_sha256", "approval_digest"],
            "global_unique_key": ["repository", "case", "arm", "approval_digest"],
            "required_sequence": [
                "AUTHENTICATE_INDEPENDENT_ISSUER_AND_RUNNER_CONTEXT",
                "VERIFY_SIGNED_PERMIT_EXACT_SCOPE_AND_RECIPIENT",
                "CHECK_FRESH_CONSENT_AND_REAL_VERITAS_BIND",
                "ATOMICALLY_PERSIST_UNKNOWN_ATTEMPT_IN_REMOTE_LEDGER",
                "EXECUTOR_ONLY_SINGLE_PROVIDER_POST_NO_RETRY",
                "PERSIST_SEALED_RESPONSE_OR_KEEP_UNKNOWN",
            ],
            "arm_order": "B_ONLY_AFTER_VERIFIED_A_ACK",
            "unknown_result": "STOP_NO_RETRY_NO_AUTOMATIC_CLEAR",
            "ledger_outage": "STOP_NO_SEND",
            "invalid_attestation": "STOP_NO_SEND",
            "binding_mismatch": "STOP_NO_SEND",
            "direct_sender_bypass": "DENY_WITH_CREDENTIAL_AND_EGRESS_POLICY",
        },
        "current_evidence": {
            "real_enrolled_issuer_and_sender": False,
            "provider_secret_exclusivity_verified": False,
            "remote_atomic_ledger_multi_runner_verified": False,
            "no_bypass_egress_verified": False,
            "423_sender_integrated_into_executor": False,
            "real_bind_last_boundary_verified": False,
            "paid_consent_granted": False,
            "provider_budget_hard_cap_verified": False,
            "live_provider_requests": 0,
            "global_consumption_claim": "NOT_PROVEN",
        },
        "status": "PAID_TASK1_NO_GO_DESIGN_NOT_DEPLOYED",
    }


def parse_strict(raw: bytes) -> object:
    """Reject duplicate keys, nonfinite constants and huge input."""
    if type(raw) is not bytes or len(raw) > 32768:
        raise Refused("CONTRACT_BYTES_EXCEEDED_OR_WRONG_TYPE")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise Refused("DUPLICATE_CONTRACT_FIELD")
            out[key] = value
        return out
    def no_constant(value):
        raise Refused("NONFINITE_CONTRACT_VALUE_" + value)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=no_constant)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Refused("INVALID_CONTRACT_JSON") from exc


def review_contract(value: object) -> Review:
    if not _exact(value, expected_contract()):
        raise Refused("DRIFT_OR_FALSE_ELEVATION_OF_INERT_CONTRACT")
    return Review(status="OFFLINE_REQUIREMENTS_INTEGRITY_ONLY_PAID_NO_GO",
                  blockers=BLOCKERS)


def review_file(path: Path = CONTRACT_FILE) -> Review:
    if not isinstance(path, Path) or not path.is_file() or path.is_symlink():
        raise Refused("EXACT_LOCAL_FILE_REQUIRED")
    return review_contract(parse_strict(path.read_bytes()))


def review_live_claims(claims: object) -> Review:
    """Never promote self-reported claims to trusted external evidence."""
    if type(claims) is not dict or any(type(k) is not str for k in claims):
        raise Refused("INVALID_SELF_REPORTED_PROOF")
    forbidden = {"provider_api_key", "authorization", "secret", "token"}
    if any(any(term in k.lower() for term in forbidden) for k in claims):
        raise Refused("SECRETS_ARE_NEVER_EVIDENCE_INPUTS")
    return Review(status="SELF_REPORTED_ATTESTATIONS_NOT_EXTERNAL_PROOF_NO_GO",
                  blockers=BLOCKERS)

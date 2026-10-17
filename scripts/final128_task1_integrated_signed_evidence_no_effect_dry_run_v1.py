#!/usr/bin/env python3
"""Task1 signed-evidence integration rehearsal: local synthetic data only.

This module cannot issue GitHub refs, reach GitHub/OpenAI APIs, or authorize
Provider calls. The intentionally PUBLIC fixture key is not a trust anchor.
"""
from __future__ import annotations

import base64
import copy
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import final128_task1_privileged_ruleset_attestation_offline_v1 as review

PREFIX = "TASK1_INTEGRATED_NO_EFFECT_V1_"
# Deliberately public fixture, identical to the synthetic test key of PR #430.
# NEVER enroll it, store it as an Actions Secret, or use it for real attestations.
_SYNTHETIC_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
_SYNTHETIC_PUBLIC = _SYNTHETIC_SIGNER.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_FAKE_REVISION = "2026-01-01T00:00:00Z"  # NOT a GitHub Ruleset reading.
NO_GO = "NO_GO_UNTRUSTED_SYNTHETIC_SIGNER_AND_NO_ATOMIC_POLICY_FENCE"
DENY = "DENY_NO_VALID_SIGNED_EVIDENCE"
EXPLICITLY_MISSING_PRODUCTION_CONTROLS = (
    "PRIVILEGED_GITHUB_OBSERVER_NOT_CONNECTED",
    "PRODUCTION_SIGNING_KEY_NOT_ENROLLED",
    "FRESH_PRIVILEGED_READ_NOT_CONNECTED",
    "ADMIN_CHANGE_RACE_NOT_CLOSED",
    "ACTUAL_TAG_ISSUER_NOT_IMPLEMENTED",
    "PROVIDER_DISPATCH_NOT_AUTHORIZED",
)


def canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z",
    )


def hypothetical_evidence(now: datetime, sha: str, run_id: str, nonce: str) -> dict:
    """Create ONLY a made-up Ruleset snapshot; no GitHub result is consulted."""
    return {
        "schema": review.SCHEMA,
        "audience": review.AUDIENCE,
        "repository": review.REPOSITORY,
        "main_sha": sha,
        "run_id": run_id,
        "challenge_hex": nonce,
        "singleton_ref": review.TAG,
        "ruleset_id": review.RULESET_ID,
        "ruleset_updated_at": _FAKE_REVISION,
        "observed_at": canonical_utc(now - timedelta(seconds=1)),
        "expires_at": canonical_utc(now + timedelta(seconds=45)),
        "ruleset": {
            "source": review.REPOSITORY,
            "source_type": "Repository",
            "target": "tag",
            "enforcement": "active",
            "conditions": {
                "ref_name": {
                    "include": sorted(review.REQUIRED_REF_INCLUDES),
                    "exclude": [],
                },
            },
            "rules": [{"type": x} for x in sorted(review.REQUIRED_RULE_TYPES)],
            "bypass_actors": [],
        },
    }


def sign_synthetic_evidence(evidence: dict) -> dict:
    """Non-secret fixture signing. Never a privileged GitHub attestation."""
    payload = copy.deepcopy(evidence)
    return {
        "evidence": payload,
        "signature_b64": base64.b64encode(
            _SYNTHETIC_SIGNER.sign(review.canonical_evidence_bytes(payload))
        ).decode("ascii"),
    }


def simulated_final_boundary(signed_evidence_check: str) -> str:
    """Deliberate fail-closed sink. No GRANT/ISSUE path exists."""
    return NO_GO if signed_evidence_check == review.OFFLINE_ONLY else DENY


def exercise_offline_cases(sha: str, run_id: str, nonce: str, now: datetime) -> list:
    """Exercise verifier and NO-EFFECT issuer decision using only synthetic inputs."""
    evidence = hypothetical_evidence(now, sha, run_id, nonce)
    normal = sign_synthetic_evidence(evidence)
    context = {
        "trusted_public_key_bytes": _SYNTHETIC_PUBLIC,
        "expected_sha": sha,
        "expected_run_id": run_id,
        "expected_challenge_hex": nonce,
        "privileged_current_ruleset_updated_at": _FAKE_REVISION,
        "observed_singleton_absent": True,  # synthetic assumption, NOT a GET
        "now": now,
    }

    def inspect(envelope, **changes):
        kwargs = dict(context)
        kwargs.update(changes)
        return review.review_candidate_offline(envelope, **kwargs)

    def resigned(modify):
        changed = copy.deepcopy(evidence)
        modify(changed)
        return sign_synthetic_evidence(changed)

    stale = resigned(lambda x: x.update({
        "observed_at": canonical_utc(now - timedelta(seconds=200)),
        "expires_at": canonical_utc(now - timedelta(seconds=190)),
    }))
    missing_bypass = resigned(lambda x: x["ruleset"].pop("bypass_actors"))
    injected_bypass = resigned(
        lambda x: x["ruleset"]["bypass_actors"].append({"actor_type": "Team", "actor_id": 999})
    )
    tampered = copy.deepcopy(normal)
    tampered["evidence"]["ruleset"]["rules"] = []

    # Every test expects a fixed result; a surprising result fails the workflow.
    cases = [
        ("SYNTHETIC_SIGNED_BASELINE", inspect(normal), review.OFFLINE_ONLY),
        ("TAMPERED_AFTER_SIGNATURE", inspect(tampered), "DENY_SIGNATURE"),
        ("EXPIRED_EVIDENCE", inspect(stale), "DENY_TIME"),
        ("BYPASS_FIELD_REDACTED", inspect(missing_bypass), "DENY_RULESET_SNAPSHOT"),
        ("BYPASS_ACTOR_PRESENT", inspect(injected_bypass), "DENY_RULESET_SNAPSHOT"),
        ("WRONG_RUN_REPLAY", inspect(normal, expected_run_id=str(int(run_id) + 1)), "DENY_RUNTIME_BINDING"),
        ("WRONG_SHA_REPLAY", inspect(normal, expected_sha="f" * 40 if sha != "f" * 40 else "e" * 40), "DENY_RUNTIME_BINDING"),
        ("WRONG_NONCE_REPLAY", inspect(normal, expected_challenge_hex="00" * 32 if nonce != "00" * 32 else "11" * 32), "DENY_RUNTIME_BINDING"),
        ("NO_ENROLLED_TRUST_ANCHOR", inspect(normal, trusted_public_key_bytes=None), "DENY_TRUST_ANCHOR_NOT_ENROLLED"),
        ("SINGLETON_PRESENT", inspect(normal, observed_singleton_absent=False), "DENY_SINGLETON_NOT_PROVEN_ABSENT"),
        ("SINGLETON_UNKNOWN", inspect(normal, observed_singleton_absent=None), "DENY_SINGLETON_NOT_PROVEN_ABSENT"),
        ("PRIVILEGED_REVISION_CHANGED", inspect(normal, privileged_current_ruleset_updated_at="2026-01-01T00:00:01Z"), "DENY_PRIVILEGED_CURRENT_REVISION"),
        ("NO_FRESH_PRIVILEGED_REVISION", inspect(normal, privileged_current_ruleset_updated_at=None), "DENY_PRIVILEGED_CURRENT_REVISION"),
    ]
    for label, actual, expected in cases:
        if actual != expected:
            raise AssertionError(PREFIX + "UNEXPECTED_" + label)
        final = simulated_final_boundary(actual)
        if final not in (NO_GO, DENY):
            raise AssertionError(PREFIX + "UNEXPECTED_ISSUER_AUTHORITY_" + label)
    if simulated_final_boundary(review.OFFLINE_ONLY) != NO_GO:
        raise AssertionError(PREFIX + "UNEXPECTED_BASELINE_ADMISSION")
    return [(label, actual, simulated_final_boundary(actual)) for label, actual, _ in cases]


def main(environ=None) -> int:
    e = os.environ if environ is None else environ
    if not (
        e.get("GITHUB_ACTIONS") == "true"
        and e.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and e.get("GITHUB_REPOSITORY") == review.REPOSITORY
        and e.get("GITHUB_ACTOR") == "veritasfuji-japan"
        and e.get("GITHUB_REF") == "refs/heads/main"
        and e.get("GITHUB_RUN_ATTEMPT") == "1"
        and re.fullmatch(r"[a-f0-9]{40}", e.get("GITHUB_SHA", ""))
        and re.fullmatch(r"[1-9][0-9]{5,19}", e.get("GITHUB_RUN_ID", ""))
    ):
        print(PREFIX + "STOP_BAD_RUNTIME_CONTEXT")
        return 1

    print(PREFIX + "SYNTHETIC_ONLY_NOT_GITHUB_OBSERVATION")
    try:
        nonce = secrets.token_hex(32)
        now = datetime.now(timezone.utc)
        cases = exercise_offline_cases(
            e["GITHUB_SHA"], e["GITHUB_RUN_ID"], nonce, now
        )
        for label, result, decision in cases:
            print(PREFIX + "CASE_" + label + "_" + result)
            if decision not in (NO_GO, DENY):
                raise AssertionError("non-denial")
        for reason in EXPLICITLY_MISSING_PRODUCTION_CONTROLS:
            print(PREFIX + "MISSING_" + reason)
        print(PREFIX + "ISSUER_" + NO_GO)
        print(PREFIX + "NO_GITHUB_REF_WRITE_NO_PROVIDER_CALL_NO_LIVE_AUTHORITY")
        print(PREFIX + "PASS_OFFLINE_CASES_" + str(len(cases)))
        return 0
    except BaseException:
        # Fixed output only; never dump cryptographic payload, nonce or credentials.
        print(PREFIX + "STOP_OFFLINE_REHEARSAL_FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())

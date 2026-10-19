#!/usr/bin/env python3
"""Task4 #474: offline-only, independent Ed25519 authority verifier.

This is an isolated synthetic authority *refusal* proof. It never approves a
real Provider POST and does not claim real IAM/credential/egress isolation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_473_offline_sender_budget_envelope_no_go_v1 as prior

ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_474_INDEPENDENT_SIGNED_AUTHORITY_LOCAL_DENY_ONLY_NO_GO_V1"
TRIAL = "task4-474-synthetic-never-authorized"
AUDIENCE = "task4-474-local-no-send-preflight"
OWNER = "OFFLINE_SYNTHETIC_FIXTURE_NOT_REAL_APPROVAL"
SENSITIVE = prior.REJECTED_ENV + (
    "TASK4_474_APPROVAL", "TASK4_474_LIVE", "TASK4_474_SIGNING_KEY",
)


class Denied(RuntimeError):
    pass


def need(condition, reason):
    if condition is not True:
        raise Denied(reason)


def deny_live():
    need(not any(os.environ.get(x) for x in SENSITIVE),
         "474_LIVE_CONTEXT_OR_KEY_FORBIDDEN")
    prior.no_live()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def make_claim(*, arm, ordinal, wire_sha, policy_digest, nonce):
    need(arm in ("A", "B") and type(ordinal) is int and 0 <= ordinal < 4,
         "474_SCOPE_ARM_ORDINAL_DENIED")
    need(type(wire_sha) is str and len(wire_sha) == 64
         and type(policy_digest) is str and len(policy_digest) == 64
         and type(nonce) is str and 1 <= len(nonce) <= 64,
         "474_INVALID_SCOPE_DIGEST")
    return {
        "schema": RULE,
        "audience": AUDIENCE,
        "owner": OWNER,
        "trial": TRIAL,
        "model": prior.MODEL,
        "case": prior.CASE,
        "arm": arm,
        "ordinal": ordinal,
        "request_sha256": wire_sha,
        "policy_sha256": policy_digest,
        "nonce": nonce,
        "max_completion_tokens": 256,
        "provider_post_allowed": False,
    }


def sign_fixture(key, claim):
    return key.sign(canonical(claim))


def verify_local_authority(*, public_key, claim, signature, expected,
                           consumed, revoked=False):
    """A verifier gets ONLY the public key; the signer is a separate object.

    A signature is proof of synthetic provenance, NOT execution authority.
    Every successful verification still results in an unconditional NO_SEND.
    """
    deny_live()
    need(type(claim) is dict and type(expected) is dict
         and set(claim) == set(expected) and claim == expected,
         "474_WRONG_REQUEST_OR_POLICY_SCOPE_DENIED")
    need(claim.get("provider_post_allowed") is False
         and claim.get("owner") == OWNER
         and claim.get("audience") == AUDIENCE,
         "474_NO_LIVE_AUTHORITY_EXISTS")
    need(not revoked, "474_REVOKED_AUTHORITY_DENIED")
    need(type(signature) is bytes and len(signature) == 64,
         "474_SIGNATURE_REQUIRED")
    try:
        public_key.verify(signature, canonical(claim))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise Denied("474_INVALID_OR_WRONG_ISSUER_SIGNATURE") from exc
    token = digest(canonical(claim))
    need(token not in consumed, "474_REPLAY_OR_ALREADY_CONSUMED_DENIED")
    consumed.add(token)
    return {"decision": "VERIFIED_SYNTHETIC_PROVENANCE_BUT_NO_SEND",
            "claim_sha256": token, "provider_post_allowed": False,
            "live_provider_posts": 0}


def verify_negative_matrix(key, valid, expected):
    public = key.public_key()
    signed = sign_fixture(key, valid)
    counts = {}
    for name, claim, signature, exp, revoked, already in [
        ("missing_signature", valid, b"", expected, False, False),
        ("wrong_signer", valid, sign_fixture(Ed25519PrivateKey.generate(), valid),
         expected, False, False),
        ("changed_request", dict(valid, request_sha256="0"*64),
         signed, expected, False, False),
        ("changed_policy", dict(valid, policy_sha256="1"*64),
         signed, expected, False, False),
        ("wrong_arm", dict(valid, arm=("B" if valid["arm"] == "A" else "A")),
         signed, expected, False, False),
        ("changed_ordinal", dict(valid, ordinal=(valid["ordinal"] + 1) % 4),
         signed, expected, False, False),
        ("wrong_audience", dict(valid, audience="task4-provider-send"),
         signed, expected, False, False),
        ("wrong_model", dict(valid, model="gpt-4.1"),
         signed, expected, False, False),
        ("forged_send_grant", dict(valid, provider_post_allowed=True),
         signed, expected, False, False),
        ("revoked", valid, signed, expected, True, False),
        ("already_consumed", valid, signed, expected, False, True),
    ]:
        consumed = {digest(canonical(valid))} if already else set()
        try:
            verify_local_authority(public_key=public, claim=claim,
                                   signature=signature, expected=exp,
                                   consumed=consumed, revoked=revoked)
        except Denied:
            counts[name] = "DENIED"
        else:
            raise Denied("474_NEGATIVE_CASE_NOT_DENIED")
    return counts


def run_offline_native_authority_join():
    deny_live()
    key = Ed25519PrivateKey.generate()  # ephemeral in-memory synthetic key
    public = key.public_key()
    policy = digest(b"task4-474-synthetic-deny-only-frozen-policy")
    observed = []
    consumed = set()
    original = prior.check_sdk_wire

    def signed_before_local_claim(arm, ordinal, raw):
        record = original(arm, ordinal, raw)
        # Intercepts ORIGINAL Native parent SDK bytes before #472 IPC claim.
        claim = make_claim(arm=arm, ordinal=ordinal,
                           wire_sha=record["original_sdk_wire_sha256"],
                           policy_digest=policy, nonce=f"{arm}-{ordinal}")
        signature = sign_fixture(key, claim)
        receipt = verify_local_authority(public_key=public, claim=claim,
                                         signature=signature, expected=claim,
                                         consumed=consumed)
        need(receipt["provider_post_allowed"] is False,
             "474_NO_LIVE_SEND_ALLOWED")
        observed.append({"arm": arm, "ordinal": ordinal,
                         "sdk_wire_sha256": record["original_sdk_wire_sha256"],
                         "authority_claim_sha256": receipt["claim_sha256"],
                         "decision": receipt["decision"]})
        return record

    with patch.object(prior, "check_sdk_wire", signed_before_local_claim):
        previous = prior.run_offline_native_budget_join()
    need(len(observed) == 8
         and [(x["arm"], x["ordinal"]) for x in observed] ==
             [(a, i) for a in ("A", "B") for i in range(4)]
         and all(x["sdk_wire_sha256"] ==
                 y["original_sdk_wire_sha256"]
                 for x, y in zip(observed,
                                 previous["hash_only_budget_preflight_receipts"]))
         and previous["real_provider_posts"] == 0
         and previous["restart_replays_denied"] == 8,
         "474_NATIVE_AUTHORITY_BOUNDARY_NOT_PROVEN")
    negative = verify_negative_matrix(
        key,
        make_claim(arm="A", ordinal=0,
                   wire_sha=observed[0]["sdk_wire_sha256"],
                   policy_digest=policy, nonce="A-0"),
        make_claim(arm="A", ordinal=0,
                   wire_sha=observed[0]["sdk_wire_sha256"],
                   policy_digest=policy, nonce="A-0"),
    )
    return {
        "rule": RULE,
        "source_base_main": prior.BASE_MAIN,
        "case": prior.CASE,
        "model": prior.MODEL,
        "same_run_native_sdk_authority_verifications": len(observed),
        "same_run_native_aead_scripted_responses":
            previous["same_run_preparse_aead_scripted_responses"],
        "same_run_isolated_worker_claims":
            previous["same_run_worker_once_claims"],
        "same_run_worker_restart_replays_denied":
            previous["restart_replays_denied"],
        "negative_cases": negative,
        "negative_cases_denied": len(negative),
        "hash_only_authority_receipts": observed,
        "synthetic_signer_key_ephemeral": True,
        "verifier_receives_private_key": False,
        "real_iam_or_network_isolation_proven": False,
        "real_issuer_authority_proven": False,
        "live_sender_implemented": False,
        "paid_owner_consent": False,
        "provider_posts": 0,
        "bank_effects": 0,
        "genuine_native_utility": None,
        "score_status": "UNSCORED",
        "no_go": True,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    deny_live()
    out = (ROOT / args.output).resolve()
    need(out.is_relative_to(ROOT) and not out.exists() and not out.is_symlink(),
         "474_REPORT_CREATE_ONLY_REPO_PATH_REQUIRED")
    report = run_offline_native_authority_join()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("TASK4_474_SIGNED_SYNTHETIC_AUTHORITY_NATIVE_NO_SEND_NO_PROVIDER")


if __name__ == "__main__":
    main()

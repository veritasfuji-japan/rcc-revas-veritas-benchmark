"""Offline research: ephemeral signer child process, verifier in parent.

NO real issuer, IAM, credential separation, paid Provider or network transport.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from scripts.task4_474_independent_signed_authority_offline_no_go_v1 import (
    RULE as PREVIOUS_RULE, make_claim, Denied,
)

RULE = "TASK4_475_SEPARATE_SIGNER_PROCESS_LOCAL_DENY_ONLY_V1"
ROOT = Path(__file__).resolve().parents[1]
BLOCK_ENV = (
    "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "GH_TOKEN", "GITHUB_TOKEN",
    "TASK4_475_APPROVAL", "TASK4_475_LIVE",
)


def ensure_offline():
    if any(os.environ.get(k) for k in BLOCK_ENV):
        raise Denied("475_SECRET_OR_LIVE_CONTEXT_REFUSED")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signer_child(conn):
    """Only this child holds the private key. No external send opcode exists."""
    try:
        ensure_offline()
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        conn.send({"public_hex": pub.hex(), "pid": os.getpid()})
        while True:
            request = conn.recv()
            if request == {"op": "stop"}:
                break
            if not isinstance(request, dict) or set(request) != {"op", "claim"}:
                conn.send({"decision": "DENY_UNSUPPORTED_OPCODE"})
                continue
            claim = request["claim"]
            if (request["op"] != "sign_synthetic_no_send"
                    or not isinstance(claim, dict)
                    or claim.get("schema") != PREVIOUS_RULE
                    or claim.get("provider_post_allowed") is not False
                    or claim.get("owner") != "OFFLINE_SYNTHETIC_FIXTURE_NOT_REAL_APPROVAL"
                    or claim.get("audience") != "task4-474-local-no-send-preflight"):
                conn.send({"decision": "DENY_NOT_SYNTHETIC_NO_SEND"})
                continue
            conn.send({"signature_hex": key.sign(canonical(claim)).hex(),
                       "decision": "SIGNED_SYNTHETIC_NO_SEND"})
    except (EOFError, BrokenPipeError):
        pass
    finally:
        conn.close()


def verify(*, public_hex, claim, signature_hex, expected, consumed,
           revoked=False):
    ensure_offline()
    if revoked:
        raise Denied("475_REVOKED")
    if claim != expected or set(claim) != set(expected):
        raise Denied("475_SCOPE_MISMATCH")
    if claim.get("provider_post_allowed") is not False:
        raise Denied("475_LIVE_NOT_AUTHORIZED")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(signature_hex), canonical(claim))
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise Denied("475_BAD_SIGNATURE") from exc
    claim_hash = digest(canonical(claim))
    if claim_hash in consumed:
        raise Denied("475_ALREADY_CONSUMED")
    consumed.add(claim_hash)
    return {"decision": "LOCAL_PROVENANCE_VERIFIED_NO_SEND",
            "claim_sha256": claim_hash, "provider_posts": 0}


def run():
    ensure_offline()
    # spawn prevents fork-inheriting signer secrets into verifier.
    parent, child = mp.get_context("spawn").Pipe()
    worker = mp.get_context("spawn").Process(target=signer_child, args=(child,))
    worker.start()
    child.close()
    try:
        info = parent.recv()
        if info["pid"] == os.getpid():
            raise Denied("475_SIGNER_MUST_BE_DISTINCT_OS_PROCESS")
        public_hex = info["public_hex"]
        claim = make_claim(arm="A", ordinal=0, wire_sha="a"*64,
                           policy_digest="b"*64, nonce="475-synthetic")
        parent.send({"op": "sign_synthetic_no_send", "claim": claim})
        signed = parent.recv()
        if signed.get("decision") != "SIGNED_SYNTHETIC_NO_SEND":
            raise Denied("475_SIGNER_REFUSED")
        sig = signed["signature_hex"]
        consumed = set()
        accepted = verify(public_hex=public_hex, claim=claim,
                          signature_hex=sig, expected=claim, consumed=consumed)
        rejected = {}
        variants = {
            "wrong_request": dict(claim, request_sha256="0"*64),
            "wrong_policy": dict(claim, policy_sha256="1"*64),
            "wrong_arm": dict(claim, arm="B"),
            "wrong_model": dict(claim, model="other"),
            "forged_send": dict(claim, provider_post_allowed=True),
        }
        cases = [
            ("replay", claim, sig, False, consumed),
            ("revoked", claim, sig, True, set()),
            ("wrong_signer", claim, Ed25519PrivateKey.generate().sign(canonical(claim)).hex(), False, set()),
            ("missing_signature", claim, "", False, set()),
        ] + [(k, v, sig, False, set()) for k, v in variants.items()]
        for name, candidate, signature, revoked, seen in cases:
            try:
                verify(public_hex=public_hex, claim=candidate,
                       signature_hex=signature, expected=claim,
                       consumed=seen, revoked=revoked)
            except Denied:
                rejected[name] = "DENIED"
            else:
                raise Denied("475_NEGATIVE_CASE_ALLOWED_" + name)
        parent.send({"op": "send_live", "claim": claim})
        unsupported = parent.recv()
        if unsupported.get("decision") != "DENY_NOT_SYNTHETIC_NO_SEND":
            raise Denied("475_SEND_OPCODE_MUST_BE_DENIED")
        return {
            "rule": RULE,
            "signer_distinct_os_pid": True,
            "signer_private_key_in_verifier": False,
            "synthetic_signed_no_send_verified": accepted["decision"],
            "negative_cases_denied": len(rejected),
            "negative_case_results": rejected,
            "live_send_opcode": unsupported["decision"],
            "hash_only_claim_sha256": accepted["claim_sha256"],
            "real_independent_iam_proven": False,
            "separate_machine_or_runner_proven": False,
            "durable_replay_or_revocation_proven": False,
            "real_issuer_owner_approval_proven": False,
            "real_provider_posts": 0,
            "genuine_native_utility": None,
            "score_status": "UNSCORED",
            "no_go": True,
        }
    finally:
        if worker.is_alive():
            try:
                parent.send({"op": "stop"})
            except (BrokenPipeError, EOFError):
                pass
        worker.join(timeout=5)
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
        parent.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    out = (ROOT / args.output).resolve()
    if not out.is_relative_to(ROOT) or out.exists() or out.is_symlink():
        raise Denied("475_CREATE_ONLY_REPO_OUTPUT_REQUIRED")
    result = run()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("TASK4_475_SEPARATE_OS_PROCESS_SYNTHETIC_SIGNER_NO_PROVIDER")


if __name__ == "__main__":
    main()

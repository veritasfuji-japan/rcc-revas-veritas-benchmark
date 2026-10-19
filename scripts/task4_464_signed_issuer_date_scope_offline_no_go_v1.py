#!/usr/bin/env python3
"""Task4 #464: offline, signed pre-first-request date/scope boundary.

Signature validity is NOT authority enrollment. The signer is a local
synthetic fixture, not a trusted issuer. No Provider client or network access.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

RULE = "TASK4_464_OFFLINE_ISSUER_DATE_SCOPE_NO_GO_V1"
CASE = "banking:user_task_4:injection_task_0:direct"
MODEL = "gpt-4.1-mini-2025-04-14"
PRESTATE = "8b653f253d3b2b033ad2baebc938bb66cb09719be8b488a470e7e82d25abbe14"
ATTACK = "0d5011fb8b275e313c83da127698f19a77095d44e82a81b4d5804046c3cb61a9"
MAIN = "18c7c088efb98023a314243413951e4d4e9a58fa"
SHA = re.compile(r"[0-9a-f]{64}\Z")
SENSITIVE = ("OPENAI_API_KEY", "TASK4_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
             "OPENAI_BASE_URL", "VERITAS_DATABASE_URL", "TASK4_464_PAID_APPROVAL")
FIELDS = frozenset((
    "schema", "case", "model", "main_sha", "native_prestate_sha256",
    "attack_sha256", "original_user_request_sha256", "recipient_sha256",
    "amount_minor_units", "currency", "execution_date", "issued_at",
    "expires_at", "issuer_role", "issuer_key_sha256", "arm",
    "first_request_sha256", "source_class", "environment",
))

class Refused(ValueError):
    pass

def need(x, reason):
    if x is not True:
        raise Refused(reason)

def canonical(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest(x):
    return hashlib.sha256(x).hexdigest()

def parse_utc(s):
    need(type(s) is str and s.endswith("Z")
         and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", s) is not None,
         "464_STRICT_UTC_TIMESTAMP_REQUIRED")
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refused("464_INVALID_TIMESTAMP") from exc
    need(d.tzinfo == timezone.utc, "464_UTC_ONLY")
    return d

@dataclass(frozen=True)
class OfflineTrustAnchor:
    """Public key supplied out-of-band; this class cannot enroll it."""
    public_key_raw: bytes
    enrolled_by_independent_operator: bool = False
    synthetic_fixture: bool = True

def validate_claim(claim, signature, anchor, *, observed_at, source_first_request_sha256,
                   trusted_request_sha256, trusted_recipient_sha256, trusted_amount_minor_units, trusted_currency):
    """Cryptographic + semantic checks, followed by mandatory research DENY.

    No caller-controlled boolean can make this function return a live permit.
    This does NOT read a machine clock as evidence of a real issuer.
    """
    need(not any(os.environ.get(k) for k in SENSITIVE),
         "464_LIVE_CREDENTIAL_OR_APPROVAL_CONTEXT_DENIED")
    need(type(claim) is dict and set(claim) == FIELDS,
         "464_EXACT_AUTHORITY_ENVELOPE_FIELDS")
    need(type(signature) is bytes and len(signature) == 64
         and type(anchor) is OfflineTrustAnchor
         and type(anchor.public_key_raw) is bytes and len(anchor.public_key_raw) == 32,
         "464_SIGNATURE_OR_TRUST_ANCHOR_SHAPE")
    need(anchor.enrolled_by_independent_operator is False
         and anchor.synthetic_fixture is True,
         "464_REAL_AUTHORITY_NOT_ENROLLED_IN_OFFLINE_HARNESS")
    try:
        Ed25519PublicKey.from_public_bytes(anchor.public_key_raw).verify(
            signature, canonical(claim))
    except (InvalidSignature, ValueError) as exc:
        raise Refused("464_SIGNATURE_INVALID") from exc
    need(claim["schema"] == RULE and claim["case"] == CASE
         and claim["model"] == MODEL and claim["main_sha"] == MAIN
         and claim["native_prestate_sha256"] == PRESTATE
         and claim["attack_sha256"] == ATTACK
         and claim["issuer_role"] == "OFFLINE_SYNTHETIC_ISSUER_NOT_AUTHORITY"
         and claim["source_class"] == "TEST_ONLY_NEVER_PROVIDER"
         and claim["environment"] == "in_memory_agentdojo_only"
         and claim["arm"] in ("A", "B"),
         "464_FROZEN_RESEARCH_SOURCE_OR_ISSUER_REQUIRED")
    need(all(type(claim[k]) is str and SHA.fullmatch(claim[k]) is not None
             for k in ("original_user_request_sha256", "recipient_sha256",
                       "issuer_key_sha256", "first_request_sha256")),
         "464_REQUIRED_OWNED_DIGEST")
    need(claim["issuer_key_sha256"] == digest(anchor.public_key_raw)
         and claim["first_request_sha256"] == source_first_request_sha256
         and claim["original_user_request_sha256"] == trusted_request_sha256\n         and claim["recipient_sha256"] == trusted_recipient_sha256,
         "464_KEY_OR_ORIGINAL_REQUEST_MISMATCH")
    need(type(claim["amount_minor_units"]) is int
         and 0 < claim["amount_minor_units"] <= 100_000_000
         and claim["currency"] == "USD"\n         and claim["amount_minor_units"] == trusted_amount_minor_units\n         and claim["currency"] == trusted_currency,
         "464_EXACT_AMOUNT_AND_CURRENCY_REQUIRED")
    issued = parse_utc(claim["issued_at"])
    expires = parse_utc(claim["expires_at"])
    observed = parse_utc(observed_at)
    need(type(claim["execution_date"]) is str
         and claim["execution_date"] == issued.date().isoformat()
         and issued <= observed < expires
         and 0 < (expires - issued).total_seconds() <= 900,
         "464_PRE_FIRST_REQUEST_DATE_EXPIRY_OR_CLOCK_DRIFT")
    return {
        "rule_of_one": RULE,
        "signed_claim_sha256": digest(canonical(claim)),
        "signature_valid": True,
        "first_request_digest_bound": True,
        "original_user_request_digest_bound": True,
        "synthetic_issuer_only": True,
        "trusted_external_issuer_attested": False,
        "trusted_wall_clock_attested": False,
        "recipient_amount_real_authority_attested": False,
        "independent_issuer_enrollment": False,
        "live_provider_post_allowed": False,
        "provider_calls": 0,
        "score_status": "UNSCORED",
        "status": "OFFLINE_SIGNED_FIXTURE_VALID_REAL_AUTHORITY_NO_GO",
    }

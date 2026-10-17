#!/usr/bin/env python3
"""Offline-only Task1 privileged Ruleset signed-evidence *candidate* verifier.

NO GitHub API, tag mutation, Provider, signer, or workflow integration.
The sole positive value intentionally does NOT authorize a live issuance.
A real issuer also needs trust-key enrollment and enforceable Ruleset change
control to close the between-read-and-tag-write (TOCTOU) gap.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "TASK1_RULESET_PRIVILEGED_EVIDENCE_CANDIDATE_V1"
AUDIENCE = "task1-ruleset-offline-review-only-v1"
REPOSITORY = "veritasfuji-japan/rcc-revas-veritas-benchmark"
TAG = "refs/tags/final128-task1-first-two-real-responses-v1-consumed"
RULESET_ID = 24921425
REQUIRED_RULE_TYPES = frozenset({"deletion", "update", "non_fast_forward"})
REQUIRED_REF_INCLUDES = frozenset({
    TAG,
    "refs/tags/final128-task1-real-ab-once-v1-*",
})
ENVELOPE_FIELDS = frozenset({"evidence", "signature_b64"})
EVIDENCE_FIELDS = frozenset({
    "schema", "audience", "repository", "main_sha", "run_id", "challenge_hex",
    "singleton_ref", "ruleset_id", "ruleset_updated_at", "observed_at",
    "expires_at", "ruleset",
})
RULESET_FIELDS = frozenset({
    "source", "source_type", "target", "enforcement", "conditions",
    "rules", "bypass_actors",
})
MAX_EVIDENCE_BYTES = 8192
MAX_AGE = timedelta(seconds=90)
MAX_LIFETIME = timedelta(seconds=120)
MAX_CLOCK_SKEW = timedelta(seconds=5)

OFFLINE_ONLY = "EVIDENCE_VALID_OFFLINE_NOT_DISPATCH_AUTHORITY"


def canonical_evidence_bytes(evidence: dict[str, Any]) -> bytes:
    """Canonical JSON *only* for offline signatures; never authority on its own."""
    return json.dumps(
        evidence, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def parse_utc(value: Any) -> datetime | None:
    """Accept only explicit UTC RFC3339 with Z; fail closed on ambiguity."""
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.utcoffset() == timedelta(0) else None


def ruleset_is_exact_snapshot(ruleset: Any) -> bool:
    """Insist on an explicit (not redacted) empty bypass list."""
    if type(ruleset) is not dict or frozenset(ruleset) != RULESET_FIELDS:
        return False
    if (ruleset["source"] != REPOSITORY
            or ruleset["source_type"] != "Repository"
            or ruleset["target"] != "tag"
            or ruleset["enforcement"] != "active"
            or type(ruleset["bypass_actors"]) is not list
            or ruleset["bypass_actors"] != []):
        return False
    conditions = ruleset["conditions"]
    if type(conditions) is not dict or frozenset(conditions) != {"ref_name"}:
        return False
    names = conditions["ref_name"]
    if type(names) is not dict or frozenset(names) != {"include", "exclude"}:
        return False
    includes, excludes = names["include"], names["exclude"]
    if (type(includes) is not list or len(includes) != len(REQUIRED_REF_INCLUDES)
            or any(type(x) is not str for x in includes)
            or frozenset(includes) != REQUIRED_REF_INCLUDES
            or excludes != [] or type(excludes) is not list):
        return False
    rules = ruleset["rules"]
    if type(rules) is not list or len(rules) != len(REQUIRED_RULE_TYPES):
        return False
    if any(type(rule) is not dict or frozenset(rule) != {"type"}
           or type(rule["type"]) is not str for rule in rules):
        return False
    return frozenset(rule["type"] for rule in rules) == REQUIRED_RULE_TYPES


def review_candidate_offline(
    envelope: Any, *,
    trusted_public_key_bytes: bytes | None,
    expected_sha: str,
    expected_run_id: str,
    expected_challenge_hex: str,
    privileged_current_ruleset_updated_at: str | None,
    observed_singleton_absent: bool,
    now: datetime,
) -> str:
    """Proof-envelope quality check only; never a live tag/Provider permission.

    Public key and context MUST be supplied from independent trusted sources,
    not copied from the attacker-controlled envelope. Nothing in this module
    provides those sources or a cryptographically atomic GitHub update.
    """
    if type(envelope) is not dict or frozenset(envelope) != ENVELOPE_FIELDS:
        return "DENY_ENVELOPE"
    evidence, signature_text = envelope["evidence"], envelope["signature_b64"]
    if type(evidence) is not dict or frozenset(evidence) != EVIDENCE_FIELDS:
        return "DENY_EVIDENCE_SHAPE"
    if type(signature_text) is not str:
        return "DENY_SIGNATURE"
    if type(trusted_public_key_bytes) is not bytes or len(trusted_public_key_bytes) != 32:
        return "DENY_TRUST_ANCHOR_NOT_ENROLLED"
    try:
        canonical = canonical_evidence_bytes(evidence)
        if len(canonical) > MAX_EVIDENCE_BYTES:
            return "DENY_EVIDENCE_SHAPE"
        signature = base64.b64decode(signature_text, validate=True)
        if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_text:
            return "DENY_SIGNATURE"
        Ed25519PublicKey.from_public_bytes(trusted_public_key_bytes).verify(
            signature, canonical,
        )
    except (ValueError, TypeError, UnicodeError, binascii.Error, InvalidSignature):
        return "DENY_SIGNATURE"

    if (evidence["schema"] != SCHEMA
            or evidence["audience"] != AUDIENCE
            or evidence["repository"] != REPOSITORY
            or evidence["singleton_ref"] != TAG
            or type(evidence["ruleset_id"]) is not int
            or evidence["ruleset_id"] != RULESET_ID):
        return "DENY_IDENTITY"
    if not (type(expected_sha) is str and re.fullmatch(r"[a-f0-9]{40}", expected_sha)
            and type(expected_run_id) is str and re.fullmatch(r"[1-9][0-9]{5,19}", expected_run_id)
            and type(expected_challenge_hex) is str and re.fullmatch(r"[a-f0-9]{64}", expected_challenge_hex)):
        return "DENY_RUNTIME_BINDING"
    if (evidence["main_sha"] != expected_sha
            or evidence["run_id"] != expected_run_id
            or evidence["challenge_hex"] != expected_challenge_hex):
        return "DENY_RUNTIME_BINDING"
    if observed_singleton_absent is not True:
        return "DENY_SINGLETON_NOT_PROVEN_ABSENT"
    revision = evidence["ruleset_updated_at"]
    if (type(privileged_current_ruleset_updated_at) is not str
            or parse_utc(privileged_current_ruleset_updated_at) is None
            or type(revision) is not str
            or revision != privileged_current_ruleset_updated_at):
        return "DENY_PRIVILEGED_CURRENT_REVISION"
    observed = parse_utc(evidence["observed_at"])
    expires = parse_utc(evidence["expires_at"])
    if (type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None
            or observed is None or expires is None):
        return "DENY_TIME"
    instant = now.astimezone(timezone.utc)
    if not (timedelta(0) < expires - observed <= MAX_LIFETIME
            and -MAX_CLOCK_SKEW <= instant - observed <= MAX_AGE
            and instant < expires):
        return "DENY_TIME"
    if not ruleset_is_exact_snapshot(evidence["ruleset"]):
        return "DENY_RULESET_SNAPSHOT"

    # This intentionally never returns GO, ADMITTED, or ISSUANCE_ALLOWED.
    # A signature and two reads cannot atomically protect GitHub Ruleset
    # configuration against concurrent administration changes.
    return OFFLINE_ONLY

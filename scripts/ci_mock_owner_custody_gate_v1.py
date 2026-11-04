"""CI-only synthetic Owner Approval admission inside isolated mock Custody.

Current validity comes from a root-enrolled *synthetic logical clock* and
revocation list, re-read per initial admission. No real trusted clock, external
owner, independent authority, or dispatch-time revocation proof is claimed.
"""
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OWNER_DOMAIN = b"BEN_SYNTHETIC_OWNER_APPROVAL_V1\0"
OWNER_SCOPE = "BEN_RESEARCH_MOCK_ONLY"
VALIDITY_SCHEMA = "ben.synthetic-owner-current-validity.v1"
MAX_TICK = 1_000_000
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("OWNER_DUPLICATE_FIELD")
        result[key] = value
    return result


def _read_json(path, need):
    raw = Path(path).read_bytes()
    need(0 < len(raw) <= 8192, "OWNER_TRUST_FILE_SIZE")
    return json.loads(raw, object_pairs_hook=_pairs)


def _current_validity(base, stmt, digest, need):
    """Re-read root-enrolled mock authority data on each unspent attempt."""
    state = _read_json(Path(base) / "trust/owner-current-validity.json", need)
    need(type(state) is dict
         and set(state) == {"schema", "clock_tick", "revoked_statement_hashes"}
         and state["schema"] == VALIDITY_SCHEMA, "OWNER_VALIDITY_SCHEMA")
    tick = state["clock_tick"]
    revoked = state["revoked_statement_hashes"]
    need(type(tick) is int and 0 <= tick <= MAX_TICK, "OWNER_CLOCK_INVALID")
    need(type(revoked) is list and len(revoked) <= 16
         and all(type(x) is str and HEX64.fullmatch(x) is not None for x in revoked)
         and len(revoked) == len(set(revoked)), "OWNER_REVOCATION_LIST_INVALID")
    need(digest(stmt) not in revoked, "OWNER_APPROVAL_REVOKED")
    lower, upper = stmt["valid_from_tick"], stmt["valid_until_tick"]
    need(lower <= tick < upper, "OWNER_APPROVAL_NOT_CURRENT")
    return tick


def enforce(base, packet, issuer_key, attested_state, canonical, digest, need, op):
    """Verify two enrolled signer keys, request, fresh status, and current validity.

    Caller: trusted CI Custody. attested_state MUST originate from nonce-bound
    backend HMAC, never Agent data. The logical clock and revocations are
    root-controlled CI fixtures, not externally authoritative sources.
    """
    owner_key = (Path(base) / "trust/owner-public-key").read_bytes()
    need(type(issuer_key) is bytes and len(issuer_key) == 32
         and type(owner_key) is bytes and len(owner_key) == 32
         and issuer_key != owner_key, "OWNER_ISSUER_NOT_INDEPENDENT")
    approval = _read_json(Path(base) / "trust/owner-approval.json", need)
    need(type(approval) is dict and set(approval) == {"statement", "signature"},
         "OWNER_EXACT_ENVELOPE")
    stmt = approval["statement"]
    need(type(stmt) is dict and set(stmt) == {
        "scope", "operation_id", "request_sha256", "prestate_sha256",
        "valid_from_tick", "valid_until_tick"}, "OWNER_STATEMENT_SHAPE")
    lower, upper = stmt["valid_from_tick"], stmt["valid_until_tick"]
    need(type(lower) is int and type(upper) is int
         and 0 <= lower < upper <= MAX_TICK, "OWNER_SIGNED_INTERVAL_INVALID")
    need(stmt == {
        "scope": OWNER_SCOPE,
        "operation_id": op,
        "request_sha256": digest(packet["request"]),
        "prestate_sha256": digest(attested_state),
        "valid_from_tick": lower,
        "valid_until_tick": upper,
    }, "OWNER_REQUEST_OR_STATE_MISMATCH")
    signature = approval["signature"]
    need(type(signature) is str and len(signature) == 128, "OWNER_SIGNATURE")
    try:
        Ed25519PublicKey.from_public_bytes(owner_key).verify(
            bytes.fromhex(signature), OWNER_DOMAIN + canonical(stmt))
    except (InvalidSignature, ValueError):
        raise ValueError("OWNER_SIGNATURE") from None
    _current_validity(base, stmt, digest, need)
    return digest(stmt)

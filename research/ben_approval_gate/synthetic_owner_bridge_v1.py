"""Research-only synthetic owner approval gate, before existing mock sink grant validation.

Not wired into production Custody. A research proposal cannot be promoted to authority.
No provider, network, real owner identity, revocation service or live Bind execution.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from research.ben_approval_gate.approval_gate import SCHEMA as PROPOSAL_SCHEMA
from scripts import ci_mock_executor_authority_boundary_v1 as mock

DOMAIN = b"BEN_SYNTHETIC_OWNER_APPROVAL_V1\0"
SCOPE = "BEN_RESEARCH_MOCK_ONLY"
FIELDS = {"scope", "operation_id", "request_sha256", "prestate_sha256"}
ENVELOPE = {"statement", "signature"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_owner_approval(approval, public_key, request, prestate):
    require(type(approval) is dict and set(approval) == ENVELOPE, "OWNER_ENVELOPE")
    statement = approval["statement"]
    require(type(statement) is dict and set(statement) == FIELDS, "OWNER_FIELDS")
    require(statement == {
        "scope": SCOPE,
        "operation_id": mock.OP,
        "request_sha256": mock.digest(request),
        "prestate_sha256": mock.digest(prestate),
    }, "OWNER_EXACT_BINDING")
    require(type(public_key) is bytes and len(public_key) == 32, "OWNER_KEY")
    signature = approval["signature"]
    require(type(signature) is str and len(signature) == 128, "OWNER_SIGNATURE")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), DOMAIN + mock.canonical(statement))
    except (InvalidSignature, ValueError):
        raise ValueError("OWNER_SIGNATURE") from None
    return statement


def preflight(approval, owner_public_key, packet, issuer_public_key, prestate):
    # Do not accept the existing review proposal as an approval, even if well-formed.
    require(not (type(approval) is dict and approval.get("schema") == PROPOSAL_SCHEMA),
            "REVIEW_PROPOSAL_IS_NOT_AUTHORITY")
    require(type(packet) is dict and set(packet) == {"request", "grant"}, "EXACT_PACKET")
    require(type(prestate) is dict and prestate == {
        "counter": 0, "revision": 0, "effect_count": 0}, "EXACT_PRESTATE")
    owner = verify_owner_approval(approval, owner_public_key, packet["request"], prestate)
    grant = mock.validate(packet, issuer_public_key)
    return {"decision": "SYNTHETIC_PREFLIGHT_ACCEPTED_NOT_EXECUTED",
            "owner_statement_sha256": mock.digest(owner),
            "issuer_statement_sha256": mock.digest(grant),
            "request_sha256": mock.digest(packet["request"]),
            "execution_authority": False, "provider_dispatch": "DENY"}

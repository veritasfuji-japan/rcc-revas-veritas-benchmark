"""Research-only synthetic owner approval gate, before existing mock sink grant validation.

Not wired into production Custody. A research proposal cannot be promoted to authority.
No provider, network, real owner identity, revocation service or live Bind execution.
"""
import sqlite3

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
    # Different signatures are insufficient if the same enrolled identity signs both.
    require(type(owner_public_key) is bytes and type(issuer_public_key) is bytes
            and owner_public_key != issuer_public_key, "OWNER_ISSUER_KEY_REUSE")
    return {"decision": "SYNTHETIC_PREFLIGHT_ACCEPTED_NOT_EXECUTED",
            "owner_statement_sha256": mock.digest(owner),
            "issuer_statement_sha256": mock.digest(grant),
            "request_sha256": mock.digest(packet["request"]),
            "execution_authority": False, "provider_dispatch": "DENY"}


def trusted_backend_snapshot(connection):
    """Read one coherent SQLite backend snapshot through a trusted read-only handle.

    The caller MUST open the actual protected backend database and protect its
    handle. A caller-chosen SQLite database is not source authentication.
    This reads state at preflight, not at final dispatch (TOCTOU remains).
    """
    require(type(connection) is sqlite3.Connection, "TRUSTED_BACKEND_HANDLE_REQUIRED")
    require(not connection.in_transaction, "BACKEND_TRANSACTION_ALREADY_ACTIVE")
    try:
        require(connection.execute("PRAGMA query_only").fetchone() == (1,),
                "READONLY_BACKEND_HANDLE_REQUIRED")
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT id, counter, denials FROM state ORDER BY id").fetchall()
        spent = connection.execute(
            "SELECT operation_id, receipt FROM spent ORDER BY operation_id").fetchall()
        require(len(rows) == 1 and rows[0][0] == 1
                and type(rows[0][1]) is int and rows[0][1] in (0, 1)
                and type(rows[0][2]) is int and rows[0][2] >= 0,
                "BACKEND_STATE_INVALID")
        counter = rows[0][1]
        expected_spent = ([(mock.OP, mock.digest({
            "operation_id": mock.OP, "request": mock.REQUEST}))] if counter else [])
        require(spent == expected_spent, "BACKEND_EFFECT_RECEIPT_INCONSISTENT")
        return {"counter": counter, "revision": counter,
                "effect_count": len(spent)}
    except sqlite3.DatabaseError:
        raise ValueError("BACKEND_SOURCE_UNREADABLE") from None
    finally:
        if connection.in_transaction:
            connection.rollback()


def preflight_from_trusted_backend(approval, owner_public_key, packet,
                                  issuer_public_key, backend_connection):
    """Offline research preflight; never an execution authorization or effect."""
    state = trusted_backend_snapshot(backend_connection)
    return preflight(approval, owner_public_key, packet, issuer_public_key, state)

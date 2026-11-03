"""Offline owner/issuer separation and exact-binding negatives, without effects."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from research.ben_approval_gate import synthetic_owner_bridge_v1 as bridge
from scripts import ci_mock_executor_authority_boundary_v1 as mock

OWNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
PRESTATE = {"counter": 0, "revision": 0, "effect_count": 0}


def fixtures():
    statement = {"scope": "CI_ONLY", "operation_id": mock.OP,
                 "request_sha256": mock.digest(mock.REQUEST)}
    packet = {"request": copy.deepcopy(mock.REQUEST), "grant": {
        "statement": statement,
        "signature": ISSUER.sign(b"CI_GRANT_V2\0" + mock.canonical(statement)).hex()}}
    owner_statement = {"scope": bridge.SCOPE, "operation_id": mock.OP,
                       "request_sha256": mock.digest(packet["request"]),
                       "prestate_sha256": mock.digest(PRESTATE)}
    approval = {"statement": owner_statement,
                "signature": OWNER.sign(bridge.DOMAIN + mock.canonical(owner_statement)).hex()}
    return approval, packet


def check(approval, packet, prestate=PRESTATE, owner_key=None, issuer_key=None):
    return bridge.preflight(approval,
        owner_key if owner_key is not None else OWNER.public_key().public_bytes_raw(),
        packet, issuer_key if issuer_key is not None else ISSUER.public_key().public_bytes_raw(),
        prestate)


def test_two_distinct_signers_exact_mock_request_preflight_only():
    approval, packet = fixtures()
    result = check(approval, packet)
    assert result["decision"] == "SYNTHETIC_PREFLIGHT_ACCEPTED_NOT_EXECUTED"
    assert result["execution_authority"] is False
    assert result["provider_dispatch"] == "DENY"


@pytest.mark.parametrize("field,value", [
    ("target", "mock://changed"), ("units", 2), ("revision", 1)])
def test_owner_approved_request_cannot_be_changed(field, value):
    approval, packet = fixtures()
    packet["request"][field] = value
    with pytest.raises(ValueError):
        check(approval, packet)


@pytest.mark.parametrize("field,value", [
    ("scope", "PRODUCTION"), ("operation_id", "OTHER"),
    ("request_sha256", "0" * 64), ("prestate_sha256", "0" * 64)])
def test_owner_statement_mutation_rejected(field, value):
    approval, packet = fixtures()
    approval["statement"][field] = value
    with pytest.raises(ValueError):
        check(approval, packet)


def test_owner_signature_from_wrong_key_rejected():
    approval, packet = fixtures()
    with pytest.raises(ValueError, match="OWNER_SIGNATURE"):
        check(approval, packet, owner_key=ISSUER.public_key().public_bytes_raw())


def test_issuer_signature_from_wrong_key_rejected():
    approval, packet = fixtures()
    with pytest.raises(ValueError, match="GRANT_SIGNATURE"):
        check(approval, packet, issuer_key=OWNER.public_key().public_bytes_raw())


def test_owner_prestate_drift_rejected():
    approval, packet = fixtures()
    with pytest.raises(ValueError, match="EXACT_PRESTATE"):
        check(approval, packet, {"counter": 1, "revision": 1, "effect_count": 1})


def test_review_proposal_never_becomes_approval():
    approval, packet = fixtures()
    with pytest.raises(ValueError, match="REVIEW_PROPOSAL_IS_NOT_AUTHORITY"):
        check({"schema": bridge.PROPOSAL_SCHEMA, "status": "RESEARCH_PROPOSAL_FORMAT_VALID"}, packet)


def test_fabricated_committed_receipt_is_not_accepted():
    approval, packet = fixtures()
    packet["receipt"] = {"final_outcome": "COMMITTED"}
    with pytest.raises(ValueError, match="EXACT_PACKET"):
        check(approval, packet)

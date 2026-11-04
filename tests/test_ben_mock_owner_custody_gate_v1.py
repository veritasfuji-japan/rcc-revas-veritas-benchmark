"""Synthetic owner-grant Custody admission negatives; no network in this file."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import ci_mock_executor_authority_boundary_v1 as mock
from scripts import ci_mock_owner_custody_gate_v1 as owner

OWNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
STATE = {'counter': 0, 'revision': 0, 'effect_count': 0}


def prepare(tmp_path):
    trust = tmp_path / 'trust'
    trust.mkdir()
    statement = {'scope': owner.OWNER_SCOPE, 'operation_id': mock.OP,
                 'request_sha256': mock.digest(mock.REQUEST),
                 'prestate_sha256': mock.digest(STATE)}
    approval = {'statement': statement, 'signature':
                OWNER.sign(owner.OWNER_DOMAIN + mock.canonical(statement)).hex()}
    (trust / 'owner-public-key').write_bytes(OWNER.public_key().public_bytes_raw())
    (trust / 'owner-approval.json').write_bytes(mock.canonical(approval))
    packet = {'request': copy.deepcopy(mock.REQUEST)}
    return packet, approval


def verify(tmp_path, packet, state=STATE, issuer_key=None):
    return owner.enforce(tmp_path, packet,
        issuer_key if issuer_key is not None else ISSUER.public_key().public_bytes_raw(),
        state, mock.canonical, mock.digest, mock.need, mock.OP)


def test_mock_custody_owner_gate_accepts_exact_signed_research_fixture(tmp_path):
    packet, approval = prepare(tmp_path)
    assert verify(tmp_path, packet) == mock.digest(approval['statement'])


@pytest.mark.parametrize('field,value', [
    ('target', 'mock://changed'),
    ('units', 2), ('revision', 1)])
def test_changed_request_denied_before_consumption(tmp_path, field, value):
    packet, _ = prepare(tmp_path)
    packet['request'][field] = value
    with pytest.raises(ValueError, match='OWNER_REQUEST_OR_STATE_MISMATCH'):
        verify(tmp_path, packet)


@pytest.mark.parametrize('field,value', [
    ('scope', 'PRODUCTION'),
    ('operation_id', 'other-operation'),
    ('request_sha256', '0' * 64),
    ('prestate_sha256', '0' * 64)])
def test_owner_statement_change_denied(tmp_path, field, value):
    packet, approval = prepare(tmp_path)
    approval['statement'][field] = value
    (tmp_path / 'trust/owner-approval.json').write_bytes(mock.canonical(approval))
    with pytest.raises(ValueError, match='OWNER_REQUEST_OR_STATE_MISMATCH'):
        verify(tmp_path, packet)


def test_different_signature_without_owner_key_denied(tmp_path):
    packet, approval = prepare(tmp_path)
    approval['signature'] = ISSUER.sign(
        owner.OWNER_DOMAIN + mock.canonical(approval['statement'])).hex()
    (tmp_path / 'trust/owner-approval.json').write_bytes(mock.canonical(approval))
    with pytest.raises(ValueError, match='OWNER_SIGNATURE'):
        verify(tmp_path, packet)


def test_same_enrolled_key_denied_before_signature(tmp_path):
    packet, _ = prepare(tmp_path)
    with pytest.raises(ValueError, match='OWNER_ISSUER_NOT_INDEPENDENT'):
        verify(tmp_path, packet, issuer_key=OWNER.public_key().public_bytes_raw())


def test_backend_state_drift_denied(tmp_path):
    packet, _ = prepare(tmp_path)
    with pytest.raises(ValueError, match='OWNER_REQUEST_OR_STATE_MISMATCH'):
        verify(tmp_path, packet, {'counter': 1, 'revision': 1, 'effect_count': 1})


def test_fabricated_owner_receipt_not_accepted(tmp_path):
    packet, approval = prepare(tmp_path)
    approval['final_outcome'] = 'COMMITTED'
    (tmp_path / 'trust/owner-approval.json').write_bytes(mock.canonical(approval))
    with pytest.raises(ValueError, match='OWNER_EXACT_ENVELOPE'):
        verify(tmp_path, packet)


@pytest.mark.parametrize('kwargs', [
    {'fault': 'before-post'},
    {'concurrent': True},
    {'restart_backend': True, 'fault': 'before-post'},
])
def test_owner_ci_mode_refuses_unproved_fault_or_concurrency_before_setup(tmp_path, kwargs):
    with pytest.raises(ValueError, match='SYNTHETIC_OWNER_SINGLE_NORMAL_RUN_ONLY'):
        mock.run(tmp_path / 'not-created', with_bind=True, with_owner=True, **kwargs)
    assert not (tmp_path / 'not-created').exists()


def test_backend_status_hmac_is_nonce_bound():
    key = b'FAKE_CI_KEY_NOT_REAL_CREDENTIAL'
    first = mock.tag(key, b'CI_BACKEND_STATUS_REPLY_V1\0',
                     {'nonce': 'a' * 32, 'operation_id': mock.OP, 'state': STATE})
    second = mock.tag(key, b'CI_BACKEND_STATUS_REPLY_V1\0',
                      {'nonce': 'b' * 32, 'operation_id': mock.OP, 'state': STATE})
    assert first != second

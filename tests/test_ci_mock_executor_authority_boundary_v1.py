import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import ci_mock_executor_authority_boundary_v1 as boundary

KEY = b'PUBLIC_UNIT_TEST_KEY_NOT_A_RUNTIME_CREDENTIAL'
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC = SIGNER.public_key().public_bytes_raw()


def packet():
    statement = {'scope': 'CI_ONLY', 'operation_id': boundary.OP,
                 'request_sha256': boundary.digest(boundary.REQUEST)}
    return {'request': copy.deepcopy(boundary.REQUEST), 'grant': {
        'statement': statement,
        'signature': SIGNER.sign(b'CI_GRANT_V2\0' + boundary.canonical(statement)).hex()}}


def test_exact_mock_scope_accepted_without_network():
    assert boundary.validate(packet(), PUBLIC)['scope'] == 'CI_ONLY'


@pytest.mark.parametrize('fault', ['signature', 'target', 'units_bool', 'revision_bool',
                                  'operation', 'extra_endpoint', 'missing_grant', 'scope'])
def test_forged_or_widened_scope_refused(fault):
    request = packet()
    if fault == 'signature':
        request['grant']['signature'] = '0' * 128
    elif fault == 'target':
        request['request']['target'] = 'https://example.invalid/'
    elif fault == 'units_bool':
        request['request']['units'] = True
    elif fault == 'revision_bool':
        request['request']['revision'] = False
    elif fault == 'operation':
        request['grant']['statement']['operation_id'] = 'another'
    elif fault == 'extra_endpoint':
        request['destination'] = 'http://192.0.2.1/'
    elif fault == 'missing_grant':
        request.pop('grant')
    elif fault == 'scope':
        request['grant']['statement']['scope'] = 'PRODUCTION'
    with pytest.raises(ValueError):
        boundary.validate(request, PUBLIC)


def test_attacker_signature_refused_under_enrolled_public_key():
    request = packet()
    attacker = Ed25519PrivateKey.generate()
    request['grant']['signature'] = attacker.sign(
        b'CI_GRANT_V2\0' + boundary.canonical(request['grant']['statement'])).hex()
    with pytest.raises(ValueError, match='GRANT_SIGNATURE'):
        boundary.validate(request, PUBLIC)


def test_nonhex_signature_refused():
    request = packet()
    request['grant']['signature'] = 'z' * 128
    with pytest.raises(ValueError, match='GRANT_SIGNATURE'):
        boundary.validate(request, PUBLIC)


def test_duplicate_json_and_oversize_refused():
    for raw in (b'{"grant":1,"grant":2}', b' ' * (boundary.LIMIT + 1)):
        with pytest.raises(ValueError):
            boundary.parse(raw)


def test_grant_and_sink_authentication_domains_are_distinct():
    value = {'operation_id': boundary.OP}
    assert boundary.tag(KEY, b'CI_GRANT_V1\0', value) != boundary.tag(KEY, b'CI_SINK_V1\0', value)


def test_supervisor_refuses_no_bind_mode(tmp_path):
    with pytest.raises(ValueError, match='REAL_BIND_CUSTODY_MODE_REQUIRED'):
        boundary.run(tmp_path / 'proof', with_bind=False)
    assert not (tmp_path / 'proof').exists()


def test_custody_refuses_no_bind_before_opening_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'role_identity', lambda uid: None)
    with pytest.raises(ValueError, match='CUSTODY_REQUIRES_REAL_BIND'):
        boundary.custody(tmp_path, with_bind=False)


def test_supervisor_refuses_unknown_fault_before_provisioning(tmp_path):
    with pytest.raises(ValueError, match='EXACT_TEST_FAULT'):
        boundary.run(tmp_path / 'proof', with_bind=True, fault='retry-anyway')
    assert not (tmp_path / 'proof').exists()


def test_custody_refuses_unknown_fault_before_opening_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'role_identity', lambda uid: None)
    with pytest.raises(ValueError, match='EXACT_TEST_FAULT'):
        boundary.custody(tmp_path, with_bind=True, fault='retry-anyway')

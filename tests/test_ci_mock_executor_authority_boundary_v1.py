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


@pytest.mark.parametrize('effects', [0, 1])
def test_backend_restart_preserves_effect_and_denials(tmp_path, effects):
    file = tmp_path / 'backend.sqlite3'
    db = boundary.backend_store(file)
    db.execute('UPDATE state SET counter=?,denials=3', (effects,))
    if effects:
        db.execute('INSERT INTO spent VALUES (?,?)', (boundary.OP,
            boundary.digest({'operation_id': boundary.OP, 'request': boundary.REQUEST})))
    before = db.execute('SELECT * FROM state').fetchall(), db.execute('SELECT * FROM spent').fetchall()
    db.close()
    db = boundary.backend_store(file, restart=True)
    after = db.execute('SELECT * FROM state').fetchall(), db.execute('SELECT * FROM spent').fetchall()
    db.close()
    assert before == after


def test_missing_backend_restart_refused_without_creating_empty_db(tmp_path):
    file = tmp_path / 'missing.sqlite3'
    with pytest.raises(ValueError, match='EXACT_BACKEND_DB_LIFECYCLE'):
        boundary.backend_store(file, restart=True)
    assert not file.exists()


def test_fresh_backend_start_refuses_existing_db(tmp_path):
    file = tmp_path / 'existing.sqlite3'
    boundary.backend_store(file).close()
    with pytest.raises(ValueError, match='EXACT_BACKEND_DB_LIFECYCLE'):
        boundary.backend_store(file)


@pytest.mark.parametrize('fault', ['missing_receipt', 'wrong_receipt', 'orphan_receipt', 'negative_denials'])
def test_backend_restart_refuses_inconsistent_durable_state(tmp_path, fault):
    file = tmp_path / 'inconsistent.sqlite3'
    db = boundary.backend_store(file)
    if fault in {'missing_receipt', 'wrong_receipt'}:
        db.execute('UPDATE state SET counter=1')
    if fault in {'wrong_receipt', 'orphan_receipt'}:
        db.execute('INSERT INTO spent VALUES (?,?)', (boundary.OP, '0' * 64))
    if fault == 'negative_denials':
        db.execute('UPDATE state SET denials=-1')
    db.close()
    with pytest.raises(ValueError):
        boundary.backend_store(file, restart=True)


def test_both_restart_requires_explicit_fault_case(tmp_path):
    with pytest.raises(ValueError, match='BACKEND_RESTART_REQUIRES_FAULT_CASE'):
        boundary.run(tmp_path / 'proof', with_bind=True, restart_backend=True)
    assert not (tmp_path / 'proof').exists()


@pytest.mark.parametrize('fault,restart_backend', [('before-post', False), ('before-post', True)])
def test_concurrency_proof_refuses_combined_fault_modes(tmp_path, fault, restart_backend):
    with pytest.raises(ValueError, match='EXACT_CONCURRENCY_MODE'):
        boundary.run(tmp_path / 'proof', with_bind=True, fault=fault,
                     restart_backend=restart_backend, concurrent=True)
    assert not (tmp_path / 'proof').exists()


def test_replica_requires_explicit_concurrency_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'role_identity', lambda uid: None)
    with pytest.raises(ValueError, match='REPLICA_REQUIRES_CONCURRENCY_PROOF'):
        boundary.custody(tmp_path, with_bind=True, replica=True)


def test_restart_cannot_arm_concurrency_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(boundary, 'role_identity', lambda uid: None)
    with pytest.raises(ValueError, match='EXACT_CONCURRENCY_MODE'):
        boundary.custody(tmp_path, with_bind=True, restart=True, concurrent=True)

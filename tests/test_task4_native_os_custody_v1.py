import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_native_os_custody_v1 as proof


def grant():
    key = Ed25519PrivateKey.generate()
    claim = proof.statement('A', 0, proof.scope()[('A', 0)])
    value = {'statement': claim, 'signature': key.sign(
        b'TASK4_NATIVE_OS_V1\0' + proof.canonical(claim)).hex()}
    return key, value


def test_exact_frozen_grant_verifies():
    key, value = grant()
    proof.verify_grant(value, 'A', 0, proof.scope()[('A', 0)], key.public_key().public_bytes_raw())


def test_fixed_scope_and_public_fixture_recipient():
    assert len(proof.scope()) == 8
    assert set(proof.scope()) == {(a, i) for a in ('A', 'B') for i in range(4)}
    assert proof.sha(proof.recipient()) == proof.RECIPIENT_SHA


@pytest.mark.parametrize('fault', ['target', 'recipient', 'scope', 'cap', 'arm', 'ordinal',
                                  'request', 'extra', 'signature', 'attacker'])
def test_even_resigned_scope_widening_or_forged_signatures_refused(fault):
    key, value = grant()
    value = copy.deepcopy(value)
    replacements = {'target': ('target', 'https://example.invalid/'),
                    'recipient': ('recipient_sha256', 'f' * 64), 'scope': ('scope', 'PRODUCTION'),
                    'cap': ('output_cap', 257), 'arm': ('arm', 'B'), 'ordinal': ('ordinal', 1),
                    'request': ('request_sha256', '0' * 64), 'extra': ('forward', True)}
    if fault in replacements:
        name, replacement = replacements[fault]
        value['statement'][name] = replacement
        value['signature'] = key.sign(b'TASK4_NATIVE_OS_V1\0' + proof.canonical(value['statement'])).hex()
    elif fault == 'signature':
        value['signature'] = '0' * 128
    else:
        value['signature'] = Ed25519PrivateKey.generate().sign(
            b'TASK4_NATIVE_OS_V1\0' + proof.canonical(value['statement'])).hex()
    with pytest.raises(ValueError):
        proof.verify_grant(value, 'A', 0, proof.scope()[('A', 0)], key.public_key().public_bytes_raw())


@pytest.mark.parametrize('value', ['!', 'YQ', None])
def test_malformed_base64_refused(value):
    with pytest.raises(ValueError):
        proof.decode(value)


@pytest.mark.parametrize('raw', [b'{"arm":"A","arm":"B"}', b' ' * (proof.LIMIT + 1)])
def test_duplicate_or_oversized_json_refused(raw):
    with pytest.raises(ValueError):
        proof.parse(raw)


def test_actual_wire_must_match_preissued_request_hash():
    key, value = grant()
    packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': proof.encode(b'{}'), 'grant': value}
    with pytest.raises(ValueError, match='EXACT_FROZEN_SDK_BYTES'):
        proof.verify(packet, key.public_key().public_bytes_raw())


def test_caller_cannot_select_additional_endpoint():
    key, value = grant()
    packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': proof.encode(b'{}'), 'grant': value,
              'destination': 'https://example.invalid/'}
    with pytest.raises(ValueError, match='EXACT_NATIVE_PACKET'):
        proof.verify(packet, key.public_key().public_bytes_raw())


@pytest.mark.parametrize('observed', [False, True])
def test_reconciliation_preserves_consumption_without_post_or_response(tmp_path, monkeypatch, observed):
    import sqlite3
    folder = tmp_path / 'custody'
    folder.mkdir()
    (folder / 'credential').write_bytes(b'test-only')
    request_sha, response_sha = 'a' * 64, 'b' * 64
    receipt = proof.digest({'operation_id': 'A0', 'request_sha256': request_sha, 'response_sha256': response_sha})
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op,state,request_sha,response_sha,backend_receipt)')
        db.execute('INSERT INTO consumed VALUES (?,?,?,?,?)', ('A0', 'CONSUMED_UNKNOWN', request_sha, None, None))
    monkeypatch.setattr(proof.kernel, 'role_identity', lambda _: None)
    def get_only(method, path, body, key):
        assert (method, path, body, key) == ('GET', '/receipt/A0', None, b'test-only')
        return 200, {'operation_id': 'A0', 'record': [request_sha, response_sha, receipt] if observed else None}
    monkeypatch.setattr(proof, 'http_call', get_only)
    result = proof.reconcile_fault(tmp_path)
    assert result == proof.reconcile_fault(tmp_path)
    assert result['post_calls'] == 0 and result['raw_response_recovered'] is False
    assert result['state'] == ('MOCK_EFFECT_CONFIRMED_NO_RESPONSE' if observed else 'CONSUMED_UNKNOWN')
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        assert db.execute('SELECT count(*) FROM consumed').fetchone()[0] == 1


@pytest.mark.parametrize('fault', ['status', 'operation', 'request', 'receipt'])
def test_reconciliation_rejects_unmatched_evidence_without_ledger_update(tmp_path, monkeypatch, fault):
    import sqlite3
    folder = tmp_path / 'custody'
    folder.mkdir()
    (folder / 'credential').write_bytes(b'test-only')
    request_sha, response_sha = 'a' * 64, 'b' * 64
    receipt = proof.digest({'operation_id': 'A0', 'request_sha256': request_sha, 'response_sha256': response_sha})
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op,state,request_sha,response_sha,backend_receipt)')
        db.execute('INSERT INTO consumed VALUES (?,?,?,?,?)', ('A0', 'CONSUMED_UNKNOWN', request_sha, None, None))
    evidence = {'operation_id': 'A0', 'record': [request_sha, response_sha, receipt]}
    status = 403 if fault == 'status' else 200
    if fault == 'operation':
        evidence['operation_id'] = 'B0'
    if fault in {'request', 'receipt'}:
        evidence['record'][0 if fault == 'request' else 2] = '0' * 64
    monkeypatch.setattr(proof.kernel, 'role_identity', lambda _: None)
    monkeypatch.setattr(proof, 'http_call', lambda *_: (status, evidence))
    with pytest.raises(ValueError):
        proof.reconcile_fault(tmp_path)
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        assert db.execute('SELECT * FROM consumed').fetchall() == [('A0', 'CONSUMED_UNKNOWN', request_sha, None, None)]


def test_fault_configuration_is_explicit_and_bounded(tmp_path):
    assert proof.fault_mode(tmp_path) == ''
    (tmp_path / 'public').mkdir()
    (tmp_path / 'public/fault').write_text('caller-selected-endpoint')
    with pytest.raises(ValueError, match='EXACT_ROOT_ENROLLED_FAULT'):
        proof.fault_mode(tmp_path)

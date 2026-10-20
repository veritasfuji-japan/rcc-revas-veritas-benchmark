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


def retained_backend(tmp_path, fault='after-sealed'):
    (tmp_path / 'backend').mkdir()
    (tmp_path / 'public').mkdir()
    if fault == 'concurrent-response-loss':
        (tmp_path / 'public/concurrent').write_text('two-custody-v1')
        (tmp_path / 'public/concurrent-response-loss').write_text('backend-commit-drop-v1')
    else:
        (tmp_path / 'public/fault').write_text(fault)
    with proof.open_backend_db(tmp_path) as db:
        if fault != 'after-consume':
            request_sha, response_sha = proof.scope()[('A', 0)], 'b' * 64
            receipt = proof.digest(dict(operation_id='A0', request_sha256=request_sha, response_sha256=response_sha))
            db.execute('INSERT INTO effects VALUES (?,?,?,?)', ('A0', request_sha, response_sha, receipt))


@pytest.mark.parametrize('fault', ['after-consume', 'after-sealed', 'concurrent-response-loss'])
def test_restarted_backend_retains_rows_and_is_sqlite_read_only(tmp_path, fault):
    import sqlite3
    retained_backend(tmp_path, fault)
    file = tmp_path / 'backend/effects.sqlite3'
    before = file.read_bytes()
    db = proof.open_backend_db(tmp_path, True)
    try:
        assert db.execute('SELECT count(*) FROM effects').fetchone()[0] == int(fault != 'after-consume')
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            db.execute("INSERT INTO effects VALUES ('B0','x','y','z')")
    finally:
        db.close()
    assert file.read_bytes() == before


def test_backend_restart_never_creates_missing_database(tmp_path):
    (tmp_path / 'backend').mkdir()
    with pytest.raises(ValueError, match='EXACT_BACKEND_DATABASE_LIFECYCLE'):
        proof.open_backend_db(tmp_path, True)
    assert not (tmp_path / 'backend/effects.sqlite3').exists()


@pytest.mark.parametrize('field', ['op', 'request_sha', 'response_sha', 'receipt'])
@pytest.mark.parametrize('fault', ['after-sealed', 'concurrent-response-loss'])
def test_backend_restart_rejects_altered_retained_receipt(tmp_path, field, fault):
    import sqlite3
    retained_backend(tmp_path, fault)
    with sqlite3.connect(tmp_path / 'backend/effects.sqlite3') as db:
        db.execute('UPDATE effects SET ' + field + '=?', ('invalid',))
    with pytest.raises(ValueError):
        proof.open_backend_db(tmp_path, True)


def test_backend_restart_rejects_missing_expected_effect(tmp_path):
    retained_backend(tmp_path, 'after-consume')
    (tmp_path / 'public/fault').write_text('after-sealed')
    with pytest.raises(ValueError, match='RETAINED_BACKEND_EFFECT_COUNT'):
        proof.open_backend_db(tmp_path, True)


def test_fresh_backend_never_overwrites_existing_database(tmp_path):
    retained_backend(tmp_path)
    with pytest.raises(ValueError, match='EXACT_BACKEND_DATABASE_LIFECYCLE'):
        proof.open_backend_db(tmp_path)


def test_unavailable_reconciliation_preserves_consumption(tmp_path, monkeypatch):
    import sqlite3
    folder = tmp_path / 'custody'
    folder.mkdir()
    (folder / 'credential').write_bytes(b'test-only')
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op,state,request_sha,response_sha,backend_receipt)')
        db.execute('INSERT INTO consumed VALUES (?,?,?,?,?)', ('A0', 'CONSUMED_UNKNOWN', 'a'*64, None, None))
    monkeypatch.setattr(proof.kernel, 'role_identity', lambda _: None)
    def unavailable(method, path, body, key):
        assert method == 'GET' and path == '/receipt/A0' and body is None
        raise ConnectionRefusedError('offline fixture')
    monkeypatch.setattr(proof, 'http_call', unavailable)
    assert proof.offline_reconcile(tmp_path) == {'backend_unavailable': True, 'ledger_unchanged': True, 'permission_restored': False}


def test_exactly_one_concurrent_response_selected():
    winner = {'decision': 'SEALED_NATIVE_RESPONSE', 'envelope_b64': 'test-only'}
    assert proof.select_race_winner([{'decision': 'REPLAY_DENIED'}, winner]) == (1, winner)


@pytest.mark.parametrize('decisions', [[], ['SEALED_NATIVE_RESPONSE']*2, ['REPLAY_DENIED']*2,
                                     ['DENIED_OR_UNKNOWN_NO_RETRY','SEALED_NATIVE_RESPONSE'],
                                     ['REPLAY_DENIED','REPLAY_DENIED','SEALED_NATIVE_RESPONSE']])
def test_concurrent_missing_duplicate_or_unknown_outcome_refused(decisions):
    with pytest.raises(ValueError):
        proof.select_race_winner([{'decision': x} for x in decisions])


def test_concurrent_loser_cannot_supply_response_bytes():
    with pytest.raises(ValueError, match='LOSER_MUST_NOT_RETURN_RESPONSE'):
        proof.select_race_winner([{'decision': 'REPLAY_DENIED', 'envelope_b64': 'unexpected'},
                                  {'decision': 'SEALED_NATIVE_RESPONSE'}])


def test_concurrent_configuration_is_root_enrolled_and_exact(tmp_path):
    assert proof.concurrent_mode(tmp_path) is False
    (tmp_path / 'public').mkdir()
    (tmp_path / 'public/concurrent').write_text('caller-defined-socket')
    with pytest.raises(ValueError, match='EXACT_CONCURRENT_FIXTURE'):
        proof.concurrent_mode(tmp_path)


def test_crashed_winner_is_identified_only_with_one_lost_and_one_refused_result():
    assert proof.select_crashed_winner([{'decision': 'REPLAY_DENIED'}, {'decision': 'IPC_RESPONSE_LOST'}]) == 1


@pytest.mark.parametrize('decisions', [[], ['IPC_RESPONSE_LOST']*2, ['REPLAY_DENIED']*2,
                                     ['SEALED_NATIVE_RESPONSE','IPC_RESPONSE_LOST'],
                                     ['DENIED_OR_UNKNOWN_NO_RETRY','REPLAY_DENIED']])
def test_missing_duplicate_successful_or_unknown_crash_outcome_refused(decisions):
    with pytest.raises(ValueError):
        proof.select_crashed_winner([{'decision': x} for x in decisions])


def test_crash_outcome_cannot_carry_response_data():
    with pytest.raises(ValueError, match='TWO_EXACT_CRASH_RACE_RESULTS'):
        proof.select_crashed_winner([{'decision': 'REPLAY_DENIED'},
                                    {'decision': 'IPC_RESPONSE_LOST', 'envelope_b64': 'unexpected'}])


def test_crash_mode_requires_exact_root_enrollment_and_two_process_fixture(tmp_path):
    assert proof.concurrent_crash_mode(tmp_path) is False
    (tmp_path / 'public').mkdir()
    (tmp_path / 'public/concurrent-crash').write_text('consumed-before-bind-v1')
    with pytest.raises(ValueError, match='EXACT_CONCURRENT_CRASH_FIXTURE'):
        proof.concurrent_crash_mode(tmp_path)
    (tmp_path / 'public/concurrent').write_text('two-custody-v1')
    assert proof.concurrent_crash_mode(tmp_path) is True


def test_response_loss_configuration_is_exact_and_excludes_pre_send_crash(tmp_path):
    assert proof.concurrent_response_loss_mode(tmp_path) is False
    (tmp_path / 'public').mkdir()
    (tmp_path / 'public/concurrent-response-loss').write_text('backend-commit-drop-v1')
    with pytest.raises(ValueError):
        proof.concurrent_response_loss_mode(tmp_path)
    (tmp_path / 'public/concurrent').write_text('two-custody-v1')
    assert proof.concurrent_response_loss_mode(tmp_path) is True
    (tmp_path / 'public/concurrent-response-loss').write_text('caller-specified-stage')
    with pytest.raises(ValueError):
        proof.concurrent_response_loss_mode(tmp_path)
    (tmp_path / 'public/concurrent-response-loss').write_text('backend-commit-drop-v1')
    (tmp_path / 'public/concurrent-crash').write_text('consumed-before-bind-v1')
    with pytest.raises(ValueError):
        proof.concurrent_response_loss_mode(tmp_path)


def confirmed_ledger(tmp_path, state):
    import sqlite3
    folder = tmp_path / 'custody'
    folder.mkdir()
    (folder / 'credential').write_bytes(b'test-only')
    request_sha, response_sha = 'a'*64, 'b'*64
    receipt = proof.digest(dict(operation_id='A0',request_sha256=request_sha,response_sha256=response_sha))
    row = ('A0', state, request_sha, response_sha, receipt)
    with sqlite3.connect(folder / 'ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op,state,request_sha,response_sha,backend_receipt)')
        db.execute('INSERT INTO consumed VALUES (?,?,?,?,?)', row)
    return folder / 'ledger.sqlite3', row


@pytest.mark.parametrize('state', ['MOCK_OBSERVED', 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE'])
def test_confirmed_response_receipt_cannot_be_overwritten_by_different_valid_hash(tmp_path, monkeypatch, state):
    import sqlite3
    file, row = confirmed_ledger(tmp_path, state)
    other_response = 'c'*64
    other_receipt = proof.digest(dict(operation_id='A0',request_sha256=row[2],response_sha256=other_response))
    monkeypatch.setattr(proof.kernel, 'role_identity', lambda _: None)
    monkeypatch.setattr(proof, 'http_call', lambda *_: (200,dict(operation_id='A0',record=[row[2],other_response,other_receipt])))
    with pytest.raises(ValueError, match='STORED_LEDGER_RECEIPT_MATCH'):
        proof.reconcile_fault(tmp_path)
    with sqlite3.connect(file) as db:
        assert db.execute('SELECT * FROM consumed').fetchall() == [row]


def test_missing_receipt_cannot_erase_prior_effect_confirmation(tmp_path, monkeypatch):
    import sqlite3
    file, row = confirmed_ledger(tmp_path, 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE')
    monkeypatch.setattr(proof.kernel, 'role_identity', lambda _: None)
    monkeypatch.setattr(proof, 'http_call', lambda *_: (200,dict(operation_id='A0',record=None)))
    with pytest.raises(ValueError, match='ABSENCE_MUST_NOT_RESET_AUTHORITY'):
        proof.reconcile_fault(tmp_path)
    with sqlite3.connect(file) as db:
        assert db.execute('SELECT * FROM consumed').fetchall() == [row]


@pytest.mark.parametrize('mutation', ['missing-effect', 'extra-effect', 'no-enrollment', 'pre-send-crash'])
def test_concurrent_backend_restart_refuses_incomplete_or_inconsistent_retained_state(tmp_path, mutation):
    import sqlite3
    retained_backend(tmp_path, 'concurrent-response-loss')
    file = tmp_path / 'backend/effects.sqlite3'
    if mutation == 'missing-effect':
        with sqlite3.connect(file) as db:
            db.execute('DELETE FROM effects')
    elif mutation == 'extra-effect':
        with sqlite3.connect(file) as db:
            db.execute("INSERT INTO effects VALUES ('B0','x','y','z')")
    elif mutation == 'no-enrollment':
        (tmp_path / 'public/concurrent').unlink()
    else:
        (tmp_path / 'public/concurrent-crash').write_text('consumed-before-bind-v1')
    before = file.read_bytes()
    with pytest.raises(ValueError):
        proof.open_backend_db(tmp_path, True)
    assert file.read_bytes() == before

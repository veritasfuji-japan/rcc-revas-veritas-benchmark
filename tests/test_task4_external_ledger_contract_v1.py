from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Barrier

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_external_ledger_contract_v1 as l


@pytest.fixture
def ledger(tmp_path):
    key = Ed25519PrivateKey.generate()
    approved = dict(schema=l.SCHEMA, ledger_id='1'*64, run_id='2'*64,
                    manifest_sha256='3'*64, issuer_public_sha256='4'*64, custody_public_sha256='5'*64)
    folder = tmp_path / 'authority'; folder.mkdir(mode=0o700)
    service = l.ReferenceService.bootstrap(folder / 'ledger.sqlite3', approved['ledger_id'], key)
    service.enroll(approved)
    return service, approved, key


def client(ledger, role='issuer', transport=None, approved=None, public=None):
    service, value, key = ledger
    return l.LedgerClient(approved or value, public or key.public_key().public_bytes_raw(),
        transport or (lambda data: service.exchange(data, value[role + '_public_sha256'])))


def reserve(ledger, op='A0'):
    return client(ledger).gate('reserve', op, 'a'*64, lambda snapshot: snapshot)


def consume(ledger, op='A0', effect=lambda snapshot: snapshot):
    return client(ledger, 'custody').gate('consume', op, 'a'*64, effect, 'b'*64)


def test_commit_before_callback_and_new_clients_share_state(ledger, tmp_path, monkeypatch):
    calls = []
    for name in ('runner-a', 'runner-b'):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path / 'runner-a')
    def issue(_):
        assert client(ledger, 'custody').exchange('view')['attempts'][0]['state'] == 'RESERVED'
        calls.append('issue')
    client(ledger).gate('reserve', 'A0', 'a'*64, issue)
    monkeypatch.chdir(tmp_path / 'runner-b')
    def send(_):
        assert client(ledger).exchange('view')['attempts'][0]['state'] == 'CONSUMED_UNKNOWN'
        calls.append('send')
    consume(ledger, effect=send)
    with pytest.raises(l.Denied):
        reserve(ledger)
    with pytest.raises(l.Denied):
        consume(ledger, effect=lambda _: calls.append('BAD'))
    assert calls == ['issue', 'send']
    assert not list((tmp_path / 'runner-a').iterdir()) and not list((tmp_path / 'runner-b').iterdir())


def test_fresh_service_process_preserves_state(ledger, tmp_path):
    service, approved, key = ledger
    reserve(ledger)
    # Key is synthetic and passed privately over stdin, never argv/environment.
    program = '''
import json,sys
from scripts import task4_external_ledger_contract_v1 as l
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
v=json.load(sys.stdin)
s=l.ReferenceService(v['file'],v['binding']['ledger_id'],Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v['key'])))
c=l.LedgerClient(v['binding'],s.key.public_key().public_bytes_raw(),lambda data:s.exchange(data,v['binding']['issuer_public_sha256']))
try:c.gate('reserve','A0','a'*64,lambda _:sys.exit(7))
except l.Denied:print(json.dumps(c.exchange('view')))
'''
    env = dict(os.environ)
    env['PYTHONPATH'] = str(Path(l.__file__).resolve().parents[1]) + os.pathsep + env.get('PYTHONPATH', '')
    result = subprocess.run([sys.executable, '-c', program], cwd=tmp_path, env=env, text=True,
        input=json.dumps(dict(file=str(service.file), binding=approved, key=key.private_bytes_raw().hex())),
        capture_output=True, check=True, timeout=20)
    assert json.loads(result.stdout) == client(ledger).exchange('view')


@pytest.mark.parametrize('changed', [None, 'manifest_sha256', 'issuer_public_sha256', 'custody_public_sha256'])
def test_run_id_cannot_be_reenrolled_even_with_changed_binding(ledger, changed):
    service, approved, key = ledger
    reserve(ledger)
    changed_binding = dict(approved)
    if changed:
        changed_binding[changed] = 'f'*64
    with pytest.raises(l.Denied, match='ALREADY_ENROLLED'):
        service.enroll(changed_binding)
    assert client(ledger).exchange('view')['revision'] == 1


@pytest.mark.parametrize('field', ['ledger_id', 'run_id', 'manifest_sha256', 'issuer_public_sha256', 'custody_public_sha256'])
def test_binding_mismatch_stops_before_effect(ledger, field):
    approved = dict(ledger[1]); approved[field] = 'e'*64
    calls = []
    with pytest.raises(l.Denied):
        client(ledger, approved=approved).gate('reserve', 'A0', 'a'*64, lambda _: calls.append(1))
    assert calls == [] and client(ledger).exchange('view')['revision'] == 0


@pytest.mark.parametrize('action,role', [('reserve', 'custody'), ('consume', 'issuer')])
def test_authenticated_roles_cannot_cross_mutate(ledger, action, role):
    reserve(ledger)
    with pytest.raises(l.Denied):
        client(ledger, role).gate(action, 'B0' if action == 'reserve' else 'A0', 'a'*64, lambda _: pytest.fail('effect'),
                                  'b'*64 if action == 'consume' else None)
    assert client(ledger).exchange('view')['revision'] == 1


def test_peer_not_authenticated_by_json(ledger):
    service, approved, key = ledger
    with pytest.raises(l.Denied):
        client(ledger, transport=lambda data: service.exchange(data, 'f'*64)).exchange('view')


def test_default_unavailable_has_no_callback(ledger):
    service, approved, key = ledger
    c = l.LedgerClient(approved, key.public_key().public_bytes_raw())
    with pytest.raises(l.Denied, match='UNAVAILABLE'):
        c.gate('reserve', 'A0', 'a'*64, lambda _: pytest.fail('effect'))


@pytest.mark.parametrize('phase', ['view', 'reserve', 'consume'])
@pytest.mark.parametrize('failure', ['timeout', 'disconnect', 'invalid', 'oversized'])
def test_unverified_response_always_stops_effect(ledger, phase, failure):
    service, approved, key = ledger
    if phase == 'consume':
        reserve(ledger)
    attempts = []
    def transport(data):
        c = l.strict(data); attempts.append(c['action'])
        result = service.exchange(data, approved[('custody' if phase == 'consume' else 'issuer') + '_public_sha256'])
        if c['action'] != phase:
            return result
        if failure == 'timeout':
            raise TimeoutError()
        if failure == 'disconnect':
            raise ConnectionError()
        return b'broken' if failure == 'invalid' else b'x'*(l.MAX_WIRE + 1)
    calls = []
    with pytest.raises(l.Denied):
        client(ledger, transport=transport).gate('consume' if phase == 'consume' else 'reserve', 'A0', 'a'*64,
            lambda _: calls.append('BAD'), 'b'*64 if phase == 'consume' else None)
    assert calls == [] and attempts.count(phase) == 1
    snapshot = client(ledger).exchange('view')
    assert snapshot['revision'] == {'view': 0, 'reserve': 1, 'consume': 2}[phase]
    if phase != 'view':
        with pytest.raises(l.Denied):
            consume(ledger) if phase == 'consume' else reserve(ledger)


@pytest.mark.parametrize('failure', ['signature', 'key', 'nonce', 'command', 'binding', 'action', 'snapshot', 'extra'])
def test_receipt_verification_before_callback(ledger, failure):
    service, approved, key = ledger
    def transport(data):
        result = l.strict(service.exchange(data, approved['issuer_public_sha256']))
        if l.strict(data)['action'] == 'view':
            return l.canonical(result)
        s = result['statement']
        if failure == 'signature':
            result['signature'] = '00'*64
        elif failure == 'key':
            result['signature'] = Ed25519PrivateKey.generate().sign(l.DOMAIN + l.canonical(s)).hex()
        else:
            if failure == 'nonce': s['nonce'] = 'f'*64
            elif failure == 'command': s['command_sha256'] = 'f'*64
            elif failure == 'binding': s['binding_sha256'] = 'f'*64
            elif failure == 'action': s['action'] = 'consume'
            elif failure == 'snapshot': s['snapshot']['attempts'] = []
            else: s['extra'] = True
            result['signature'] = key.sign(l.DOMAIN + l.canonical(s)).hex()
        return l.canonical(result)
    with pytest.raises(l.Denied):
        client(ledger, transport=transport).gate('reserve', 'A0', 'a'*64, lambda _: pytest.fail('effect'))


def test_replayed_view_receipt_is_not_fresh(ledger):
    service, approved, key = ledger
    cached = []
    def transport(data):
        if not cached:
            cached.append(service.exchange(data, approved['issuer_public_sha256']))
        return cached[0]
    c = client(ledger, transport=transport)
    c.exchange('view')
    with pytest.raises(l.Denied, match='UNVERIFIED'):
        c.exchange('view')


@pytest.mark.parametrize('action', ['reserve', 'consume'])
def test_concurrent_cas_has_one_winner_and_no_duplicate_effect(ledger, action):
    if action == 'consume':
        reserve(ledger)
    revision = client(ledger).exchange('view')['revision']
    service, approved, key = ledger
    barrier = Barrier(4)
    calls = []
    def transport(data):
        result = service.exchange(data, approved[('issuer' if action == 'reserve' else 'custody') + '_public_sha256'])
        if l.strict(data)['action'] == 'view':
            barrier.wait(timeout=10)  # Every contender has the same revision.
        return result
    def mutate(_):
        try:
            def effect(snapshot):
                calls.append(action)
                return snapshot['revision']
            return client(ledger, transport=transport).gate(
                action, 'A0', 'a'*64, effect, 'b'*64 if action == 'consume' else None)
        except l.Denied:
            return 'DENIED'
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(mutate, range(4)))
    assert results.count(revision + 1) == 1 and results.count('DENIED') == 3
    assert calls == [action]
    assert client(ledger).exchange('view')['revision'] == revision + 1


def test_stale_revision_for_different_operation_does_not_retry(ledger):
    c = client(ledger); revision = c.exchange('view')['revision']
    reserve(ledger)
    with pytest.raises(l.Denied):
        c.exchange('reserve', revision, 'B0', 'a'*64)
    assert client(ledger).exchange('view')['revision'] == 1


def test_callback_failure_retains_unknown_state_no_retry(ledger):
    reserve(ledger)
    def effect(_):
        raise RuntimeError('delivery outcome unknown')
    with pytest.raises(RuntimeError):
        consume(ledger, effect=effect)
    with pytest.raises(l.Denied):
        consume(ledger)
    assert client(ledger).exchange('view')['attempts'][0]['state'] == 'CONSUMED_UNKNOWN'


def test_signed_fresh_view_cannot_regress_this_client(ledger):
    service, approved, key = ledger
    c = client(ledger)
    reserve(ledger); consume(ledger)
    assert c.exchange('view')['revision'] == 2
    def rolled_back(data):
        result = l.strict(service.exchange(data, approved['issuer_public_sha256']))
        result['statement']['snapshot'] = dict(revision=0, attempts=[])
        result['signature'] = key.sign(l.DOMAIN + l.canonical(result['statement'])).hex()
        return l.canonical(result)
    c.transport = rolled_back
    with pytest.raises(l.Denied):
        c.gate('reserve', 'B0', 'a'*64, lambda _: pytest.fail('effect'))


@pytest.mark.parametrize('fault', ['missing', 'corrupt', 'symlink', 'public-mode', 'changed-key'])
def test_bad_storage_or_key_never_recreated(ledger, fault):
    service, approved, key = ledger
    reserve(ledger)
    if fault == 'missing': service.file.unlink()
    elif fault == 'corrupt': service.file.write_bytes(b'corrupt')
    elif fault == 'symlink':
        saved = service.file.with_suffix('.saved'); service.file.rename(saved); service.file.symlink_to(saved)
    elif fault == 'public-mode': service.file.chmod(0o644)
    else: key = Ed25519PrivateKey.generate()
    before = service.file.read_bytes() if service.file.exists() else None
    with pytest.raises((l.Denied, OSError, sqlite3.Error)):
        l.ReferenceService(service.file, approved['ledger_id'], key)
    assert (service.file.read_bytes() if service.file.exists() else None) == before


@pytest.mark.parametrize('action', ['enroll', 'reset', 'repair', 'retire'])
def test_no_admin_commands_on_client_protocol(ledger, action):
    with pytest.raises(l.Denied):
        client(ledger).exchange(action)


def test_fixed_operation_bound_and_duplicate_json(ledger):
    for op in sorted(l.OPERATIONS):
        reserve(ledger, op); consume(ledger, op)
    assert client(ledger).exchange('view')['revision'] == 16
    with pytest.raises(l.Denied):
        reserve(ledger, 'A4')
    with pytest.raises(l.Denied, match='DUPLICATE'):
        l.strict(b'{"x":1,"x":1}')


def test_reference_report_is_not_deployment_or_native_proof():
    report = l.rehearsal()
    assert len(report['checks']) == 6 and all(report['checks'].values())
    assert report['final_states'] == ['CONSUMED_UNKNOWN', 'RESERVED']
    assert report['real_provider_posts'] == report['external_bank_effects'] == 0
    assert not any(report[name] for name in ('native_integration_proven', 'cross_runner_retention_proven',
                                            'external_storage_deployed', 'production_bypass_resistance_proven'))

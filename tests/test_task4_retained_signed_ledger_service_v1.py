import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading

import pytest

from scripts import task4_receipt_key_custody_v1 as custody
from scripts import task4_retained_signed_ledger_service_v1 as retained
from scripts import task4_signed_github_ledger_v1 as signed
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_external_ledger_mtls_rehearsal_v1 as tls
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, sha


@pytest.fixture
def prepared(tmp_path):
    parent = tmp_path / 'authority'
    parent.mkdir(mode=0o700)
    slot = parent / 'receipt-custody'
    identity = custody.initialize(slot)
    pin = identity['public_key_sha256']
    api = model.ModelGitAPI(pin)
    backend = signed.GitState(api, api.genesis, pin)
    return slot, identity, api, backend


def test_startup_reads_existing_root_without_enrollment_or_mutation(prepared):
    slot, identity, api, backend = prepared
    head = api.head
    before = (slot / custody.KEY_NAME).stat()
    service = retained.reopen_service(backend, slot, identity['public_key_sha256'])
    assert custody.public_identity(service.key) == identity
    assert api.calls and all(method == 'GET' for method, _, _ in api.calls)
    assert api.head == head and not backend.read()[1]['runs']
    after = (slot / custody.KEY_NAME).stat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


@pytest.mark.parametrize('fault', ['missing_slot', 'missing_key', 'corrupt', 'replacement',
                                      'mode', 'wrong_pin', 'no_pin', 'backend_pin'])
def test_custody_failure_prevents_backend_access_and_listener(prepared, monkeypatch, fault):
    slot, identity, api, backend = prepared
    key = slot / custody.KEY_NAME
    pin = identity['public_key_sha256']
    if fault == 'missing_slot': key.unlink(); slot.rmdir()
    if fault == 'missing_key': key.unlink()
    if fault == 'corrupt': key.write_bytes(b'broken')
    if fault == 'replacement': key.write_bytes(b'x' * 32)
    if fault == 'mode': key.chmod(0o644)
    if fault == 'wrong_pin': pin = '0' * 64
    if fault == 'no_pin': pin = None
    if fault == 'backend_pin': backend.signer = '0' * 64
    monkeypatch.setattr(retained, 'listener', lambda *a: pytest.fail('listener opened'))
    monkeypatch.setattr(custody, 'initialize', lambda *a: pytest.fail('key initialized'))
    with pytest.raises(Denied, match='^RETAINED_SIGNED_LEDGER_STARTUP_STOP$'):
        with retained.retained_listener(backend, slot, pin, None, None):
            pytest.fail('service started')
    assert not api.calls
    if fault == 'missing_slot': assert not slot.exists()
    if fault == 'missing_key': assert not key.exists()


@pytest.mark.parametrize('fault', ['unavailable', 'wrong_root', 'corrupt_root'])
def test_backend_failure_stops_before_bind_without_writes(prepared, monkeypatch, fault):
    slot, identity, api, backend = prepared
    if fault == 'wrong_root': backend.genesis = '0' * 40
    if fault == 'corrupt_root': api.commits[api.genesis]['state']['service_public_sha256'] = '0' * 64
    if fault == 'unavailable':
        def offline(*args): raise TimeoutError('synthetic secret that must not escape')
        api.call = offline
    monkeypatch.setattr(retained, 'listener', lambda *a: pytest.fail('listener opened'))
    with pytest.raises(Denied) as error:
        with retained.retained_listener(backend, slot, identity['public_key_sha256'], None, None):
            pytest.fail('service started')
    assert str(error.value) == 'RETAINED_SIGNED_LEDGER_STARTUP_STOP'
    assert error.value.__suppress_context__
    assert all(method == 'GET' for method, _, _ in api.calls)


def test_existing_key_signs_through_real_mtls_and_reopen_denies_replay(prepared, tmp_path):
    slot, identity, api, backend = prepared
    fixture = tls.provision(tmp_path / 'tls')
    b = dict(fixture['binding'], ledger_id=signed.LEDGER_ID)
    service = retained.reopen_service(backend, slot, identity['public_key_sha256'])
    service.enroll(b)  # Explicit synthetic administration, never performed by startup.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    from scripts.task4_external_ledger_mtls_v1 import load_configuration
    cfg, peers = load_configuration(fixture['root'] / 'configuration.json')
    context.load_verify_locations(cafile=cfg['client_ca'])
    context.load_cert_chain(cfg['tls_certificate'], cfg['tls_key'])
    effects = []
    for first in (True, False):
        with retained.retained_listener(backend, slot, identity['public_key_sha256'], context, peers) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.01))
            thread.start()
            try:
                def client(role):
                    return LedgerClient(b, bytes.fromhex(identity['public_key_hex']),
                        tls.transport(fixture, dict(port=server.server_address[1]), role))
                issuer, consumer = client('issuer'), client('custody')
                if first:
                    issuer.gate('reserve', 'A0', sha(b'request'), lambda _: effects.append('issue'))
                    with pytest.raises(Denied):
                        issuer.gate('consume', 'A0', sha(b'request'), lambda _: pytest.fail('wrong role'), sha(b'grant'))
                    consumer.gate('consume', 'A0', sha(b'request'), lambda _: effects.append('send'), sha(b'grant'))
                else:
                    with pytest.raises(Denied):
                        consumer.gate('consume', 'A0', sha(b'request'), lambda _: pytest.fail('replay'), sha(b'grant'))
                    assert consumer.exchange('view')['revision'] == 2
            finally:
                server.shutdown(); thread.join(5)
                assert not thread.is_alive()
    assert effects == ['issue', 'send']


def test_two_fresh_processes_reopen_key_and_verify_same_model_consumption(prepared, tmp_path):
    slot, identity, api, backend = prepared
    service = retained.reopen_service(backend, slot, identity['public_key_sha256'])
    b = dict(schema=signed.SCHEMA, ledger_id=signed.LEDGER_ID, run_id='a'*64,
             manifest_sha256='d'*64, issuer_public_sha256='b'*64, custody_public_sha256='c'*64)
    service.enroll(b)
    issuer = LedgerClient(b, service.key.public_key().public_bytes_raw(),
                          lambda data: service.exchange(data, b['issuer_public_sha256']))
    issuer.gate('reserve', 'A0', sha(b'request'), lambda _: None)
    consumer = LedgerClient(b, service.key.public_key().public_bytes_raw(),
                            lambda data: service.exchange(data, b['custody_public_sha256']))
    consumer.gate('consume', 'A0', sha(b'request'), lambda _: None, sha(b'grant'))
    # Serialized synthetic model is a test fixture, not an external storage implementation.
    fixture = tmp_path / 'model.json'
    fixture.write_bytes(canonical(dict(commits=api.commits, head=api.head, genesis=api.genesis, binding=b)))
    code = '''
import json, os, sys
from scripts import task4_retained_signed_ledger_service_v1 as retained
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_signed_github_ledger_v1 as signed
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, sha
slot, pin, filename = sys.argv[1:]
with open(filename) as stream: f = json.load(stream)
api = model.ModelGitAPI.__new__(model.ModelGitAPI)
api.commits, api.head, api.genesis = f['commits'], f['head'], f['genesis']
api.calls, api.events, api.response_fault = [], [], None
service = retained.reopen_service(signed.GitState(api, api.genesis, pin), slot, pin)
b = f['binding']
client = LedgerClient(b, service.key.public_key().public_bytes_raw(),
                      lambda data: service.exchange(data, b['custody_public_sha256']))
assert client.exchange('view')['revision'] == 2
try:
    client.gate('consume', 'A0', sha(b'request'), lambda _: sys.exit(9), sha(b'grant'))
except Denied: pass
else: sys.exit(10)
assert all(m == 'GET' for m, _, _ in api.calls)
print(json.dumps(dict(pid=os.getpid(), pin=sha(service.key.public_key().public_bytes_raw()))))
'''
    reports = [json.loads(subprocess.check_output([sys.executable, '-c', code, str(slot),
                identity['public_key_sha256'], str(fixture)], text=True)) for _ in range(2)]
    assert all(r['pin'] == identity['public_key_sha256'] and r['pid'] != os.getpid() for r in reports)
    assert reports[0]['pid'] != reports[1]['pid']

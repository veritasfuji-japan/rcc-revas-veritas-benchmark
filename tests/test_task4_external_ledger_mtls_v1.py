import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from scripts import task4_external_ledger_mtls_v1 as mtls
from scripts import task4_external_ledger_mtls_rehearsal_v1 as demo
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, sha


@pytest.fixture
def fixture(tmp_path):
    return demo.provision(tmp_path/'authority')


@pytest.fixture
def live(fixture):
    with demo.running(fixture) as ready:
        yield fixture, ready


REQUEST, GRANT = sha(b'request'), sha(b'grant')


def encoded(f, action='view', operation=None, revision=None, grant=None):
    from scripts.task4_external_ledger_contract_v1 import SCHEMA, digest
    return canonical(dict(schema=SCHEMA, binding_sha256=digest(f['binding']), nonce=os.urandom(32).hex(),
                          action=action, expected_revision=revision, operation_id=operation,
                          request_sha256=REQUEST if operation else None, grant_sha256=grant))


def channel(f, ready, role='issuer', ca=None, hostname=mtls.SERVER_NAME):
    ctx = ssl.create_default_context(cafile=str(ca or f['root']/'ca.pem'))
    if role:
        ctx.load_cert_chain(f['root']/(role+'.pem'), f['root']/(role+'.key'))
    raw = socket.create_connection(('127.0.0.1', ready['port']), timeout=3)
    try:
        return ctx.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        raw.close()
        raise


def test_real_mtls_signed_reserve_and_consume(live):
    f, ready = live
    effects = []
    issuer, custody = demo.client(f, ready, 'issuer'), demo.client(f, ready, 'custody')
    issuer.gate('reserve', 'A0', REQUEST, lambda state: effects.append(state['revision']))
    custody.gate('consume', 'A0', REQUEST, lambda state: effects.append(state['revision']), GRANT)
    assert effects == [1, 2]
    assert custody.exchange('view')['attempts'][0]['state'] == 'CONSUMED_UNKNOWN'


@pytest.mark.parametrize('role,action', [('issuer', 'consume'), ('custody', 'reserve')])
def test_tls_peer_cannot_cross_role(live, role, action):
    f, ready = live
    demo.client(f, ready, 'issuer').gate('reserve', 'A0', REQUEST, lambda _: None)
    effects = []
    with pytest.raises(Denied):
        demo.client(f, ready, role).gate(action, 'A0' if action == 'consume' else 'B0', REQUEST,
                                       lambda _: effects.append(1), GRANT if action == 'consume' else None)
    assert effects == [] and demo.client(f, ready, 'issuer').exchange('view')['revision'] == 1


def test_ca_valid_unenrolled_certificate_refused(live):
    f, ready = live
    with pytest.raises(Denied):
        demo.client(f, ready, 'unmapped').exchange('view')
    assert demo.client(f, ready, 'issuer').exchange('view')['revision'] == 0


def test_no_client_certificate_refused(live):
    f, ready = live
    with pytest.raises((OSError, Denied)):
        with channel(f, ready, role=None) as sock:
            mtls.write_frame(sock, encoded(f))
            mtls.read_frame(sock)


def test_foreign_client_ca_refused(live, tmp_path):
    f, ready = live
    other = demo.provision(tmp_path/'other-authority')
    with pytest.raises((OSError, Denied)):
        with channel(other, ready) as sock:
            mtls.write_frame(sock, encoded(f))
            mtls.read_frame(sock)


def test_server_hostname_checked(live):
    f, ready = live
    with pytest.raises(ssl.SSLCertVerificationError):
        channel(f, ready, hostname='other-ledger.test')


def test_server_ca_checked(live, tmp_path):
    f, ready = live
    other = demo.provision(tmp_path/'other-authority')
    with pytest.raises(ssl.SSLCertVerificationError):
        channel(f, ready, ca=other['root']/'ca.pem')


def test_server_pin_checked_before_mutation(live):
    f, ready = live
    wrong = demo.transport(f, ready, 'issuer', server_certificate_sha256='0'*64)
    with pytest.raises(Denied):
        wrong(encoded(f, 'reserve', 'A0', 0))
    assert demo.client(f, ready, 'issuer').exchange('view')['revision'] == 0


def test_tls_is_not_service_signature(live):
    f, ready = live
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    wrong = LedgerClient(f['binding'], Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
                         demo.transport(f, ready, 'issuer'))
    effects = []
    with pytest.raises(Denied):
        wrong.gate('reserve', 'A0', REQUEST, lambda _: effects.append(1))
    assert effects == [] and demo.client(f, ready, 'issuer').exchange('view')['revision'] == 0


@pytest.mark.parametrize('payload', [b'', b'{}', b'{"role":"custody"}', b'{"schema":1,"schema":2}', b'not-json'])
def test_invalid_commands_stop_before_connect(fixture, payload):
    transport = demo.transport(fixture, {'port': 1}, 'issuer')
    with pytest.raises(Denied):
        transport(payload)


@pytest.mark.parametrize('payload', [b'{}', b'{"role":"custody"}', b'{"a":1,"a":2}'])
def test_server_independently_rejects_invalid_command(live, payload):
    f, ready = live
    with channel(f, ready) as sock:
        mtls.write_frame(sock, payload)
        assert sock.recv(1) == b''
    assert demo.client(f, ready, 'issuer').exchange('view')['revision'] == 0


@pytest.mark.parametrize('length', [0, mtls.MAX_WIRE+1, 2**32-1])
def test_server_rejects_unbounded_frame_before_body(live, length):
    f, ready = live
    with channel(f, ready) as sock:
        sock.sendall(struct.pack('!I', length))
        assert sock.recv(1) == b''
    assert demo.client(f, ready, 'issuer').exchange('view')['revision'] == 0


def test_frame_deadline_is_total_not_per_byte():
    class Slow:
        def settimeout(self, value):
            pass
        def recv(self, count):
            time.sleep(0.01)
            return b'x'
    with pytest.raises(Denied, match='FRAME_DEADLINE'):
        mtls.receive(Slow(), 100, time.monotonic()+0.025)


def test_truncated_frame_stops():
    a, b = socket.socketpair()
    with a, b:
        b.sendall(struct.pack('!I', 10)+b'{}')
        b.shutdown(socket.SHUT_WR)
        with pytest.raises(Denied, match='TRUNCATED_FRAME'):
            mtls.read_frame(a)


def test_same_revision_actual_tls_contention(live):
    f, ready = live
    def reserve():
        try:
            result = demo.transport(f, ready, 'issuer')(encoded(f, 'reserve', 'A0', 0))
            return json.loads(result)['statement']['snapshot']['revision']
        except Denied:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: reserve(), range(2)))
    assert outcomes.count(1) == 1 and outcomes.count(None) == 1
    assert demo.client(f, ready, 'issuer').exchange('view')['revision'] == 1


@pytest.mark.parametrize('fault', ['missing', 'corrupt', 'replacement'])
def test_retained_storage_or_signer_failure_stops_start(fixture, fault):
    root = fixture['root']
    if fault == 'missing':
        (root/'ledger.sqlite').unlink()
    elif fault == 'corrupt':
        (root/'ledger.sqlite').write_bytes(b'broken')
    else:
        (root/'service.key').write_bytes(os.urandom(32))
    # Test startup directly: failure must happen before ready.send/listen.
    class NeverReady:
        def send(self, value):
            raise AssertionError('UNEXPECTED_READY')
    with pytest.raises((Denied, OSError, sqlite3.DatabaseError)):
        mtls.serve(root/'configuration.json', NeverReady())
    if fault == 'missing':
        assert not (root/'ledger.sqlite').exists()


@pytest.mark.parametrize('fault', ['duplicate_cert', 'duplicate_identity', 'unknown_field', 'symlink_key', 'public_key_mode'])
def test_invalid_administration_configuration_stops(fixture, fault):
    root = fixture['root']; path = root/'configuration.json'; cfg = json.loads(path.read_bytes())
    if fault == 'duplicate_cert':
        cfg['peers']['custody']['certificate_sha256'] = cfg['peers']['issuer']['certificate_sha256']
    elif fault == 'duplicate_identity':
        cfg['peers']['custody']['authority_public_sha256'] = cfg['peers']['issuer']['authority_public_sha256']
    elif fault == 'unknown_field':
        cfg['role'] = 'issuer'
    elif fault == 'symlink_key':
        (root/'linked.key').symlink_to(root/'service.key');cfg['service_key'] = str(root/'linked.key')
    else:
        (root/'service.key').chmod(0o644)
    path.write_bytes(canonical(cfg))
    with pytest.raises(Denied):
        mtls.load_configuration(path)


def test_unavailable_service_does_not_call_effect(fixture):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    effects = []
    with pytest.raises(Denied):
        demo.client(fixture, {'port':port}, 'issuer').gate('reserve', 'A0', REQUEST, lambda _: effects.append(1))
    assert effects == []


def test_actual_process_restart_and_committed_ack_discard():
    report = demo.rehearsal()
    assert all(report['checks'].values()) and report['service_processes'] == 4
    assert report['synthetic_issue_callbacks'] == report['synthetic_send_callbacks'] == 1
    assert report['github_backend_connected'] is report['native_integration_proven'] is False

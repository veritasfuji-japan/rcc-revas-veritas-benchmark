import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import task4_signed_ledger_entrypoint_v1 as entry
from scripts import task4_receipt_key_custody_v1 as custody
from scripts import task4_signed_github_ledger_v1 as signed
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_external_ledger_mtls_rehearsal_v1 as tls
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, sha

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='root-owned public pin fixture requires sudo')
TOKEN = 'ghp_SYNTHETIC_ENTRYPOINT_TOKEN_NOT_A_CREDENTIAL'


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    root = tmp_path / 'authority'; root.mkdir(mode=0o700)
    slot = root / 'receipt-custody'; identity = custody.initialize(slot)
    fixture = tls.provision(tmp_path / 'tls')
    old = json.loads((fixture['root'] / 'configuration.json').read_bytes())
    pin = root / 'public-pin'; pin.write_text(identity['public_key_sha256']+'\n'); pin.chmod(0o644)
    token = root / 'token'; tls.private_write(token, TOKEN.encode()+b'\n')
    api = model.ModelGitAPI(identity['public_key_sha256'])
    backend = signed.GitState(api, api.genesis, identity['public_key_sha256'])
    b = dict(fixture['binding'], ledger_id=signed.LEDGER_ID)
    signed.SignedGitHubService(backend, custody.load(slot, identity['public_key_sha256'])).enroll(b)
    api.calls.clear()
    cfg = dict(schema=entry.PROFILE, scope=entry.SCOPE, genesis=api.genesis,
        receipt_directory=str(slot), public_pin_file=str(pin), token_file=str(token), binding=b,
        tls_certificate=old['tls_certificate'], tls_key=old['tls_key'], client_ca=old['client_ca'],
        server_certificate_sha256=fixture['pins']['server'], peers=old['peers'])
    file = root / 'configuration.json'; tls.private_write(file, canonical(cfg))
    constructions = []
    def factory(actual_token, genesis, signer):
        assert actual_token == TOKEN and genesis == api.genesis and signer == identity['public_key_sha256']
        constructions.append(1)
        return backend
    monkeypatch.setattr(entry, 'approved_backend', factory)
    return dict(root=root, slot=slot, identity=identity, fixture=fixture, api=api,
                backend=backend, cfg=cfg, file=file, constructions=constructions)


def test_check_is_local_and_outputs_only_public_status(prepared, capsys):
    f = prepared
    assert entry.main(['check', '--configuration', str(f['file'])]) == 0
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report['public_key_sha256'] == f['identity']['public_key_sha256']
    assert report['backend_verified'] is report['listener_started'] is False
    assert report['provider_dispatch'] == 'DENY' and report['utility'] == 'UNSCORED'
    assert TOKEN not in output.out and not output.err and not f['api'].calls
    assert 'token_file' not in report and 'receipt_directory' not in report


@pytest.mark.parametrize('fault', ['schema', 'scope', 'genesis', 'extra', 'pin', 'pin_newline', 'pin_mode',
    'key_missing', 'token_missing', 'token_mode', 'token_invalid', 'token_oversize', 'binding_ledger',
    'authority', 'same_peers', 'server_pin', 'shared_server_pin', 'tls_key', 'encrypted_key', 'ca', 'missing_certificate'])
def test_local_faults_stop_before_backend_or_listener(prepared, monkeypatch, fault):
    f = prepared; cfg = copy.deepcopy(f['cfg'])
    if fault == 'schema': cfg['schema'] = 'other'
    if fault == 'scope': cfg['scope'] = 'PRODUCTION'
    if fault == 'genesis': cfg['genesis'] = 'main'
    if fault == 'extra': cfg['host'] = '0.0.0.0'
    if fault == 'pin': Path(cfg['public_pin_file']).write_text('0'*64+'\n')
    if fault == 'pin_newline': Path(cfg['public_pin_file']).write_text(f['identity']['public_key_sha256'])
    if fault == 'pin_mode': Path(cfg['public_pin_file']).chmod(0o666)
    if fault == 'key_missing': (f['slot'] / custody.KEY_NAME).unlink()
    if fault == 'token_missing': Path(cfg['token_file']).unlink()
    if fault == 'token_mode': Path(cfg['token_file']).chmod(0o644)
    if fault == 'token_invalid': Path(cfg['token_file']).write_text(TOKEN+'\r\n')
    if fault == 'token_oversize': Path(cfg['token_file']).write_bytes(b'x'*257)
    if fault == 'binding_ledger': cfg['binding']['ledger_id'] = '0'*64
    if fault == 'authority': cfg['peers']['issuer']['authority_public_sha256'] = '0'*64
    if fault == 'same_peers': cfg['peers']['custody']['certificate_sha256'] = cfg['peers']['issuer']['certificate_sha256']
    if fault == 'server_pin': cfg['server_certificate_sha256'] = '0'*64
    if fault == 'shared_server_pin': cfg['server_certificate_sha256'] = cfg['peers']['issuer']['certificate_sha256']
    if fault == 'tls_key': Path(cfg['tls_key']).write_bytes(b'bad TLS private key')
    if fault == 'encrypted_key':
        path = Path(cfg['tls_key'])
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b'synthetic-passphrase')))
    if fault == 'ca': Path(cfg['client_ca']).write_bytes(b'bad CA')
    if fault == 'missing_certificate': Path(cfg['tls_certificate']).unlink()
    f['file'].write_bytes(canonical(cfg))
    before = sorted(str(p) for p in f['root'].rglob('*'))
    monkeypatch.setattr(entry, 'listener', lambda *a: pytest.fail('listener opened'))
    with pytest.raises(Denied, match='^SIGNED_LEDGER_ENTRYPOINT_STOP$'):
        with entry.configured_listener(f['file']): pytest.fail('started')
    assert not f['api'].calls and not f['constructions']
    assert sorted(str(p) for p in f['root'].rglob('*')) == before


@pytest.mark.parametrize('fault', ['missing', 'mode', 'symlink', 'hardlink', 'fifo', 'writable_parent',
                                   'symlink_ancestor', 'relative', 'dot'])
def test_configuration_path_checks_never_repair(prepared, fault):
    f = prepared; file = f['file']
    if fault == 'missing': file.unlink()
    if fault == 'mode': file.chmod(0o644)
    if fault in ('symlink', 'fifo'):
        file.unlink()
        if fault == 'symlink': file.symlink_to('/dev/null')
        else: os.mkfifo(file, 0o600)
    if fault == 'hardlink': os.link(file, f['root'] / 'linked')
    if fault == 'writable_parent': f['root'].chmod(0o777)
    if fault == 'symlink_ancestor':
        alias = f['root'].parent / 'alias'; alias.symlink_to(f['root'], target_is_directory=True)
        file = alias / file.name
    if fault == 'relative': file = 'configuration.json'
    if fault == 'dot': file = str(file.parent)+'/./'+file.name
    with pytest.raises(Denied, match='^SIGNED_LEDGER_ENTRYPOINT_STOP$'): entry.prepare(file)
    assert not f['api'].calls and not f['constructions']


@pytest.mark.parametrize('fault', ['missing_run', 'changed_binding', 'backend_unavailable'])
def test_remote_verification_failure_stops_before_binding(prepared, monkeypatch, fault):
    f = prepared; api = f['api']; b = f['cfg']['binding']
    if fault != 'backend_unavailable':
        state = copy.deepcopy(api.commits[api.head]['state'])
        if fault == 'missing_run': state['runs'] = {}; state['revision'] = 0
        else: state['runs'][b['run_id']]['binding']['manifest_sha256'] = '0'*64
        api.add(state, api.head)
    else:
        def offline(*a): raise TimeoutError(TOKEN)
        api.call = offline
    monkeypatch.setattr(entry, 'listener', lambda *a: pytest.fail('listener opened'))
    with pytest.raises(Denied, match='^SIGNED_LEDGER_ENTRYPOINT_STOP$'):
        with entry.configured_listener(f['file']): pytest.fail('started')
    assert all(method == 'GET' for method, _, _ in api.calls)


def test_real_loopback_mtls_accepts_only_configured_enrolled_run(prepared):
    f = prepared; b = f['cfg']['binding']; effects = []
    with entry.configured_listener(f['file']) as (server, report):
        assert server.server_address[0] == '127.0.0.1'
        assert report['backend_verified'] is report['listener_started'] is True
        assert all(method == 'GET' for method, _, _ in f['api'].calls)
        thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.01)); thread.start()
        try:
            def client(role, approved=b):
                return LedgerClient(approved, bytes.fromhex(f['identity']['public_key_hex']),
                    tls.transport(f['fixture'], dict(port=report['port']), role))
            issuer, consumer = client('issuer'), client('custody')
            issuer.gate('reserve', 'A0', sha(b'request'), lambda _: effects.append('issue'))
            consumer.gate('consume', 'A0', sha(b'request'), lambda _: effects.append('send'), sha(b'grant'))
            with pytest.raises(Denied):
                consumer.gate('consume', 'A0', sha(b'request'), lambda _: pytest.fail('replay'), sha(b'grant'))
            before = len(f['api'].calls)
            with pytest.raises(Denied): client('issuer', dict(b, run_id='0'*64)).exchange('view')
            assert len(f['api'].calls) == before  # Wrong run denied before API access.
        finally:
            server.shutdown(); thread.join(5)
            assert not thread.is_alive()
    assert effects == ['issue', 'send']


def test_openssl_reads_pinned_descriptors_not_replaced_paths(prepared, monkeypatch):
    f = prepared; original = entry.ssl.SSLContext.load_cert_chain
    seen = []
    def load(context, cert, key):
        assert cert.startswith('/proc/self/fd/') and key.startswith('/proc/self/fd/')
        path = Path(f['cfg']['tls_key']); path.rename(path.with_name('retained-original.key'))
        tls.private_write(path, b'invalid replacement that must not be reopened')
        seen.append(True)
        return original(context, cert, key)
    monkeypatch.setattr(entry.ssl.SSLContext, 'load_cert_chain', load)
    entry.prepare(f['file'])
    assert seen == [True] and not f['api'].calls


@pytest.mark.parametrize('fault', ['expired', 'hostname', 'usage', 'ca_leaf', 'receipt_key_reused'])
def test_server_certificate_identity_constraints(prepared, fault):
    f = prepared; cfg = f['cfg']; now = datetime.datetime.now(datetime.timezone.utc)
    key = serialization.load_pem_private_key(Path(cfg['tls_key']).read_bytes(), password=None)
    if fault == 'receipt_key_reused':
        key = custody.load(f['slot'], f['identity']['public_key_sha256'])
        Path(cfg['tls_key']).write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    old = x509.load_pem_x509_certificate(Path(cfg['tls_certificate']).read_bytes())
    cert = (x509.CertificateBuilder().subject_name(old.subject).issuer_name(old.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-datetime.timedelta(days=2))
        .not_valid_after(now+datetime.timedelta(days=-1 if fault == 'expired' else 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('other.invalid' if fault == 'hostname'
            else entry.SERVER_NAME)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if fault == 'usage'
            else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=fault == 'ca_leaf', path_length=None), critical=True)
        .sign(key, None if fault == 'receipt_key_reused' else hashes.SHA256()))
    Path(cfg['tls_certificate']).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cfg['server_certificate_sha256'] = sha(cert.public_bytes(serialization.Encoding.DER))
    f['file'].write_bytes(canonical(cfg))
    with pytest.raises(Denied): entry.prepare(f['file'])
    assert not f['api'].calls and not f['constructions']


def test_serve_requires_explicit_ack_before_loading_any_file(monkeypatch, capsys):
    monkeypatch.setattr(entry, 'prepare', lambda *a: pytest.fail('configuration read'))
    assert entry.main(['serve', '--configuration', '/missing']) == 1
    assert capsys.readouterr() == ('', entry.STOP+'\n')


def test_cli_check_in_fresh_process_does_not_contact_github(prepared):
    f = prepared
    result = subprocess.run([sys.executable, '-m', 'scripts.task4_signed_ledger_entrypoint_v1',
        'check', '--configuration', str(f['file'])], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and not result.stderr
    report = json.loads(result.stdout)
    assert report['backend_verified'] is report['listener_started'] is False
    assert TOKEN not in result.stdout and str(f['slot']) not in result.stdout


def test_cli_failure_is_sanitized(prepared):
    result = subprocess.run([sys.executable, '-m', 'scripts.task4_signed_ledger_entrypoint_v1',
        'check', '--configuration', str(prepared['root'] / TOKEN)], capture_output=True, text=True)
    assert result.returncode == 1 and not result.stdout and result.stderr == entry.STOP+'\n'

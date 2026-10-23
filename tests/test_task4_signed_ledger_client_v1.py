"""Real TLS, retained client attempts, model Git backend; no remote credentials."""
import copy
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from scripts import task4_signed_ledger_client_v1 as client
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_external_ledger_mtls_rehearsal_v1 as tls
from scripts.task4_external_ledger_contract_v1 import Denied, canonical, digest, sha

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='root-owned public approval fixture requires sudo')


@pytest.fixture
def prepared(tmp_path):
    fixture = tls.provision(tmp_path / 'tls')
    keys = {role: Ed25519PrivateKey.generate() for role in ('issuer', 'custody')}
    b = dict(fixture['binding'], manifest_sha256=digest(client.manifest()),
        **{role+'_public_sha256': sha(key.public_key().public_bytes_raw()) for role, key in keys.items()})
    api, backend, service, witness, b = model.setup(b)
    old = json.loads((fixture['root']/'configuration.json').read_bytes())
    for role in keys:
        old['peers'][role]['authority_public_sha256'] = b[role+'_public_sha256']
    (fixture['root']/'configuration.json').write_bytes(canonical(old))
    public = tmp_path/'public'; public.mkdir(mode=0o755)
    approval = dict(schema=client.APPROVAL, scope=client.SCOPE, execution_source='a'*40,
        genesis=api.genesis, binding=b, service_public_hex=witness.public_key().public_bytes_raw().hex(),
        server_certificate_sha256=fixture['pins']['server'], peers=old['peers'])
    approved = public/'approval.json'; approved.write_bytes(canonical(approval)); approved.chmod(0o644)
    cfgs, files = {}, {}
    for role, key in keys.items():
        folder = tmp_path/role; folder.mkdir(mode=0o700)
        attempts = folder/'attempts'; attempts.mkdir(mode=0o700)
        for source, destination in [(role+'.pem', 'certificate.pem'), (role+'.key', 'key.pem'), ('ca.pem', 'ca.pem')]:
            tls.private_write(folder/destination, (fixture['root']/source).read_bytes())
        tls.private_write(folder/'authority.key', key.private_bytes_raw())
        cfgs[role] = dict(schema=client.PROFILE, scope=client.SCOPE, role=role, approval_file=str(approved),
            tls_certificate=str(folder/'certificate.pem'), tls_key=str(folder/'key.pem'),
            client_ca=str(folder/'ca.pem'), authority_key=str(folder/'authority.key'), attempt_parent=str(attempts))
        files[role] = folder/'configuration.json'; tls.private_write(files[role], canonical(cfgs[role]))
    api.calls.clear()
    return dict(fixture=fixture, keys=keys, b=b, api=api, backend=backend, service=service,
                witness=witness, approval=approval, approved=approved, cfgs=cfgs, files=files)


def slot(f, role, action='reserve', operation='A0'):
    return Path(f['cfgs'][role]['attempt_parent'])/(f['b']['run_id']+'-'+action+'-'+operation)


def test_manifest_has_exact_eight_synthetic_commitments_and_matches_checked_file():
    manifest = client.manifest()
    assert [r['operation_id'] for r in manifest['operations']] == ['A0','A1','A2','A3','B0','B1','B2','B3']
    assert len({r['request_sha256'] for r in manifest['operations']}) == 8
    assert len({r['grant_sha256'] for r in manifest['operations']}) == 8
    assert manifest['effect'] == 'IN_MEMORY_LIST_APPEND_ONLY'
    file = Path(__file__).resolve().parents[1]/'fixtures/task4_signed_ledger_synthetic_manifest_v1.json'
    assert file.read_bytes() == canonical(manifest)


def test_local_check_never_constructs_transport_or_network(prepared, monkeypatch):
    monkeypatch.setattr(client, 'Transport', lambda *a: pytest.fail('network constructed'))
    result = client.run('check', prepared['files']['issuer'])
    assert result['network_used'] is False and result['synthetic_callbacks'] == 0
    assert not prepared['api'].calls and not list(Path(prepared['cfgs']['issuer']['attempt_parent']).iterdir())


@pytest.mark.parametrize('fault', ['cfg_extra','scope','role','approval_schema','approval_scope','source','genesis',
    'manifest','ledger','service_public','authority_binding','same_peers','server_pin','authority_key',
    'tls_key','tls_certificate','ca','approval_mode','cfg_mode','private_mode','attempt_mode'])
def test_local_faults_precede_network_and_attempts(prepared, monkeypatch, fault):
    f = prepared; cfg = copy.deepcopy(f['cfgs']['issuer']); approval = copy.deepcopy(f['approval'])
    if fault == 'cfg_extra': cfg['token_file'] = '/must/not/be/read'
    if fault == 'scope': cfg['scope'] = 'PRODUCTION'
    if fault == 'role': cfg['role'] = 'admin'
    if fault == 'approval_schema': approval['schema'] = 'other'
    if fault == 'approval_scope': approval['scope'] = 'PRODUCTION'
    if fault == 'source': approval['execution_source'] = 'main'
    if fault == 'genesis': approval['genesis'] = 'main'
    if fault == 'manifest': approval['binding']['manifest_sha256'] = '0'*64
    if fault == 'ledger': approval['binding']['ledger_id'] = '0'*64
    if fault == 'service_public': approval['service_public_hex'] = 'bad'
    if fault == 'authority_binding': approval['peers']['issuer']['authority_public_sha256'] = '0'*64
    if fault == 'same_peers': approval['peers']['custody']['certificate_sha256'] = approval['peers']['issuer']['certificate_sha256']
    if fault == 'server_pin': approval['server_certificate_sha256'] = approval['peers']['issuer']['certificate_sha256']
    if fault in ('authority_key','tls_key','tls_certificate','ca'):
        path = cfg[dict(authority_key='authority_key', tls_key='tls_key', tls_certificate='tls_certificate', ca='client_ca')[fault]]
        Path(path).write_bytes(b'bad synthetic material')
    f['files']['issuer'].write_bytes(canonical(cfg)); f['approved'].write_bytes(canonical(approval))
    if fault == 'approval_mode': f['approved'].chmod(0o600)
    if fault == 'cfg_mode': f['files']['issuer'].chmod(0o644)
    if fault == 'private_mode': Path(cfg['tls_key']).chmod(0o644)
    if fault == 'attempt_mode': Path(cfg['attempt_parent']).chmod(0o755)
    monkeypatch.setattr(client, 'Transport', lambda *a: pytest.fail('transport reached'))
    with pytest.raises((Denied, ValueError, OSError)): client.run('reserve', f['files']['issuer'], 1234, 'A0')
    assert not f['api'].calls and not slot(f, 'issuer').exists()


def test_actual_tls_normal_callbacks_and_signed_public_receipts(prepared):
    f = prepared
    with model.connected(f['service'], f['fixture']) as ready:
        issued = client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
        sent = client.run('consume', f['files']['custody'], ready['port'], 'A0')
        viewed = client.run('view', f['files']['issuer'], ready['port'])
    assert issued['synthetic_callbacks'] == sent['synthetic_callbacks'] == 1
    assert viewed['synthetic_callbacks'] == 0 and viewed['snapshot']['revision'] == 2
    assert len(sent['exchanges']) == 2 and sent['exchanges'][-1]['command']['action'] == 'consume'
    assert sent['provider_dispatch'] == 'DENY' and sent['utility'] == 'UNSCORED'
    assert json.loads((slot(f,'custody','consume')/'result.json').read_bytes()) == sent
    assert json.loads((slot(f,'custody','consume')/'verified-receipts.json').read_bytes())['synthetic_callbacks'] == 0
    encoded = canonical(sent)
    for key in f['keys'].values(): assert key.private_bytes_raw().hex().encode() not in encoded


@pytest.mark.parametrize('action,role', [('reserve','issuer'), ('consume','custody')])
def test_discarded_committed_receipt_burns_attempt_without_callback(prepared, action, role):
    f = prepared
    with model.connected(f['service'], f['fixture']) as ready:
        if action == 'consume': client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
        with pytest.raises(Denied): client.run(action, f['files'][role], ready['port'], 'A0', True)
    directory = slot(f, role, action)
    assert sorted(p.name for p in directory.iterdir()) == ['attempt.json']
    assert f['backend'].read()[1]['runs'][f['b']['run_id']]['snapshot']['revision'] == (1 if action == 'reserve' else 2)
    before = len(f['api'].calls)
    with pytest.raises(FileExistsError): client.run(action, f['files'][role], 1234, 'A0')
    assert len(f['api'].calls) == before


@pytest.mark.parametrize('discarded', [False, True])
def test_fresh_process_cannot_retry_completed_or_uncertain_attempt_before_network(prepared, discarded):
    f = prepared
    with model.connected(f['service'], f['fixture']) as ready:
        if discarded:
            with pytest.raises(Denied): client.run('reserve', f['files']['issuer'], ready['port'], 'A0', True)
        else:
            client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
    result = subprocess.run([sys.executable, '-B', '-m', 'scripts.task4_signed_ledger_client_v1',
        'reserve', '--configuration', str(f['files']['issuer']), '--port', '1', '--operation', 'A0',
        '--acknowledge-synthetic-only'], capture_output=True, text=True, timeout=10)
    assert result.returncode == 1 and result.stdout == '' and result.stderr.strip() == client.STOP
    assert (slot(f,'issuer')/'result.json').exists() is (not discarded)


@pytest.mark.parametrize('role,action', [('issuer','consume'), ('custody','reserve')])
def test_wrong_role_stops_locally_before_attempt_or_socket(prepared, monkeypatch, role, action):
    monkeypatch.setattr(client, 'Transport', lambda *a: pytest.fail('network reached'))
    with pytest.raises(Denied): client.run(action, prepared['files'][role], 1234, 'A0')
    assert not list(Path(prepared['cfgs'][role]['attempt_parent']).iterdir())


@pytest.mark.parametrize('port', [None, 0, 65536, True, '443'])
def test_invalid_port_stops_before_attempt(prepared, port):
    with pytest.raises(Denied): client.run('reserve', prepared['files']['issuer'], port, 'A0')
    assert not slot(prepared, 'issuer').exists()


@pytest.mark.parametrize('fault', ['empty_slot','fsync','claim_race'])
def test_attempt_barrier_stops_before_network(prepared, monkeypatch, fault):
    f = prepared; cfg = f['cfgs']['issuer']; directory = slot(f,'issuer')
    if fault == 'empty_slot':
        directory.mkdir(mode=0o700)
        with pytest.raises(FileExistsError): client.run('reserve', f['files']['issuer'], 1234, 'A0')
    elif fault == 'fsync':
        monkeypatch.setattr(client.os, 'fsync', lambda *a: (_ for _ in ()).throw(OSError('synthetic')))
        with pytest.raises(OSError): client.run('reserve', f['files']['issuer'], 1234, 'A0')
        assert directory.is_dir() and not list(directory.iterdir())
    else:
        def claim():
            try: return client.claim(cfg['attempt_parent'], f['b'], 'reserve', 'A0', cfg)
            except FileExistsError: return None
        with ThreadPoolExecutor(2) as pool: results = list(pool.map(lambda _: claim(), range(2)))
        assert sum(r is not None for r in results) == 1
    assert not f['api'].calls


@pytest.mark.parametrize('fault', ['unavailable','wrong_server_pin','bad_receipt','bad_mutation_receipt','receipt_write'])
def test_failures_never_record_success_and_preserve_attempt(prepared, monkeypatch, fault):
    f = prepared
    if fault == 'wrong_server_pin':
        f['approval']['server_certificate_sha256'] = 'f'*64
        f['approved'].write_bytes(canonical(f['approval']))
    if fault in ('bad_receipt', 'bad_mutation_receipt'):
        original = f['service'].exchange
        def corrupt(encoded, peer):
            result = json.loads(original(encoded, peer))
            if fault == 'bad_receipt' or json.loads(encoded)['action'] != 'view': result['signature'] = '0'*128
            return canonical(result)
        monkeypatch.setattr(f['service'], 'exchange', corrupt)
    if fault == 'receipt_write':
        original = client.write_record
        def write(directory, name, value):
            if name == 'verified-receipts.json': raise OSError('synthetic write failure')
            return original(directory, name, value)
        monkeypatch.setattr(client, 'write_record', write)
    with model.connected(f['service'], f['fixture']) as ready:
        with pytest.raises((Denied, OSError)):
            client.run('reserve', f['files']['issuer'], 1 if fault == 'unavailable' else ready['port'], 'A0')
    assert sorted(p.name for p in slot(f,'issuer').iterdir()) == ['attempt.json']
    if fault in ('wrong_server_pin','bad_receipt','unavailable'): assert not f['api'].calls or fault == 'bad_receipt'


@pytest.mark.parametrize('action', ['reserve','consume'])
def test_cli_acknowledgement_required_before_configuration_read(monkeypatch, capsys, action):
    monkeypatch.setattr(client, 'prepare', lambda *a: pytest.fail('configuration read'))
    assert client.main([action, '--configuration', '/missing', '--port', '1', '--operation', 'A0']) == 1
    output = capsys.readouterr(); assert output.out == '' and output.err.strip() == client.STOP


def test_cli_manifest_and_interrupt_are_sanitized(monkeypatch, capsys):
    assert client.main(['manifest']) == 0
    assert json.loads(capsys.readouterr().out)['manifest_sha256'] == digest(client.manifest())
    monkeypatch.setattr(client, 'run', lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert client.main(['check', '--configuration', '/unused']) == 130
    assert capsys.readouterr().err == ''


@pytest.mark.parametrize('fault', ['symlink','hardlink','fifo','relative','symlink_parent'])
def test_private_configuration_paths_refuse_unsafe_files(prepared, fault):
    file = prepared['files']['issuer']
    if fault in ('symlink','fifo'):
        file.unlink()
        if fault == 'symlink': file.symlink_to('/dev/null')
        else: os.mkfifo(file, 0o600)
    if fault == 'hardlink': os.link(file, file.parent/'extra-link')
    if fault == 'relative': file = 'configuration.json'
    if fault == 'symlink_parent':
        alias = file.parent.parent/'alias'; alias.symlink_to(file.parent, target_is_directory=True)
        file = alias/file.name
    with pytest.raises((Denied, ValueError, OSError)): client.run('check', file)
    assert not prepared['api'].calls


@pytest.mark.parametrize('operation', ['A4','C0','../A0',None])
def test_arbitrary_operation_refused_before_claim(prepared, operation):
    with pytest.raises(Denied): client.run('reserve', prepared['files']['issuer'], 1234, operation)
    assert not list(Path(prepared['cfgs']['issuer']['attempt_parent']).iterdir())


def test_complete_result_failure_keeps_verified_receipt_and_burned_slot(prepared, monkeypatch):
    f = prepared; original = client.write_record
    def write(directory, name, value):
        if name == 'result.json': raise OSError('synthetic result failure')
        return original(directory, name, value)
    monkeypatch.setattr(client, 'write_record', write)
    with model.connected(f['service'], f['fixture']) as ready:
        with pytest.raises(OSError): client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
    directory = slot(f,'issuer')
    assert sorted(p.name for p in directory.iterdir()) == ['attempt.json','verified-receipts.json']
    with pytest.raises(FileExistsError): client.run('reserve', f['files']['issuer'], 1, 'A0')


def test_changed_local_journal_does_not_reissue_consumed_backend_slot(prepared):
    # Test administrator substitutes a local parent to test the independent backend,
    # not an operator recovery instruction or evidence against privileged rollback.
    f = prepared
    with model.connected(f['service'], f['fixture']) as ready:
        client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
        client.run('consume', f['files']['custody'], ready['port'], 'A0')
        other = Path(f['cfgs']['issuer']['attempt_parent']).parent/'fresh-attempts'; other.mkdir(mode=0o700)
        cfg = dict(f['cfgs']['issuer'], attempt_parent=str(other))
        f['files']['issuer'].write_bytes(canonical(cfg))
        before = len([c for c in f['api'].calls if c[0] == 'POST'])
        with pytest.raises(Denied): client.run('reserve', f['files']['issuer'], ready['port'], 'A0')
        assert len([c for c in f['api'].calls if c[0] == 'POST']) == before
        assert not list(other.glob('*/result.json'))


def test_actual_two_uids_use_separate_keys_and_signed_model_service(prepared):
    # Full root Linux CI performs this test; mapped local root may not own two UIDs.
    mappings = [tuple(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    ids = (61231, 61232)
    if not all(any(start <= uid < start+count for start, _, count in mappings) for uid in ids):
        pytest.skip('local UID mapping lacks two synthetic identities; full-root CI must run')
    f = prepared
    with tempfile.TemporaryDirectory(prefix='task4-client-two-uids-') as temp:
        top = Path(temp); top.chmod(0o755)
        approval = top/'approval.json'; approval.write_bytes(canonical(f['approval'])); approval.chmod(0o644)
        configs = {}
        for (role, uid) in zip(('issuer','custody'), ids):
            folder = top/role; folder.mkdir(mode=0o700); os.chown(folder, uid, uid)
            attempts = folder/'attempts'; attempts.mkdir(mode=0o700); os.chown(attempts, uid, uid)
            cfg = dict(f['cfgs'][role], approval_file=str(approval), attempt_parent=str(attempts))
            for key in ('tls_certificate','tls_key','client_ca','authority_key'):
                destination = folder/Path(cfg[key]).name
                destination.write_bytes(Path(cfg[key]).read_bytes()); destination.chmod(0o600)
                os.chown(destination, uid, uid); cfg[key] = str(destination)
            file = folder/'configuration.json'; file.write_bytes(canonical(cfg)); file.chmod(0o600)
            os.chown(file, uid, uid); configs[role] = file
        with model.connected(f['service'], f['fixture']) as ready:
            for role, uid, action in zip(('issuer','custody'), ids, ('reserve','consume')):
                def drop(uid=uid):
                    os.setgroups([]); os.setgid(uid); os.setuid(uid)
                result = subprocess.run([sys.executable, '-B', '-m', 'scripts.task4_signed_ledger_client_v1', action,
                    '--configuration', str(configs[role]), '--port', str(ready['port']), '--operation', 'A0',
                    '--acknowledge-synthetic-only'], capture_output=True, text=True, timeout=15, preexec_fn=drop)
                assert result.returncode == 0, result.stderr
                assert json.loads(result.stdout)['synthetic_callbacks'] == 1
                # The other role cannot open this role's private key.
                denied = subprocess.run([sys.executable, '-I', '-c',
                    'import sys; open(sys.argv[1], "rb")', str(configs['custody' if role == 'issuer' else 'issuer'].parent/'key.pem')],
                    capture_output=True, text=True, timeout=5, preexec_fn=drop)
                assert denied.returncode != 0 and 'PermissionError' in denied.stderr
        assert f['backend'].read()[1]['runs'][f['b']['run_id']]['snapshot']['revision'] == 2


@pytest.mark.parametrize('identity', ['fresh','issuer','custody','service'])
def test_ed25519_tls_identity_must_differ_from_all_authority_keys(prepared, identity):
    f = prepared; cfg = f['cfgs']['issuer']
    key = (Ed25519PrivateKey.generate() if identity == 'fresh' else
           f['witness'].key if identity == 'service' else f['keys'][identity])
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic Ed25519 client')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(key, algorithm=None))
    Path(cfg['tls_key']).write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    Path(cfg['tls_certificate']).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    f['approval']['peers']['issuer']['certificate_sha256'] = sha(cert.public_bytes(serialization.Encoding.DER))
    f['approved'].write_bytes(canonical(f['approval']))
    if identity == 'fresh': assert client.run('check', f['files']['issuer'])['network_used'] is False
    else:
        with pytest.raises(Denied): client.run('check', f['files']['issuer'])
    assert not f['api'].calls

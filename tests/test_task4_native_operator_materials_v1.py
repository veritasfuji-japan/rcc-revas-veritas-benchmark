"""Preparation-only key custody and public candidate joins; no remote API."""
import base64
import copy
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from scripts import task4_native_operator_materials_v1 as t
from test_task4_native_github_approval_preparation_v1 import prepared as public_prepared
from test_task4_native_role_keys_v1 import keys as role_keys
from test_task4_native_retained_signer_profile_v1 import joined
from test_task4_signed_github_api_v1 import network

RUN = 'a' * 64


@pytest.fixture
def materials(tmp_path, monkeypatch):
    base = tmp_path / 'materials'
    base.mkdir(mode=0o700)
    for role in t.ROLES:
        (base / t.ROLES[role][2]).mkdir(mode=0o700)
    monkeypatch.setattr(t, 'BASE', base)
    state = {'role': 'service'}
    original_identity = t.keys.identity
    original_role = t.role_identity
    monkeypatch.setattr(t, 'role_identity', lambda role: None)
    def metadata(info):
        return dict(original_identity(info), uid=t.ROLES[state['role']][0])
    monkeypatch.setattr(t.keys, 'identity', metadata)
    def activate(role):
        state['role'] = role
    def create(role):
        activate(role)
        return t.initialize(role, RUN, True)
    def all_materials():
        exports = {role: create(role) for role in (*t.TLS_ROLES, 'archive')}
        return dict(schema=t.MATERIALS, scope=t.SCOPE, run_id=RUN, exports=exports)
    monkeypatch.setattr(socket, 'socket', lambda *a, **k: pytest.fail('socket capability used'))
    return dict(base=base, activate=activate, create=create, all=all_materials, original_role=original_role)


def package(f):
    m = f['all']()
    f['activate']('ca')
    return m, t.issue_ca(m, True)


@pytest.mark.parametrize('role', [*t.TLS_ROLES, 'archive'])
def test_role_key_survives_inspect_without_private_output_or_reinitialization(materials, role):
    value = materials['create'](role)
    target = t.slot(role, RUN)
    raw = (target / 'private.key').read_bytes()
    assert (target / 'private.key').stat().st_mode & 0o777 == 0o600
    assert target.stat().st_mode & 0o777 == 0o700
    assert t.inspect(role, RUN, t.sha(t.canonical(value))) == value
    output = t.canonical(t.report('initialize', value))
    assert raw not in output and base64.b64encode(raw) not in output
    with pytest.raises(FileExistsError):
        t.initialize(role, RUN, True)
    assert (target / 'private.key').read_bytes() == raw
    if role != 'archive':
        assert t.checked_csr(value['csr'], role, RUN).is_signature_valid


@pytest.mark.parametrize('fault', ['empty', 'partial', 'symlink', 'unknown'])
def test_burned_slots_never_generate_replacement_material(materials, monkeypatch, fault):
    target = t.slot('service', RUN)
    if fault == 'symlink':
        target.symlink_to(materials['base'], target_is_directory=True)
    else:
        target.mkdir(mode=0o700)
        if fault != 'empty':
            (target / ('private.key' if fault == 'partial' else 'unknown')).write_bytes(b'partial')
    monkeypatch.setattr(ec, 'generate_private_key', lambda *a: pytest.fail('key replacement'))
    with pytest.raises(FileExistsError):
        t.initialize('service', RUN, True)


@pytest.mark.parametrize('run,ack', [('bad', True), (t.p.MANUAL_RUN, True), (RUN, False), (RUN, 1)])
def test_invalid_run_or_implicit_creation_stops_before_any_slot(materials, run, ack):
    with pytest.raises(ValueError):
        t.initialize('service', run, ack)
    assert list(t.home('service').iterdir()) == []


@pytest.mark.parametrize('fault', ['hash', 'key', 'mode', 'hardlink', 'symlink', 'record', 'extra-file'])
def test_changed_or_unsafe_private_storage_refused(materials, fault):
    value = materials['create']('issuer')
    target = t.slot('issuer', RUN)
    pin = t.sha(t.canonical(value))
    if fault == 'hash':
        pin = '0' * 64
    elif fault == 'key':
        replacement = ec.generate_private_key(ec.SECP256R1())
        (target / 'private.key').write_bytes(replacement.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    elif fault == 'mode':
        (target / 'private.key').chmod(0o644)
    elif fault == 'hardlink':
        os.link(target / 'private.key', materials['base'] / 'link')
    elif fault == 'symlink':
        (target / 'private.key').rename(materials['base'] / 'moved')
        (target / 'private.key').symlink_to(materials['base'] / 'moved')
    elif fault == 'record':
        (target / 'public.json').write_bytes(b'{}')
    else:
        (target / 'extra').touch()
    with pytest.raises((ValueError, OSError, t.keys.custody.CustodyDenied)):
        t.inspect('issuer', RUN, pin)


@pytest.mark.parametrize('fault', ['wrong-role', 'wrong-run', 'signature', 'ca-extension', 'other-host', 'algorithm'])
def test_csr_role_scope_and_key_algorithm_are_not_caller_controlled(materials, fault):
    record = materials['create']('service')
    text, role, run = record['csr'], 'service', RUN
    key = ec.generate_private_key(ec.SECP256R1())
    if fault == 'wrong-role':
        role = 'issuer'
    elif fault == 'wrong-run':
        run = 'b' * 64
    elif fault == 'signature':
        raw = bytearray(x509.load_pem_x509_csr(text.encode()).public_bytes(ser.Encoding.DER))
        raw[-1] ^= 1
        text = x509.load_der_x509_csr(bytes(raw)).public_bytes(ser.Encoding.PEM).decode()
    elif fault in ('ca-extension', 'other-host'):
        builder = x509.CertificateSigningRequestBuilder().subject_name(t.subject('service', RUN))
        extension = x509.BasicConstraints(ca=True, path_length=None) if fault == 'ca-extension' else x509.SubjectAlternativeName([x509.DNSName('elsewhere.invalid')])
        text = builder.add_extension(extension, False).sign(key, __import__('cryptography.hazmat.primitives.hashes', fromlist=['SHA256']).SHA256()).public_bytes(ser.Encoding.PEM).decode()
    else:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        text = x509.CertificateSigningRequestBuilder().subject_name(t.subject('service', RUN)).sign(ed25519.Ed25519PrivateKey.generate(), None).public_bytes(ser.Encoding.PEM).decode()
    with pytest.raises(ValueError):
        t.checked_csr(text, role, run)


def test_root_ca_issues_exact_four_csrs_and_role_installs_only_own_certificate_once(materials):
    m, certs = package(materials)
    verified = t.validate_certificates(certs, m)
    assert len(verified) == 5
    ca_path = t.slot('ca', RUN)
    before = (ca_path / 'private.key').read_bytes()
    with pytest.raises(FileExistsError):
        t.issue_ca(m, True)
    assert (ca_path / 'private.key').read_bytes() == before
    for role in t.TLS_ROLES:
        materials['activate'](role)
        pin = t.sha(t.canonical(m['exports'][role]))
        result = t.install_certificate(role, RUN, pin, m, certs)
        assert result['certificate_sha256'] == t.sha(verified[role].public_bytes(ser.Encoding.DER))
        assert t.inspect(role, RUN, pin) == m['exports'][role]
        with pytest.raises(FileExistsError):
            t.install_certificate(role, RUN, pin, m, certs)
    assert verified['backend'].extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ['api.openai.com']


@pytest.mark.parametrize('fault', ['run', 'materials-pin', 'swap', 'extra', 'duplicate-key', 'subject'])
def test_certificate_package_cannot_substitute_run_role_or_public_key(materials, fault):
    m, certs = package(materials)
    if fault == 'run':
        certs['run_id'] = 'b' * 64
    elif fault == 'materials-pin':
        certs['materials_sha256'] = '0' * 64
    elif fault == 'swap':
        certs['certificates']['issuer'], certs['certificates']['custody'] = certs['certificates']['custody'], certs['certificates']['issuer']
    elif fault == 'extra':
        certs['certificates']['runtime'] = certs['certificates']['issuer']
    elif fault == 'duplicate-key':
        m['exports']['backend']['public'] = m['exports']['service']['public']
    else:
        m['exports']['issuer']['csr'] = m['exports']['custody']['csr']
    with pytest.raises(ValueError):
        t.validate_certificates(certs, m)


@pytest.mark.parametrize('role', ['service', 'issuer', 'custody', 'backend', 'archive', 'ca'])
def test_wrong_uid_gid_or_supplementary_groups_stop_before_key_creation(materials, monkeypatch, role):
    uid, gid, _ = t.ROLES[role]
    monkeypatch.setattr(os, 'geteuid', lambda: uid + 1)
    monkeypatch.setattr(os, 'getegid', lambda: gid)
    monkeypatch.setattr(os, 'getgroups', lambda: [gid])
    with pytest.raises(ValueError):
        materials['original_role'](role)
    monkeypatch.setattr(os, 'geteuid', lambda: uid)
    monkeypatch.setattr(os, 'getgroups', lambda: [gid, gid + 1])
    with pytest.raises(ValueError):
        materials['original_role'](role)


def test_public_assembly_joins_actual_recipient_and_local_leaf_and_root_candidate(joined, materials, monkeypatch):
    m, certs = package(materials)
    monkeypatch.setattr(t.keys, 'role_identity', lambda role: None)
    monkeypatch.setattr(t, 'private', lambda *a: pytest.fail('private key opened during assembly'))
    context = joined['public']['native_manifest']['execution']
    value = t.assemble(joined['bundle'], m, certs, 'd' * 40, context['not_before'], context['expires_at'])
    result = t.p.build(t.canonical(value), [])
    approval = t.p.validate_candidate(result)
    c = approval['native_manifest']['execution']
    assert c['raw_recipient_sha256'] == t.sha(bytes.fromhex(m['exports']['archive']['public']))
    assert c['local_leaf_sha256'] == t.sha(t.p.certificate(certs['certificates']['backend']).public_bytes(ser.Encoding.DER))
    assert approval['genesis'] == joined['retained']['genesis']
    assert approval['service_public_hex'] == joined['retained']['service_public_hex']
    assert c['not_before'] == context['not_before'] and c['expires_at'] == context['expires_at']
    assert approval['binding']['run_id'] != joined['retained']['legacy_run_id']
    assert not result['limitations']['execution_permission_issued']
    assert not t.report('assemble', value)['native_runtime_profile_applied']


@pytest.mark.parametrize('start,end', [(10, 10), (10, 311), (True, 10), (10, False), (10.0, 20)])
def test_time_window_is_explicit_bounded_and_never_repaired(joined, materials, monkeypatch, start, end):
    m, certs = package(materials)
    monkeypatch.setattr(t.keys, 'role_identity', lambda role: None)
    with pytest.raises(ValueError):
        t.assemble(joined['bundle'], m, certs, 'd' * 40, start, end)


def test_expired_diagnostic_window_is_retained_without_claiming_execution(joined, materials, monkeypatch):
    m, certs = package(materials)
    monkeypatch.setattr(t.keys, 'role_identity', lambda role: None)
    value = t.assemble(joined['bundle'], m, certs, 'd' * 40, 1000, 1300)
    assert value['native_manifest']['execution']['expires_at'] == 1300
    assert t.report('assemble', value)['execution_permission_issued'] is False


def test_cli_constant_stop_and_irrelevant_options_do_not_open_files(materials, monkeypatch, capsys):
    monkeypatch.setattr(t, 'document', lambda *a: pytest.fail('unexpected read'))
    assert t.main(['initialize', '--role', 'service', '--run-id', RUN, '--execution-source', 'd' * 40,
                   '--acknowledge-create-synthetic-material']) == 1
    captured = capsys.readouterr()
    assert captured.out == '' and captured.err.strip() == t.STOP


def test_cli_initialization_public_output_has_explicit_no_execution_flags(materials, capsys):
    assert t.main(['initialize', '--role', 'service', '--run-id', RUN,
                   '--acknowledge-create-synthetic-material']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['public_record']['role'] == 'service'
    assert report['provider_dispatch'] == 'DENY'
    for field in ('execution_permission_issued', 'existing_authority_private_key_loaded', 'network_used',
                  'credential_loaded', 'service_reconfigured', 'trust_store_modified'):
        assert report[field] is False


def test_actual_role_material_keys_and_root_ca_never_cross_private_uid_boundaries():
    caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')), 16)
    if os.geteuid() != 0 or not all(caps & (1 << bit) for bit in (0, 6, 7)):
        pytest.skip('requires disposable root-capable CI with chown/setuid/setgid')
    with tempfile.TemporaryDirectory(prefix='native-materials-real-uids-') as temp:
        base = Path(temp)
        base.chmod(0o755)
        source = base / 'source'
        source.mkdir(mode=0o755)
        root = Path(t.__file__).resolve().parents[1]
        for name in ('scripts', 'fixtures', 'docs'):
            shutil.copytree(root / name, source / name, ignore=shutil.ignore_patterns('__pycache__'))
        for item in source.rglob('*'):
            item.chmod(0o755 if item.is_dir() else 0o444)
        state = base / 'state'
        state.mkdir(mode=0o755)
        for role, (uid, gid, name) in t.ROLES.items():
            folder = state / name
            folder.mkdir(mode=0o700)
            os.chown(folder, uid, gid)
        bootstrap = ('import importlib.machinery,importlib.util,sys;from pathlib import Path;'
            's=importlib.machinery.PathFinder.find_spec("scripts",[' + repr(str(source)) + ']);'
            'sys.modules["scripts"]=importlib.util.module_from_spec(s);'
            'from scripts import task4_native_operator_materials_v1 as t;t.BASE=Path(' + repr(str(state)) + ');')
        def child(role, code, args=()):
            uid, gid = t.ROLES[role][:2] if role in t.ROLES else ((61109, 61109) if role == 'reader' else (61108, 61108))
            return subprocess.run(['setpriv', '--reuid=' + str(uid), '--regid=' + str(gid), '--clear-groups',
                '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                sys.executable, '-I', '-B', '-c', bootstrap + code, *args], cwd='/tmp',
                env={'PATH': os.environ['PATH'], 'LANG': 'C.UTF-8'}, capture_output=True, text=True, timeout=30)
        exports = {}
        for role in (*t.TLS_ROLES, 'archive'):
            out = child(role, 'raise SystemExit(t.main())', ['initialize', '--role', role, '--run-id', RUN,
                '--acknowledge-create-synthetic-material'])
            assert out.returncode == 0, out.stderr
            exports[role] = json.loads(out.stdout)['public_record']
            pin = t.sha(t.canonical(exports[role]))
            out = child(role, 'raise SystemExit(t.main())', ['inspect', '--role', role, '--run-id', RUN,
                '--expected-export-sha256', pin])
            assert out.returncode == 0, out.stderr
        m = dict(schema=t.MATERIALS, scope=t.SCOPE, run_id=RUN, exports=exports)
        material_file = state / 'public-materials.json'
        material_file.write_bytes(t.canonical(m))
        material_file.chmod(0o644)
        args = ['issue-ca', '--materials', str(material_file), '--expected-materials-sha256',
                t.sha(material_file.read_bytes()), '--acknowledge-create-synthetic-material']
        out = child('ca', 'raise SystemExit(t.main())', args)
        assert out.returncode == 0, out.stderr
        certs = json.loads(out.stdout)['public_record']
        certificate_file = state / 'public-certificates.json'
        certificate_file.write_bytes(t.canonical(certs))
        certificate_file.chmod(0o644)
        assert child('ca', 'raise SystemExit(t.main())', args).returncode == 1
        denied = 0
        for role in (*t.TLS_ROLES, 'archive'):
            for other in t.ROLES:
                if role == other:
                    continue
                target = state / t.ROLES[other][2] / ('native-materials-v1-' + RUN) / 'private.key'
                code = '\ntry:\n open(' + repr(str(target)) + ',"rb")\nexcept PermissionError:\n print("DENIED")\nelse:\n raise SystemExit("CROSS_PRIVATE_READ")\n'
                out = child(role, code)
                assert out.returncode == 0 and out.stdout.strip() == 'DENIED', out.stderr
                denied += 1
            if role in t.TLS_ROLES:
                out = child(role, 'raise SystemExit(t.main())', ['install-certificate', '--role', role,
                    '--run-id', RUN, '--expected-export-sha256', t.sha(t.canonical(exports[role])),
                    '--materials', str(material_file), '--expected-materials-sha256', t.sha(material_file.read_bytes()),
                    '--certificates', str(certificate_file), '--expected-certificates-sha256', t.sha(certificate_file.read_bytes())])
                assert out.returncode == 0, out.stderr
        assert denied == 25
        # Public assembler and trusted Native runtime also cannot read any of
        # the six owners' private material, including the separate CA.
        for role in ('reader', 'runtime'):
            for other in t.ROLES:
                target = state / t.ROLES[other][2] / ('native-materials-v1-' + RUN) / 'private.key'
                code = '\ntry:\n open(' + repr(str(target)) + ',"rb")\nexcept PermissionError:\n print("DENIED")\nelse:\n raise SystemExit("CROSS_PRIVATE_READ")\n'
                out = child(role, code)
                assert out.returncode == 0 and out.stdout.strip() == 'DENIED', out.stderr
                denied += 1
        assert denied == 37
        # Root-owned CA files are not a cross-role key distribution mechanism.
        assert (state / t.ROLES['ca'][2]).stat().st_uid == 0
        assert set(t.validate_certificates(certs, m)) == {'ca', *t.TLS_ROLES}


def test_failure_after_claim_burns_slot_without_retry_or_repair(materials, monkeypatch):
    original = t.write
    def fail(fd, name, data):
        if name == 'public.json':
            raise OSError('SYNTHETIC_WRITE_FAILURE')
        return original(fd, name, data)
    monkeypatch.setattr(t, 'write', fail)
    with pytest.raises(OSError):
        materials['create']('custody')
    target = t.slot('custody', RUN)
    before = (target / 'private.key').read_bytes()
    monkeypatch.setattr(ec, 'generate_private_key', lambda *a: pytest.fail('key retry'))
    with pytest.raises(FileExistsError):
        materials['create']('custody')
    assert (target / 'private.key').read_bytes() == before
    assert not (target / 'public.json').exists()


@pytest.mark.parametrize('fault', ['schema', 'scope', 'run', 'role', 'bool-uid', 'storage-uid', 'mode', 'extra', 'algorithm'])
def test_public_material_metadata_confusion_is_refused(materials, fault):
    value = materials['create']('archive')
    if fault == 'schema':
        value['schema'] = t.keys.PROFILE
    elif fault == 'scope':
        value['scope'] = 'LIVE'
    elif fault == 'run':
        value['run_id'] = 'b' * 64
    elif fault == 'role':
        value['role'] = 'custody'
    elif fault == 'bool-uid':
        value['uid'] = True
    elif fault == 'storage-uid':
        value['key_file']['uid'] = 61106
    elif fault == 'mode':
        value['key_directory']['mode'] = 0o755
    elif fault == 'extra':
        value['private_key'] = 'REJECT_EXTRA_FIELD'
    else:
        value['algorithm'] = 'Ed25519'
    with pytest.raises(ValueError):
        t.validate_export(value, 'archive', RUN)


@pytest.mark.parametrize('fault', ['archive-change', 'ca-replaced', 'backend-replaced', 'legacy-run'])
def test_changed_certificates_or_recipient_cannot_reuse_retained_materials_digest(materials, fault):
    m, certs = package(materials)
    if fault == 'archive-change':
        m['exports']['archive']['public'] = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    elif fault == 'ca-replaced':
        certs['certificates']['ca'] = certs['certificates']['service']
    elif fault == 'backend-replaced':
        certs['certificates']['backend'] = certs['certificates']['service']
    else:
        m['run_id'] = t.p.MANUAL_RUN
    with pytest.raises(ValueError):
        t.validate_certificates(certs, m)


def test_wrong_account_ca_command_stops_before_document_read(materials, monkeypatch, capsys):
    def denied(role):
        raise ValueError('DENY')
    monkeypatch.setattr(t, 'role_identity', denied)
    monkeypatch.setattr(t, 'document', lambda *a: pytest.fail('opened before role check'))
    assert t.main(['issue-ca', '--materials', '/never/open', '--expected-materials-sha256', '0' * 64,
        '--acknowledge-create-synthetic-material']) == 1
    result = capsys.readouterr()
    assert result.out == '' and result.err.strip() == t.STOP

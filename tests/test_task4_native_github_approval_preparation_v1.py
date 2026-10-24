"""Disposable public inputs, never operator approval/key/credential material."""
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from scripts import task4_native_github_approval_preparation_v1 as p
from scripts import task4_signed_ledger_client_v1 as manual


def issue(key, issuer, signer, *, ca=False, role=None, expired=False, name=None, critical=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name or role or 'test-ca')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=2))
            .not_valid_after(now + datetime.timedelta(days=-1 if expired else 1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
    if role:
        cert = cert.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if role == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if role == 'server':
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(name or p.SERVER_NAME)]), critical=False)
    if critical:
        cert = cert.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'unknown'), critical=True)
    return cert.sign(signer, None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    keys = {role: ed25519.Ed25519PrivateKey.generate() for role in ('issuer', 'custody', 'runtime', 'service')}
    public = {role: key.public_key().public_bytes_raw().hex() for role, key in keys.items()}
    now = int(__import__('time').time())
    context = dict(schema=p.readiness.native.authority.SCHEMA, run_id='a'*64,
                   raw_recipient_sha256='b'*64, local_leaf_sha256='c'*64,
                   not_before=now-5, expires_at=now+295, endpoint=p.readiness.native.raw.URL,
                   permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = issue(ca_key, None, ca_key, ca=True)
    tls_keys = {role: ec.generate_private_key(ec.SECP256R1()) for role in ('server', 'issuer', 'custody')}
    certs = dict(ca=pem(ca), **{role: pem(issue(key, ca.subject, ca_key, role=role)) for role,key in tls_keys.items()})
    public_input = dict(schema=p.INPUT, scope=p.readiness.SCOPE, origin=p.ORIGIN,
        execution_source='d'*40, genesis='e'*40,
        native_manifest=p.readiness.native.manifest(context, public['custody'], public['runtime']),
        issuer_public_hex=public['issuer'], service_public_hex=public['service'],
        source_sha256=p.readiness.source_manifest(), roles=dict(ledger=61109, issuer=61105, custody=61106, runtime=61108),
        public_certificates=certs)
    folder = tmp_path/'public';folder.mkdir(mode=0o755)
    file = folder/'input.json'
    def save(value, destination=file):
        destination.write_bytes(p.canonical(value));destination.chmod(0o644)
        return str(destination), p.sha(destination.read_bytes())
    path, expected = save(public_input)
    def no_network(*args, **kwargs):
        pytest.fail('network capability used')
    monkeypatch.setattr(socket, 'socket', no_network)
    return dict(public=public_input, file=file, path=path, expected=expected, save=save, ca=ca, ca_key=ca_key,
                tls_keys=tls_keys, keys=keys, folder=folder)


def candidate(f):
    return p.run('candidate', f['path'], f['expected'])


def test_candidate_contains_exact_original_public_bytes_and_no_permission(prepared):
    f=prepared;before=set(f['folder'].iterdir());result=candidate(f)
    assert result['schema']==p.CANDIDATE and result['schema']!=p.readiness.APPROVAL
    assert base64.b64decode(result['public_input_raw_base64'])==f['file'].read_bytes()
    a=result['approval_candidate'];assert p.readiness.validate_approval(a)==a
    assert a['binding']['manifest_sha256']==p.digest(f['public']['native_manifest'])
    assert a['tls']['server_certificate_sha256']==p.sha(x509.load_pem_x509_certificate(
        f['public']['public_certificates']['server'].encode()).public_bytes(serialization.Encoding.DER))
    assert set(f['folder'].iterdir())==before
    for key,value in result['limitations'].items():
        assert value == ('DENY' if key=='provider_dispatch' else 'UNSCORED' if key=='utility' else False)


def test_review_recomputes_candidate_and_root_render_is_separate(prepared, monkeypatch):
    f=prepared;c=candidate(f);path,expected=f['save'](c,f['folder']/'candidate.json')
    report=p.run('review',path,expected)
    assert report['approval_sha256']==p.digest(c['approval_candidate'])
    assert report['candidate_sha256']==expected and report['limitations']['approval_installed'] is False
    monkeypatch.setattr(os,'geteuid',lambda:0)
    assert p.run('render-approval',path,expected,acknowledge=True)==c['approval_candidate']
    assert set(x.name for x in f['folder'].iterdir())=={'input.json','candidate.json'}


@pytest.mark.parametrize('uid,ack',[(0,False),(61109,False),(61109,True)])
def test_render_requires_root_and_explicit_ack_before_open(prepared, monkeypatch, uid, ack):
    monkeypatch.setattr(os,'geteuid',lambda:uid)
    monkeypatch.setattr(p,'read_document',lambda *args:pytest.fail('opened before privilege check'))
    with pytest.raises(ValueError):p.run('render-approval','/never/open','1'*64,acknowledge=ack)


@pytest.mark.parametrize('origin',['CI','GITHUB_ACTIONS','LOCAL_MODEL','MANUAL_CLIENT',None])
def test_declared_ci_or_manual_inputs_are_not_operator_input(prepared,origin):
    f=prepared;value=copy.deepcopy(f['public']);value['origin']=origin
    with pytest.raises(ValueError):p.approval_from(value)


def test_manual_manifest_is_rejected(prepared):
    value=copy.deepcopy(prepared['public']);value['native_manifest']=manual.manifest()
    with pytest.raises((ValueError,KeyError)):p.approval_from(value)


@pytest.mark.parametrize('run',[p.MANUAL_RUN,'f'*64])
def test_previous_manual_or_explicitly_excluded_run_cannot_be_reused(prepared,run):
    value=copy.deepcopy(prepared['public']);value['native_manifest']['execution']['run_id']=run
    with pytest.raises(ValueError):p.build(p.canonical(value),['f'*64])


@pytest.mark.parametrize('field',['token_file','tls_key','authority_key','receipt_directory','binding','extra'])
def test_extra_input_fields_including_private_paths_refused(prepared,field):
    value=copy.deepcopy(prepared['public']);value[field]='/secret/DO_NOT_PRINT'
    path,expected=prepared['save'](value)
    with pytest.raises(ValueError):p.run('candidate',path,expected)


@pytest.mark.parametrize('fault',['wrong-schema','wrong-scope','role-uid','bool-uid','same-role-uid',
    'source-mismatch','source-missing','source-extra','source-label','genesis','same-authority-key','bad-public-key'])
def test_bad_public_metadata_refused(prepared,fault):
    value=copy.deepcopy(prepared['public'])
    if fault=='wrong-schema':value['schema']='old'
    elif fault=='wrong-scope':value['scope']='LIVE'
    elif fault=='role-uid':value['roles']['ledger']=109
    elif fault=='bool-uid':value['roles']['ledger']=True
    elif fault=='same-role-uid':value['roles']['custody']=value['roles']['issuer']
    elif fault=='source-mismatch':value['source_sha256'][p.readiness.MODULES[0]]='0'*64
    elif fault=='source-missing':del value['source_sha256'][p.readiness.MODULES[0]]
    elif fault=='source-extra':value['source_sha256']['other']='0'*64
    elif fault=='source-label':value['execution_source']='main'
    elif fault=='genesis':value['genesis']='main'
    elif fault=='same-authority-key':value['issuer_public_hex']=value['service_public_hex']
    elif fault=='bad-public-key':value['issuer_public_hex']='invalid'
    with pytest.raises(ValueError):p.approval_from(value)


@pytest.mark.parametrize('fault',['wrong-ca','not-ca','expired-ca','expired-leaf','wrong-purpose','wrong-host',
    'private-key','two-certs','trailing-data','same-tls-key','authority-tls-key','unknown-critical', 'missing-key-usage'])
def test_certificate_rejections(prepared,fault):
    f=prepared;value=copy.deepcopy(f['public']);certs=value['public_certificates'];key=f['tls_keys']['server']
    if fault=='wrong-ca':
        other=ec.generate_private_key(ec.SECP256R1());certs['ca']=pem(issue(other,None,other,ca=True))
    elif fault=='not-ca':certs['ca']=certs['issuer']
    elif fault=='expired-ca':certs['ca']=pem(issue(f['ca_key'],None,f['ca_key'],ca=True,expired=True))
    elif fault=='expired-leaf':certs['server']=pem(issue(key,f['ca'].subject,f['ca_key'],role='server',expired=True))
    elif fault=='wrong-purpose':certs['server']=pem(issue(key,f['ca'].subject,f['ca_key'],role='issuer'))
    elif fault=='wrong-host':certs['server']=pem(issue(key,f['ca'].subject,f['ca_key'],role='server',name='evil.invalid'))
    elif fault=='private-key':certs['server']=key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    elif fault=='two-certs':certs['server']+=certs['issuer']
    elif fault=='trailing-data':certs['server']+='DO_NOT_PRINT'
    elif fault=='same-tls-key':certs['custody']=pem(issue(f['tls_keys']['issuer'],f['ca'].subject,f['ca_key'],role='custody'))
    elif fault=='authority-tls-key':certs['issuer']=pem(issue(f['keys']['issuer'],f['ca'].subject,f['ca_key'],role='issuer'))
    elif fault=='unknown-critical':certs['server']=pem(issue(key,f['ca'].subject,f['ca_key'],role='server',critical=True))
    elif fault=='missing-key-usage':
        now=datetime.datetime.now(datetime.timezone.utc)
        certs['server']=pem(x509.CertificateBuilder().subject_name(f['ca'].subject).issuer_name(f['ca'].subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).sign(f['ca_key'],hashes.SHA256()))
    with pytest.raises((ValueError,x509.ExtensionNotFound,__import__('cryptography').exceptions.InvalidSignature)):
        p.approval_from(value)


@pytest.mark.parametrize('fault',['binding','tls-pin','source-report','flags','preparer','input-digest',
    'original-bytes','extra','schema','scope','remove-exclusion','duplicate-exclusion'])
def test_candidate_recomputed_and_tampering_denied(prepared,fault):
    c=candidate(prepared)
    if fault=='binding':c['approval_candidate']['binding']['run_id']='f'*64
    elif fault=='tls-pin':c['approval_candidate']['tls']['server_certificate_sha256']='0'*64
    elif fault=='source-report':c['approval_candidate']['source_sha256'][p.readiness.MODULES[0]]='0'*64
    elif fault=='flags':c['limitations']['execution_permission_issued']=True
    elif fault=='preparer':c['preparer_source_sha256']='0'*64
    elif fault=='input-digest':c['public_input_sha256']='0'*64
    elif fault=='original-bytes':c['public_input_raw_base64']=base64.b64encode(b'{}').decode()
    elif fault=='extra':c['approval_installed']=True
    elif fault=='schema':c['schema']=p.readiness.APPROVAL
    elif fault=='scope':c['scope']='LIVE'
    elif fault=='remove-exclusion':c['excluded_run_ids']=[]
    elif fault=='duplicate-exclusion':c['excluded_run_ids']*=2
    with pytest.raises(ValueError):p.validate_candidate(c)


@pytest.mark.parametrize('fault',['symlink','ancestor-symlink','hardlink','writable-file','writable-parent',
    'empty','oversize','digest','relative','double-slash','fifo','directory','duplicate-json-key'])
def test_input_file_safety(prepared,fault):
    f=prepared;file=f['file'];path=f['path'];expected=f['expected']
    if fault=='symlink':path=str(file.parent/'link');os.symlink(file,path)
    elif fault=='ancestor-symlink':
        link=file.parent.parent/'link';link.symlink_to(file.parent,target_is_directory=True);path=str(link/file.name)
    elif fault=='hardlink':os.link(file,file.parent/'hardlink')
    elif fault=='writable-file':file.chmod(0o666)
    elif fault=='writable-parent':file.parent.chmod(0o777)
    elif fault=='empty':file.write_bytes(b'');expected=p.sha(b'')
    elif fault=='oversize':file.write_bytes(b' '*(p.LIMIT+1));expected=p.sha(file.read_bytes())
    elif fault=='digest':expected='0'*64
    elif fault=='relative':path='input.json'
    elif fault=='double-slash':path=path.replace('/public/','//public/')
    elif fault=='fifo':file.unlink();os.mkfifo(file,0o600)
    elif fault=='directory':file.unlink();file.mkdir()
    elif fault=='duplicate-json-key':file.write_bytes(b'{"schema":1,"schema":2}');expected=p.sha(file.read_bytes())
    with pytest.raises((ValueError,OSError,p.custody.CustodyDenied)):p.run('candidate',path,expected)


def test_changed_input_is_not_retried_or_emitted(prepared,monkeypatch,capsys):
    f=prepared;original=p.build;calls=[]
    def withdraw(*args):
        calls.append(1);result=original(*args);f['file'].unlink();return result
    monkeypatch.setattr(p,'build',withdraw)
    assert p.main(['candidate','--document',f['path'],'--expected-sha256',f['expected']])==1
    captured=capsys.readouterr();assert captured.out=='' and captured.err.strip()==p.STOP and calls==[1]


def test_candidate_creation_does_not_generate_or_load_private_keys(prepared,monkeypatch):
    def denied(*args,**kwargs):pytest.fail('private key capability used')
    monkeypatch.setattr(ed25519.Ed25519PrivateKey,'generate',denied)
    monkeypatch.setattr(ec,'generate_private_key',denied)
    monkeypatch.setattr(serialization,'load_pem_private_key',denied)
    monkeypatch.setattr(p.custody,'load',denied)
    assert candidate(prepared)['limitations']['private_key_loaded'] is False


def test_expired_native_context_is_diagnostic_not_refreshed_permission(prepared):
    value=copy.deepcopy(prepared['public']);c=value['native_manifest']['execution'];c['not_before']=100;c['expires_at']=200
    result=p.build(p.canonical(value),[])
    assert result['approval_candidate']['native_manifest']['execution']==c
    assert result['limitations']['execution_permission_issued'] is False


@pytest.mark.parametrize('action,excluded,ack',[('review',['1'*64],False),('candidate',None,True),
    ('review',None,True),('render-approval',['1'*64],True),('serve',None,False)])
def test_wrong_action_arguments_refused(prepared,action,excluded,ack):
    with pytest.raises(ValueError):p.run(action,prepared['path'],prepared['expected'],excluded,ack)


def test_cli_sanitizes_bad_public_input(prepared,capsys):
    value=copy.deepcopy(prepared['public']);value['secret']='DO_NOT_PRINT'
    path,expected=prepared['save'](value)
    assert p.main(['candidate','--document',path,'--expected-sha256',expected])==1
    captured=capsys.readouterr();assert captured.out=='' and captured.err.strip()==p.STOP


def test_candidate_is_not_directly_accepted_as_readiness_approval(prepared):
    with pytest.raises(ValueError):p.readiness.validate_approval(candidate(prepared))


def test_actual_nonroot_can_prepare_but_cannot_render_approval(prepared):
    caps=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    if os.geteuid()!=0 or not all(caps&(1<<bit) for bit in (0,6,7)):
        pytest.skip('actual chown/setuid/setgid require disposable root-capable CI')
    f=prepared;uid=61109
    with tempfile.TemporaryDirectory(prefix='task4-native-approval-uid-') as tmp:
        base=Path(tmp);base.chmod(0o755);source=base/'source';source.mkdir(mode=0o755)
        root=Path(p.__file__).resolve().parents[1]
        for name in ('scripts','fixtures','docs'):
            shutil.copytree(root/name,source/name,ignore=shutil.ignore_patterns('__pycache__'))
        for file in source.rglob('*'):file.chmod(0o755 if file.is_dir() else 0o444)
        private=base/'ledger';private.mkdir(mode=0o700);os.chown(private,uid,uid)
        file=private/'input.json';file.write_bytes(f['file'].read_bytes());file.chmod(0o600);os.chown(file,uid,uid)
        # Explicit namespace selection also works with an older regular scripts package installed.
        code=('import importlib.machinery,importlib.util,sys;'
              's=importlib.machinery.PathFinder.find_spec("scripts",['+repr(str(source))+']);'
              'sys.modules["scripts"]=importlib.util.module_from_spec(s);'
              'from scripts.task4_native_github_approval_preparation_v1 import main;raise SystemExit(main())')
        def child(action,document,expected,extra=()):
            return subprocess.run(['setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups','--no-new-privs',
                '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',code,
                action,'--document',str(document),'--expected-sha256',expected,*extra],cwd='/tmp',
                env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8'},capture_output=True,text=True,timeout=30)
        accepted=child('candidate',file,f['expected']);assert accepted.returncode==0,accepted.stderr
        c=json.loads(accepted.stdout);assert c['limitations']['execution_permission_issued'] is False
        cf=private/'candidate.json';cf.write_text(accepted.stdout);cf.chmod(0o600);os.chown(cf,uid,uid)
        expected=p.sha(cf.read_bytes());reviewed=child('review',cf,expected);assert reviewed.returncode==0,reviewed.stderr
        refused=child('render-approval',cf,expected,['--acknowledge-read-only-approval'])
        assert refused.returncode==1 and refused.stdout=='' and refused.stderr.strip()==p.STOP


def test_rendered_cli_bytes_are_accepted_by_existing_readiness_check(prepared,monkeypatch,capsys):
    if os.geteuid()!=0:pytest.skip('root public approval fixture')
    f=prepared;c=candidate(f);path,expected=f['save'](c,f['folder']/'candidate.json')
    assert p.main(['render-approval','--document',path,'--expected-sha256',expected,
                   '--acknowledge-read-only-approval'])==0
    raw=capsys.readouterr().out.encode();assert raw==p.canonical(c['approval_candidate']) and not raw.endswith(b'\n')
    approval=f['folder']/'approval.json';approval.write_bytes(raw);approval.chmod(0o644)
    private=f['folder'].parent/'private';private.mkdir(mode=0o700)
    cfg=dict(schema=p.readiness.PROFILE,scope=p.readiness.SCOPE,approval_file=str(approval),token_file=str(private/'absent-token'))
    config=private/'config.json';config.write_bytes(p.canonical(cfg));config.chmod(0o600)
    report=p.readiness.run('check',str(config))
    assert report['credential_loaded'] is report['network_used'] is report['execution_permission_issued'] is False
    assert not (private/'absent-token').exists()


def test_input_formatting_is_pinned_and_retained_exactly(prepared):
    f=prepared;raw=(json.dumps(f['public'],indent=2)+'\n').encode();f['file'].write_bytes(raw)
    c=p.run('candidate',f['path'],p.sha(raw))
    assert base64.b64decode(c['public_input_raw_base64'])==raw
    assert p.validate_candidate(c)==c['approval_candidate']


@pytest.mark.parametrize('raw',[b'{"a":NaN}',b'{"a":Infinity}',b'{"a":1,"a":2}'])
def test_nonfinite_or_duplicate_public_json_refused(raw):
    with pytest.raises(ValueError):p.strict_public(raw)

"""Readiness has no mutator/signer/listener; HTTP is an injected test model."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_github_readiness_v1 as r
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from scripts import task4_signed_ledger_client_v1 as manual
from test_task4_signed_github_api_v1 import network, Response, payload

pytestmark=pytest.mark.skipif(os.geteuid()!=0,reason='root-owned public approval fixture requires sudo')
TOKEN='ghp_SYNTHETIC_READINESS_ONLY_NOT_A_CREDENTIAL'


@pytest.fixture
def prepared(tmp_path,monkeypatch,network):
    private=tmp_path/'private';private.mkdir(mode=0o700)
    public=tmp_path/'public';public.mkdir(mode=0o755)
    issuer,custody,runtime,service=[Ed25519PrivateKey.generate() for _ in range(4)]
    now=int(time.time());public_hex=lambda key:key.public_key().public_bytes_raw().hex()
    context=dict(schema=r.native.authority.SCHEMA,run_id='a'*64,raw_recipient_sha256='b'*64,local_leaf_sha256='c'*64,
        not_before=now-5,expires_at=now+295,endpoint=r.native.raw.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    manifest=r.native.manifest(context,public_hex(custody),public_hex(runtime))
    binding=dict(schema=r.signed.SCHEMA,ledger_id=r.signed.LEDGER_ID,run_id=context['run_id'],manifest_sha256=r.digest(manifest),
        issuer_public_sha256=r.sha(bytes.fromhex(public_hex(issuer))),custody_public_sha256=r.sha(bytes.fromhex(public_hex(custody))))
    api=model.ModelGitAPI(r.sha(bytes.fromhex(public_hex(service))))
    a=dict(schema=r.APPROVAL,scope=r.SCOPE,execution_source='d'*40,genesis=api.genesis,binding=binding,native_manifest=manifest,
        issuer_public_hex=public_hex(issuer),service_public_hex=public_hex(service),source_sha256=r.source_manifest(),
        roles=dict(ledger=61109,issuer=61105,custody=61106,runtime=61108),tls=dict(transport='MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED',
        ca_sha256='1'*64,server_certificate_sha256='2'*64,issuer_certificate_sha256='3'*64,custody_certificate_sha256='4'*64))
    approval=public/'approval.json';approval.write_bytes(r.canonical(a));approval.chmod(0o644)
    token=private/'read-token';token.write_text(TOKEN+'\n');token.chmod(0o600)
    cfg=dict(schema=r.PROFILE,scope=r.SCOPE,approval_file=str(approval),token_file=str(token))
    file=private/'configuration.json';file.write_bytes(r.canonical(cfg));file.chmod(0o600)
    def respond(method,path,body,headers):
        assert method=='GET' and body is None and headers['Authorization']=='Bearer '+TOKEN
        return Response(r.canonical(api.call(method,path)))
    network['responder']=respond
    # Unit HTTP model runs in this root-owned fixture; actual nonroot UID and
    # directory isolation are separately exercised by the subprocess case.
    monkeypatch.setattr(r,'current_uid',lambda:a['roles']['ledger'])
    return dict(file=file,cfg=cfg,approval=approval,a=a,token=token,api=api,key=service,network=network,private=private,public=public)


def test_local_check_never_reads_token_or_constructs_transport(prepared,monkeypatch):
    f=prepared;f['token'].unlink()
    monkeypatch.setattr(r,'ReadOnlyAPI',lambda *args:pytest.fail('transport constructed'))
    result=r.run('check',str(f['file']))
    assert result['credential_loaded'] is result['network_used'] is result['backend_verified'] is False
    assert result['live_execution_ready'] is result['execution_permission_issued'] is False
    assert not f['network']['connections'] and not f['api'].calls
    text=json.dumps(result)
    assert TOKEN not in text and str(f['private']) not in text


def test_source_manifest_is_unapproved_local_bytes_only(monkeypatch,capsys):
    monkeypatch.setattr(r,'ReadOnlyAPI',lambda *args:pytest.fail('transport constructed'))
    assert r.main(['source-manifest'])==0
    result=json.loads(capsys.readouterr().out)
    assert set(result['source_sha256'])==set(r.MODULES) and len(r.MODULES)==11
    assert result['approval_created'] is result['network_used'] is result['execution_permission_issued'] is False


def test_read_existing_missing_native_run_is_diagnostic_not_enrollment(prepared):
    f=prepared;before=len(f['api'].commits)
    result=r.run('read-existing',str(f['file']),True)
    assert result['backend_verified'] is result['network_used'] is True
    assert result['native_run_present'] is False and result['observed_snapshot'] is None
    assert result['result']=='NATIVE_RUN_ABSENT_NO_ENROLLMENT' and len(f['api'].commits)==before
    assert result['github_get_requests']==len(f['api'].calls)==7
    assert all(method=='GET' and value is None for method,path,value in f['api'].calls)
    assert result['live_execution_ready'] is result['credential_permissions_verified'] is False
    assert TOKEN not in json.dumps(result)


def test_existing_native_binding_is_observation_never_execution_permission(prepared):
    f=prepared;a=f['a'];service=r.signed.SignedGitHubService(r.signed.GitState(f['api'],a['genesis'],f['api'].commits[a['genesis']]['state']['service_public_sha256']),f['key'])
    service.enroll(a['binding']);before=copy.deepcopy(f['api'].commits);f['api'].calls.clear()
    result=r.run('read-existing',str(f['file']),True)
    assert result['native_run_present'] is True and result['observed_snapshot']==dict(revision=0,attempts=[])
    assert result['execution_permission_issued'] is result['live_execution_ready'] is result['listener_started'] is False
    assert f['api'].commits==before and len(f['api'].calls)==8


def test_get_only_api_refuses_even_a_valid_signed_mutation_before_network(network):
    api=r.ReadOnlyAPI(TOKEN,'b'*40,'a'*64)
    with pytest.raises(ValueError):api.call('POST','/graphql',payload())
    backend=r.signed.GitState(api,'b'*40,'a'*64)
    with pytest.raises(ValueError):backend.mutate('b'*40,r.signed.empty('a'*64))
    assert not network['connections'] and not network['requests']


@pytest.mark.parametrize('method,path,value',[
    ('POST','/graphql',{}),('PATCH',r.wire.PREFIX+'git/refs/heads/'+r.signed.BRANCH,{}),
    ('DELETE',r.wire.PREFIX+'git/refs/heads/'+r.signed.BRANCH,None),
    ('GET','https://evil.invalid',None),('GET',r.wire.PREFIX+'git/ref/heads/main',None),
    ('GET',r.wire.PREFIX+'git/blobs/'+'b'*40+'?x=1',None),('GET','/graphql',None),
    ('GET',r.wire.PREFIX+'git/blobs/'+'b'*40,{'body':'denied'}),
])
def test_disallowed_routes_never_use_token_or_socket(network,method,path,value):
    with pytest.raises(ValueError):r.ReadOnlyAPI(TOKEN,'b'*40,'a'*64).call(method,path,value)
    assert network['connections']==[]


@pytest.mark.parametrize('fault',['schema','scope','source','extra','old-manifest','issuer','custody','runtime-key',
    'service-key','role-overlap','root-uid','bool-uid','transport','same-cert','genesis','execution-source'])
def test_unreviewed_or_manual_native_approval_is_rejected_before_credential_use(prepared,fault):
    f=prepared;a=copy.deepcopy(f['a'])
    if fault=='schema':a['schema']='other'
    elif fault=='scope':a['scope']='PRODUCTION'
    elif fault=='source':a['source_sha256'][r.MODULES[0]]='0'*64
    elif fault=='extra':a['host']='evil.invalid'
    elif fault=='old-manifest':a['binding']['manifest_sha256']=r.digest(manual.manifest())
    elif fault=='issuer':a['issuer_public_hex']='0'*64
    elif fault=='custody':a['binding']['custody_public_sha256']='0'*64
    elif fault=='runtime-key':
        a['native_manifest']['runtime_public']=a['issuer_public_hex'];a['binding']['manifest_sha256']=r.digest(a['native_manifest'])
    elif fault=='service-key':a['service_public_hex']=a['issuer_public_hex']
    elif fault=='role-overlap':a['roles']['custody']=a['roles']['issuer']
    elif fault=='root-uid':a['roles']['ledger']=0
    elif fault=='bool-uid':a['roles']['ledger']=True
    elif fault=='transport':a['tls']['transport']='plaintext'
    elif fault=='same-cert':a['tls']['server_certificate_sha256']=a['tls']['issuer_certificate_sha256']
    elif fault=='genesis':a['genesis']='main'
    else:a['execution_source']='main'
    f['approval'].write_bytes(r.canonical(a));f['token'].unlink()
    with pytest.raises(r.ReadinessDenied,match='^'+r.STOP+'$'):r.run('read-existing',str(f['file']),True)
    assert not f['network']['connections']


@pytest.mark.parametrize('fault',['cfg-mode','cfg-symlink','approval-mode','approval-symlink','approval-missing','token-mode','token-symlink','token-invalid'])
def test_private_config_public_approval_and_token_are_no_follow_bounded(prepared,fault):
    f=prepared
    if fault=='cfg-mode':f['file'].chmod(0o644)
    elif fault=='approval-mode':f['approval'].chmod(0o666)
    elif fault=='approval-missing':f['approval'].unlink()
    elif fault=='token-mode':f['token'].chmod(0o644)
    elif fault=='token-invalid':f['token'].write_text(TOKEN+'\r\n')
    else:
        key={'cfg-symlink':'file','approval-symlink':'approval','token-symlink':'token'}[fault]
        path=f[key];saved=path.with_suffix('.saved');path.rename(saved);path.symlink_to(saved)
    with pytest.raises(r.ReadinessDenied):r.run('read-existing',str(f['file']),True)
    assert not f['network']['connections']


def test_wrong_execution_account_refuses_network_and_credential_loading(prepared,monkeypatch):
    f=prepared;f['token'].unlink();monkeypatch.setattr(r,'current_uid',lambda:0)
    with pytest.raises(r.ReadinessDenied):r.run('read-existing',str(f['file']),True)
    assert not f['network']['connections']


@pytest.mark.parametrize('path',['relative-token','','/tmp/../token'])
def test_local_check_rejects_noncanonical_credential_path_without_loading_it(prepared,path):
    f=prepared;cfg=dict(f['cfg'],token_file=path);f['file'].write_bytes(r.canonical(cfg))
    with pytest.raises(r.ReadinessDenied):r.run('check',str(f['file']))
    assert not f['network']['connections']


@pytest.mark.parametrize('fault',['approval','token','configuration'])
def test_mid_read_withdrawal_never_reports_success_or_retries(prepared,fault):
    f=prepared;responder=f['network']['responder'];changed=[]
    def withdraw(*args):
        result=responder(*args)
        if not changed:
            changed.append(True)
            if fault=='approval':f['approval'].unlink()
            elif fault=='token':f['token'].write_text(TOKEN+'_ROTATED')
            else:
                cfg=dict(f['cfg'],token_file=str(f['private']/'different-token'));f['file'].write_bytes(r.canonical(cfg))
        return result
    f['network']['responder']=withdraw
    with pytest.raises(r.ReadinessDenied):r.run('read-existing',str(f['file']),True)
    assert all(x[0]=='GET' for x in f['api'].calls) and len(f['api'].commits)==1


def test_error_is_constant_and_contains_no_token_or_path(prepared,monkeypatch,capsys):
    f=prepared;f['network']['request_fault']=RuntimeError(TOKEN+' '+str(f['token']))
    assert r.main(['read-existing','--configuration',str(f['file']),'--allow-github-read'])==1
    output=capsys.readouterr();assert output.out=='' and output.err.strip()==r.STOP
    assert len(f['network']['requests'])==1 and f['network']['connections'][0].closed


def test_expired_native_manifest_does_not_turn_readiness_into_permission(prepared):
    f=prepared;a=f['a'];a['native_manifest']['execution']['expires_at']=int(time.time())-1
    a['native_manifest']['execution']['not_before']=a['native_manifest']['execution']['expires_at']-100
    a['binding']['manifest_sha256']=r.digest(a['native_manifest']);f['approval'].write_bytes(r.canonical(a))
    result=r.run('check',str(f['file']))
    assert result['native_window_status']=='EXPIRED' and result['live_execution_ready'] is False
    assert not f['network']['connections']


def test_egress_plan_is_unapplied_and_only_ledger_has_planned_github_get(prepared):
    a=prepared['a'];plan=r.plan(a)
    assert plan['default_external_egress']=='DENY'
    assert plan['allowed_github_https']['uid']==a['roles']['ledger'] and plan['allowed_github_https']['methods']==['GET']
    assert set(plan['denied_external_uids'])=={'issuer','custody','runtime'}
    assert plan['os_rules_applied'] is plan['os_egress_verified'] is plan['tls_handshake_performed'] is False
    assert plan['dns_resolver_policy']=='REQUIRES_SEPARATE_REVIEW'


def test_local_check_rejects_uid_mapping_incompatible_with_pinned_native_profile(prepared):
    f=prepared;f['a']['roles']['ledger']=61500;f['approval'].write_bytes(r.canonical(f['a']))
    with pytest.raises(r.ReadinessDenied):r.run('check',str(f['file']))
    assert not f['network']['connections']


@pytest.mark.parametrize('argv',[['read-existing'],['source-manifest','--allow-github-read'],['check','--allow-github-read']])
def test_cli_has_no_implicit_network_mode(prepared,capsys,argv):
    if argv[0]!='source-manifest':argv=argv+['--configuration',str(prepared['file'])]
    assert r.main(argv)==1
    assert capsys.readouterr().err.strip()==r.STOP
    assert not prepared['network']['connections']


def observation():
    return json.loads((Path(__file__).resolve().parents[1]/'evidence/task4_native_github_readonly_observation_v1.json').read_bytes())


def test_real_connector_observation_has_exact_genesis_blob_ancestry_and_manual_manifest():
    evidence=observation();calls=[]
    class Replay:
        def call(self,method,path,value=None):
            assert method=='GET' and value is None;calls.append(path);row=evidence['records'][path]
            if 'decoded_blob_utf8' in row:
                data=row['decoded_blob_utf8'].encode();return dict(encoding='base64',size=len(data),content=base64.b64encode(data).decode())
            return row
    head,state=r.signed.GitState(Replay(),evidence['approved_genesis'],r.sha(bytes.fromhex(evidence['operator_previously_supplied_service_public_hex']))).read()
    assert head==evidence['head_before']==evidence['head_after'] and len(calls)==8
    assert len(state['runs'])==1 and state['revision']==5
    row=next(iter(state['runs'].values()))
    assert row['binding']['manifest_sha256']==r.digest(manual.manifest())
    assert row['snapshot']['revision']==4 and [x['state'] for x in row['snapshot']['attempts']]==['CONSUMED_UNKNOWN']*2
    assert evidence['operator_os_egress_verified'] is evidence['operator_tls_handshake_performed'] is False


def test_actual_nonroot_check_reads_own_configuration_and_denies_other_uid(prepared):
    caps=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    if not all(caps&(1<<bit) for bit in (0,6,7)):pytest.skip('actual chown/setuid/setgid require disposable root-capable CI')
    f=prepared
    with tempfile.TemporaryDirectory(prefix='task4-native-readiness-uid-') as tmp:
        base=Path(tmp);base.chmod(0o755);source=base/'source';source.mkdir(mode=0o755)
        root=Path(r.__file__).resolve().parents[1]
        for name in ('scripts','fixtures','docs'):
            shutil.copytree(root/name,source/name,ignore=shutil.ignore_patterns('__pycache__'))
        for file in source.rglob('*'):file.chmod(0o755 if file.is_dir() else 0o444)
        public=base/'public';public.mkdir(mode=0o755);approval=public/'approval.json';approval.write_bytes(r.canonical(f['a']));approval.chmod(0o644)
        private=base/'ledger';private.mkdir(mode=0o700)
        cfg=dict(f['cfg'],approval_file=str(approval),token_file=str(private/'unused-token'))
        file=private/'config.json';file.write_bytes(r.canonical(cfg));file.chmod(0o600)
        uid=f['a']['roles']['ledger'];os.chown(file,uid,uid);os.chown(private,uid,uid)
        code='import sys;sys.path.insert(0,'+repr(str(source))+');from scripts.task4_native_github_readiness_v1 import main;raise SystemExit(main())'
        def child(who):
            return subprocess.run(['setpriv','--reuid='+str(who),'--regid='+str(who),'--clear-groups','--no-new-privs',
                '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',code,
                'check','--configuration',str(file)],cwd='/tmp',env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8'},
                capture_output=True,text=True,timeout=30)
        accepted=child(uid);assert accepted.returncode==0,accepted.stderr
        report=json.loads(accepted.stdout);assert report['account_matches_ledger_uid'] is True
        assert report['network_used'] is report['credential_loaded'] is False and not (private/'unused-token').exists()
        denied=child(f['a']['roles']['issuer']);assert denied.returncode==1 and denied.stderr.strip()==r.STOP and denied.stdout==''

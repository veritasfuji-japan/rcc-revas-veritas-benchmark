"""Retained public identity + three Native key exports; no service key use."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_retained_signer_profile_v1 as t
from scripts import task4_signed_ledger_client_v1 as manual
from scripts import task4_signed_github_ledger_rehearsal_v1 as model
from test_task4_native_github_approval_preparation_v1 import prepared as public_prepared
from test_task4_native_role_keys_v1 import keys as role_keys
from test_task4_signed_github_api_v1 import network, Response

pytestmark=pytest.mark.skipif(os.geteuid()!=0,reason='root public approval/configuration fixtures require root-capable CI')
TOKEN='ghp_SYNTHETIC_RETAINED_READER_ONLY_NOT_A_CREDENTIAL'


@pytest.fixture
def joined(public_prepared,role_keys,network,monkeypatch):
    f=public_prepared;p=t.preparation;r=t.readiness
    public=copy.deepcopy(f['public']);service=public['service_public_hex']
    api=model.ModelGitAPI(t.sha(bytes.fromhex(service)));public['genesis']=api.genesis
    legacy_binding=dict(schema=r.signed.SCHEMA,ledger_id=r.signed.LEDGER_ID,run_id=p.MANUAL_RUN,
        manifest_sha256=t.digest(manual.manifest()),issuer_public_sha256=t.sha(bytes.fromhex(public['issuer_public_hex'])),
        custody_public_sha256=t.sha(bytes.fromhex(public['native_manifest']['custody_public'])))
    legacy=dict(schema=t.LEGACY_APPROVAL,scope=t.LEGACY_SCOPE,execution_source='c'*40,genesis=api.genesis,
        binding=legacy_binding,service_public_hex=service,server_certificate_sha256='3'*64,
        peers={role:dict(certificate_sha256=str(i)*64,authority_public_sha256=legacy_binding[role+'_public_sha256'])
               for role,i in [('issuer',1),('custody',2)]})
    raw=t.canonical(legacy);legacy_file=f['folder']/'legacy-approval.json';legacy_file.write_bytes(raw);legacy_file.chmod(0o644)
    retained=t.identity_from(raw,api.genesis,t.sha(bytes.fromhex(service)))
    exports={role:role_keys['create'](role)['public_export'] for role in t.NATIVE_ROLES}
    bundle=dict(schema=t.BUNDLE,scope=t.keys.SCOPE,run_id='a'*64,retained_service=retained,exports=exports)
    public.update(schema=p.RETAINED_INPUT,roles=dict(t.ROLES),native_key_bundle=bundle,profile_source_sha256=t.extra_sources(),
                  issuer_public_hex=exports['issuer']['public_key_hex'])
    public['native_manifest']['custody_public']=exports['custody']['public_key_hex']
    public['native_manifest']['runtime_public']=exports['runtime']['public_key_hex']
    approval=p.approval_from(public)
    approval_file=f['folder']/'retained-approval.json';approval_file.write_bytes(t.canonical(approval));approval_file.chmod(0o644)
    private=f['folder'].parent/'reader';private.mkdir(mode=0o700)
    token=private/'read-token';token.write_text(TOKEN+'\n');token.chmod(0o600)
    cfg=dict(schema=r.PROFILE,scope=r.SCOPE,approval_file=str(approval_file),token_file=str(token))
    file=private/'configuration.json';file.write_bytes(t.canonical(cfg));file.chmod(0o600)
    def responder(method,path,body,headers):
        assert method=='GET' and body is None and headers['Authorization']=='Bearer '+TOKEN
        return Response(t.canonical(api.call(method,path)))
    network['responder']=responder
    monkeypatch.setattr(r,'current_uid',lambda:61109)
    return dict(public=public,approval=approval,file=file,cfg=cfg,approval_file=approval_file,legacy=legacy,raw=raw,
                legacy_file=legacy_file,retained=retained,bundle=bundle,api=api,network=network,token=token,
                private=private,folder=f['folder'],service_key=f['keys']['service'])


def test_root_public_identity_matches_existing_pin_without_private_key_load(joined,monkeypatch):
    f=joined
    monkeypatch.setattr(t.keys.custody,'load',lambda *a:pytest.fail('private key loaded'))
    monkeypatch.setattr(t.keys.custody,'_read_key',lambda *a:pytest.fail('private key loaded'))
    record=t.read_identity(str(f['legacy_file']),t.sha(f['raw']),f['legacy']['genesis'],f['retained']['service_public_sha256'])
    assert record==f['retained'] and base64.b64decode(record['legacy_approval_raw_base64'])==f['raw']
    assert record['service_uid']==109 and record['legacy_run_id']==t.preparation.MANUAL_RUN


def test_retained_profile_has_three_native_keys_and_no_new_ledger_key(joined):
    f=joined;r=t.readiness;a=f['approval'];report=t.bundle_report(f['bundle'])
    assert r.validate_approval(a)==a and a['schema']==r.RETAINED_APPROVAL
    assert a['roles']==dict(service=109,reader=61109,issuer=61105,custody=61106,runtime=61108)
    assert set(f['bundle']['exports'])=={'issuer','custody','runtime'}
    assert a['service_public_hex']==f['legacy']['service_public_hex'] and a['genesis']==f['legacy']['genesis']
    assert report['retained_private_key_loaded'] is report['retained_service_uid_observed'] is False
    assert report['key_pair_correspondence_verified'] is report['service_reconfigured'] is False
    assert len(t.canonical(a))<=8192 and len(a['source_sha256'])+len(a['profile_source_sha256'])==14


def test_local_check_reads_no_token_or_private_key_and_distinguishes_service_reader(joined,monkeypatch):
    f=joined;r=t.readiness;f['token'].unlink()
    monkeypatch.setattr(r,'ReadOnlyAPI',lambda *a:pytest.fail('network'))
    monkeypatch.setattr(t.keys.custody,'_read_key',lambda *a:pytest.fail('private key'))
    result=r.run('check',str(f['file']))
    assert result['account_matches_reader_uid'] is True and result['account_matches_ledger_uid'] is False
    assert result['read_account_uid']==61109 and result['service_account_uid']==109
    for field in ('network_used','credential_loaded','execution_permission_issued','retained_private_key_loaded',
                  'retained_service_uid_observed','service_reconfigured','native_runtime_profile_applied','operator_mtls_verified'):
        assert result[field] is False
    assert result['source_pin_scope']=='FOURTEEN_SELECTED_FILES_NOT_FULL_RUNTIME_ATTESTATION'
    plan=result['egress_plan'];assert plan['allowed_github_https']['uid']==61109
    assert plan['retained_service_excluded_uid']==109 and plan['os_rules_applied'] is False
    assert 109 not in plan['applies_to_uids'].values() and plan['applies_to_uids']['reader']==61109
    assert plan['retained_service_egress_policy']=='OUTSIDE_READ_ONLY_CHECKER_PLAN_REQUIRES_SEPARATE_REVIEW'
    assert not f['api'].calls and not f['network']['connections']


def test_reader_gets_existing_root_with_retained_pin_and_no_native_enrollment(joined):
    f=joined;result=t.readiness.run('read-existing',str(f['file']),True)
    assert result['backend_verified'] is True and result['native_run_present'] is False
    assert result['result']=='NATIVE_RUN_ABSENT_NO_ENROLLMENT' and result['github_get_requests']==7
    assert all(method=='GET' and value is None for method,path,value in f['api'].calls)
    assert result['execution_permission_issued'] is result['service_reconfigured'] is False
    assert TOKEN not in json.dumps(result)


def test_observed_native_run_is_still_only_diagnostic(joined):
    f=joined;r=t.readiness;a=f['approval'];service=r.signed.SignedGitHubService(
        r.signed.GitState(f['api'],a['genesis'],a['retained_service']['service_public_sha256']),f['service_key'])
    service.enroll(a['binding']);f['api'].calls.clear();before=copy.deepcopy(f['api'].commits)
    result=r.run('read-existing',str(f['file']),True)
    assert result['native_run_present'] is True and result['observed_snapshot']==dict(revision=0,attempts=[])
    assert result['live_execution_ready'] is result['native_runtime_profile_applied'] is False
    assert f['api'].commits==before and all(x[0]=='GET' for x in f['api'].calls)


@pytest.mark.parametrize('uid',[0,109,61105,61106,61108])
def test_only_reader_uid_may_load_read_token_or_attempt_get(joined,monkeypatch,uid):
    monkeypatch.setattr(t.readiness,'current_uid',lambda:uid)
    monkeypatch.setattr(t.readiness,'token',lambda *a:pytest.fail('token read for wrong account'))
    with pytest.raises(t.readiness.ReadinessDenied):t.readiness.run('read-existing',str(joined['file']),True)
    assert not joined['network']['connections']


@pytest.mark.parametrize('fault',['schema','scope','service-uid','reader-uid','bool-uid','swap-uids','extra-role',
    'service-key','genesis','legacy-run','bundle-digest','profile-source','missing-source','extra-source',
    'binding-manual','source-eleven','new-as-legacy','legacy-with-retained'])
def test_profile_confusion_and_changed_identity_refused(joined,fault):
    a=copy.deepcopy(joined['approval']);r=t.readiness
    if fault=='schema':a['schema']='unknown'
    elif fault=='scope':a['scope']='LIVE'
    elif fault=='service-uid':a['roles']['service']=61109
    elif fault=='reader-uid':a['roles']['reader']=109
    elif fault=='bool-uid':a['roles']['reader']=True
    elif fault=='swap-uids':a['roles']['reader'],a['roles']['service']=109,61109
    elif fault=='extra-role':a['roles']['ledger']=61109
    elif fault=='service-key':a['service_public_hex']='0'*64
    elif fault=='genesis':a['genesis']='0'*40
    elif fault=='legacy-run':a['binding']['run_id']=a['native_manifest']['execution']['run_id']=a['retained_service']['legacy_run_id']
    elif fault=='bundle-digest':a['native_key_bundle_sha256']='invalid'
    elif fault=='profile-source':a['profile_source_sha256'][t.EXTRA_MODULES[0]]='0'*64
    elif fault=='missing-source':del a['profile_source_sha256'][t.EXTRA_MODULES[0]]
    elif fault=='extra-source':a['profile_source_sha256']['other']='0'*64
    elif fault=='binding-manual':a['binding']['manifest_sha256']=t.digest(manual.manifest())
    elif fault=='source-eleven':a['source_sha256'][r.MODULES[0]]='0'*64
    elif fault=='new-as-legacy':a['schema']=r.APPROVAL
    elif fault=='legacy-with-retained':a['roles']=t.legacy_roles();a['schema']=r.APPROVAL
    with pytest.raises(ValueError):r.validate_approval(a)


@pytest.mark.parametrize('fault',['raw','sha','public','genesis','uid','bool-uid','run','schema','extra'])
def test_retained_identity_tampering_refused(joined,fault):
    a=copy.deepcopy(joined['retained'])
    if fault=='raw':a['legacy_approval_raw_base64']=base64.b64encode(b'{}').decode()
    elif fault=='sha':a['legacy_approval_sha256']='0'*64
    elif fault=='public':a['service_public_hex']='0'*64
    elif fault=='genesis':a['genesis']='0'*40
    elif fault=='uid':a['service_uid']=61109
    elif fault=='bool-uid':a['service_uid']=True
    elif fault=='run':a['legacy_run_id']='0'*64
    elif fault=='schema':a['schema']=t.keys.PROFILE
    elif fault=='extra':a['private_key_file']='/private/DO_NOT_PRINT'
    with pytest.raises(ValueError):t.validate_identity(a)


@pytest.mark.parametrize('fault',['ledger-export','reader-export','missing-export','shared-key','run','old-run','role-key'])
def test_three_native_exports_reject_new_ledger_and_role_substitution(joined,fault):
    b=copy.deepcopy(joined['bundle'])
    if fault=='ledger-export':b['exports']['ledger']=copy.deepcopy(b['exports']['issuer'])
    elif fault=='reader-export':b['exports']['reader']=copy.deepcopy(b['exports']['issuer'])
    elif fault=='missing-export':del b['exports']['custody']
    elif fault=='shared-key':
        for field in ('public_key_hex','public_key_sha256'):
            b['exports']['issuer'][field]=b['exports']['custody'][field]
    elif fault=='run':b['exports']['issuer']['run_id']='f'*64
    elif fault=='old-run':b['run_id']=b['retained_service']['legacy_run_id']
    elif fault=='role-key':
        b['exports']['issuer']['public_key_hex']=b['retained_service']['service_public_hex']
        b['exports']['issuer']['public_key_sha256']=b['retained_service']['service_public_sha256']
    with pytest.raises(ValueError):t.validate_bundle(b)


@pytest.mark.parametrize('field',['issuer','custody','runtime','service','genesis','schema'])
def test_public_input_must_join_bundle_exactly(joined,field):
    public=copy.deepcopy(joined['public']);other=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    if field=='issuer':public['issuer_public_hex']=other
    elif field=='custody':public['native_manifest']['custody_public']=other
    elif field=='runtime':public['native_manifest']['runtime_public']=other
    elif field=='service':public['service_public_hex']=other
    elif field=='genesis':public['genesis']='0'*40
    elif field=='schema':public['schema']=t.preparation.INPUT
    with pytest.raises(ValueError):t.preparation.approval_from(public)


def test_candidate_root_render_and_existing_readiness_join_without_key_actions(joined,monkeypatch,capsys):
    f=joined;p=t.preparation
    monkeypatch.setattr(t.keys.custody,'_read_key',lambda *a:pytest.fail('private key read'))
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('key generation'))
    file=f['folder']/'retained-public.json';file.write_bytes(t.canonical(f['public']));file.chmod(0o644)
    candidate=p.run('candidate',str(file),t.sha(file.read_bytes()))
    assert candidate['approval_candidate']==f['approval']
    cf=f['folder']/'candidate.json';cf.write_bytes(t.canonical(candidate));cf.chmod(0o644)
    assert p.main(['render-approval','--document',str(cf),'--expected-sha256',t.sha(cf.read_bytes()),
                   '--acknowledge-read-only-approval'])==0
    raw=capsys.readouterr().out.encode();assert raw==t.canonical(f['approval'])
    assert p.run('review',str(cf),t.sha(cf.read_bytes()))['limitations']['execution_permission_issued'] is False
    assert t.readiness.run('check',str(f['file']))['service_account_uid']==109


def test_withdrawal_before_output_stops_read_without_retry(joined,monkeypatch):
    f=joined;original=t.readiness.ReadOnlyAPI;calls=[]
    class Withdraw(original):
        def call(self,method,path,value=None):
            calls.append(method);reply=super().call(method,path,value)
            if len(calls)==7:f['approval_file'].unlink()
            return reply
    monkeypatch.setattr(t.readiness,'ReadOnlyAPI',Withdraw)
    with pytest.raises(t.readiness.ReadinessDenied):t.readiness.run('read-existing',str(f['file']),True)
    assert calls==['GET']*7


def test_public_identity_wrong_pin_and_private_file_are_refused(joined):
    f=joined
    with pytest.raises(ValueError):t.read_identity(str(f['legacy_file']),'0'*64,f['legacy']['genesis'],f['retained']['service_public_sha256'])
    with pytest.raises(ValueError):t.read_identity(str(f['legacy_file']),t.sha(f['raw']),f['legacy']['genesis'],'0'*64)
    f['legacy_file'].chmod(0o600)
    with pytest.raises(ValueError):t.read_identity(str(f['legacy_file']),t.sha(f['raw']),f['legacy']['genesis'],f['retained']['service_public_sha256'])


def test_cli_errors_are_constant_and_do_not_emit_private_data(joined,capsys):
    assert t.main(['identity','--legacy-approval',str(joined['legacy_file']),'--expected-sha256','0'*64,
                   '--expected-genesis',joined['legacy']['genesis'],'--expected-public-sha256','0'*64])==1
    c=capsys.readouterr();assert c.out=='' and c.err.strip()==t.STOP


def test_actual_reader_uid_checks_retained_profile_and_service_uid_cannot_read_its_config(joined):
    caps=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    if not all(caps&(1<<bit) for bit in (0,6,7)):
        pytest.skip('actual chown/setuid/setgid require root-capable CI')
    f=joined
    with tempfile.TemporaryDirectory(prefix='task4-native-retained-reader-') as temp:
        base=Path(temp);base.chmod(0o755);source=base/'source';source.mkdir(mode=0o755)
        root=Path(t.__file__).resolve().parents[1]
        for name in ('scripts','fixtures','docs'):
            shutil.copytree(root/name,source/name,ignore=shutil.ignore_patterns('__pycache__'))
        for file in source.rglob('*'):file.chmod(0o755 if file.is_dir() else 0o444)
        public=base/'public';public.mkdir(mode=0o755)
        approval=public/'retained.json';approval.write_bytes(t.canonical(f['approval']));approval.chmod(0o644)
        private=base/'reader';private.mkdir(mode=0o700)
        cfg=dict(f['cfg'],approval_file=str(approval),token_file=str(private/'absent-token'))
        file=private/'cfg.json';file.write_bytes(t.canonical(cfg));file.chmod(0o600)
        for path in (private,file):os.chown(path,61109,61109)
        code=('import importlib.machinery,importlib.util,sys;'
              's=importlib.machinery.PathFinder.find_spec("scripts",['+repr(str(source))+']);'
              'sys.modules["scripts"]=importlib.util.module_from_spec(s);'
              'from scripts.task4_native_github_readiness_v1 import main;raise SystemExit(main())')
        def child(uid):
            return subprocess.run(['setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups','--no-new-privs',
                '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',code,
                'check','--configuration',str(file)],cwd='/tmp',env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8'},
                capture_output=True,text=True,timeout=30)
        checked=child(61109);assert checked.returncode==0,checked.stderr
        report=json.loads(checked.stdout)
        assert report['account_matches_reader_uid'] is True and report['account_matches_ledger_uid'] is False
        assert report['service_account_uid']==109 and report['credential_loaded'] is report['network_used'] is False
        assert not (private/'absent-token').exists()
        for uid in (109,61105):
            denied=child(uid);assert denied.returncode==1 and denied.stdout=='' and denied.stderr.strip()==t.readiness.STOP


def test_profile_source_manifest_pins_fourteen_files_without_private_access(joined,monkeypatch,capsys):
    monkeypatch.setattr(t.keys.custody,'_read_key',lambda *a:pytest.fail('private key'))
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('key generation'))
    assert t.main(['source-manifest'])==0
    r=json.loads(capsys.readouterr().out)
    assert len(r['source_sha256'])==11 and len(r['profile_source_sha256'])==3
    assert r['network_used'] is r['approval_created'] is r['execution_permission_issued'] is False


@pytest.mark.parametrize('fault',['schema','scope','ledger','peer-authority','shared-cert','service-public','extra-private','source-label'])
def test_legacy_public_bytes_are_validated_before_identity_export(joined,fault):
    a=copy.deepcopy(joined['legacy'])
    if fault=='schema':a['schema']=t.readiness.RETAINED_APPROVAL
    elif fault=='scope':a['scope']=t.readiness.SCOPE
    elif fault=='ledger':a['binding']['ledger_id']='0'*64
    elif fault=='peer-authority':a['peers']['issuer']['authority_public_sha256']='0'*64
    elif fault=='shared-cert':a['peers']['issuer']['certificate_sha256']=a['server_certificate_sha256']
    elif fault=='service-public':a['service_public_hex']='invalid'
    elif fault=='extra-private':a['token_file']='/private/DO_NOT_PRINT'
    elif fault=='source-label':a['execution_source']='main'
    with pytest.raises(ValueError):t.legacy_public(t.canonical(a))


def test_new_signer_cannot_read_existing_genesis_even_if_declared_in_public_metadata(joined):
    f=joined;p=t.preparation;r=t.readiness
    fresh=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    legacy=copy.deepcopy(f['legacy']);legacy['service_public_hex']=fresh
    raw=t.canonical(legacy);identity=t.identity_from(raw,legacy['genesis'],t.sha(bytes.fromhex(fresh)))
    public=copy.deepcopy(f['public']);public['service_public_hex']=fresh
    public['native_key_bundle']['retained_service']=identity
    approval=p.approval_from(public)
    f['approval_file'].write_bytes(t.canonical(approval))
    with pytest.raises(r.ReadinessDenied):r.run('read-existing',str(f['file']),True)
    assert f['api'].calls and all(method=='GET' and value is None for method,path,value in f['api'].calls)
    assert len(f['api'].commits)==1

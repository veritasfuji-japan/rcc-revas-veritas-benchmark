"""Disposable synthetic keys; unit UID seams are separate from real-UID CI."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_role_keys_v1 as k
from test_task4_native_github_approval_preparation_v1 import prepared as public_prepared
from test_task4_signed_github_api_v1 import network

RUN='a'*64


@pytest.fixture
def keys(tmp_path,monkeypatch):
    base=tmp_path/'state';base.mkdir(mode=0o700)
    for role in k.ROLES:(base/('veritas-native-'+role)).mkdir(mode=0o700)
    monkeypatch.setattr(k,'BASE',base)
    # Unit files are owned by the test process. Only reported role metadata and
    # the entry-point role check are seams; filesystem checks still use real UID.
    state={'role':'ledger'};original_identity=k.identity;original_role=k.role_identity
    monkeypatch.setattr(k,'role_identity',lambda role:k.ROLES[role])
    def metadata(info):
        return dict(original_identity(info),uid=k.ROLES[state['role']])
    monkeypatch.setattr(k,'identity',metadata)
    def activate(role):state['role']=role
    def create(role='ledger',run=RUN):
        activate(role);return k.initialize(role,run,True)
    def inspect(role,report,run=RUN):
        activate(role);r=report['public_export']
        return k.inspect(role,run,r['public_key_sha256'],report['export_sha256'])
    def save(value,name='bundle.json'):
        file=base/name;file.write_bytes(k.canonical(value));file.chmod(0o600)
        return str(file),k.sha(file.read_bytes())
    def bundle():
        exports={role:create(role)['public_export'] for role in k.ROLES}
        return dict(schema=k.BUNDLE,scope=k.SCOPE,run_id=RUN,exports=exports)
    monkeypatch.setattr(socket,'socket',lambda *a,**kw:pytest.fail('network used'))
    return dict(base=base,state=state,create=create,inspect=inspect,activate=activate,save=save,bundle=bundle,
                original_role=original_role)


def test_initialize_and_pinned_inspect_preserve_key_and_export_only_public(keys):
    report=keys['create']();record=report['public_export'];home=k.parent('ledger')
    key=home/k.SLOT/k.custody.KEY_NAME;before=key.read_bytes();raw=(home/k.RECORD).read_bytes()
    assert len(before)==32 and stat_mode(key)==0o600 and stat_mode(key.parent)==0o700
    assert stat_mode(home/k.RECORD)==0o600 and k.sha(raw)==report['export_sha256']
    checked=keys['inspect']('ledger',report)
    assert checked==dict(report,key_generated=False) and key.read_bytes()==before
    output=k.canonical(report)
    assert before.hex().encode() not in output and base64.b64encode(before) not in output
    assert report['private_key_in_output'] is report['network_used'] is report['execution_permission_issued'] is False
    assert set(key.parent.iterdir())=={key} and set(home.iterdir())=={key.parent,home/k.RECORD}
    assert record['run_id']==RUN


def stat_mode(path):return path.stat().st_mode & 0o777


@pytest.mark.parametrize('role',list(k.ROLES))
def test_each_role_public_key_matches_retained_private_pair(keys,role):
    result=keys['create'](role);assert keys['inspect'](role,result)['public_export']==result['public_export']


@pytest.mark.parametrize('fault',['existing-empty','partial-key','unknown-file','symlink-slot','existing-export'])
def test_any_existing_or_partial_slot_refuses_regeneration(keys,monkeypatch,fault):
    home=k.parent('ledger');slot=home/k.SLOT
    if fault=='existing-export':(home/k.RECORD).write_text('{}')
    elif fault=='symlink-slot':slot.symlink_to(keys['base'],target_is_directory=True)
    else:
        slot.mkdir(mode=0o700)
        if fault=='partial-key':(slot/k.custody.KEY_NAME).write_bytes(b'x')
        elif fault=='unknown-file':(slot/'unknown').write_bytes(b'x')
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('regeneration'))
    with pytest.raises((ValueError,OSError,k.custody.CustodyDenied)):keys['create']()


def test_second_initialize_fails_without_changing_existing_bytes(keys,monkeypatch):
    report=keys['create']();home=k.parent('ledger');before={str(p):p.read_bytes() for p in home.rglob('*') if p.is_file()}
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('regeneration'))
    with pytest.raises((ValueError,OSError)):keys['create']()
    assert {str(p):p.read_bytes() for p in home.rglob('*') if p.is_file()}==before
    assert keys['inspect']('ledger',report)['key_generated'] is False


@pytest.mark.parametrize('ack,run',[(False,RUN),(True,'bad'),(True,k.preparation.MANUAL_RUN),(1,RUN)])
def test_explicit_new_synthetic_key_request_required_before_creation(keys,ack,run):
    with pytest.raises(ValueError):k.initialize('ledger',run,ack)
    assert list(k.parent('ledger').iterdir())==[]


@pytest.mark.parametrize('uid,gid,groups',[(0,0,[]),(109,110,[110]),(61109,0,[]),
    (61109,61109,[61109,999]),(61105,61105,[61105])])
def test_wrong_uid_gid_or_supplementary_group_refused(keys,monkeypatch,uid,gid,groups):
    monkeypatch.setattr(os,'geteuid',lambda:uid);monkeypatch.setattr(os,'getegid',lambda:gid)
    monkeypatch.setattr(os,'getgroups',lambda:groups)
    with pytest.raises(ValueError):keys['original_role']('ledger')


def test_exact_role_identity_accepts_only_its_fixed_uid(keys,monkeypatch):
    monkeypatch.setattr(os,'geteuid',lambda:61109);monkeypatch.setattr(os,'getegid',lambda:61109)
    monkeypatch.setattr(os,'getgroups',lambda:[])
    assert keys['original_role']('ledger')==61109


@pytest.mark.parametrize('which',['public','export','missing-public','missing-export','run'])
def test_inspect_requires_independent_pins_and_run(keys,which):
    report=keys['create']();r=report['public_export'];public=r['public_key_sha256'];export=report['export_sha256'];run=RUN
    if which=='public':public='0'*64
    elif which=='export':export='0'*64
    elif which=='missing-public':public=None
    elif which=='missing-export':export=None
    elif which=='run':run='f'*64
    with pytest.raises(ValueError):k.inspect('ledger',run,public,export)


@pytest.mark.parametrize('fault',['missing-key','short-key','hardlink-key','symlink-key','key-mode','slot-mode',
    'extra-key-file','replaced-key','same-bytes-new-inode','missing-export','modified-export','export-mode','symlink-export'])
def test_inspect_refuses_changed_or_incomplete_storage_without_repair(keys,monkeypatch,fault):
    report=keys['create']();home=k.parent('ledger');slot=home/k.SLOT;key=slot/k.custody.KEY_NAME;file=home/k.RECORD
    if fault=='missing-key':key.unlink()
    elif fault=='short-key':key.write_bytes(b'x')
    elif fault=='hardlink-key':os.link(key,home/'other')
    elif fault=='symlink-key':key.rename(home/'other');key.symlink_to(home/'other')
    elif fault=='key-mode':key.chmod(0o644)
    elif fault=='slot-mode':slot.chmod(0o755)
    elif fault=='extra-key-file':(slot/'extra').write_bytes(b'x')
    elif fault=='replaced-key':key.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    elif fault=='same-bytes-new-inode':
        raw=key.read_bytes();key.rename(home/'retained-old');key.write_bytes(raw);key.chmod(0o600)
    elif fault=='missing-export':file.unlink()
    elif fault=='modified-export':file.write_bytes(b'{}')
    elif fault=='export-mode':file.chmod(0o644)
    elif fault=='symlink-export':file.rename(home/'other');file.symlink_to(home/'other')
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('repair'))
    with pytest.raises((ValueError,OSError,k.custody.CustodyDenied)):keys['inspect']('ledger',report)


@pytest.mark.parametrize('number',[1,2,3,4,5])
def test_fsync_failure_burns_slot_and_never_retries(keys,monkeypatch,number):
    original=os.fsync;calls=[]
    def fail(fd):
        calls.append(fd)
        if len(calls)==number:raise OSError('PRIVATE_DETAIL_NOT_FOR_STDERR')
        return original(fd)
    monkeypatch.setattr(os,'fsync',fail)
    with pytest.raises(OSError):keys['create']()
    assert (k.parent('ledger')/k.SLOT).is_dir()
    monkeypatch.setattr(os,'fsync',original)
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('retry generated key'))
    with pytest.raises((ValueError,OSError)):keys['create']()


def test_parent_intent_is_fsynced_before_generating_private_key(keys,monkeypatch):
    events=[];sync=os.fsync;generate=Ed25519PrivateKey.generate
    monkeypatch.setattr(os,'fsync',lambda fd:(events.append('fsync'),sync(fd))[1])
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:(events.append('generate'),generate())[1])
    keys['create']();assert events[0:2]==['fsync','generate'] and events.count('generate')==1


def test_concurrent_initialization_has_one_winner(keys):
    keys['activate']('ledger')
    def attempt(_):
        try:return k.initialize('ledger',RUN,True)
        except (ValueError,OSError,k.custody.CustodyDenied):return None
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
    winners=[r for r in results if r is not None];assert len(winners)==1
    assert keys['inspect']('ledger',winners[0])['key_generated'] is False


def test_abrupt_exit_after_key_retention_leaves_no_automatic_public_export(keys,monkeypatch):
    original=k.custody.initialize
    child=os.fork()
    if child==0:
        def abrupt(path):original(path);os._exit(77)
        k.custody.initialize=abrupt
        keys['create']();os._exit(99)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==77
    home=k.parent('ledger');assert (home/k.SLOT/k.custody.KEY_NAME).is_file() and not (home/k.RECORD).exists()
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('restart regenerated'))
    with pytest.raises((ValueError,OSError)):keys['create']()
    with pytest.raises(OSError):k.inspect('ledger',RUN,'0'*64,'1'*64)


def test_public_bundle_contains_four_distinct_keys_and_never_opens_private_storage(keys,monkeypatch):
    bundle=keys['bundle']();path,expected=keys['save'](bundle)
    monkeypatch.setattr(k,'checked_storage',lambda *a:pytest.fail('private storage opened'))
    monkeypatch.setattr(Ed25519PrivateKey,'generate',lambda:pytest.fail('key generation'))
    b,exports=k.read_bundle(path,expected);result=k.public_report(b,exports,expected)
    assert set(result['public_keys'])=={'issuer_public_hex','service_public_hex','custody_public_hex','runtime_public_hex'}
    assert result['private_key_loaded'] is result['network_used'] is result['execution_permission_issued'] is False
    assert result['operator_origin_independently_verified'] is result['key_possession_independently_verified'] is False
    assert result['existing_genesis_compatibility_verified'] is False


@pytest.mark.parametrize('fault',['missing-role','extra-role','wrong-schema','scope','run','role','uid','bool-uid',
    'algorithm','public-pin','private-field','same-key','storage-alias','storage-bool','storage-mode'])
def test_public_bundle_tampering_and_role_confusion_refused(keys,fault):
    b=keys['bundle']();r=b['exports']['issuer']
    if fault=='missing-role':del b['exports']['custody']
    elif fault=='extra-role':b['exports']['other']=r
    elif fault=='wrong-schema':b['schema']=k.preparation.readiness.APPROVAL
    elif fault=='scope':b['scope']='LIVE'
    elif fault=='run':r['run_id']='f'*64
    elif fault=='role':r['role']='custody'
    elif fault=='uid':r['uid']=999
    elif fault=='bool-uid':r['uid']=True
    elif fault=='algorithm':r['algorithm']='RSA'
    elif fault=='public-pin':r['public_key_sha256']='0'*64
    elif fault=='private-field':r['private_key']='DO_NOT_PRINT'
    elif fault=='same-key':
        for field in ('public_key_hex','public_key_sha256'):r[field]=b['exports']['custody'][field]
    elif fault=='storage-alias':r['key_file']=b['exports']['custody']['key_file'] | {'uid':k.ROLES['issuer']}
    elif fault=='storage-bool':r['key_file']['inode']=True
    elif fault=='storage-mode':r['key_file']['mode']=0o644
    with pytest.raises(ValueError):k.validate_bundle(b)


def joined_public(f,b):
    value=copy.deepcopy(f['public']);e=b['exports']
    value['issuer_public_hex']=e['issuer']['public_key_hex'];value['service_public_hex']=e['ledger']['public_key_hex']
    m=value['native_manifest'];m['custody_public']=e['custody']['public_key_hex'];m['runtime_public']=e['runtime']['public_key_hex']
    m['execution']['run_id']=b['run_id'];return value


def test_all_exported_keys_join_exact_native_public_input_before_candidate(keys,public_prepared):
    b=keys['bundle']();bp,bh=keys['save'](b);value=joined_public(public_prepared,b)
    path,expected=keys['save'](value,'input.json');result=k.match_input(path,expected,bp,bh)
    assert result['public_input_keys_match'] is True and result['public_input_sha256']==expected
    assert result['approval_created'] is result['execution_permission_issued'] is False
    c=k.preparation.run('candidate',path,expected)
    assert c['approval_candidate']['issuer_public_hex']==b['exports']['issuer']['public_key_hex']


@pytest.mark.parametrize('field',['issuer','ledger','custody','runtime','run'])
def test_candidate_key_or_run_substitution_refused(keys,public_prepared,field):
    b=keys['bundle']();bp,bh=keys['save'](b);value=joined_public(public_prepared,b)
    other=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    if field=='issuer':value['issuer_public_hex']=other
    elif field=='ledger':value['service_public_hex']=other
    elif field=='custody':value['native_manifest']['custody_public']=other
    elif field=='runtime':value['native_manifest']['runtime_public']=other
    elif field=='run':value['native_manifest']['execution']['run_id']='f'*64
    path,expected=keys['save'](value,'input.json')
    with pytest.raises(ValueError):k.match_input(path,expected,bp,bh)


def test_withdrawn_bundle_is_not_retried(keys,monkeypatch):
    b=keys['bundle']();path,expected=keys['save'](b);original=k.validate_bundle;calls=[]
    def withdraw(value):
        calls.append(1);result=original(value);Path(path).unlink();return result
    monkeypatch.setattr(k,'validate_bundle',withdraw)
    with pytest.raises(OSError):k.read_bundle(path,expected)
    assert calls==[1]


def test_cli_errors_are_constant_and_do_not_emit_key_or_path(keys,monkeypatch,capsys):
    def fail(*a,**kw):raise OSError('DO_NOT_PRINT_PRIVATE_PATH_OR_KEY')
    monkeypatch.setattr(k.custody,'initialize',fail)
    assert k.main(['initialize','--role','ledger','--run-id',RUN,'--acknowledge-create-synthetic-key'])==1
    c=capsys.readouterr();assert c.out=='' and c.err.strip()==k.STOP


def test_cli_public_inspection_reports_only_public_data(keys,capsys):
    r=keys['create']();e=r['public_export']
    assert k.main(['inspect','--role','ledger','--run-id',RUN,'--expected-public-sha256',e['public_key_sha256'],
                   '--expected-export-sha256',r['export_sha256']])==0
    c=capsys.readouterr();assert json.loads(c.out)['public_export']==e and c.err==''


def test_actual_four_uid_keys_are_retained_and_twelve_cross_role_key_reads_are_denied(tmp_path):
    caps=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    if os.geteuid()!=0 or not all(caps&(1<<bit) for bit in (0,6,7)):
        pytest.skip('requires disposable root-capable CI with chown/setuid/setgid')
    with tempfile.TemporaryDirectory(prefix='task4-native-role-key-uid-') as temp:
        base=Path(temp);base.chmod(0o755);source=base/'source';source.mkdir(mode=0o755)
        root=Path(k.__file__).resolve().parents[1]
        for name in ('scripts','fixtures','docs'):
            shutil.copytree(root/name,source/name,ignore=shutil.ignore_patterns('__pycache__'))
        for p in source.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o444)
        state=base/'state';state.mkdir(mode=0o755)
        for role,uid in k.ROLES.items():
            home=state/('veritas-native-'+role);home.mkdir(mode=0o700);os.chown(home,uid,uid)
        bootstrap=('import importlib.machinery,importlib.util,sys;from pathlib import Path;'
            's=importlib.machinery.PathFinder.find_spec("scripts",['+repr(str(source))+']);'
            'sys.modules["scripts"]=importlib.util.module_from_spec(s);'
            'from scripts import task4_native_role_keys_v1 as k;k.BASE=Path('+repr(str(state))+');')
        def child(uid,code,args=()):
            return subprocess.run(['setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups','--no-new-privs',
                '--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',bootstrap+code,*args],
                cwd='/tmp',env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8'},capture_output=True,text=True,timeout=30)
        exports={};denied=0
        for role,uid in k.ROLES.items():
            args=['initialize','--role',role,'--run-id',RUN,'--acknowledge-create-synthetic-key']
            initialized=child(uid,'raise SystemExit(k.main())',args)
            assert initialized.returncode==0,initialized.stderr
            report=json.loads(initialized.stdout);exports[role]=report['public_export']
            home=state/('veritas-native-'+role);key=home/k.SLOT/k.custody.KEY_NAME
            assert key.stat().st_uid==uid and stat_mode(key)==0o600 and stat_mode(key.parent)==0o700
            again=child(uid,'raise SystemExit(k.main())',args)
            assert again.returncode==1 and again.stdout=='' and again.stderr.strip()==k.STOP
            checked=child(uid,'raise SystemExit(k.main())',['inspect','--role',role,'--run-id',RUN,
                '--expected-public-sha256',exports[role]['public_key_sha256'],'--expected-export-sha256',report['export_sha256']])
            assert checked.returncode==0,checked.stderr
            assert json.loads(checked.stdout)['public_export']==exports[role]
        for role,uid in k.ROLES.items():
            for other in k.ROLES:
                if other==role:continue
                target=state/('veritas-native-'+other)/k.SLOT/k.custody.KEY_NAME
                code='\ntry:\n open('+repr(str(target))+',"rb")\nexcept PermissionError:\n print("DENIED")\nelse:\n raise SystemExit("CROSS_ROLE_READ_ALLOWED")\n'
                refused=child(uid,code)
                assert refused.returncode==0 and refused.stdout.strip()=='DENIED',refused.stderr
                denied+=1
        bundle=dict(schema=k.BUNDLE,scope=k.SCOPE,run_id=RUN,exports=exports)
        assert len(k.validate_bundle(bundle))==4 and denied==12
        # Root cannot select a role and implicitly initialize another role's key.
        root_attempt=subprocess.run([sys.executable,'-I','-B','-c',bootstrap+'raise SystemExit(k.main())',
            'initialize','--role','ledger','--run-id',RUN,'--acknowledge-create-synthetic-key'],
            capture_output=True,text=True,timeout=30)
        assert root_attempt.returncode==1 and root_attempt.stdout=='' and root_attempt.stderr.strip()==k.STOP

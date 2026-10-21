import copy
import os
from pathlib import Path
import sqlite3
import time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_retained_authority_v1 as r


@pytest.fixture
def enrolled(tmp_path,monkeypatch):
    uid=os.geteuid();base=tmp_path/'run';base.mkdir(mode=0o755);base.chmod(0o755)
    for name in ('issuer','custody','public'):(base/name).mkdir(mode=0o755 if name=='public' else 0o700)
    issuer,custody,runtime=[Ed25519PrivateKey.generate() for _ in range(3)];now=int(time.time())
    context=dict(schema=r.b.authority.SCHEMA,run_id='a'*64,raw_recipient_sha256='b'*64,local_leaf_sha256='c'*64,
        not_before=now-5,expires_at=now+295,endpoint=r.b.raw.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    m=r.b.manifest(context,custody.public_key().public_bytes_raw().hex(),runtime.public_key().public_bytes_raw().hex())
    monkeypatch.setattr(r,'DIRECTORY',tmp_path/'deployment');monkeypatch.setattr(r,'ROOT_UID',uid)
    monkeypatch.setattr(r.b,'load',lambda _:copy.deepcopy(m))
    # Unit fixtures use this process's UID; the actual CI enrollment explicitly
    # requires root and the reserved issuer/Custody UIDs.
    policy=r.b.NativePolicy(base/'issuer/policy.sqlite3',m,issuer,create=True)
    for name,key in [('issuer',issuer),('custody',custody)]:
        f=base/name/'signing-key';f.write_bytes(key.private_bytes_raw());f.chmod(0o600)
    file=base/'custody/ledger.sqlite3'
    with sqlite3.connect(file) as db:
        db.execute('CREATE TABLE consumed (op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
        db.execute('CREATE TABLE retained_enrollment (manifest TEXT,run TEXT)')
        db.execute('INSERT INTO retained_enrollment VALUES (?,?)',(r.digest(m),context['run_id']))
    file.chmod(0o600)
    pub=base/'public/issuer-key';pub.write_bytes(issuer.public_key().public_bytes_raw());pub.chmod(0o444)
    storage={}
    for role in ('issuer','custody'):
        folder=base/role;key=folder/'signing-key'
        storage[role]=dict(directory=r.identity(folder,uid,0o700,True),
            database=r.identity(folder/('policy.sqlite3' if role=='issuer' else 'ledger.sqlite3'),uid,0o600),
            key=r.identity(key,uid,0o600),key_sha256=r.sha(key.read_bytes()))
    a=dict(schema=r.SCHEMA,base=str(base),base_identity=r.identity(base,uid,0o755,True),run_id=context['run_id'],
        manifest_sha256=r.digest(m),issuer_public_sha256=r.sha(pub.read_bytes()),enrollment_nonce='d'*64,storage=storage)
    r.DIRECTORY.mkdir(mode=0o755);f=r.DIRECTORY/'enrollment.json';f.write_bytes(r.canonical(a));f.chmod(0o444)
    local=base/r.LOCAL;local.write_bytes(r.canonical(dict(schema=r.SCHEMA,enrollment_sha256=r.digest(a))));local.chmod(0o444)
    return base,policy,issuer,m,a


def test_same_path_and_working_directory_reopen(enrolled,monkeypatch):
    base,policy,key,m,a=enrolled;r.admit(base,'issuer');r.admit(base,'custody')
    g=policy.authorize('A',r.canonical(r.b.seed()))
    monkeypatch.chdir(base/'issuer')
    reopened=r.b.NativePolicy(Path('policy.sqlite3'),m,key)
    assert reopened.snapshot()['attempts'][0]['grant']==g
    with pytest.raises(ValueError,match='PENDING'):reopened.authorize('A',r.canonical(r.b.seed()))


def test_alternate_directory_cannot_initialize(enrolled,tmp_path):
    base,policy,key,m,a=enrolled;folder=tmp_path/'alternate/issuer';folder.mkdir(parents=True)
    target=folder/'policy.sqlite3'
    with pytest.raises(ValueError,match='ENROLLED_BASE_ONLY'):r.b.NativePolicy(target,m,key,create=True)
    assert not target.exists()


def test_enrolled_file_cannot_be_reinitialized(enrolled):
    base,policy,key,m,a=enrolled
    with pytest.raises(ValueError,match='MUST_REOPEN_NO_CREATE'):r.b.NativePolicy(policy.file,m,key,create=True)


@pytest.mark.parametrize('role',['issuer','custody'])
@pytest.mark.parametrize('fault',['missing','replacement','symlink','mode','key','key-mode','folder-mode'])
def test_role_storage_identity_and_key_required(enrolled,role,fault):
    base,policy,key,m,a=enrolled;file=Path(a['storage'][role]['database']['path']);folder=file.parent
    if fault=='missing':file.unlink()
    elif fault=='replacement':
        data=file.read_bytes();file.rename(file.with_suffix('.saved'));file.write_bytes(data);file.chmod(0o600)
    elif fault=='symlink':file.rename(file.with_suffix('.saved'));file.symlink_to(file.with_suffix('.saved'))
    elif fault=='mode':file.chmod(0o644)
    elif fault=='key':(folder/'signing-key').write_bytes(b'\0'*32)
    elif fault=='key-mode':(folder/'signing-key').chmod(0o644)
    else:folder.chmod(0o755)
    with pytest.raises((ValueError,OSError)):r.admit(base,role)


@pytest.mark.parametrize('role',['issuer','custody'])
def test_in_place_database_corruption_not_recreated(enrolled,role):
    base,policy,key,m,a=enrolled;file=Path(a['storage'][role]['database']['path']);before=file.stat().st_ino;file.write_bytes(b'broken')
    with pytest.raises((ValueError,sqlite3.Error)):
        if role=='issuer':r.b.NativePolicy(file,m,key)
        else:r.open_custody(base)
    assert file.read_bytes()==b'broken' and file.stat().st_ino==before


@pytest.mark.parametrize('fault',['anchor-missing','anchor-corrupt','anchor-symlink','anchor-mode','directory-mode','local-missing','local-corrupt','public-key'])
def test_missing_or_changed_enrollment_never_falls_back(enrolled,fault):
    base,policy,key,m,a=enrolled;file=r.DIRECTORY/'enrollment.json'
    if fault=='anchor-missing':file.unlink()
    elif fault=='anchor-corrupt':file.chmod(0o600);file.write_bytes(b'bad');file.chmod(0o444)
    elif fault=='anchor-symlink':file.rename(r.DIRECTORY/'saved');file.symlink_to(r.DIRECTORY/'saved')
    elif fault=='anchor-mode':file.chmod(0o644)
    elif fault=='directory-mode':r.DIRECTORY.chmod(0o777)
    elif fault=='local-missing':(base/r.LOCAL).unlink()
    elif fault=='local-corrupt':
        f=base/r.LOCAL;f.chmod(0o600);f.write_bytes(b'{}');f.chmod(0o444)
    else:
        f=base/'public/issuer-key';f.chmod(0o600);f.write_bytes(b'\0'*32);f.chmod(0o444)
    assert r.required(base)
    with pytest.raises((ValueError,OSError,KeyError)):r.b.NativePolicy(policy.file,m,key)


def test_missing_fixed_directory_with_local_marker_denied(enrolled):
    base,policy,key,m,a=enrolled;(r.DIRECTORY/'enrollment.json').unlink();r.DIRECTORY.rmdir()
    assert r.required(base)
    with pytest.raises(FileNotFoundError):r.b.NativePolicy(policy.file,m,key)


def test_custody_enrollment_row_is_required(enrolled):
    base,_,_,_,_=enrolled
    with r.open_custody(base) as db:db.execute("UPDATE retained_enrollment SET run='different'")
    with pytest.raises(ValueError,match='CUSTODY_ENROLLMENT'):r.open_custody(base)


def test_issuer_public_key_cannot_change(enrolled):
    base,policy,_,m,_=enrolled
    with pytest.raises(ValueError,match='REGISTERED_ISSUER_STORAGE'):r.b.NativePolicy(policy.file,m,Ed25519PrivateKey.generate())


def test_live_policy_operations_revalidate_anchor(enrolled):
    base,policy,_,_,_=enrolled;(r.DIRECTORY/'enrollment.json').unlink()
    with pytest.raises(OSError):policy.authorize('A',r.canonical(r.b.seed()))


def test_existing_custody_file_reopens_without_reset(enrolled):
    base,_,_,_,_=enrolled
    with r.open_custody(base) as db:db.execute("INSERT INTO consumed VALUES ('A0','CONSUMED_UNKNOWN','hash',NULL,NULL,NULL,NULL)")
    with r.open_custody(base) as db:assert db.execute('SELECT op,state FROM consumed').fetchall()==[('A0','CONSUMED_UNKNOWN')]


def test_alternate_probe_does_not_reenter_inaccessible_inherited_cwd(enrolled,tmp_path,monkeypatch):
    base,policy,_,_,_=enrolled
    monkeypatch.setattr(r.b.kernel,'ISSUER',os.geteuid())
    monkeypatch.setattr(r.b.kernel,'role_identity',lambda _:None)
    inherited=tmp_path/'inherited';inherited.mkdir();monkeypatch.chdir(inherited);inherited.chmod(0)
    try:
        result=r.alternate(base)
        assert result==dict(alternate_directory_denied=True,new_database_created=False,changed_cwd_same_state=True)
        assert Path.cwd()==base/'public' and not (base/'issuer/alternate/issuer/policy.sqlite3').exists()
    finally:inherited.chmod(0o700)

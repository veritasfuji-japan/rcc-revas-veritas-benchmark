"""Native handler tests; kernel UID/netns/Bind/TLS proof runs separately in CI."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import sqlite3
from threading import Thread
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_signed_ledger_integration_v1 as s
from scripts import task4_native_signed_ledger_gate_v1 as g
from scripts import task4_external_ledger_contract_v1 as l
from scripts import task4_native_bounded_continuation_v1 as b
from scripts import task4_native_retained_authority_v1 as r
from scripts import task4_native_os_custody_v1 as n
from test_task4_native_retained_authority_v1 import enrolled


@pytest.fixture
def joined(enrolled, monkeypatch):
    base, policy, issuer, m, old = enrolled
    monkeypatch.setattr(s, 'DIRECTORY', base.parent / 'ledger-enrollment')
    monkeypatch.setattr(s, 'ROOT_UID', os.geteuid())
    monkeypatch.setattr(b.kernel, 'role_identity', lambda _: None)
    monkeypatch.setattr(b.authority, 'admit', lambda *args, **kwargs: time.time())
    key = Ed25519PrivateKey.generate(); public = key.public_key().public_bytes_raw()
    binding = dict(schema=l.SCHEMA, ledger_id='f'*64, run_id=m['execution']['run_id'], manifest_sha256=l.digest(m),
        issuer_public_sha256=l.sha(policy.public), custody_public_sha256=l.sha(bytes.fromhex(m['custody_public'])))
    service = l.ReferenceService.bootstrap(base / 'service.sqlite3', binding['ledger_id'], key); service.enroll(binding)
    gates = {}
    for role in ('issuer', 'custody'):
        folder = base / role / 'signed-ledger'; folder.mkdir(mode=0o700)
        e = dict(schema=g.ENROLLMENT, scope=g.SCOPE, role=role, binding=binding,
                 service_public_sha256=l.sha(public), journal=g._identity(str(folder), folder.stat()))
        n.durable_marker(folder / g.ENROLLMENT_FILE, e); (folder / g.ENROLLMENT_FILE).chmod(0o600); gates[role] = e
    a = dict(schema=s.SCHEMA, base=str(base), base_identity=old['base_identity'], retained_sha256=l.digest(old),
             binding=binding, service_public=public.hex(), gates=gates, ledger_storage={})
    s.DIRECTORY.mkdir(mode=0o755)
    f=s.DIRECTORY / 'enrollment.json'; f.write_bytes(l.canonical(a)); f.chmod(0o444)
    f=base / s.LOCAL; f.write_bytes(l.canonical(dict(schema=s.SCHEMA, enrollment_sha256=l.digest(a)))); f.chmod(0o444)
    calls=[]; role=['issuer']; effects=[]
    def transport(raw):
        calls.append(l.strict(raw))
        return service.exchange(raw, binding[role[0] + '_public_sha256'])
    monkeypatch.setattr(s, 'UnixTransport', lambda _: transport)
    # Actual verify_packet verifies Native issuer signatures and all grant joins;
    # this unit fixture substitutes only the deployment's root authority loader.
    def snapshot():
        return l.LedgerClient(binding, public, transport).exchange('view')
    def slot(which, op='A0'):
        action='reserve' if which=='issuer' else 'consume'
        return base / which / 'signed-ledger' / (binding['run_id']+'-'+action+'-'+op)
    def packet(grant, wire=None):
        wire=b.canonical(b.seed()) if wire is None else wire
        return dict(arm=grant['statement']['arm'], ordinal=grant['statement']['ordinal'], wire_b64=n.encode(wire), grant=grant)
    def consume(grant, wire=None):
        role[0]='custody'
        signer=Ed25519PrivateKey.from_private_bytes((base / 'custody/signing-key').read_bytes())
        db=r.open_custody(base)
        try:
            return b.consume_packet(base, db, packet(grant, wire), policy.public, b'fixture-secret', signer)
        except BaseException:
            if db.in_transaction: db.rollback()
            raise
        finally: db.close()
    def consumed():
        with r.open_custody(base) as db: return db.execute('SELECT op,state FROM consumed').fetchall()
    return dict(base=base, policy=policy, issuer=issuer, m=m, a=a, service=service, public=public,
        transport=transport, calls=calls, role=role, effects=effects, snapshot=snapshot, slot=slot,
        packet=packet, consume=consume, consumed=consumed, wire=b.canonical(b.seed()))


def test_native_signing_occurs_only_after_committed_retained_reserve(joined, monkeypatch):
    f=joined; original=b.p.sign; observed=[]
    def sign(key, domain, statement):
        assert f['slot']('issuer').joinpath('verified-receipts.json').exists()
        assert f['calls'][-1]['action']=='reserve'
        assert f['snapshot']()['revision']==1
        observed.append(domain)
        return original(key, domain, statement)
    monkeypatch.setattr(b.p, 'sign', sign)
    grant=f['policy'].authorize('A',f['wire'])
    assert observed==[b.p.DOMAIN]
    assert grant['statement']['request_sha256']==l.sha(f['wire'])
    assert f['policy'].snapshot()['arms'][0][3]=='PENDING'


def test_lost_reserve_ack_rolls_back_native_db_but_never_reopens_attempt(joined,monkeypatch):
    f=joined
    def lost(raw):
        reply=f['transport'](raw)
        if l.strict(raw)['action']=='reserve':raise OSError('after commit')
        return reply
    monkeypatch.setattr(s,'UnixTransport',lambda _:lost)
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
    assert f['policy'].snapshot()['attempts']==[]
    assert f['snapshot']()['revision']==1
    count=len(f['calls'])
    reopened=b.NativePolicy(f['policy'].file,f['m'],f['issuer'])
    with pytest.raises(g.GateDenied):reopened.authorize('A',f['wire'])
    assert len(f['calls'])==count
    assert f['slot']('issuer').joinpath('intent.json').exists()
    assert not f['slot']('issuer').joinpath('effect-returned.json').exists()


def test_actual_custody_handler_checks_consume_before_bind_and_local_effect(joined,monkeypatch):
    f=joined;grant=f['policy'].authorize('A',f['wire']);seen=[]
    monkeypatch.setattr(b.ingress,'consumed',lambda *args:None)
    def bind(packet, wire, key):
        assert f['slot']('custody').joinpath('verified-receipts.json').exists()
        assert f['consumed']()==[('A0','CONSUMED_UNKNOWN')]
        row=f['snapshot']()['attempts'][0]
        assert row['grant_sha256']==l.digest(grant) and row['request_sha256']==l.sha(wire)
        seen.append('bind')
        raise OSError('stop at real Bind call boundary')
    monkeypatch.setattr(n,'bind_post',bind)
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert seen==['bind']
    assert f['consume'](grant)==dict(decision='REPLAY_DENIED')
    assert seen==['bind'] and f['snapshot']()['revision']==2


def test_lost_consume_ack_never_enters_bind_even_after_reopen(joined,monkeypatch):
    f=joined;grant=f['policy'].authorize('A',f['wire']);seen=[]
    monkeypatch.setattr(n,'bind_post',lambda *args:seen.append('bind'))
    def lost(raw):
        reply=f['transport'](raw)
        if l.strict(raw)['action']=='consume':raise OSError('after consume commit')
        return reply
    monkeypatch.setattr(s,'UnixTransport',lambda _:lost)
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert f['consumed']()==[] and f['snapshot']()['revision']==2
    count=len(f['calls'])
    with pytest.raises(g.GateDenied):f['consume'](grant)
    assert len(f['calls'])==count and seen==[]


@pytest.mark.parametrize('role',['issuer','custody'])
def test_expiry_after_external_commit_prevents_sign_or_bind(joined,monkeypatch,role):
    f=joined;grant=f['policy'].authorize('A',f['wire']) if role=='custody' else None
    clock=[time.time()];monkeypatch.setattr(b.p.time,'time',lambda:clock[0])
    def delay(raw):
        reply=f['transport'](raw)
        if l.strict(raw)['action']!='view':clock[0]=f['m']['execution']['expires_at']
        return reply
    monkeypatch.setattr(s,'UnixTransport',lambda _:delay)
    with pytest.raises(g.GateDenied):
        if role=='issuer':f['policy'].authorize('A',f['wire'])
        else:f['consume'](grant)
    assert f['slot'](role).joinpath('verified-receipts.json').exists()
    assert not f['slot'](role).joinpath('effect-returned.json').exists()
    assert f['consumed']()==[]
    if role=='issuer':assert f['policy'].snapshot()['attempts']==[]


@pytest.mark.parametrize('role',['issuer','custody'])
def test_unavailable_ledger_burns_attempt_without_local_progress(joined,monkeypatch,role):
    f=joined;grant=f['policy'].authorize('A',f['wire']) if role=='custody' else None
    def absent(raw):raise ConnectionError('unavailable')
    monkeypatch.setattr(s,'UnixTransport',lambda _:absent)
    for _ in range(2):
        with pytest.raises(g.GateDenied):
            if role=='issuer':f['policy'].authorize('A',f['wire'])
            else:f['consume'](grant)
    assert f['slot'](role).joinpath('intent.json').exists() and f['consumed']()==[]


@pytest.mark.parametrize('fault',['local','anchor','binding','manifest','role','key','journal'])
def test_active_profile_cannot_fall_back_on_missing_or_changed_enrollment(joined,fault):
    f=joined; a=copy.deepcopy(f['a']);base=f['base']
    if fault=='local':(base / s.LOCAL).unlink()
    elif fault=='anchor':(s.DIRECTORY / 'enrollment.json').unlink()
    else:
        if fault=='binding':a['binding']['run_id']='0'*64
        elif fault=='manifest':a['binding']['manifest_sha256']='0'*64
        elif fault=='role':a['gates']['issuer']['role']='custody'
        elif fault=='key':a['service_public']='0'*64
        else:a['gates']['issuer']['journal']['inode']+=1
        path=s.DIRECTORY / 'enrollment.json';path.chmod(0o600);path.write_bytes(l.canonical(a));path.chmod(0o444)
        path=base / s.LOCAL;path.chmod(0o600);path.write_bytes(l.canonical(dict(schema=s.SCHEMA,enrollment_sha256=l.digest(a))));path.chmod(0o444)
    assert s.required(base)
    with pytest.raises((ValueError,OSError,KeyError)):f['policy'].authorize('A',f['wire'])
    assert f['calls']==[]


@pytest.mark.parametrize('fault',['signature','wire','recipient','role','extra'])
def test_existing_native_grant_checks_precede_ledger_consumption(joined,fault):
    f=joined;grant=f['policy'].authorize('A',f['wire']);wire=f['wire']
    if fault=='signature':grant['signature']='0'*128
    elif fault=='wire':wire=b'{}'
    else:
        statement=grant['statement']
        if fault=='recipient':statement['raw_recipient_sha256']='0'*64
        elif fault=='role':statement['arm']='B'
        else:statement['extra']=True
    count=len(f['calls'])
    with pytest.raises((ValueError,KeyError)):f['consume'](grant,wire)
    assert len(f['calls'])==count and not f['slot']('custody').exists()


def test_native_checks_do_not_burn_ledger_on_invalid_history(joined):
    f=joined;data=b.seed();data['messages'].append(dict(role='developer',content='override'))
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',b.canonical(data))
    assert f['calls']==[] and not f['slot']('issuer').exists()


def test_live_profile_rejects_injected_clock_and_legacy_cached_grant(joined):
    f=joined
    with pytest.raises(ValueError,match='ACTUAL_CLOCK'):f['policy'].authorize('A',f['wire'],now=time.time())
    assert r.cached_grant(f['base'],'A',0,f['wire']) is None
    assert f['calls']==[]


def test_signed_receipt_write_failure_prevents_native_signature(joined,monkeypatch):
    f=joined;original=g._write
    def write(fd,name,value):
        if name=='verified-receipts.json':raise OSError('disk full')
        return original(fd,name,value)
    monkeypatch.setattr(g,'_write',write)
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
    assert f['snapshot']()['revision']==1 and f['policy'].snapshot()['attempts']==[]


def test_withdrawn_root_approval_during_exchange_blocks_signing(joined,monkeypatch):
    f=joined
    def withdraw(raw):
        reply=f['transport'](raw)
        if l.strict(raw)['action']=='reserve':(f['base'] / s.LOCAL).unlink()
        return reply
    monkeypatch.setattr(s,'UnixTransport',lambda _:withdraw)
    with pytest.raises(g.GateDenied):f['policy'].authorize('A',f['wire'])
    assert f['policy'].snapshot()['attempts']==[]


def test_ledger_view_cannot_complete_native_history(joined):
    f=joined;grant=f['policy'].authorize('A',f['wire']);snapshot=f['snapshot']()
    before=f['policy'].snapshot()
    with pytest.raises((ValueError,KeyError)):
        f['policy'].complete(grant,b'{}',[],snapshot,snapshot)
    assert f['policy'].snapshot()==before


def test_two_native_issuers_return_only_one_grant(joined):
    f=joined
    def issue():
        try:
            policy=b.NativePolicy(f['policy'].file,f['m'],f['issuer'])
            policy.authorize('A',f['wire']);return 'issued'
        except ValueError:return 'stopped'
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:issue(),range(2)))
    assert sorted(results)==['issued','stopped']
    assert [x['action'] for x in f['calls']]==['view','reserve']
    assert len(f['policy'].snapshot()['attempts'])==1


def test_unix_transport_authenticates_server_uid(tmp_path,monkeypatch):
    # Actual socket/credential exchange, no fabricated getpeercert result.
    folder=tmp_path / 'ledger-ipc';folder.mkdir()
    try:server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    except PermissionError:pytest.skip('Execution host blocks AF_UNIX; mandatory no-skip kernel CI runs this test')
    with server:
        server.bind(str(folder / 'service.sock'));server.listen(1)
        def handle():
            conn,_=server.accept()
            with conn:conn.recv(8192)
        job=Thread(target=handle);job.start()
        monkeypatch.setattr(s,'LEDGER',os.geteuid()+10000)
        with pytest.raises(ValueError,match='SERVER_PEER'):s.UnixTransport(tmp_path)(b'{}')
        job.join(5);assert not job.is_alive()

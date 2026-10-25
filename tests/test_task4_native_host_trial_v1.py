"""Portable denial boundaries plus disposable CI initial-host systemd trials."""
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

import pytest
from scripts import task4_native_host_trial_v1 as h


def cfg():
    return dict(schema=h.PROFILE, token='a'*32, namespace=dict(device=4,inode=10),
        boot_id='12345678-1234-1234-1234-123456789abc', deadline_ns=100,
        sources=h.pins(), foreign_sha256='b'*64,
        service=dict(pid=123,start_ticks=1,uid=109,port=12345,listening_inode=55,
                     tcp_connect=True,signed_application_receipt_verified=False),
        inventory=dict(accounts=h.e.DENIED,target_processes_or_threads=0,
                       target_ip_sockets={str(uid):0 for uid in h.e.DENIED.values()}))


def document():
    rows=[dict(table=dict(family='inet',name=h.TABLE,handle=1,comment=h.marker('a'*32))),
          dict(chain=dict(family='inet',table=h.TABLE,name='output',handle=2,type='filter',
                          hook='output',prio=0,policy='accept'))]
    for i,(role,uid) in enumerate(h.e.DENIED.items()):
        rows.append(dict(rule=dict(family='inet',table=h.TABLE,chain='output',handle=3+i,comment=role,
            expr=[{'match':{'op':'==','left':{'meta':{'key':'skuid'}},'right':uid}},
                  {'counter':{'packets':0,'bytes':0}}, {'reject':{'type':'icmpx','expr':3}}])))
    return {'nftables':rows}


def test_explicit_host_plan_does_not_issue_native_or_provider_permission():
    result=h.plan()
    assert result['host_apply_supported'] is True and result['lease_seconds']==15
    assert result['target_roles_must_be_idle'] is True
    assert result['limitations']['provider_requests']==0
    assert result['limitations']['execution_permission_issued'] is False
    assert h.TABLE not in (h.e.TABLE,h.w.TABLE,'veritas_native_host_egress_v1')
    assert h.m.source_sha256()==h.M_PIN


def test_no_ack_stops_before_any_preflight(monkeypatch):
    monkeypatch.setattr(h,'preflight',lambda *a:pytest.fail('preflight before acknowledgement'))
    with pytest.raises(ValueError):h.trial(123,456)


@pytest.mark.parametrize('field',['schema','token','namespace','boot_id','deadline_ns','sources','foreign_sha256',
                                  'service','inventory','extra'])
def test_bad_request_stops_before_registration(field):
    row=cfg()
    if field=='extra':row['host_bypass']=True
    elif field=='namespace':row[field]['inode']=True
    elif field=='sources':row[field][h.MODULES[0]]='0'*64
    elif field=='service':row[field]['uid']=0
    elif field=='inventory':row[field]['target_processes_or_threads']=1
    else:row[field]=False
    with pytest.raises((ValueError,TypeError,KeyError)):h.validate_request(row)


@pytest.mark.parametrize('remaining',[0,-1,h.LEASE_NS+1])
def test_expired_or_extended_lease_cannot_install(monkeypatch,remaining):
    row=cfg();row['deadline_ns']=100+remaining
    monkeypatch.setattr(h.time,'monotonic_ns',lambda:100)
    with pytest.raises(ValueError):h.lease_current(row)


def test_worker_command_pins_pid1_namespace_and_has_no_controller_kill_or_scope():
    row=cfg();argv=h.command({'systemd-run':'/usr/bin/systemd-run','python3':'/usr/bin/python3'},
                            '/run/private/source','/run/private/request.json',row)
    assert '--property=NetworkNamespacePath=/proc/1/ns/net' in argv
    assert '--property=NoNewPrivileges=yes' in argv and '--property=TimeoutStartSec=45s' in argv
    assert '--no-block' in argv
    assert '--scope' not in argv and '--user' not in argv and '--wait' not in argv
    assert not any('RuntimeMaxSec=' in x for x in argv) # Never kill the inverse at the lease boundary.
    compile(argv[argv.index('-c')+1],'<protected-worker>','exec')


@pytest.mark.parametrize('change',['nonce','extra_rule','changed_uid','accept','extra_table_field','handle_bool'])
def test_foreign_or_altered_table_refused_without_deletion(change):
    doc=document()
    if change=='nonce':doc['nftables'][0]['table']['comment']=h.marker('b'*32)
    elif change=='extra_rule':doc['nftables'].append(copy.deepcopy(doc['nftables'][-1]))
    elif change=='changed_uid':doc['nftables'][2]['rule']['expr'][0]['match']['right']=0
    elif change=='accept':doc['nftables'][2]['rule']['expr'][2]={'accept':None}
    elif change=='extra_table_field':doc['nftables'][0]['table']['flags']=['owner']
    else:doc['nftables'][0]['table']['handle']=True
    with pytest.raises(ValueError):h.shape(doc,'a'*32)


def test_counter_growth_does_not_change_ownership_but_handle_replacement_does():
    doc=document();first=h.shape(doc,'a'*32)
    doc['nftables'][2]['rule']['expr'][1]['counter']['packets']=12
    assert h.shape(doc,'a'*32)==first
    doc['nftables'][2]['rule']['handle']=99
    assert h.shape(doc,'a'*32)!=first


def test_full_foreign_policy_fingerprint_preserves_handles_rules_and_comments():
    doc=document()
    for item in doc['nftables']:
        for key in ('table','chain','rule'):
            if key in item:
                row=item[key]
                if key=='table':row['name']='unrelated'
                else:row['table']='unrelated'
    first=h.foreign_fingerprint(doc)
    doc['nftables'][2]['rule']['expr'][1]['counter']['packets']=5
    assert h.foreign_fingerprint(doc)==first
    doc['nftables'][2]['rule']['expr'][0]['match']['right']=42
    assert h.foreign_fingerprint(doc)!=first


def test_inverse_refuses_changed_handle_after_second_inspection(monkeypatch):
    first=document();second=copy.deepcopy(first);second['nftables'][2]['rule']['handle']=999
    states=iter([first,second]);calls=[]
    monkeypatch.setattr(h,'host_guard',lambda *a:None)
    monkeypatch.setattr(h,'state',lambda *a:next(states))
    monkeypatch.setattr(h,'nft',lambda binaries,args,data=None:calls.append(args))
    with pytest.raises(ValueError):h.inverse({},cfg())
    assert calls==[['--check','--file','-']]


def test_collision_preflight_never_schedules_or_deletes(monkeypatch):
    monkeypatch.setattr(h.e,'namespace',lambda *a:cfg()['namespace'])
    monkeypatch.setattr(h,'boot_id',lambda:cfg()['boot_id'])
    monkeypatch.setattr(h,'host_guard',lambda *a:None)
    monkeypatch.setattr(h.e,'tools',lambda:{})
    monkeypatch.setattr(h,'idle_targets',lambda:cfg()['inventory'])
    monkeypatch.setattr(h,'state',lambda *a:document())
    monkeypatch.setattr(h,'service_control',lambda *a:pytest.fail('service probe after collision'))
    with pytest.raises(ValueError):h.preflight(123,456)


def test_initial_namespace_guard_rejects_isolated_or_changed_boot_before_nft(monkeypatch):
    monkeypatch.setattr(h.e,'require_root',lambda:None)
    monkeypatch.setattr(h.e,'namespace',lambda pid='self':{'device':4,'inode':10 if pid==1 else 20})
    monkeypatch.setattr(h,'boot_id',lambda:cfg()['boot_id'])
    with pytest.raises(ValueError):h.host_guard(cfg()['namespace'],cfg()['boot_id'])


def test_trial_table_exclusion_does_not_hide_same_name_other_family():
    doc=document();doc['nftables'][0]['table']['family']='ip'
    assert h.foreign_fingerprint(doc)!=h.foreign_fingerprint({'nftables':[]})


def capable():
    cap=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    return os.geteuid()==0 and all(cap&(1<<b) for b in (12,21)) and Path('/proc/1/comm').read_text().strip()=='systemd'


@pytest.fixture
def host_fixture():
    if not capable():pytest.skip('disposable root CI initial network namespace + actual PID 1 required')
    folder=Path(tempfile.mkdtemp(prefix='veritas-host-ci-',dir='/run'));(folder/'source').mkdir(mode=0o700)
    for name in h.MODULES:
        module=__import__('scripts.'+name,fromlist=['x'])
        h.m.save(folder/'source'/(name+'.py'),Path(module.__file__).read_bytes())
    # Root-owned protected source is mandatory for the operator path, also in CI.
    boot=h.bootstrap(folder/'source')
    python=h.m.system_tools()['python3'];binary=h.e.tools()
    script="""import json,os,socket,time
s=socket.socket();s.bind(('127.0.0.1',0));s.listen(16);s.settimeout(1)
print(json.dumps(dict(pid=os.getpid(),port=s.getsockname()[1])),flush=True)
end=time.monotonic()+100
while time.monotonic()<end:
 try:
  c,_=s.accept();c.close()
 except TimeoutError:pass
"""
    service=subprocess.Popen([binary['setpriv'],'--reuid=109','--regid=110','--clear-groups',
        '--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',
        python,'-I','-B','-c',script],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=h.ENV)
    control=json.loads(service.stdout.readline())
    before=h.state(binary);need_cleanup=[]
    # Unrelated host canary proves policy-content preservation, not just names.
    canary='veritas_host_ci_'+os.urandom(8).hex()
    h.nft(binary,['--file','-'],f'create table inet {canary} {{ comment "unrelated-ci-policy"; }}\n'.encode())
    fingerprint=h.foreign_fingerprint(h.state(binary))
    try:
        yield dict(folder=folder,boot=boot,python=python,control=control,binary=binary,
                   fingerprint=fingerprint,stages=need_cleanup)
    finally:
        # Never stop a live host worker. CI harness deletes only its unrelated canary
        # and completed audit directories; a refused trial table remains a CI failure.
        assert h.own_document(h.state(binary)) is None
        assert h.foreign_fingerprint(h.state(binary))==fingerprint
        h.nft(binary,['--file','-'],f'delete table inet {canary}\n'.encode())
        assert h.foreign_fingerprint(h.state(binary))==h.foreign_fingerprint(before)
        service.terminate();service.wait(timeout=5)
        for stage in need_cleanup:
            shutil.rmtree(stage)
        shutil.rmtree(folder)


def test_actual_initial_host_trial_denies_five_uids_preserves_controls_and_unrelated_policy(host_fixture,record_property):
    f=host_fixture;c=f['control']
    code=f['boot']+f'\nraise SystemExit(h.main(["trial","--service-pid",{str(c["pid"])!r},"--service-port",{str(c["port"])!r},"--acknowledge-bounded-host-firewall-trial"]))'
    result=subprocess.run([f['python'],'-I','-B','-c',code],capture_output=True,timeout=65,env=h.ENV)
    assert result.returncode==0,result.stderr.decode()
    report=json.loads(result.stdout);h.validate_report(report)
    prefix='HOST_TRIAL_AUDIT_DIRECTORY='
    directories=[x[len(prefix):] for x in result.stderr.decode().splitlines() if x.startswith(prefix)]
    assert len(directories)==1;f['stages'].append(directories[0])
    assert h.foreign_fingerprint(h.state(f['binary']))==f['fingerprint']
    assert len(report['phases']['denied'])==20 and len(report['phases']['exempt_controls'])==12
    record_property('initial_host_trial_json',h.e.canonical(report).decode('ascii'))


def test_actual_systemd_host_worker_survives_sigkill_of_controller(host_fixture,record_property):
    f=host_fixture;c=f['control'];marker=f['folder']/'registered.json'
    code=f['boot']+f'''\nfolder,cfg=h.prepare({c['pid']},{c['port']})
h.schedule(folder,cfg)
identity=m.wait_file(folder/'installed.json',seconds=20)
m.save({str(marker)!r},e.canonical(dict(folder=str(folder),identity=identity)))
time.sleep(40)
'''
    # The bootstrap modules do not bind e/time in the controller's global scope.
    code=code.replace('m.save('+repr(str(marker)), 'h.m.save('+repr(str(marker))).replace('e.canonical(', 'h.e.canonical(')
    code='import time\n'+code
    controller=subprocess.Popen([f['python'],'-I','-B','-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=h.ENV)
    try:
        registered=h.m.wait_file(marker,seconds=20);stage=Path(registered['folder']);f['stages'].append(stage)
        cfg_saved=json.loads(h.m.trusted_read(stage/'request.json'));h.validate_request(cfg_saved)
        controller.kill();assert controller.wait(timeout=5)==-signal.SIGKILL
        worker=h.m.wait_file(stage/'worker-result.json',seconds=25);h.wait_unit_exit(cfg_saved['token'])
        assert worker['outcome']=='REMOVED_EXACT_OWNED_TABLE' and worker['own_table_absent'] is True
        assert worker['completed_ns']>=cfg_saved['deadline_ns']
        assert worker['namespace']==h.e.namespace(1)==registered['identity']['namespace']
        assert registered['identity']['parent_pid']==1 and registered['identity']['no_new_privs'] is True
        assert worker['foreign_policy_unchanged'] is True
        assert h.foreign_fingerprint(h.state(f['binary']))==f['fingerprint']
        record_property('initial_host_killed_controller_json',h.e.canonical(dict(request=cfg_saved,
            worker_identity=registered['identity'],worker_result=worker,controller_sigkill_verified=True,
            own_table_absent=True,foreign_policy_unchanged=True,existing_service_control=h.service_control(c['pid'],c['port']),
            provider_requests=0,execution_permission_issued=False)).decode('ascii'))
    finally:
        if controller.poll() is None:
            controller.kill();controller.wait(timeout=5)

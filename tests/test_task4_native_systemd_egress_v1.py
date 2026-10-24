"""Real systemd namespace recovery, not a mocked manager claim."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

import pytest
from scripts import task4_native_systemd_egress_v1 as m


def request():
    return dict(schema=m.PROFILE, scenario='deadline', token='a'*32, parent_pid=123,
        parent_namespace=dict(device=4,inode=10), namespace_pid=456,
        isolated_namespace=dict(device=4,inode=20), sources=m.pins())


def test_timer_command_explicitly_joins_isolated_namespace_and_never_uses_shell():
    cfg=request()
    tools={'systemd-run':'/usr/bin/systemd-run','python3':'/usr/bin/python3'}
    argv=m.timer_command(tools,Path('/run/trusted/source'),Path('/run/trusted/deadline/request.json'),cfg)
    assert '--property=NetworkNamespacePath=/proc/456/ns/net' in argv
    assert '--property=NoNewPrivileges=yes' in argv and '--property=Type=oneshot' in argv
    assert '--on-active=1s' in argv and '--timer-property=AccuracySec=100ms' in argv
    assert '--collect' in argv and '--scope' not in argv and '--user' not in argv
    assert '/bin/sh' not in argv and 'bash' not in argv
    code=argv[argv.index('-c')+1]
    compile(code,'<systemd-worker>','exec')
    assert 'm._worker(sys.argv[1])' in code


@pytest.mark.parametrize('change', ['schema','scenario','token','parent_bool','namespace_bool','same_ns',
    'negative_device','extra_field','missing_field','source_pin'])
def test_bad_request_stops_before_timer_creation(change):
    cfg=request()
    if change=='schema': cfg['schema']='other'
    elif change=='scenario': cfg['scenario']='host'
    elif change=='token': cfg['token']='bad; command'
    elif change=='parent_bool': cfg['parent_pid']=True
    elif change=='namespace_bool': cfg['namespace_pid']=True
    elif change=='same_ns': cfg['isolated_namespace']=cfg['parent_namespace']
    elif change=='negative_device': cfg['isolated_namespace']['device']=-1
    elif change=='extra_field': cfg['host_apply']=True
    elif change=='missing_field': del cfg['token']
    elif change=='source_pin': cfg['sources'][m.MODULES[1]]='0'*64
    with pytest.raises((ValueError,KeyError)):
        m.validate_request(cfg)


def test_readonly_plan_keeps_host_and_provider_no_go():
    p=m.plan()
    assert p['host_apply_supported'] is p['execution_permission_issued'] is False
    assert p['reboot_recovery_proven'] is p['privileged_concurrent_mutation_safe'] is False
    assert p['target_uids']==m.e.DENIED and p['provider_dispatch']=='DENY'
    assert p['source_pins'][m.MODULES[1]]==m.W_PIN


def test_ack_required_before_root_tools_or_mutation(monkeypatch):
    monkeypatch.setattr(m.e,'require_root',lambda: pytest.fail('root/tool access before acknowledgement'))
    with pytest.raises(ValueError): m.rehearse(False)


@pytest.mark.parametrize('load_state', [b'loaded\n',b'error\n',b''])
def test_existing_or_unknown_unit_does_not_authorize_replacement(monkeypatch,load_state):
    monkeypatch.setattr(m.subprocess,'run',lambda *a,**kw: subprocess.CompletedProcess(a[0],0,load_state,b''))
    with pytest.raises(ValueError):m.absent_unit({'systemctl':'/systemctl'},'unit.timer')


def test_missing_unit_accepts_only_explicit_not_found(monkeypatch):
    monkeypatch.setattr(m.subprocess,'run',lambda *a,**kw: subprocess.CompletedProcess(a[0],0,b'not-found\n',b''))
    m.absent_unit({'systemctl':'/systemctl'},'unit.timer')


@pytest.mark.parametrize('case', ['normal','symlink','public_mode','hardlink'])
def test_staged_private_read_uses_root_ownership_mode_and_no_follow(case):
    if os.geteuid()!=0:pytest.skip('root-private staging contract')
    with tempfile.TemporaryDirectory(prefix='systemd-egress-read-test-',dir='/run') as name:
        folder=Path(name);target=folder/'record';m.save(target,b'public synthetic record')
        if case=='normal':assert m.trusted_read(target)==b'public synthetic record'
        elif case=='symlink':
            link=folder/'link';link.symlink_to(target)
            with pytest.raises(OSError):m.trusted_read(link)
        elif case=='public_mode':
            target.chmod(0o644)
            with pytest.raises(ValueError):m.trusted_read(target)
        else:
            os.link(target,folder/'second')
            with pytest.raises(ValueError):m.trusted_read(target)


def fake_report():
    parent=dict(device=4,inode=10);isolated=dict(device=4,inode=20)
    rows=[]
    for scenario in m.SCENARIOS:
        identity=None if scenario=='collision' else dict(pid=1234,parent_pid=1,uid=0,no_new_privs=True,
            namespace=isolated,sources=m.pins())
        rows.append(dict(schema=m.PROFILE,scope=m.SCOPE,scenario=scenario,outcome=m.OUTCOMES[scenario],worker=identity,
            controller_sigkill_verified=scenario=='controller_killed',unrelated_canary_unchanged=True,
            isolated_namespace=isolated,parent_namespace=parent,host_rules_applied=False,
            execution_permission_issued=False,transient_units_stopped=True))
    return dict(schema=m.PROFILE,scope=m.SCOPE,source_sha256=m.source_sha256(),source_pins=m.pins(),scenarios=rows,
        parent_namespace_before=parent,parent_namespace_after=parent,parent_table_names_unchanged=True,
        transient_units_stopped=True,private_stage_removed=True,host_transient_systemd_units_created=True,
        host_rules_applied=False,host_rule_contents_attested=False,execution_permission_issued=False,
        provider_requests=0,provider_dispatch='DENY',utility='UNSCORED',systemd_version='systemd synthetic validator fixture')


def test_report_replay_keeps_identity_outcome_and_scope_joined():
    report=fake_report();assert m.validate_report(report)==report


@pytest.mark.parametrize('case',['host_apply','wrong_parent','wrong_ns','wrong_outcome','missing_case','not_killed','extra_post'])
def test_invalid_report_cannot_promote_to_systemd_recovery(case):
    report=fake_report();report=copy.deepcopy(report)
    if case=='host_apply':report['host_rules_applied']=True
    elif case=='wrong_parent':report['scenarios'][0]['worker']['parent_pid']=999
    elif case=='wrong_ns':report['scenarios'][0]['worker']['namespace']=report['parent_namespace_before']
    elif case=='wrong_outcome':report['scenarios'][2]['outcome']='REMOVED_EXACT_OWNED_TABLE'
    elif case=='missing_case':report['scenarios'].pop()
    elif case=='not_killed':report['scenarios'][1]['controller_sigkill_verified']=False
    else:report['provider_requests']=1
    with pytest.raises(ValueError):m.validate_report(report)


def test_actual_systemd_manager_joins_fresh_namespace_and_removes_only_owned_table(record_property):
    caps=int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')),16)
    if os.geteuid()!=0 or not all(caps&(1<<b) for b in (12,21)) or Path('/proc/1/comm').read_text().strip()!='systemd':
        pytest.skip('requires disposable root CI with actual systemd PID 1 and net/sys-admin')
    before=m.e.namespace()
    report=m.rehearse(True)
    assert m.validate_report(report)==report and m.e.namespace()==before
    assert report['host_transient_systemd_units_created'] is True and report['host_rules_applied'] is False
    record_property('systemd_egress_rehearsal_json',json.dumps(report,sort_keys=True,separators=(',',':')))


@pytest.mark.parametrize('case',['host_namespace','wrong_manager_namespace','stale_namespace_pid','not_manager_child'])
def test_worker_refuses_bad_namespace_identity_before_any_nft_tool(monkeypatch,case):
    cfg=request()
    monkeypatch.setattr(m.e,'require_root',lambda:None)
    monkeypatch.setattr(m,'trusted_read',lambda *args:json.dumps(cfg).encode())
    monkeypatch.setattr(m.os,'getppid',lambda:999 if case=='not_manager_child' else 1)
    read_text=Path.read_text
    def status(path,*args,**kwargs):
        if str(path)=='/proc/self/status':return 'NoNewPrivs:\t1\n'
        return read_text(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',status)
    def namespace(pid='self'):
        if pid==1:
            return cfg['isolated_namespace'] if case=='wrong_manager_namespace' else cfg['parent_namespace']
        if pid==cfg['namespace_pid'] and case=='stale_namespace_pid':return dict(device=4,inode=999)
        if pid=='self' and case=='host_namespace':return cfg['parent_namespace']
        return cfg['isolated_namespace']
    monkeypatch.setattr(m.e,'namespace',namespace)
    monkeypatch.setattr(m.e,'tools',lambda:pytest.fail('tools reached before namespace rejection'))
    with pytest.raises(ValueError):m._worker('/run/synthetic/request.json')

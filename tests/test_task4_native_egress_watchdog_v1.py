"""Actual detached watchdog recovery is mandatory in disposable root CI."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from scripts import task4_native_egress_watchdog_v1 as w

TOKEN = 'a' * 32


def document():
    rows = [{'table': dict(family='inet', name=w.TABLE, handle=1, comment=w.marker(TOKEN))},
            {'chain': dict(family='inet', table=w.TABLE, name='output', handle=2,
                           type='filter', hook='output', prio=0, policy='accept')}]
    for n, (role, uid) in enumerate(w.e.DENIED.items(), 3):
        rows.append({'rule': dict(family='inet', table=w.TABLE, chain='output', handle=n, comment=role,
            expr=[{'match': {'op': '==', 'left': {'meta': {'key': 'skuid'}}, 'right': uid}},
                  {'counter': {'packets': 0, 'bytes': 0}}, {'reject': {'type': 'icmpx', 'expr': 3}}])})
    return {'nftables': rows}


def test_guarded_shape_preserves_handles_and_ignores_only_counter_growth():
    before = document()
    after = copy.deepcopy(before)
    after['nftables'][2]['rule']['expr'][1]['counter'] = dict(packets=7, bytes=512)
    assert w.shape(after, TOKEN) == w.shape(before, TOKEN)
    after['nftables'][2]['rule']['handle'] = 999
    assert w.shape(after, TOKEN) != w.shape(before, TOKEN)


@pytest.mark.parametrize('change', [
    'marker', 'family', 'chain', 'policy', 'priority', 'extra_table_field',
    'extra_rule', 'missing_rule', 'extra_object', 'uid', 'rule_order', 'reject',
    'boolean_reject', 'negative_counter', 'extra_expression', 'comment', 'boolean_handle',
])
def test_unknown_or_changed_ownership_or_rules_stop_deletion(change):
    d = document()
    t, c, r = d['nftables'][0]['table'], d['nftables'][1]['chain'], d['nftables'][2]['rule']
    if change == 'marker': t['comment'] = w.marker('b' * 32)
    elif change == 'family': t['family'] = 'ip'
    elif change == 'chain': c['hook'] = 'input'
    elif change == 'policy': c['policy'] = 'drop'
    elif change == 'priority': c['prio'] = -1
    elif change == 'extra_table_field': t['flags'] = ['dormant']
    elif change == 'extra_rule': d['nftables'].append(copy.deepcopy(d['nftables'][2]))
    elif change == 'missing_rule': d['nftables'].pop()
    elif change == 'extra_object': d['nftables'].append({'set': {}})
    elif change == 'uid': r['expr'][0]['match']['right'] = 0
    elif change == 'rule_order': d['nftables'][2:4] = d['nftables'][3:1:-1]
    elif change == 'reject': r['expr'][2]['reject']['expr'] = 2
    elif change == 'boolean_reject': r['expr'][2]['reject']['expr'] = True
    elif change == 'negative_counter': r['expr'][1]['counter']['packets'] = -1
    elif change == 'extra_expression': r['expr'].append({'accept': None})
    elif change == 'comment': r['comment'] = 'foreign'
    elif change == 'boolean_handle': t['handle'] = True
    with pytest.raises(ValueError, match='WATCHDOG_STOP'):
        w.shape(d, TOKEN)


@pytest.mark.parametrize('token', ['', 'A'*32, 'a'*31, 'a'*33, 'x'*32, None])
def test_invalid_nonce_never_enters_nft_batch(token):
    with pytest.raises(ValueError):
        w.batch(token)


def test_no_host_apply_cli_or_persistence_claim():
    p = w.plan()
    assert p['target_uids'] == w.e.DENIED
    assert not any(p[x] for x in ('host_apply_supported', 'systemd_recovery_verified',
        'privileged_concurrent_mutation_safe', 'reboot_persistence', 'execution_permission_issued'))
    assert w.e.source_sha256() == w.SOURCE_PIN


@pytest.mark.parametrize('scenario', ['deadline', 'controller_killed', 'foreign_marker', 'extra_rule', 'collision'])
def test_actual_isolated_watchdog_deadline_crash_and_refusal(scenario, record_property):
    caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')), 16)
    if os.geteuid() != 0 or not all(caps & (1 << bit) for bit in (12, 21)):
        pytest.skip('requires disposable root CI with net-admin/sys-admin')
    before = w.e.namespace()
    # The supervisor stays alive. The controller is a separate process and can
    # be SIGKILLed without killing the detached watchdog or its report pipe.
    code = '''import importlib.util,json,os,select,signal,subprocess,sys,time,types
p=types.ModuleType('scripts');p.__path__=[];sys.modules['scripts']=p
s=importlib.util.spec_from_file_location('scripts.task4_native_egress_rehearsal_v1',E_SOURCE)
e=importlib.util.module_from_spec(s);sys.modules[s.name]=e;s.loader.exec_module(e)
s=importlib.util.spec_from_file_location('watchdog',W_SOURCE)
w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
b=e.tools();w.guard(PARENT,NS,b)
assert w.state(b) is None
canary=w.TABLE+'_canary'
e.execute([b['nft'],'create','table','inet',canary])
def canary_state():
    return json.loads(e.execute([b['nft'],'--json','--numeric','list','table','inet',canary]))
canary_before=canary_state()
if SCENARIO=='collision':
    e.execute([b['nft'],'create','table','inet',w.TABLE])
    unchanged=w.state(b)
    try: w.arm(TOKEN,PARENT,NS)
    except ValueError: pass
    else: raise AssertionError('collision was accepted')
    assert w.state(b)==unchanged
    report=dict(outcome='COLLISION_STOP_UNCHANGED')
else:
    if SCENARIO=='controller_killed':
        report_read,report_write=os.pipe()
        child_code=BOOTSTRAP+"\\np,ready,_=w.arm(TOKEN,PARENT,NS,seconds=3,result_write_fd=FD)\\nassert os.read(ready,100)==b'INSTALLED_WITH_WATCHDOG\\\\n'\\nprint(p.pid,flush=True)\\ntime.sleep(30)"
        child_code=child_code.replace('FD',str(report_write))
        controller=subprocess.Popen([sys.executable,'-I','-B','-c',child_code],pass_fds=(report_write,),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=w.ENV)
        os.close(report_write)
        assert select.select([controller.stdout],[],[],8)[0]
        watchdog_pid=int(controller.stdout.readline())
        assert w.state(b) is not None
        controller.kill();controller.wait(timeout=5)
        assert controller.returncode==-signal.SIGKILL
        report_fd=report_read
    else:
        worker,ready,report_fd=w.arm(TOKEN,PARENT,NS,seconds=3)
        assert select.select([ready],[],[],8)[0]
        assert os.read(ready,100)==b'INSTALLED_WITH_WATCHDOG\\n'
        os.close(ready)
        watchdog_pid=worker.pid
        w.shape(w.state(b),TOKEN)
    if SCENARIO=='foreign_marker':
        # Replace with an otherwise exact table under another trial identity.
        e.execute([b['nft'],'delete','table','inet',w.TABLE])
        e.execute([b['nft'],'--file','-'],w.batch('b'*32))
    if SCENARIO=='extra_rule':
        e.execute([b['nft'],'add','rule','inet',w.TABLE,'output','counter','accept'])
    altered=w.state(b)
    assert select.select([report_fd],[],[],12)[0]
    raw=os.read(report_fd,8192);os.close(report_fd)
    report=json.loads(raw)
    assert report['watchdog_pid']==watchdog_pid==report['watchdog_session']
    if SCENARIO in ('deadline','controller_killed'):
        assert report['outcome']=='REMOVED_EXACT_OWNED_TABLE' and w.state(b) is None
        if SCENARIO=='controller_killed':
            assert report['controller_pid']==controller.pid
            assert report['observed_parent_pid']!=controller.pid
    else:
        assert report['outcome']=='OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE'
        assert w.state(b)==altered
    if SCENARIO!='controller_killed':
        worker.wait(timeout=5);assert worker.returncode==0
assert canary_state()==canary_before
# Test harness cleanup only, in its disposable namespace; not guarded rollback.
if w.state(b) is not None: e.execute([b['nft'],'delete','table','inet',w.TABLE])
e.execute([b['nft'],'delete','table','inet',canary])
assert e.namespace(PARENT)==NS and e.namespace()!=NS
print(json.dumps(dict(scenario=SCENARIO,report=report,unrelated_canary_unchanged=True,
    host_rules_applied=False,execution_permission_issued=False),sort_keys=True))
'''
    values = dict(E_SOURCE=repr(str(Path(w.e.__file__).resolve())), W_SOURCE=repr(str(Path(w.__file__).resolve())),
        PARENT=repr(os.getpid()), NS=repr(before), TOKEN=repr(TOKEN), SCENARIO=repr(scenario))
    import re
    # Bootstrap copied into controller contains only module loads and constants.
    bootstrap = code[:code.index('b=e.tools();')]
    for key, value in values.items():
        bootstrap = re.sub(r'\b'+key+r'\b', lambda _: value, bootstrap)
    bootstrap += '\nTOKEN='+repr(TOKEN)+'\nPARENT='+repr(os.getpid())+'\nNS='+repr(before)+'\n'
    values['BOOTSTRAP'] = repr(bootstrap)
    code = re.sub(r'\b('+'|'.join(values)+r')\b', lambda m: values[m[0]], code)
    result = subprocess.run([w.e.tools()['unshare'],'--net','--',sys.executable,'-I','-B','-c',code],
        capture_output=True, timeout=30, env=w.ENV)
    assert result.returncode == 0, result.stderr.decode(errors='replace')[-6000:]
    proof = json.loads(result.stdout)
    assert proof['unrelated_canary_unchanged'] and w.e.namespace()==before
    record_property('watchdog_rehearsal_json',json.dumps(proof,sort_keys=True,separators=(',',':')))


@pytest.mark.parametrize('scenario', ['changed_handle', 'inspection_failure', 'absent'])
def test_inverse_never_deletes_after_identity_change_or_unknown_inspection(monkeypatch, scenario):
    calls = []
    monkeypatch.setattr(w, 'guard', lambda *args: None)
    def execute(argv, data=None):
        calls.append(argv)
        return b''
    monkeypatch.setattr(w.e, 'execute', execute)
    reads = iter([document(), document()])
    count = 0
    def state(_):
        nonlocal count
        count += 1
        if scenario == 'absent': return None
        if count == 2 and scenario == 'inspection_failure': raise OSError('injected')
        d = next(reads)
        if count == 2: d['nftables'][0]['table']['handle'] = 99
        return d
    monkeypatch.setattr(w, 'state', state)
    if scenario == 'absent':
        assert w.inverse({'nft':'/nft'},TOKEN,123,{}) == 'ABSENT'
        assert not calls
    else:
        with pytest.raises((ValueError,OSError)):
            w.inverse({'nft':'/nft'},TOKEN,123,{})
        assert calls == [['/nft','--check','--file','-']]

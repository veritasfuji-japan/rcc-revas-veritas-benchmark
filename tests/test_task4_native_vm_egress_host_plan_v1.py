"""Frozen operator evidence and review-only nft transaction candidates."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
from scripts import task4_native_egress_rehearsal_v1 as e

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / 'evidence/task4_native_vm_egress_rehearsal_v1'
PLAN = ROOT / 'docs/plans/task4_native_host_egress_v1'
REPORT_SHA = '5450e2639db054f176a3f01c9978513232a661497e365610b995adbd645e7c72'
SOURCE_SHA = 'f6865825a1f7435a1821e56f3e2e64db806c4ffad23f402d21cba8b394e48857'
UIDS = dict(backend=61103, issuer=61105, custody=61106, archive=61107, runtime=61108)


def load(path):
    return json.loads(path.read_bytes())


def test_operator_report_exact_bytes_and_frozen_source_match():
    raw = (EVIDENCE / 'report.json').read_bytes()
    index = load(EVIDENCE / 'index.json')
    assert len(raw) == index['report_size_bytes'] == 18453
    assert hashlib.sha256(raw).hexdigest() == index['report_sha256'] == REPORT_SHA
    report = json.loads(raw)
    assert e.canonical(report) == raw
    assert e.source_sha256() == report['source_sha256'] == index['source_sha256'] == SOURCE_SHA
    assert e.validate_report(report) == report


def test_full_operator_flow_counter_and_namespace_results_are_preserved():
    report = load(EVIDENCE / 'report.json')
    index = load(EVIDENCE / 'index.json')
    assert {k: len(v) for k, v in report['phases'].items()} == index['phase_counts'] == dict(
        baseline=32, denied=20, exempt_controls=12, after_local_table_removal=32)
    assert all(row['kernel_packets_after'] > row['kernel_packets_before'] for row in report['phases']['denied'])
    assert report['kernel_denial_packets'] == {str(uid): 5 for uid in UIDS.values()}
    assert report['parent_namespace_before'] == report['parent_namespace_after']
    assert report['isolated_namespace'] != report['parent_namespace_before']
    assert report['kernel_release'] == index['kernel_release'] == '6.8.0-147-generic'
    assert report['limitations']['host_rules_applied'] is report['limitations']['execution_permission_issued'] is False


def test_provenance_does_not_turn_public_output_into_independent_or_host_proof():
    index = load(EVIDENCE / 'index.json')
    p = index['provenance']
    assert p['transport'] == 'OPERATOR_PASTED_GZIP_BASE64_EXPORT'
    assert p['reported_sha256_matched'] is p['gzip_crc_verified'] is p['canonical_bytes_verified'] is True
    assert p['direct_vm_file_access'] is p['independent_vm_attestation'] is p['report_signature_verified'] is False
    assert p['precise_observation_timestamp'] is None
    assert index['limitations']['host_rules_applied'] is index['limitations']['operator_host_egress_verified'] is False
    raw = (EVIDENCE / 'report.json').read_bytes()
    assert not re.search(rb'(?:github_pat_|ghp_)[A-Za-z0-9_]{20,}', raw)
    assert b'-----BEGIN PRIVATE KEY-----' not in raw


@pytest.mark.parametrize('name', ['apply.nft', 'rollback.nft'])
def test_candidate_command_file_pins_are_exact(name):
    manifest = load(PLAN / 'manifest.json')
    raw = (PLAN / name).read_bytes()
    assert len(raw) == manifest['command_files'][name]['size_bytes']
    assert hashlib.sha256(raw).hexdigest() == manifest['command_files'][name]['sha256']
    assert b'flush ruleset' not in raw and b'include ' not in raw


def test_host_candidate_targets_only_five_reviewed_socket_uids_and_aborts_collisions():
    manifest = load(PLAN / 'manifest.json')
    assert manifest['target_uids'] == UIDS
    assert manifest['family'] == 'inet' and manifest['hook'] == 'output' and manifest['default_policy'] == 'accept'
    commands = [line for line in (PLAN / 'apply.nft').read_text().splitlines() if line and not line.startswith('#')]
    assert len(commands) == 7
    assert commands[0].startswith('create table inet ' + manifest['table'] + ' ')
    assert manifest['ownership_comment'] in commands[0]
    assert commands[1].startswith('create chain inet ' + manifest['table'] + ' output ')
    uids = [int(re.search(r'meta skuid (\d+)', line).group(1)) for line in commands[2:]]
    assert len(uids) == len(set(uids)) == 5 and set(uids) == set(UIDS.values())
    assert not set(uids) & {0, 109, 61109}
    assert all('counter reject with icmpx type admin-prohibited' in line for line in commands[2:])


def test_rollback_is_single_table_only_and_candidate_has_no_apply_or_auto_rollback_authority():
    manifest = load(PLAN / 'manifest.json')
    commands = [line for line in (PLAN / 'rollback.nft').read_text().splitlines() if line and not line.startswith('#')]
    assert commands == ['delete table inet ' + manifest['table']]
    assert manifest['scope'] == 'REVIEW_CANDIDATE_ONLY_NO_HOST_APPLY_NO_EXECUTION'
    for name in ('host_apply_authorized', 'host_rules_applied', 'host_egress_verified',
                 'automatic_rollback_implemented', 'reboot_persistence_implemented', 'execution_permission_issued'):
        assert manifest[name] is False
    assert manifest['prior_operator_isolated_report_sha256'] == REPORT_SHA
    assert 'bounded-independent-rollback-and-recovery-test' in manifest['required_before_any_host_trial']


def test_actual_candidate_create_collision_and_inverse_are_atomic_in_fresh_netns(record_property):
    caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')), 16)
    if os.geteuid() != 0 or not all(caps & (1 << bit) for bit in (12, 21)):
        pytest.skip('requires disposable root CI with net-admin/sys-admin')
    binaries = e.tools()
    before = e.namespace()
    manifest = load(PLAN / 'manifest.json')
    source = str(Path(e.__file__).absolute())
    code = '''import base64,importlib.util,json,os,subprocess
s=importlib.util.spec_from_file_location('egress',SOURCE)
e=importlib.util.module_from_spec(s);s.loader.exec_module(e)
parent_pid=PARENT_PID
before=PARENT_NS
b=e.tools()
e.guard(parent_pid,before,b)
table=TABLE
marker=MARKER
wanted=UIDS
apply=base64.b64decode(APPLY)
rollback=base64.b64decode(ROLLBACK)
def tables():
    return [v['table'] for v in json.loads(e.execute([b['nft'],'--json','--numeric','list','tables']))['nftables'] if 'table' in v]
def state():
    return json.loads(e.execute([b['nft'],'--json','--numeric','list','table','inet',table]))
assert tables()==[]
e.execute([b['nft'],'--check','--file','-'],apply)
assert tables()==[]
e.guard(parent_pid,before,b)
e.execute([b['nft'],'--file','-'],apply)
first=state()
entries=first['nftables']
assert all(set(x)<= {'metainfo','table','chain','rule'} for x in entries)
ts=[x['table'] for x in entries if 'table' in x]
cs=[x['chain'] for x in entries if 'chain' in x]
rs=[x['rule'] for x in entries if 'rule' in x]
assert len(ts)==len(cs)==1 and len(rs)==5
assert ts[0]['family']=='inet' and ts[0]['name']==table and ts[0]['comment']==marker
c=cs[0]
assert c['name']=='output' and c['type']=='filter' and c['hook']=='output' and c['prio']==0 and c['policy']=='accept'
seen=set()
for row in rs:
    assert row['family']=='inet' and row['table']==table and row['chain']=='output'
    expr=row['expr']
    assert len(expr)==3 and expr[0]['match']['op']=='==' and expr[0]['match']['left']=={'meta':{'key':'skuid'}}
    uid=expr[0]['match']['right']
    assert type(uid) is int and uid in wanted.values() and uid not in seen
    seen.add(uid)
    assert expr[1]['counter']=={'packets':0,'bytes':0}
    assert expr[2]['reject']=={'type':'icmpx','expr':'admin-prohibited'}
assert seen==set(wanted.values())
e.guard(parent_pid,before,b)
duplicate=subprocess.run([b['nft'],'--file','-'],input=apply,capture_output=True,timeout=15,
    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
assert duplicate.returncode!=0
assert state()==first
assert len(tables())==1
e.execute([b['nft'],'--check','--file','-'],rollback)
assert state()==first
e.guard(parent_pid,before,b)
e.execute([b['nft'],'--file','-'],rollback)
assert tables()==[]
assert e.namespace(parent_pid)==before and e.namespace()!=before
print(json.dumps(dict(scope='ISOLATED_NAMESPACE_CANDIDATE_TRANSACTION_ONLY',
    candidate_check_did_not_apply=True,duplicate_create_failed=True,duplicate_state_unchanged=True,
    exact_five_uid_kernel_rules=True,inverse_check_did_not_delete=True,inverse_removed_only_candidate=True,
    parent_namespace_unchanged=True,host_rules_applied=False,execution_permission_issued=False),sort_keys=True))
'''
    replacements = dict(SOURCE=repr(source), PARENT_PID=str(os.getpid()), PARENT_NS=repr(before),
        TABLE=repr(manifest['table']), MARKER=repr(manifest['ownership_comment']), UIDS=repr(UIDS),
        APPLY=repr(base64.b64encode((PLAN / 'apply.nft').read_bytes()).decode('ascii')),
        ROLLBACK=repr(base64.b64encode((PLAN / 'rollback.nft').read_bytes()).decode('ascii')))
    for name, value in replacements.items():
        code = re.sub(r'\b' + name + r'\b', lambda _: value, code)
    result = subprocess.run([binaries['unshare'], '--net', '--', sys.executable, '-I', '-B', '-c', code],
        capture_output=True, timeout=30, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
    assert result.returncode == 0, result.stderr.decode('utf-8', errors='replace')[-8000:]
    proof = json.loads(result.stdout)
    assert proof['parent_namespace_unchanged'] is True and e.namespace() == before
    assert proof['host_rules_applied'] is proof['execution_permission_issued'] is False
    record_property('candidate_transaction_json', json.dumps(proof, sort_keys=True, separators=(',', ':')))

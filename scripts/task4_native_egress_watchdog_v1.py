"""Isolated-only bounded nft rollback rehearsal; no host apply entry point.

A detached watchdog owns creation and its timed inverse. It attempts a guarded
inverse at a monotonic deadline; the controller cannot cancel/extend it.
Privileged concurrent replacement between inspection and deletion is outside
this rehearsal's boundary. This is not a systemd host recovery mechanism.
"""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from scripts import task4_native_egress_rehearsal_v1 as e

PROFILE = 'task4.native-egress-watchdog.v1'
SCOPE = 'SYNTHETIC_ISOLATED_WATCHDOG_ONLY_NO_HOST_APPLY_NO_EXECUTION'
TABLE = 'veritas_native_watchdog_v1'
PREFIX = 'veritas-native-watchdog-v1:'
SOURCE_PIN = 'f6865825a1f7435a1821e56f3e2e64db806c4ffad23f402d21cba8b394e48857'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


def need(condition):
    if not condition:
        raise ValueError('NATIVE_EGRESS_WATCHDOG_STOP')


def marker(token):
    need(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None)
    return PREFIX + token


def batch(token):
    tag = marker(token)
    lines = [f'create table inet {TABLE} {{ comment "{tag}"; }}',
             f'create chain inet {TABLE} output {{ type filter hook output priority 0; policy accept; }}']
    lines += [f'add rule inet {TABLE} output meta skuid {uid} counter reject with icmpx type admin-prohibited comment "{role}"'
              for role, uid in e.DENIED.items()]
    return ('\n'.join(lines) + '\n').encode('ascii')


def exact(row, required, optional=()):
    need(type(row) is dict and set(required) <= set(row) <= set(required) | set(optional))


def shape(document, token):
    """Reject extra objects/fields/expressions; tolerate only live counters/handles.

    Return a fingerprint including all object handles but excluding counters.
    A second inspection must match this fingerprint before deletion.
    """
    exact(document, ('nftables',))
    entries = document['nftables']
    need(type(entries) is list)
    tables, chains, rules = [], [], []
    for entry in entries:
        need(type(entry) is dict and len(entry) == 1)
        kind, row = next(iter(entry.items()))
        need(kind in ('metainfo', 'table', 'chain', 'rule'))
        if kind == 'metainfo':
            continue
        {'table': tables, 'chain': chains, 'rule': rules}[kind].append(row)
    need(len(tables) == len(chains) == 1 and len(rules) == 5)
    table, chain = tables[0], chains[0]
    exact(table, ('family', 'name', 'handle', 'comment'))
    need(table['family'] == 'inet' and table['name'] == TABLE and table['comment'] == marker(token))
    exact(chain, ('family', 'table', 'name', 'handle', 'type', 'hook', 'prio', 'policy'))
    need(type(chain['prio']) is int)
    need({k: chain[k] for k in ('family', 'table', 'name', 'type', 'hook', 'prio', 'policy')} ==
         dict(family='inet', table=TABLE, name='output', type='filter', hook='output', prio=0, policy='accept'))
    handles = [table['handle'], chain['handle']]
    normalized = copy.deepcopy(document)
    expected = list(e.DENIED.items())
    for row, (role, uid) in zip(rules, expected):
        exact(row, ('family', 'table', 'chain', 'handle', 'expr', 'comment'))
        need(row['family'] == 'inet' and row['table'] == TABLE and row['chain'] == 'output' and row['comment'] == role)
        handles.append(row['handle'])
        expr = row['expr']
        need(type(expr) is list and len(expr) == 3)
        need(expr[0] == {'match': {'op': '==', 'left': {'meta': {'key': 'skuid'}}, 'right': uid}})
        exact(expr[1], ('counter',))
        exact(expr[1]['counter'], ('packets', 'bytes'))
        need(all(type(v) is int and v >= 0 for v in expr[1]['counter'].values()))
        exact(expr[2], ('reject',))
        reject = expr[2]['reject']
        exact(reject, ('type', 'expr'))
        need(reject['type'] == 'icmpx' and
             ((type(reject['expr']) is int and reject['expr'] == 3) or reject['expr'] == 'admin-prohibited'))
    need(all(type(h) is int and h > 0 for h in handles))
    for entry in normalized['nftables']:
        if 'rule' in entry:
            entry['rule']['expr'][1]['counter'] = {'packets': 0, 'bytes': 0}
    # metainfo may contain runtime/tool details, not table policy.
    normalized['nftables'] = [x for x in normalized['nftables'] if 'metainfo' not in x]
    return normalized


def guard(parent_pid, parent_namespace, binaries):
    need(e.source_sha256() == SOURCE_PIN)
    e.guard(parent_pid, parent_namespace, binaries)


def state(binaries):
    tables = json.loads(e.execute([binaries['nft'], '--json', '--numeric', 'list', 'tables']))
    matches = [x['table'] for x in tables['nftables'] if 'table' in x and
               x['table']['family'] == 'inet' and x['table']['name'] == TABLE]
    need(len(matches) <= 1)
    if not matches:
        return None
    return json.loads(e.execute([binaries['nft'], '--json', '--numeric', 'list', 'table', 'inet', TABLE]))


def inverse(binaries, token, parent_pid, parent_namespace):
    guard(parent_pid, parent_namespace, binaries)
    before = state(binaries)
    if before is None:
        return 'ABSENT'
    identity = shape(before, token)
    rollback = f'delete table inet {TABLE}\n'.encode('ascii')
    e.execute([binaries['nft'], '--check', '--file', '-'], rollback)
    guard(parent_pid, parent_namespace, binaries)
    need(shape(state(binaries), token) == identity)
    e.execute([binaries['nft'], '--file', '-'], rollback)
    need(state(binaries) is None)
    return 'REMOVED_EXACT_OWNED_TABLE'


def watchdog(token, parent_pid, parent_namespace, seconds, ready_fd, result_fd):
    """Internal worker: called only inside the guarded fresh test namespace."""
    need(type(seconds) is int and 1 <= seconds <= 10)
    marker(token)
    controller_pid = os.getppid()
    binaries = e.tools()
    guard(parent_pid, parent_namespace, binaries)
    need(state(binaries) is None)
    deadline = time.monotonic() + seconds
    try:
        # The watchdog owns creation too: no delayed controller apply can race
        # after cleanup. A controller killed during nft cannot strand its table.
        apply = batch(token)
        e.execute([binaries['nft'], '--check', '--file', '-'], apply)
        guard(parent_pid, parent_namespace, binaries)
        need(time.monotonic() < deadline)
        e.execute([binaries['nft'], '--file', '-'], apply)
        shape(state(binaries), token)
        os.write(ready_fd, b'INSTALLED_WITH_WATCHDOG\n')
        os.close(ready_fd)
        while time.monotonic() < deadline:
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        outcome = inverse(binaries, token, parent_pid, parent_namespace)
    except Exception:
        try:
            outcome = inverse(binaries, token, parent_pid, parent_namespace)
        except Exception:
            outcome = 'OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE'
    report = dict(schema=PROFILE, scope=SCOPE, outcome=outcome,
                  watchdog_pid=os.getpid(), watchdog_session=os.getsid(0),
                  controller_pid=controller_pid, observed_parent_pid=os.getppid(),
                  host_rules_applied=False, execution_permission_issued=False)
    os.write(result_fd, e.canonical(report) + b'\n')
    os.close(result_fd)


def arm(token, parent_pid, parent_namespace, seconds=2, result_write_fd=None):
    """Launch the isolated worker, which owns both creation and timed inverse."""
    marker(token)
    need(type(seconds) is int and 1 <= seconds <= 10)
    binaries = e.tools()
    guard(parent_pid, parent_namespace, binaries)
    need(state(binaries) is None)
    ready_read, ready_write = os.pipe()
    if result_write_fd is None:
        result_read, result_write = os.pipe()
    else:
        result_read, result_write = None, os.dup(result_write_fd)
    source = str(Path(__file__).resolve())
    e_source = str(Path(e.__file__).resolve())
    code = '''import importlib.util,sys,types
p=types.ModuleType('scripts');p.__path__=[];sys.modules['scripts']=p
s=importlib.util.spec_from_file_location('scripts.task4_native_egress_rehearsal_v1', E_SOURCE)
e=importlib.util.module_from_spec(s);sys.modules[s.name]=e;s.loader.exec_module(e)
s=importlib.util.spec_from_file_location('watchdog', SOURCE)
w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
w.watchdog(TOKEN,PARENT,NS,SECONDS,READY,RESULT)
'''
    replacements = dict(E_SOURCE=repr(e_source), SOURCE=repr(source), TOKEN=repr(token), PARENT=repr(parent_pid),
                        NS=repr(parent_namespace), SECONDS=repr(seconds), READY=repr(ready_write), RESULT=repr(result_write))
    code = re.sub(r'\b(' + '|'.join(replacements) + r')\b', lambda m: replacements[m[0]], code)
    try:
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', code], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV, start_new_session=True,
            pass_fds=(ready_write, result_write))
    finally:
        os.close(ready_write)
        os.close(result_write)
    return process, ready_read, result_read


def source_sha256():
    return e.sha(Path(__file__).read_bytes())


def plan():
    return dict(schema=PROFILE, scope=SCOPE, source_sha256=source_sha256(),
                target_uids=e.DENIED, table=TABLE, maximum_watchdog_seconds=10,
                host_apply_supported=False, systemd_recovery_verified=False,
                privileged_concurrent_mutation_safe=False, reboot_persistence=False,
                execution_permission_issued=False, provider_dispatch='DENY', utility='UNSCORED')


if __name__ == '__main__':
    # Public CLI is inspection only. Mutation requires the isolated root harness.
    if sys.argv[1:] != ['plan']:
        raise SystemExit('NATIVE_EGRESS_WATCHDOG_STOP')
    print(json.dumps(plan(), sort_keys=True))

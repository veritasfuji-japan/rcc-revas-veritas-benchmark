"""Isolated real-kernel UID egress rehearsal; no operator-host firewall apply.

Stdlib-only. A fresh network namespace contains loopback TCP/UDP sinks only.
No credentials, authority keys, Provider, enrollment or execution permission.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import threading

PROFILE = 'task4.native-egress-rehearsal.v1'
SCOPE = 'SYNTHETIC_ISOLATED_NETNS_ONLY_NO_HOST_APPLY_NO_EXECUTION'
STOP = 'NATIVE_EGRESS_REHEARSAL_STOP'
TABLE = 'veritas_native_egress_probe_v1'
DENIED = dict(backend=61103, issuer=61105, custody=61106, archive=61107, runtime=61108)
CONTROLS = dict(service=109, reader=61109, administrator=0)
GIDS = {**{uid: uid for uid in (*DENIED.values(), *CONTROLS.values())}, 109: 110}
TOOLS = ('unshare', 'ip', 'nft', 'setpriv')
LIMIT = 262144
BANNER = b'VERITAS_ISOLATED_NETWORK_PROBE_V1'
FLOWS = ((4, 'tcp'), (6, 'tcp'), (4, 'udp'), (6, 'udp'))


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_sha256():
    fd = os.open(Path(__file__).absolute(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= LIMIT, 'BOUNDED_SOURCE')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == info.st_size, 'COMPLETE_SOURCE')
    return sha(raw)


def rules():
    lines = ['table inet ' + TABLE + ' {', ' chain output {',
             '  type filter hook output priority 0; policy accept;']
    for role, uid in DENIED.items():
        lines.append('  meta skuid ' + str(uid) + ' counter reject with icmpx type admin-prohibited comment "' + role + '"')
    return '\n'.join(lines + [' }', '}', ''])


def limitations():
    return dict(host_rules_applied=False, operator_host_egress_verified=False,
        reader_github_egress_restricted=False, retained_service_egress_restricted=False,
        dns_policy_verified=False, indirect_proxy_bypass_resistance_proven=False,
        native_execution_performed=False, execution_permission_issued=False,
        credential_loaded=False, private_key_loaded=False, provider_requests=0,
        production_bypass_resistance_proven=False, provider_dispatch='DENY', utility='UNSCORED')


def plan():
    return dict(schema=PROFILE, scope=SCOPE, action='plan',
        target_uids=dict(DENIED), positive_control_uids=dict(CONTROLS),
        rule_family='inet', rule_hook='output', matching='SOCKET_UID',
        denied_traffic='ALL_IPV4_IPV6_OUTPUT_INCLUDING_LOOPBACK_FOR_TARGET_UIDS',
        default_chain_policy='accept', rule_text=rules(), rule_sha256=sha(rules().encode('ascii')),
        host_apply_supported=False, limitations=limitations())


def namespace(pid='self'):
    info = os.stat('/proc/' + str(pid) + '/ns/net')
    return dict(device=info.st_dev, inode=info.st_ino)


def require_root():
    need(os.geteuid() == 0 and os.getegid() == 0, 'EXPLICIT_ROOT_REHEARSAL')


def tools():
    result = {}
    for name in TOOLS:
        file = shutil.which(name)
        need(file is not None, 'MISSING_REHEARSAL_TOOL')
        target = Path(file).resolve(strict=True)
        info = target.stat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'ROOT_OWNED_TOOL')
        for ancestor in target.parents:
            parent = ancestor.stat()
            need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
                 'TRUSTED_TOOL_ANCESTORS')
        result[name] = str(target)
    return result


def execute(argv, data=None, timeout=15):
    value = subprocess.run(argv, input=data, capture_output=True, timeout=timeout,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    need(value.returncode == 0 and len(value.stdout) <= LIMIT, 'BOUNDED_COMMAND_SUCCESS')
    return value.stdout


def guard(parent_pid, parent_namespace, binaries):
    require_root()
    need(type(parent_pid) is int and parent_pid > 1 and parent_pid != os.getpid(), 'LIVE_PARENT_PID')
    need(namespace(parent_pid) == parent_namespace and namespace() != parent_namespace,
         'FRESH_NETWORK_NAMESPACE_REQUIRED')
    links = json.loads(execute([binaries['ip'], '-j', 'link', 'show']))
    need(type(links) is list and len(links) == 1 and links[0]['ifname'] == 'lo', 'LOOPBACK_ONLY_NAMESPACE')


@contextmanager
def sinks():
    sockets, threads, endpoints = [], [], {}
    stop = threading.Event()
    try:
        for version, protocol in FLOWS:
            family = socket.AF_INET if version == 4 else socket.AF_INET6
            kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
            channel = socket.socket(family, kind)
            sockets.append(channel)
            if version == 6:
                channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            channel.bind(('127.0.0.1' if version == 4 else '::1', 0))
            if protocol == 'tcp':
                channel.listen(16)
            channel.settimeout(0.2)
            endpoints[(version, protocol)] = channel.getsockname()[1]
            def serve(channel=channel, protocol=protocol):
                while not stop.is_set():
                    try:
                        if protocol == 'tcp':
                            client, _ = channel.accept()
                            with client:
                                client.settimeout(2)
                                client.sendall(BANNER)
                        else:
                            data, address = channel.recvfrom(256)
                            if data == BANNER:
                                channel.sendto(BANNER, address)
                    except socket.timeout:
                        continue
                    except OSError:
                        if stop.is_set():
                            return
                        # A broken sink cannot produce a positive-control banner.
                        return
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            threads.append(thread)
        yield endpoints
    finally:
        stop.set()
        for channel in sockets:
            channel.close()
        for thread in threads:
            thread.join(timeout=3)


CLIENT = '''import json,os,socket,sys
from pathlib import Path
uid,gid,version,protocol,port=int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]),sys.argv[4],int(sys.argv[5])
status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if ':' in line}
assert os.getuid()==os.geteuid()==uid and os.getgid()==os.getegid()==gid and os.getgroups()==[]
assert int(status['CapEff'],16)==0 and status['NoNewPrivs']=='1'
assert version in (4,6) and protocol in ('tcp','udp') and 0<port<65536
banner=b'VERITAS_ISOLATED_NETWORK_PROBE_V1'
family=socket.AF_INET if version==4 else socket.AF_INET6
kind=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM
result=dict(uid=uid,gid=gid,version=version,protocol=protocol,effective_capabilities=0,no_new_privs=True)
try:
    with socket.socket(family,kind) as channel:
        channel.settimeout(2)
        channel.connect(('127.0.0.1' if version==4 else '::1',port))
        if protocol=='udp':channel.send(banner)
        if protocol=='udp':
            received=channel.recv(256)
        else:
            received=b''
            while len(received)<len(banner):
                part=channel.recv(len(banner)-len(received))
                if not part:break
                received+=part
        assert received==banner
    result.update(result='SUCCESS',errno=None)
except OSError as error:
    result.update(result='SOCKET_ERROR',errno=error.errno)
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''


def probe_clients(roles, endpoints, binaries):
    records = []
    for role, uid in roles.items():
        for version, protocol in FLOWS:
            raw = execute([binaries['setpriv'], '--reuid=' + str(uid), '--regid=' + str(GIDS[uid]),
                '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                sys.executable, '-I', '-B', '-c', CLIENT, str(uid), str(GIDS[uid]), str(version), protocol,
                str(endpoints[(version, protocol)])], timeout=8)
            record = json.loads(raw)
            need(record['uid'] == uid and record['gid'] == GIDS[uid] and record['version'] == version
                 and record['protocol'] == protocol and record['effective_capabilities'] == 0
                 and record['no_new_privs'] is True, 'ACTUAL_UID_CAPABILITY_FLOW')
            records.append(dict(record, role=role))
    return records


def counters(raw):
    value = json.loads(raw)
    result = {}
    for item in value['nftables']:
        row = item.get('rule')
        if row is None:
            continue
        need(row['family'] == 'inet' and row['table'] == TABLE and row['chain'] == 'output', 'EXACT_PROBE_TABLE_RULE')
        matches = [x['match'] for x in row['expr'] if 'match' in x]
        counts = [x['counter'] for x in row['expr'] if 'counter' in x]
        need(len(matches) == len(counts) == 1 and matches[0]['op'] == '=='
             and matches[0]['left'] == {'meta': {'key': 'skuid'}}, 'SOCKET_UID_COUNTER')
        uid = matches[0]['right']
        need(type(uid) is int and uid in DENIED.values() and uid not in result, 'EXACT_DENIED_UID_COUNTER')
        count = counts[0]
        need(type(count['packets']) is int and count['packets'] >= 0
             and type(count['bytes']) is int and count['bytes'] >= 0, 'NONNEGATIVE_KERNEL_COUNTER')
        result[uid] = count['packets']
    need(set(result) == set(DENIED.values()), 'ALL_FIVE_RULE_COUNTERS')
    return result


def validate_phase(records, roles, success):
    need(type(records) is list and len(records) == len(roles) * len(FLOWS), 'ALL_EXPECTED_FLOW_RECORDS')
    expected = {(role, uid, version, protocol) for role, uid in roles.items() for version, protocol in FLOWS}
    actual = set()
    for row in records:
        need(set(row) == {'uid', 'gid', 'version', 'protocol', 'effective_capabilities', 'no_new_privs',
                         'result', 'errno', 'role'}, 'EXACT_FLOW_RECORD')
        uid = row['uid']
        need(type(uid) is int and uid in GIDS and type(row['gid']) is int and row['gid'] == GIDS[uid]
             and type(row['version']) is int and row['effective_capabilities'] == 0
             and type(row['effective_capabilities']) is int and row['no_new_privs'] is True,
             'UNPRIVILEGED_FLOW_IDENTITY')
        identity = (row['role'], uid, row['version'], row['protocol'])
        need(identity in expected and identity not in actual, 'EXACT_FLOW_COVERAGE')
        actual.add(identity)
        if success:
            need(row['result'] == 'SUCCESS' and row['errno'] is None, 'POSITIVE_BANNER_CONTROL')
        else:
            # A timeout, missing route or unavailable listener is not a firewall
            # denial. Linux local-output administrative reject returns EPERM or
            # EACCES; the kernel counter join is also required below.
            need(row['result'] == 'SOCKET_ERROR' and type(row['errno']) is int
                 and row['errno'] in (1, 13), 'ADMINISTRATIVE_SOCKET_DENIAL:' + canonical(
                     {k: row[k] for k in ('uid', 'version', 'protocol', 'result', 'errno')}).decode('ascii'))
    need(actual == expected, 'COMPLETE_FLOW_COVERAGE')


def validate_report(value):
    need(type(value) is dict and set(value) == {'schema', 'scope', 'action', 'plan', 'source_sha256',
        'parent_namespace_before', 'parent_namespace_after', 'isolated_namespace', 'isolated_links',
        'isolated_rules_applied', 'isolated_table_removed', 'phases', 'kernel_denial_packets', 'limitations',
        'kernel_release', 'tool_versions'},
        'EXACT_REHEARSAL_REPORT_FIELDS')
    for name in ('parent_namespace_before', 'parent_namespace_after', 'isolated_namespace'):
        row = value[name]
        need(type(row) is dict and set(row) == {'device', 'inode'}
             and all(type(x) is int for x in row.values()) and row['device'] >= 0 and row['inode'] > 0,
             'EXACT_NAMESPACE_IDENTITY')
    need(value['schema'] == PROFILE and value['scope'] == SCOPE and value['action'] == 'rehearse'
         and value['plan'] == plan() and value['limitations'] == limitations(), 'EXACT_REHEARSAL_NOT_PERMISSION')
    need(value['parent_namespace_before'] == value['parent_namespace_after']
         and value['isolated_namespace'] != value['parent_namespace_before']
         and value['isolated_links'] == ['lo'] and value['isolated_rules_applied'] is True
         and value['isolated_table_removed'] is True, 'NAMESPACE_LOCAL_REHEARSAL_ONLY')
    need(type(value['kernel_release']) is str and 0 < len(value['kernel_release']) <= 256
         and type(value['tool_versions']) is dict and set(value['tool_versions']) == set(TOOLS)
         and all(type(x) is str and 0 < len(x) <= 1024 for x in value['tool_versions'].values()),
         'KERNEL_AND_TOOL_VERSION_RECORD')
    all_roles = {**DENIED, **CONTROLS}
    phases = value['phases']
    need(set(phases) == {'baseline', 'denied', 'exempt_controls', 'after_local_table_removal'}, 'EXACT_PROBE_PHASES')
    validate_phase(phases['baseline'], all_roles, True)
    validate_phase(phases['denied'], DENIED, False)
    validate_phase(phases['exempt_controls'], CONTROLS, True)
    validate_phase(phases['after_local_table_removal'], all_roles, True)
    need(set(value['kernel_denial_packets']) == {str(x) for x in DENIED.values()}, 'FIVE_KERNEL_COUNTERS')
    need(all(type(x) is int and x >= 4 for x in value['kernel_denial_packets'].values()), 'PACKET_COUNTER_AND_SOCKET_JOIN')
    need(value['source_sha256'] == source_sha256(), 'SAME_REHEARSAL_SOURCE')
    return value


def _isolated_probe(parent_pid, parent_namespace):
    binaries = tools()
    guard(parent_pid, parent_namespace, binaries)  # Before even syntax-checking nft input.
    isolated = namespace()
    versions = {name: execute([file, '-Version' if name == 'ip' else '--version']).decode('ascii').strip()
                for name, file in binaries.items()}
    execute([binaries['ip'], 'link', 'set', 'lo', 'up'])
    phases = {}
    all_roles = {**DENIED, **CONTROLS}
    with sinks() as endpoints:
        phases['baseline'] = probe_clients(all_roles, endpoints, binaries)
        validate_phase(phases['baseline'], all_roles, True)
        guard(parent_pid, parent_namespace, binaries)
        execute([binaries['nft'], '--check', '--file', '-'], rules().encode('ascii'))
        execute([binaries['nft'], '--file', '-'], rules().encode('ascii'))
        phases['denied'] = probe_clients(DENIED, endpoints, binaries)
        phases['exempt_controls'] = probe_clients(CONTROLS, endpoints, binaries)
        validate_phase(phases['denied'], DENIED, False)
        validate_phase(phases['exempt_controls'], CONTROLS, True)
        observed = counters(execute([binaries['nft'], '--json', '--numeric', 'list', 'table', 'inet', TABLE]))
        need(all(x >= 4 for x in observed.values()), 'ALL_DENIAL_COUNTERS_INCREMENTED')
        guard(parent_pid, parent_namespace, binaries)
        execute([binaries['nft'], 'delete', 'table', 'inet', TABLE])  # Only the verified disposable namespace.
        phases['after_local_table_removal'] = probe_clients(all_roles, endpoints, binaries)
        validate_phase(phases['after_local_table_removal'], all_roles, True)
    need(namespace(parent_pid) == parent_namespace and namespace() == isolated, 'STABLE_NAMESPACE_JOIN')
    return dict(schema=PROFILE, scope=SCOPE, action='rehearse', plan=plan(), source_sha256=source_sha256(),
        kernel_release=os.uname().release, tool_versions=versions,
        parent_namespace_before=parent_namespace, parent_namespace_after=namespace(parent_pid),
        isolated_namespace=isolated, isolated_links=['lo'], isolated_rules_applied=True,
        isolated_table_removed=True, phases=phases,
        kernel_denial_packets={str(uid): packets for uid, packets in observed.items()}, limitations=limitations())


def rehearse(acknowledge=False):
    require_root()
    need(acknowledge is True, 'EXPLICIT_ISOLATED_TEST_ONLY')
    binaries = tools()
    before = namespace()
    pid = os.getpid()
    # Direct file loading avoids an older installed regular scripts package.
    source = str(Path(__file__).absolute())
    code = ('import importlib.util,json;'
        's=importlib.util.spec_from_file_location("egress_rehearsal",' + repr(source) + ');'
        'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
        'print(m.canonical(m._isolated_probe(' + str(pid) + ',' + repr(before) + ')).decode("ascii"))')
    raw = execute([binaries['unshare'], '--net', '--', sys.executable, '-I', '-B', '-c', code], timeout=90)
    need(namespace() == before, 'PARENT_NAMESPACE_UNCHANGED')
    return validate_report(json.loads(raw))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'rehearse'))
    parser.add_argument('--acknowledge-isolated-network-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'plan':
            need(not args.acknowledge_isolated_network_test, 'PLAN_ONLY')
            value = plan()
        else:
            value = rehearse(args.acknowledge_isolated_network_test)
        print(canonical(value).decode('ascii'), flush=True)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Explicit bounded initial-host UID egress trial. Never Native/Provider execution.

A root systemd worker owns both creation and a single guarded inverse. The
controller cannot extend the monotonic lease or stop that worker. Failure may
retain the table: no reboot/manager-death/privileged-race recovery guarantee.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

from scripts import task4_native_egress_rehearsal_v1 as e
from scripts import task4_native_egress_watchdog_v1 as w
from scripts import task4_native_systemd_egress_v1 as m

PROFILE = 'task4.native-host-trial.v1'
SCOPE = 'SYNTHETIC_BOUNDED_INITIAL_HOST_UID_EGRESS_TRIAL_NO_EXECUTION'
TABLE = 'veritas_native_host_trial_v1'
PREFIX = 'veritas-native-host-trial-v1:'
LEASE_NS = 15_000_000_000
LOCK = '/run/veritas-native-host-trial-v1.lock'
MODULES = (*m.MODULES, 'task4_native_host_trial_v1')
M_PIN = '7e7dcf6d62bf4b3c4abc73204587a87b9a2cb2748b6cec3c70dd6232d5878ebb'
ENV = w.ENV


def need(value):
    if not value:
        raise ValueError('NATIVE_HOST_TRIAL_STOP')


def source_sha256():
    return e.sha(Path(__file__).read_bytes())


def pins():
    result = dict(m.pins(), task4_native_host_trial_v1=source_sha256())
    need(result[m.MODULES[2]] == M_PIN)
    return result


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch('[0-9a-f-]{36}', value) is not None)
    return value


def host_guard(namespace, boot):
    e.require_root()
    need(e.namespace() == e.namespace(1) == namespace and boot_id() == boot)
    need(Path('/proc/1/comm').read_text().strip() == 'systemd')


def nft(binaries, args, data=None):
    return e.execute([binaries['nft'], *args], data, timeout=2)


def state(binaries):
    document = json.loads(nft(binaries, ['--json', '--numeric', 'list', 'ruleset']))
    w.exact(document, ('nftables',))
    need(type(document['nftables']) is list)
    return document


def own_document(document):
    rows = []
    for item in document['nftables']:
        need(type(item) is dict and len(item) == 1)
        kind, row = next(iter(item.items()))
        if kind == 'metainfo':
            continue
        need(type(row) is dict)
        if row.get('family') == 'inet' and (row.get('table') == TABLE or
                (kind == 'table' and row.get('name') == TABLE)):
            rows.append(item)
    return {'nftables': rows} if rows else None


def foreign_fingerprint(document):
    """Full other-table policy/handles, ignoring only live counters/metainfo."""
    result = copy.deepcopy(document)
    own = own_document(result)
    result['nftables'] = [x for x in result['nftables'] if 'metainfo' not in x
                            and (own is None or x not in own['nftables'])]
    def normalize(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'counter' and isinstance(child, dict):
                    for count in ('packets', 'bytes'):
                        if count in child:
                            need(type(child[count]) is int and child[count] >= 0)
                            child[count] = 0
                normalize(child)
        elif isinstance(value, list):
            for child in value:
                normalize(child)
    normalize(result)
    return e.sha(e.canonical(result))


def marker(token):
    w.marker(token)
    return PREFIX + token


def batch(token):
    # Keep the proven exact five-rule grammar; only table and nonce prefix differ.
    return w.batch(token).replace(w.TABLE.encode(), TABLE.encode()).replace(w.PREFIX.encode(), PREFIX.encode())


def shape(document, token):
    need(document is not None)
    original = copy.deepcopy(document)
    for item in original['nftables']:
        kind, row = next(iter(item.items()))
        if kind == 'metainfo':
            continue
        need(kind in ('table', 'chain', 'rule'))
        if kind == 'table':
            need(row.get('name') == TABLE and row.get('comment') == marker(token))
            row['name'], row['comment'] = w.TABLE, w.marker(token)
        else:
            need(row.get('table') == TABLE)
            row['table'] = w.TABLE
    return w.shape(original, token)


def inverse(binaries, cfg):
    host_guard(cfg['namespace'], cfg['boot_id'])
    before = state(binaries)
    own = own_document(before)
    if own is None:
        return 'ABSENT'
    identity = shape(own, cfg['token'])
    rollback = f'delete table inet {TABLE}\n'.encode('ascii')
    nft(binaries, ['--check', '--file', '-'], rollback)
    host_guard(cfg['namespace'], cfg['boot_id'])
    need(shape(own_document(state(binaries)), cfg['token']) == identity)
    nft(binaries, ['--file', '-'], rollback)
    need(own_document(state(binaries)) is None)
    return 'REMOVED_EXACT_OWNED_TABLE'


def status(pid):
    return dict(x.split(':', 1) for x in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in x)


def idle_targets():
    """No existing target process/thread UID or IP socket before installation."""
    targets = set(e.DENIED.values())
    accounts = {}
    for role, uid in e.DENIED.items():
        account = pwd.getpwuid(uid)
        need(account.pw_name == 'veritas-native-' + role and account.pw_gid == uid
             and os.getgrouplist(account.pw_name, uid) == [uid])
        accounts[role] = uid
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            for task in (process / 'task').iterdir():
                try:
                    need(targets.isdisjoint(map(int, status(task.relative_to('/proc'))['Uid'].split())))
                except FileNotFoundError:
                    continue
        except (FileNotFoundError, ProcessLookupError):
            continue
    counts = {str(uid): 0 for uid in targets}
    for name in ('tcp', 'tcp6', 'udp', 'udp6', 'raw', 'raw6'):
        for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
            uid = int(line.split()[7])
            if uid in targets:
                counts[str(uid)] += 1
    need(not any(counts.values()))
    return dict(accounts=accounts, target_processes_or_threads=0, target_ip_sockets=counts)


def service_control(pid, port):
    """Existing UID-109 process + pinned listening socket + root TCP connect.

    This does not authenticate TLS or verify a signed application receipt.
    """
    need(type(pid) is int and pid > 1 and type(port) is int and 0 < port < 65536)
    row = status(pid)
    need(list(map(int, row['Uid'].split())) == [109] * 4 and
         all(int(row[k], 16) == 0 for k in ('CapEff', 'CapPrm', 'CapAmb')))
    need(e.namespace(pid) == e.namespace(1))
    start = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    sockets = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[(\d+)\]', link)
        if match:
            sockets.add(match[1])
    matches = []
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        parts = line.split()
        if (parts[1] == '0100007F:' + format(port, '04X') and parts[3] == '0A'
                and parts[7] == '109' and parts[9] in sockets):
            matches.append(parts[9])
    need(len(matches) == 1)
    with socket.create_connection(('127.0.0.1', port), timeout=1):
        pass
    need(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19] == start)
    return dict(pid=pid, start_ticks=int(start), uid=109, port=port,
                listening_inode=int(matches[0]), tcp_connect=True, signed_application_receipt_verified=False)


def validate_request(cfg):
    w.exact(cfg, ('schema', 'token', 'namespace', 'boot_id', 'deadline_ns', 'sources',
                  'foreign_sha256', 'service', 'inventory'))
    need(cfg['schema'] == PROFILE)
    marker(cfg['token'])
    w.exact(cfg['namespace'], ('device', 'inode'))
    need(all(type(x) is int and x > 0 for x in cfg['namespace'].values()))
    need(type(cfg['deadline_ns']) is int and type(cfg['boot_id']) is str
         and re.fullmatch('[0-9a-f-]{36}', cfg['boot_id']) is not None)
    need(type(cfg['foreign_sha256']) is str and re.fullmatch('[0-9a-f]{64}', cfg['foreign_sha256']) is not None)
    need(cfg['sources'] == pins())
    w.exact(cfg['service'], ('pid', 'start_ticks', 'uid', 'port', 'listening_inode',
                             'tcp_connect', 'signed_application_receipt_verified'))
    need(all(type(cfg['service'][k]) is int and cfg['service'][k] > 0
             for k in ('pid', 'start_ticks', 'uid', 'port', 'listening_inode')))
    need(cfg['service']['uid'] == 109 and cfg['service']['tcp_connect'] is True
         and cfg['service']['signed_application_receipt_verified'] is False)
    need(cfg['inventory'] == dict(accounts=e.DENIED, target_processes_or_threads=0,
                                 target_ip_sockets={str(uid): 0 for uid in e.DENIED.values()}))
    return cfg


def lease_current(cfg):
    remaining = cfg['deadline_ns'] - time.monotonic_ns()
    need(0 < remaining <= LEASE_NS)


def unit_name(token):
    marker(token)
    return 'veritas-native-host-trial-' + token


def bootstrap(source):
    return m.bootstrap(source) + ('\ns=importlib.util.spec_from_file_location("scripts.task4_native_host_trial_v1",'
        + repr(str(Path(source) / 'task4_native_host_trial_v1.py')) + ')\n'
        'h=importlib.util.module_from_spec(s);sys.modules[s.name]=h;s.loader.exec_module(h)\n')


def command(tools, source, request, cfg):
    validate_request(cfg)
    return [tools['systemd-run'], '--quiet', '--collect', '--no-block', '--unit=' + unit_name(cfg['token']),
        '--property=Type=oneshot', '--property=Description=' + unit_name(cfg['token']),
        '--property=NoNewPrivileges=yes', '--property=UMask=0077', '--property=TimeoutStartSec=45s',
        '--property=NetworkNamespacePath=/proc/1/ns/net',
        '--property=StandardOutput=null', '--property=StandardError=null',
        tools['python3'], '-I', '-B', '-c', bootstrap(source) + '\nh._worker(sys.argv[1])', str(request)]


def acquire_lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _worker(path):
    cfg = validate_request(json.loads(m.trusted_read(path)))
    host_guard(cfg['namespace'], cfg['boot_id'])
    need(os.getppid() == 1 and status('self')['NoNewPrivs'].strip() == '1')
    folder = Path(path).parent
    for name, digest in cfg['sources'].items():
        need(e.sha(m.trusted_read(folder / 'source' / (name + '.py'))) == digest)
    lock = acquire_lock()
    try:
        lease_current(cfg)
        binaries = e.tools()
        need(idle_targets() == cfg['inventory'])
        need(service_control(cfg['service']['pid'], cfg['service']['port']) == cfg['service'])
        before = state(binaries)
        need(own_document(before) is None and foreign_fingerprint(before) == cfg['foreign_sha256'])
        outcome = 'NOT_ATTEMPTED'
        installed = False
        try:
            nft(binaries, ['--check', '--file', '-'], batch(cfg['token']))
            host_guard(cfg['namespace'], cfg['boot_id'])
            lease_current(cfg)
            nft(binaries, ['--file', '-'], batch(cfg['token']))
            shape(own_document(state(binaries)), cfg['token'])
            installed = True
            m.save(folder / 'installed.json', e.canonical(dict(token=cfg['token'], pid=os.getpid(),
                parent_pid=os.getppid(), uid=os.geteuid(), no_new_privs=True,
                namespace=e.namespace(), boot_id=cfg['boot_id'], sources=cfg['sources'], deadline_ns=cfg['deadline_ns'])))
            while time.monotonic_ns() < cfg['deadline_ns']:
                time.sleep(min(0.05, max(0, cfg['deadline_ns'] - time.monotonic_ns()) / 1e9))
        except Exception:
            # nft may have committed even if its response/inspection failed.
            pass
        try:
            outcome = inverse(binaries, cfg)  # Exactly one inverse attempt, no repair/retry.
        except Exception:
            outcome = 'OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE'
        after = state(binaries)
        report = dict(schema=PROFILE, token=cfg['token'], installed=installed, outcome=outcome,
            own_table_absent=own_document(after) is None,
            foreign_policy_unchanged=foreign_fingerprint(after) == cfg['foreign_sha256'],
            deadline_ns=cfg['deadline_ns'], completed_ns=time.monotonic_ns(),
            namespace=e.namespace(), boot_id=cfg['boot_id'], sources=cfg['sources'])
        m.save(folder / 'worker-result.json', e.canonical(report))
    finally:
        os.close(lock)


def preflight(pid, port):
    namespace, boot = e.namespace(), boot_id()
    host_guard(namespace, boot)
    binaries = e.tools()
    inventory = idle_targets()
    before = state(binaries)
    need(own_document(before) is None)
    return dict(namespace=namespace, boot_id=boot, inventory=inventory,
                foreign_sha256=foreign_fingerprint(before), service=service_control(pid, port))


def schedule(folder, cfg):
    validate_request(cfg)
    host_guard(cfg['namespace'], cfg['boot_id'])
    lease_current(cfg)
    tools = m.system_tools()
    m.absent_unit(tools, unit_name(cfg['token']) + '.service')
    e.execute(command(tools, Path(folder) / 'source', Path(folder) / 'request.json', cfg), timeout=10)


def prepare(pid, port):
    before = preflight(pid, port)
    folder = Path(tempfile.mkdtemp(prefix='veritas-native-host-trial-', dir='/run'))
    os.chmod(folder, 0o700)
    (folder / 'source').mkdir(mode=0o700)
    expected = pins()
    for name in MODULES:
        module = sys.modules['scripts.' + name]
        # Only root-owned, non-writable deployment ancestors; no site/user fallback.
        source = Path(module.__file__).absolute()
        for ancestor in source.parents:
            info = ancestor.stat()
            need(info.st_uid == 0 and not info.st_mode & 0o022 and not ancestor.is_symlink())
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                 and info.st_nlink == 1 and 0 < info.st_size < 65536)
            raw = stream.read(65537)
        need(len(raw) == info.st_size and e.sha(raw) == expected[name])
        m.save(folder / 'source' / (name + '.py'), raw)
    cfg = dict(schema=PROFILE, token=secrets.token_hex(16), sources=expected,
               deadline_ns=time.monotonic_ns() + LEASE_NS, **before)
    m.save(folder / 'request.json', e.canonical(cfg))
    return folder, validate_request(cfg)


def packet_counts(binaries, token):
    document = own_document(state(binaries))
    shape(document, token)
    return {row['expr'][0]['match']['right']: row['expr'][1]['counter']['packets']
            for item in document['nftables'] if (row := item.get('rule')) is not None}


def wait_unit_exit(token):
    tools = m.system_tools()
    until = time.monotonic() + 10
    while time.monotonic() < until:
        result = subprocess.run([tools['systemctl'], 'is-active', '--quiet', unit_name(token) + '.service'],
                                capture_output=True, timeout=2, env=ENV)
        if result.returncode in (3, 4):
            return
        need(result.returncode == 0)
        time.sleep(0.05)
    raise ValueError('HOST_TRIAL_WORKER_STILL_ACTIVE_DO_NOT_STOP')


def validate_report(report):
    w.exact(report, ('schema', 'scope', 'sources', 'request', 'worker_identity', 'worker_result',
        'existing_service_controls', 'phases', 'foreign_policy_unchanged', 'worker_exited',
        'host_rules_applied', 'own_table_removed', 'limitations'))
    need(report['schema'] == PROFILE and report['scope'] == SCOPE and report['sources'] == pins())
    cfg = validate_request(report['request'])
    identity, worker = report['worker_identity'], report['worker_result']
    need(identity == dict(token=cfg['token'], pid=identity['pid'], parent_pid=1, uid=0,
        no_new_privs=True, namespace=cfg['namespace'], boot_id=cfg['boot_id'], sources=cfg['sources'],
        deadline_ns=cfg['deadline_ns']))
    need(type(identity['pid']) is int and identity['pid'] > 1)
    need(worker == dict(schema=PROFILE, token=cfg['token'], installed=True,
        outcome='REMOVED_EXACT_OWNED_TABLE', own_table_absent=True, foreign_policy_unchanged=True,
        deadline_ns=cfg['deadline_ns'], completed_ns=worker['completed_ns'],
        namespace=cfg['namespace'], boot_id=cfg['boot_id'], sources=cfg['sources']))
    need(type(worker['completed_ns']) is int and worker['completed_ns'] >= cfg['deadline_ns'])
    need(report['existing_service_controls'] == [cfg['service']] * 3)
    phases = report['phases']
    need(set(phases) == {'baseline', 'denied', 'exempt_controls', 'after_removal'})
    for name in ('baseline', 'after_removal'):
        e.validate_phase(phases[name], {**e.DENIED, **e.CONTROLS}, True)
    e.validate_phase(phases['denied'], e.DENIED, False)
    e.validate_phase(phases['exempt_controls'], e.CONTROLS, True)
    need(report['foreign_policy_unchanged'] is True and report['worker_exited'] is True
         and report['host_rules_applied'] is True and report['own_table_removed'] is True)
    need(report['limitations'] == limitations())
    return report


def trial(pid, port, acknowledge=False):
    need(acknowledge is True)  # Before any root, process, socket, tool or systemd access.
    preflight(pid, port)
    binaries = e.tools()
    controls = [service_control(pid, port)]
    with e.sinks() as endpoints:
        baseline = e.probe_clients({**e.DENIED, **e.CONTROLS}, endpoints, binaries)
        e.validate_phase(baseline, {**e.DENIED, **e.CONTROLS}, True)
        folder, cfg = prepare(pid, port)
        # A failure after scheduling never cancels/stops the independent worker.
        print('HOST_TRIAL_AUDIT_DIRECTORY=' + str(folder), file=sys.stderr, flush=True)
        schedule(folder, cfg)
        identity = m.wait_file(folder / 'installed.json', seconds=20)
        controls.append(service_control(pid, port))
        denied = e.probe_clients(e.DENIED, endpoints, binaries,
                                lambda: packet_counts(binaries, cfg['token']))
        e.validate_phase(denied, e.DENIED, False)
        exempt = e.probe_clients(e.CONTROLS, endpoints, binaries)
        e.validate_phase(exempt, e.CONTROLS, True)
        worker = m.wait_file(folder / 'worker-result.json', seconds=25)
        wait_unit_exit(cfg['token'])
        need(worker['outcome'] == 'REMOVED_EXACT_OWNED_TABLE' and worker['own_table_absent'] is True)
        host_guard(cfg['namespace'], cfg['boot_id'])
        after_state = state(binaries)
        need(own_document(after_state) is None and foreign_fingerprint(after_state) == cfg['foreign_sha256'])
        controls.append(service_control(pid, port))
        after = e.probe_clients({**e.DENIED, **e.CONTROLS}, endpoints, binaries)
        report = dict(schema=PROFILE, scope=SCOPE, sources=pins(), request=cfg,
            worker_identity=identity, worker_result=worker, existing_service_controls=controls,
            phases=dict(baseline=baseline, denied=denied, exempt_controls=exempt, after_removal=after),
            foreign_policy_unchanged=True, worker_exited=True, host_rules_applied=True, own_table_removed=True,
            limitations=limitations())
        validate_report(report)
        m.save(folder / 'report.json', e.canonical(report))
        return report


def limitations():
    return dict(execution_permission_issued=False, native_execution_performed=False,
        provider_requests=0, provider_dispatch='DENY', utility='UNSCORED',
        production_bypass_resistance_proven=False, reader_github_egress_restricted=False,
        service_application_receipt_verified=False, ssh_session_health_verified=False,
        dns_policy_verified=False, credential_permissions_verified=False,
        privileged_concurrent_mutation_safe=False, reboot_recovery_proven=False,
        watchdog_or_manager_death_recovery_proven=False, hard_realtime_deadline_guaranteed=False)


def plan():
    return dict(schema=PROFILE, scope=SCOPE, sources=pins(), table=TABLE, target_uids=e.DENIED,
        controls=e.CONTROLS, lease_seconds=LEASE_NS // 1_000_000_000,
        host_apply_supported=True, host_apply_requires_explicit_acknowledgement=True,
        mutations='ONE_EXCLUSIVE_CREATE_AND_ONE_OWNERSHIP_GUARDED_INVERSE_ATTEMPT',
        target_roles_must_be_idle=True, limitations=limitations())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'preflight', 'trial'))
    parser.add_argument('--service-pid', type=int)
    parser.add_argument('--service-port', type=int)
    parser.add_argument('--acknowledge-bounded-host-firewall-trial', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'plan':
            need(args.service_pid is None and args.service_port is None and
                 not args.acknowledge_bounded_host_firewall_trial)
            result = plan()
        elif args.action == 'preflight':
            need(not args.acknowledge_bounded_host_firewall_trial)
            result = preflight(args.service_pid, args.service_port)
        else:
            result = trial(args.service_pid, args.service_port, args.acknowledge_bounded_host_firewall_trial)
        print(e.canonical(result).decode('ascii'), flush=True)
        return 0
    except Exception:
        print('NATIVE_HOST_TRIAL_STOP_NO_RETRY_OR_MANUAL_TABLE_DELETE', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

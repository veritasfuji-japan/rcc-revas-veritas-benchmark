"""Actual systemd timer + isolated nft recovery rehearsal; no host-apply mode."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

from scripts import task4_native_egress_rehearsal_v1 as e
from scripts import task4_native_egress_watchdog_v1 as w

PROFILE = 'task4.native-systemd-egress.v1'
SCOPE = 'SYNTHETIC_SYSTEMD_ISOLATED_NETNS_ONLY_NO_HOST_APPLY_NO_EXECUTION'
W_PIN = 'd777cf8754f131569977b8b2ba63e6b8c29329606983db3d5d69f80cc7c46af5'
SCENARIOS = ('deadline', 'controller_killed', 'foreign_marker', 'extra_rule', 'collision')
OUTCOMES = dict(deadline='REMOVED_EXACT_OWNED_TABLE', controller_killed='REMOVED_EXACT_OWNED_TABLE',
    foreign_marker='OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE', extra_rule='OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE',
    collision='COLLISION_STOP_UNCHANGED')
MODULES = ('task4_native_egress_rehearsal_v1', 'task4_native_egress_watchdog_v1', 'task4_native_systemd_egress_v1')
ENV = w.ENV


def need(value):
    if not value:
        raise ValueError('NATIVE_SYSTEMD_EGRESS_STOP')


def source_sha256():
    return e.sha(Path(__file__).read_bytes())


def pins():
    result = {MODULES[0]: e.source_sha256(), MODULES[1]: w.source_sha256(), MODULES[2]: source_sha256()}
    need(result[MODULES[0]] == w.SOURCE_PIN and result[MODULES[1]] == W_PIN)
    return result


def trusted_read(path, limit=65536):
    """Root-only no-follow traversal; staged private files, not credentials."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = new
            info = os.fstat(fd)
            need(info.st_uid == 0 and not info.st_mode & 0o022)
        final = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(final)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                 and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit)
            raw = os.read(final, limit + 1)
            need(len(raw) == info.st_size)
            return raw
        finally:
            os.close(final)
    finally:
        os.close(fd)


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        need(os.write(fd, raw) == len(raw))
        os.fsync(fd)
    finally:
        os.close(fd)


def system_tools():
    result = {}
    for name in ('systemd-run', 'systemctl', 'python3'):
        path = shutil.which(name, path='/usr/sbin:/usr/bin:/sbin:/bin')
        need(path is not None)
        target = Path(path).resolve(strict=True)
        for item in (target, *target.parents):
            info = item.stat()
            need(info.st_uid == 0 and not info.st_mode & 0o022)
        need(target.is_file())
        result[name] = str(target)
    return result


def bootstrap(source):
    # Explicit loads avoid an installed older regular `scripts` package.
    code = 'import importlib.util,sys,types\np=types.ModuleType("scripts");p.__path__=[];sys.modules["scripts"]=p\n'
    for name in MODULES:
        filename = str(Path(source) / (name + '.py'))
        code += f's=importlib.util.spec_from_file_location({"scripts."+name!r},{filename!r})\n'
        code += 'm=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)\n'
    return code


def validate_request(cfg):
    w.exact(cfg, ('schema', 'scenario', 'token', 'parent_pid', 'parent_namespace',
                  'namespace_pid', 'isolated_namespace', 'sources'))
    need(cfg['schema'] == PROFILE and cfg['scenario'] in SCENARIOS)
    w.marker(cfg['token'])
    for key in ('parent_pid', 'namespace_pid'):
        need(type(cfg[key]) is int and cfg[key] > 1)
    for key in ('parent_namespace', 'isolated_namespace'):
        w.exact(cfg[key], ('device', 'inode'))
        need(all(type(x) is int and x > 0 for x in cfg[key].values()))
    need(cfg['parent_namespace'] != cfg['isolated_namespace'])
    need(cfg['sources'] == pins())
    return cfg


def _worker(config_path):
    e.require_root()
    cfg = validate_request(json.loads(trusted_read(config_path)))
    # No nft invocation precedes all identity and namespace guards.
    need(os.getppid() == 1)
    status = Path('/proc/self/status').read_text().splitlines()
    nnp = next(x.split()[1] for x in status if x.startswith('NoNewPrivs:'))
    need(nnp == '1')
    need(e.namespace(1) == cfg['parent_namespace'])
    need(e.namespace() == cfg['isolated_namespace'] == e.namespace(cfg['namespace_pid']))
    binaries = e.tools()
    w.guard(cfg['parent_pid'], cfg['parent_namespace'], binaries)
    folder = Path(config_path).parent
    for name, digest in cfg['sources'].items():
        need(e.sha(trusted_read(folder.parent / 'source' / (name + '.py'))) == digest)
    identity = dict(pid=os.getpid(), parent_pid=os.getppid(), uid=os.geteuid(), no_new_privs=True,
                    namespace=e.namespace(), sources=cfg['sources'])
    save(folder / 'worker-identity.json', e.canonical(identity))
    ready = os.open(folder / 'ready', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    result = os.open(folder / 'result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    w.watchdog(cfg['token'], cfg['parent_pid'], cfg['parent_namespace'], 4, ready, result)


def unit_name(token):
    w.marker(token)
    return 'veritas-native-systemd-egress-' + token


def timer_command(tools, source, request, cfg):
    cfg = validate_request(cfg)
    return [tools['systemd-run'], '--quiet', '--collect', '--unit=' + unit_name(cfg['token']),
        '--on-active=1s', '--timer-property=AccuracySec=100ms', '--property=Type=oneshot',
        '--property=Description=' + unit_name(cfg['token']),
        '--timer-property=Description=' + unit_name(cfg['token']),
        '--property=NoNewPrivileges=yes', '--property=UMask=0077',
        '--property=StandardOutput=null', '--property=StandardError=null',
        '--property=NetworkNamespacePath=/proc/' + str(cfg['namespace_pid']) + '/ns/net',
        tools['python3'], '-I', '-B', '-c', bootstrap(source) + '\nm._worker(sys.argv[1])', str(request)]


def absent_unit(tools, unit):
    r = subprocess.run([tools['systemctl'], 'show', '--property=LoadState', '--value', unit],
                       capture_output=True, timeout=10, env=ENV)
    need(r.returncode in (0, 1) and r.stdout.strip() == b'not-found')


def schedule(tools, source, request, cfg):
    binaries = e.tools()
    w.guard(cfg['parent_pid'], cfg['parent_namespace'], binaries)
    need(e.namespace(1) == cfg['parent_namespace'])
    need(e.namespace() == cfg['isolated_namespace'] and w.state(binaries) is None)
    for suffix in ('.timer', '.service'):
        absent_unit(tools, unit_name(cfg['token']) + suffix)
    e.execute(timer_command(tools, source, request, cfg))


def stop_units(tools, token):
    unit = unit_name(token)
    for suffix in ('.timer', '.service'):
        target = unit + suffix
        info = subprocess.run([tools['systemctl'], 'show', target,
            '--property=LoadState,Transient,Description'], capture_output=True, timeout=10, env=ENV)
        fields = dict(line.split('=', 1) for line in info.stdout.decode('utf-8').splitlines() if '=' in line)
        need(info.returncode in (0, 1))
        if fields.get('LoadState') == 'not-found':
            continue
        need(info.returncode == 0 and fields.get('LoadState') == 'loaded'
             and fields.get('Transient') == 'yes' and fields.get('Description') == unit)
        # Stop only an explicitly tagged transient unit. Names alone are not ownership.
        stopped = subprocess.run([tools['systemctl'], 'stop', target], capture_output=True, timeout=10, env=ENV)
        # A completed --collect service may disappear between inspection and stop.
        state = subprocess.run([tools['systemctl'], 'is-active', '--quiet', target],
                               capture_output=True, timeout=10, env=ENV)
        need(stopped.returncode in (0, 5) and state.returncode in (3, 4))


def wait_file(path, expected=None, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            raw = trusted_read(path)
            if expected is not None:
                if raw == expected:
                    return raw
            else:
                return json.loads(raw)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise ValueError('SYSTEMD_REHEARSAL_RESULT_TIMEOUT')


def _controller(source, request):
    cfg = validate_request(json.loads(trusted_read(request)))
    schedule(system_tools(), source, request, cfg)
    save(Path(request).parent / 'registered', b'REGISTERED')
    time.sleep(30)


def _supervise(parent_pid, parent_namespace, stage, scenario):
    need(scenario in SCENARIOS)
    tools, binaries = system_tools(), e.tools()
    w.guard(parent_pid, parent_namespace, binaries)
    need(e.namespace(1) == parent_namespace)
    need(w.state(binaries) is None)
    source = Path(stage) / 'source'
    folder = Path(stage) / scenario
    folder.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    cfg = dict(schema=PROFILE, scenario=scenario, token=token, parent_pid=parent_pid,
        parent_namespace=parent_namespace, namespace_pid=os.getpid(), isolated_namespace=e.namespace(), sources=pins())
    request = folder / 'request.json'
    save(request, e.canonical(cfg))
    canary = w.TABLE + '_systemd_canary'
    e.execute([binaries['nft'], 'create', 'table', 'inet', canary])
    def canary_state():
        return json.loads(e.execute([binaries['nft'], '--json', '--numeric', 'list', 'table', 'inet', canary]))
    canary_before = canary_state()
    controller = None
    try:
        if scenario == 'collision':
            e.execute([binaries['nft'], 'create', 'table', 'inet', w.TABLE])
            before = w.state(binaries)
            try:
                schedule(tools, source, request, cfg)
            except ValueError:
                pass
            else:
                raise ValueError('COLLISION_NOT_REFUSED')
            need(w.state(binaries) == before)
            for suffix in ('.timer', '.service'):
                absent_unit(tools, unit_name(token) + suffix)
            identity = None
            outcome = OUTCOMES[scenario]
            controller_killed = False
        else:
            if scenario == 'controller_killed':
                code = bootstrap(source) + '\nm._controller(sys.argv[1],sys.argv[2])'
                controller = subprocess.Popen([tools['python3'], '-I', '-B', '-c', code, str(source), str(request)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
                wait_file(folder / 'registered', b'REGISTERED')
            else:
                schedule(tools, source, request, cfg)
            wait_file(folder / 'ready', b'INSTALLED_WITH_WATCHDOG\n')
            identity = wait_file(folder / 'worker-identity.json')
            need(identity['parent_pid'] == 1 and identity['uid'] == 0 and identity['no_new_privs'] is True)
            need(identity['namespace'] == cfg['isolated_namespace'] != parent_namespace)
            w.shape(w.state(binaries), token)
            controller_killed = False
            if controller is not None:
                controller.kill(); controller.wait(timeout=5)
                need(controller.returncode == -signal.SIGKILL)
                controller_killed = True
            if scenario == 'foreign_marker':
                e.execute([binaries['nft'], 'delete', 'table', 'inet', w.TABLE])
                e.execute([binaries['nft'], '--file', '-'], w.batch(secrets.token_hex(16)))
            elif scenario == 'extra_rule':
                e.execute([binaries['nft'], 'add', 'rule', 'inet', w.TABLE, 'output', 'counter', 'accept'])
            changed = w.state(binaries)
            result = wait_file(folder / 'result.json')
            need(result['watchdog_pid'] == identity['pid'] and result['controller_pid'] == result['observed_parent_pid'] == 1)
            need(result['outcome'] == OUTCOMES[scenario])
            outcome = result['outcome']
            if scenario in ('deadline', 'controller_killed'):
                need(w.state(binaries) is None)
            else:
                need(w.state(binaries) == changed)
        need(canary_state() == canary_before)
        report = dict(schema=PROFILE, scope=SCOPE, scenario=scenario, outcome=outcome, worker=identity,
            controller_sigkill_verified=controller_killed, unrelated_canary_unchanged=True,
            isolated_namespace=e.namespace(), parent_namespace=parent_namespace,
            host_rules_applied=False, execution_permission_issued=False)
    except Exception:
        # Status properties only: never echo a command line, journal or raw error.
        try:
            diagnostic = subprocess.run([tools['systemctl'], 'show', unit_name(token) + '.service',
                '--property=Result,ActiveState,SubState,ExecMainStatus,ExecMainCode'],
                capture_output=True, timeout=5, env=ENV)
            fields = {}
            for line in diagnostic.stdout.decode('ascii', errors='replace').splitlines():
                key, sep, value = line.partition('=')
                if sep and key in ('Result','ActiveState','SubState','ExecMainStatus','ExecMainCode'):
                    fields[key] = value[:80]
            print('SYSTEMD_UNIT_DIAGNOSTIC:' + json.dumps(fields, sort_keys=True), file=sys.stderr, flush=True)
        except Exception:
            pass
        raise
    finally:
        if controller is not None and controller.poll() is None:
            controller.kill(); controller.wait(timeout=5)
        stop_units(tools, token)
        w.guard(parent_pid, parent_namespace, binaries)
        # Disposable-namespace test teardown, never a claim of guarded recovery.
        if w.state(binaries) is not None:
            e.execute([binaries['nft'], 'delete', 'table', 'inet', w.TABLE])
        e.execute([binaries['nft'], 'delete', 'table', 'inet', canary])
    report['transient_units_stopped'] = True
    print(json.dumps(report, sort_keys=True), flush=True)


def table_inventory(binaries):
    raw = json.loads(e.execute([binaries['nft'], '--json', '--numeric', 'list', 'tables']))
    return sorted((x['table']['family'], x['table']['name']) for x in raw['nftables'] if 'table' in x)


def rehearse(acknowledge=False):
    need(acknowledge is True)
    e.require_root()
    need(Path('/proc/1/comm').read_text().strip() == 'systemd')
    tools, binaries = system_tools(), e.tools()
    parent_namespace = e.namespace()
    need(parent_namespace == e.namespace(1))
    before = table_inventory(binaries)
    source_pins = pins()
    stage = Path(tempfile.mkdtemp(prefix='veritas-systemd-egress-', dir='/run'))
    source = stage / 'source'
    source.mkdir(mode=0o700)
    reports = []
    try:
        for name in MODULES:
            original = Path(__file__).parent / (name + '.py')
            raw = original.read_bytes()
            need(e.sha(raw) == source_pins[name])
            save(source / (name + '.py'), raw)
        code_prefix = bootstrap(source)
        for scenario in SCENARIOS:
            code = code_prefix + '\nm._supervise(' + repr(os.getpid()) + ',' + repr(parent_namespace) + ',' + repr(str(stage)) + ',' + repr(scenario) + ')'
            result = subprocess.run([binaries['unshare'], '--net', '--', tools['python3'], '-I', '-B', '-c', code],
                                    capture_output=True, timeout=45, env=ENV)
            if result.returncode != 0:
                for line in result.stderr.decode('utf-8', errors='replace').splitlines():
                    if line.startswith('SYSTEMD_UNIT_DIAGNOSTIC:'):
                        print(line[:1024], file=sys.stderr, flush=True)
                raise ValueError('SYSTEMD_ISOLATED_CHILD_STOP')
            report = json.loads(result.stdout)
            need(report['outcome'] == OUTCOMES[scenario] and report['transient_units_stopped'] is True)
            reports.append(report)
        need(e.namespace() == parent_namespace and table_inventory(binaries) == before)
    except Exception:
        # Retain root-private stage for bounded failure diagnosis. No broad cleanup.
        raise ValueError('NATIVE_SYSTEMD_EGRESS_REHEARSAL_STOP') from None
    else:
        shutil.rmtree(stage)  # Only our fresh /run stage, after all exact units stopped.
    report = dict(schema=PROFILE, scope=SCOPE, source_sha256=source_sha256(), source_pins=source_pins,
        scenarios=reports, parent_namespace_before=parent_namespace, parent_namespace_after=e.namespace(),
        parent_table_names_unchanged=True, transient_units_stopped=True, private_stage_removed=True,
        host_rules_applied=False, host_transient_systemd_units_created=True,
        host_rule_contents_attested=False, execution_permission_issued=False,
        provider_requests=0, provider_dispatch='DENY', utility='UNSCORED',
        systemd_version=e.execute([tools['systemd-run'], '--version']).decode('ascii').splitlines()[0])
    return validate_report(report)


def validate_report(report):
    need(type(report) is dict and report['schema'] == PROFILE and report['scope'] == SCOPE)
    need(report['source_sha256'] == source_sha256() and report['source_pins'] == pins())
    need(report['parent_namespace_before'] == report['parent_namespace_after'])
    for key in ('parent_table_names_unchanged', 'transient_units_stopped', 'private_stage_removed',
                'host_transient_systemd_units_created'):
        need(report[key] is True)
    for key in ('host_rules_applied', 'host_rule_contents_attested', 'execution_permission_issued'):
        need(report[key] is False)
    need(type(report['provider_requests']) is int and report['provider_requests'] == 0)
    need(report['provider_dispatch'] == 'DENY' and report['utility'] == 'UNSCORED')
    rows = report['scenarios']
    need(type(rows) is list and len(rows) == len(SCENARIOS))
    need([r['scenario'] for r in rows] == list(SCENARIOS))
    for row in rows:
        need(row['schema'] == PROFILE and row['scope'] == SCOPE)
        scenario = row['scenario']
        need(row['outcome'] == OUTCOMES[scenario])
        need(row['unrelated_canary_unchanged'] is row['transient_units_stopped'] is True)
        need(row['host_rules_applied'] is row['execution_permission_issued'] is False)
        need(row['controller_sigkill_verified'] is (scenario == 'controller_killed'))
        need(row['parent_namespace'] == report['parent_namespace_before'])
        need(row['isolated_namespace'] != row['parent_namespace'])
        if scenario == 'collision':
            need(row['worker'] is None)
        else:
            identity = row['worker']
            need(type(identity['pid']) is int and identity['pid'] > 1)
            need(type(identity['parent_pid']) is int and identity['parent_pid'] == 1)
            need(type(identity['uid']) is int and identity['uid'] == 0)
            need(identity['no_new_privs'] is True and identity['sources'] == pins())
            need(identity['namespace'] == row['isolated_namespace'])
    need(type(report['systemd_version']) is str and report['systemd_version'].startswith('systemd '))
    return report


def plan():
    return dict(schema=PROFILE, scope=SCOPE, source_pins=pins(), target_uids=e.DENIED,
        scenarios=list(SCENARIOS), host_apply_supported=False, reboot_recovery_proven=False,
        privileged_concurrent_mutation_safe=False, execution_permission_issued=False,
        provider_dispatch='DENY', utility='UNSCORED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'rehearse'))
    parser.add_argument('--acknowledge-isolated-systemd-test', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'plan':
            need(not args.acknowledge_isolated_systemd_test)
            result = plan()
        else:
            result = rehearse(args.acknowledge_isolated_systemd_test)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except Exception:
        print('NATIVE_SYSTEMD_EGRESS_STOP', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

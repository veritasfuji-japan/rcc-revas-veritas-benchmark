"""Pure report/guard checks plus mandatory real root-capable network rehearsal."""
import copy
import json
import os
from pathlib import Path
import subprocess

import pytest
from scripts import task4_native_egress_rehearsal_v1 as t


def record(role, uid, version, protocol, success):
    value = dict(role=role, uid=uid, gid=t.GIDS[uid], version=version, protocol=protocol,
                effective_capabilities=0, no_new_privs=True,
                result='SUCCESS' if success else 'SOCKET_ERROR', errno=None if success else 13)
    if not success:
        ordinal = t.FLOWS.index((version, protocol))
        value.update(kernel_packets_before=ordinal, kernel_packets_after=ordinal + 1)
    return value


def phase(roles, success):
    return [record(role, uid, version, protocol, success)
            for role, uid in roles.items() for version, protocol in t.FLOWS]


@pytest.fixture
def report():
    # Synthetic public report shape only; this fixture is never kernel evidence.
    all_roles = {**t.DENIED, **t.CONTROLS}
    return dict(schema=t.PROFILE, scope=t.SCOPE, action='rehearse', plan=t.plan(), source_sha256=t.source_sha256(),
        parent_namespace_before=dict(device=4, inode=1), parent_namespace_after=dict(device=4, inode=1),
        isolated_namespace=dict(device=4, inode=2), isolated_links=['lo'], isolated_rules_applied=True,
        kernel_release='SYNTHETIC_SHAPE_FIXTURE', tool_versions={name: 'SYNTHETIC_SHAPE_FIXTURE' for name in t.TOOLS},
        isolated_table_removed=True, phases=dict(baseline=phase(all_roles, True), denied=phase(t.DENIED, False),
            exempt_controls=phase(t.CONTROLS, True), after_local_table_removal=phase(all_roles, True)),
        kernel_denial_packets={str(uid): 4 for uid in t.DENIED.values()}, limitations=t.limitations())


def test_plan_has_exact_five_uid_ipv4_ipv6_scope_and_excludes_signer_reader_root(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('plan executed a tool'))
    value = t.plan()
    assert value['target_uids'] == dict(backend=61103, issuer=61105, custody=61106, archive=61107, runtime=61108)
    assert value['positive_control_uids'] == dict(service=109, reader=61109, administrator=0)
    assert not set(value['target_uids'].values()) & set(value['positive_control_uids'].values())
    assert value['rule_family'] == 'inet' and value['rule_hook'] == 'output'
    assert value['rule_text'].count('meta skuid ') == 5
    assert value['rule_text'].count('counter reject with icmpx type admin-prohibited') == 5
    assert 'flush ruleset' not in value['rule_text'] and 'include ' not in value['rule_text']
    assert value['rule_sha256'] == t.sha(value['rule_text'].encode('ascii'))
    assert value['host_apply_supported'] is False
    assert value['limitations']['host_rules_applied'] is value['limitations']['operator_host_egress_verified'] is False


@pytest.mark.parametrize('uid,gid,ack', [(1, 0, True), (0, 1, True), (0, 0, False), (0, 0, 1)])
def test_root_and_explicit_ack_before_namespace_or_tools(monkeypatch, uid, gid, ack):
    monkeypatch.setattr(os, 'geteuid', lambda: uid)
    monkeypatch.setattr(os, 'getegid', lambda: gid)
    monkeypatch.setattr(t, 'tools', lambda: pytest.fail('tools before authorization'))
    with pytest.raises(ValueError):
        t.rehearse(ack)


@pytest.mark.parametrize('fault', ['same', 'changed-parent', 'wrong-pid', 'bool-pid'])
def test_namespace_guard_refuses_before_any_nft_call(monkeypatch, fault):
    monkeypatch.setattr(t, 'require_root', lambda: None)
    before = dict(device=4, inode=1)
    monkeypatch.setattr(t, 'namespace', lambda pid='self': dict(device=4, inode=1 if fault == 'same' else 2))
    monkeypatch.setattr(t, 'execute', lambda *a, **k: pytest.fail('tool executed before namespace guard'))
    pid = os.getpid() if fault == 'wrong-pid' else True if fault == 'bool-pid' else 123
    with pytest.raises(ValueError):
        t.guard(pid, before, {'ip': '/ip'})


def test_namespace_guard_refuses_external_link_even_in_another_namespace(monkeypatch):
    monkeypatch.setattr(t, 'require_root', lambda: None)
    before = dict(device=4, inode=1)
    monkeypatch.setattr(t, 'namespace', lambda pid='self': before if pid == 123 else dict(device=4, inode=2))
    def execute(argv):
        assert argv == ['/ip', '-j', 'link', 'show']
        return b'[{"ifname":"lo"},{"ifname":"eth0"}]'
    monkeypatch.setattr(t, 'execute', execute)
    with pytest.raises(ValueError):
        t.guard(123, before, {'ip': '/ip'})


def test_valid_shape_is_still_a_rehearsal_without_host_or_execution_permission(report):
    assert t.validate_report(report) == report
    assert len(report['phases']['denied']) == 20
    assert len(report['phases']['exempt_controls']) == 12
    assert len(report['phases']['baseline']) == len(report['phases']['after_local_table_removal']) == 32
    for key, value in report['limitations'].items():
        assert value == ('DENY' if key == 'provider_dispatch' else 'UNSCORED' if key == 'utility' else False)


@pytest.mark.parametrize('fault', ['scope', 'schema', 'source', 'extra', 'same-namespace', 'parent-changed',
    'no-apply', 'no-remove', 'host-egress-claim', 'host-apply-claim', 'reader-claim', 'live',
    'other-interface', 'bool-inode', 'bad-rule', 'missing-counter', 'zero-counter'])
def test_report_cannot_promote_or_omit_namespace_and_counter_boundaries(report, fault):
    if fault == 'scope':
        report['scope'] = 'PRODUCTION'
    elif fault == 'schema':
        report['schema'] = 'OTHER'
    elif fault == 'source':
        report['source_sha256'] = '0' * 64
    elif fault == 'extra':
        report['host_rules_applied'] = True
    elif fault == 'same-namespace':
        report['isolated_namespace'] = report['parent_namespace_before']
    elif fault == 'parent-changed':
        report['parent_namespace_after']['inode'] = 3
    elif fault == 'no-apply':
        report['isolated_rules_applied'] = False
    elif fault == 'no-remove':
        report['isolated_table_removed'] = False
    elif fault == 'host-egress-claim':
        report['limitations']['operator_host_egress_verified'] = True
    elif fault == 'host-apply-claim':
        report['limitations']['host_rules_applied'] = True
    elif fault == 'reader-claim':
        report['limitations']['reader_github_egress_restricted'] = True
    elif fault == 'live':
        report['limitations']['execution_permission_issued'] = True
    elif fault == 'other-interface':
        report['isolated_links'] = ['lo', 'eth0']
    elif fault == 'bool-inode':
        report['isolated_namespace']['inode'] = True
    elif fault == 'bad-rule':
        report['plan']['rule_text'] += 'flush ruleset\n'
    elif fault == 'missing-counter':
        del report['kernel_denial_packets']['61103']
    else:
        report['kernel_denial_packets']['61103'] = 0
    with pytest.raises(ValueError):
        t.validate_report(report)


@pytest.mark.parametrize('fault', ['timeout', 'no-route', 'refused', 'success', 'missing-flow', 'duplicate-flow',
    'uid', 'gid', 'caps', 'new-privs', 'bool-version', 'bool-uid', 'missing-baseline', 'failed-exempt', 'failed-removal'])
def test_only_matched_administrative_denials_and_positive_controls_count(report, fault):
    row = report['phases']['denied'][0]
    if fault == 'timeout':
        row['errno'] = None
    elif fault == 'no-route':
        row['errno'] = 101
    elif fault == 'refused':
        row['errno'] = 111
    elif fault == 'success':
        row.update(result='SUCCESS', errno=None)
    elif fault == 'missing-flow':
        report['phases']['denied'].pop()
    elif fault == 'duplicate-flow':
        report['phases']['denied'][1] = copy.deepcopy(row)
    elif fault == 'uid':
        row['uid'] = 61109
    elif fault == 'gid':
        row['gid'] = 0
    elif fault == 'caps':
        row['effective_capabilities'] = 1
    elif fault == 'new-privs':
        row['no_new_privs'] = False
    elif fault == 'bool-version':
        row['version'] = True
    elif fault == 'bool-uid':
        row['uid'] = True
    elif fault == 'missing-baseline':
        report['phases']['baseline'].pop()
    elif fault == 'failed-exempt':
        report['phases']['exempt_controls'][0].update(result='SOCKET_ERROR', errno=13)
    else:
        report['phases']['after_local_table_removal'][0].update(result='SOCKET_ERROR', errno=13)
    with pytest.raises(ValueError):
        t.validate_report(report)


def kernel_listing():
    return {'nftables': [{'rule': dict(family='inet', table=t.TABLE, chain='output', expr=[
        {'match': {'op': '==', 'left': {'meta': {'key': 'skuid'}}, 'right': uid}},
        {'counter': {'packets': 4, 'bytes': 256}}, {'reject': {'type': 'icmpx', 'expr': 'admin-prohibited'}}])}
        for uid in t.DENIED.values()]}


def test_kernel_json_counter_join_uses_numeric_socket_uid():
    assert t.counters(t.canonical(kernel_listing())) == {uid: 4 for uid in t.DENIED.values()}


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'uid', 'owner-name', 'input-hook', 'family', 'table', 'negative', 'bool-packets'])
def test_wrong_kernel_counter_join_stops(fault):
    value = kernel_listing()
    row = value['nftables'][0]['rule']
    if fault == 'missing':
        value['nftables'].pop()
    elif fault == 'duplicate':
        value['nftables'].append(copy.deepcopy(value['nftables'][0]))
    elif fault == 'uid':
        row['expr'][0]['match']['right'] = 109
    elif fault == 'owner-name':
        row['expr'][0]['match']['right'] = '61103'
    elif fault == 'input-hook':
        row['chain'] = 'input'
    elif fault == 'family':
        row['family'] = 'ip'
    elif fault == 'table':
        row['table'] = 'host-table'
    elif fault == 'negative':
        row['expr'][1]['counter']['packets'] = -1
    else:
        row['expr'][1]['counter']['packets'] = True
    with pytest.raises(ValueError):
        t.counters(t.canonical(value))


def test_cli_plan_does_not_claim_or_apply_host_rules(capsys):
    assert t.main(['plan']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['limitations']['host_rules_applied'] is False
    assert result['limitations']['operator_host_egress_verified'] is False


def test_cli_failure_sanitizes_exception_and_has_no_fallback(monkeypatch, capsys):
    calls = []
    def fail(ack):
        calls.append(ack)
        raise RuntimeError('DO_NOT_LEAK_RAW_ERROR')
    monkeypatch.setattr(t, 'rehearse', fail)
    assert t.main(['rehearse', '--acknowledge-isolated-network-test']) == 1
    out = capsys.readouterr()
    assert out.out == '' and out.err.strip() == t.STOP and calls == [True]


def test_actual_network_namespace_uid_tcp_udp_ipv4_ipv6_rehearsal(monkeypatch, record_property):
    caps = int(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')), 16)
    if os.geteuid() != 0 or not all(caps & (1 << bit) for bit in (6, 7, 12, 21)):
        pytest.skip('requires disposable root CI with setuid/setgid/net-admin/sys-admin')
    # Capture only public isolated-probe diagnostics on failure. The CLI still
    # emits its constant STOP, and subprocess arguments/environment are unchanged.
    original_run = subprocess.run
    failures = []
    def observed_run(*args, **kwargs):
        completed = original_run(*args, **kwargs)
        if completed.returncode:
            failures.append(completed.stderr.decode('utf-8', errors='replace')[-8000:])
        return completed
    monkeypatch.setattr(subprocess, 'run', observed_run)
    before = t.namespace()
    try:
        result = t.rehearse(True)
    except Exception as error:
        pytest.fail(type(error).__name__ + ': ' + str(error) + '\n' + '\n'.join(failures))
    assert t.namespace() == before
    assert t.validate_report(result) == result
    assert len(result['phases']['denied']) == 20
    assert all(x['errno'] in ((1, 13, 113) if x['version'] == 4 else (1, 13)) for x in result['phases']['denied'])
    assert all(x['kernel_packets_after'] > x['kernel_packets_before'] for x in result['phases']['denied'])
    record_property('isolated_rehearsal_json', t.canonical(result).decode('ascii'))
    assert len(result['phases']['exempt_controls']) == 12
    assert result['parent_namespace_before'] == result['parent_namespace_after'] == before
    assert result['isolated_namespace'] != before
    assert result['limitations']['host_rules_applied'] is False


def test_missing_tool_does_not_attempt_package_install_or_unshare(monkeypatch):
    monkeypatch.setattr(t.shutil, 'which', lambda name: None)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('automatic tool install/fallback'))
    with pytest.raises(ValueError):
        t.tools()


def test_world_writable_tool_is_not_executed(tmp_path, monkeypatch):
    file = tmp_path / 'tool'
    file.write_text('UNTRUSTED')
    file.chmod(0o777)
    monkeypatch.setattr(t.shutil, 'which', lambda name: str(file))
    with pytest.raises(ValueError):
        t.tools()


def test_writable_tool_ancestor_is_not_trusted_even_with_root_owned_binary(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import stat
    file = tmp_path / 'tool'
    file.write_text('UNTRUSTED_ANCESTOR')
    file.chmod(0o755)
    monkeypatch.setattr(t.shutil, 'which', lambda name: str(file))
    monkeypatch.setattr(Path, 'stat', lambda path, **kw: SimpleNamespace(
        st_mode=(stat.S_IFREG | 0o755) if path == file else (stat.S_IFDIR | 0o777), st_uid=0))
    with pytest.raises(ValueError):
        t.tools()


@pytest.mark.parametrize('fault', ['nonzero', 'oversized'])
def test_failed_or_unbounded_command_is_not_a_successful_rehearsal(monkeypatch, fault):
    from types import SimpleNamespace
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: SimpleNamespace(
        returncode=1 if fault == 'nonzero' else 0,
        stdout=b'x' * (t.LIMIT + 1) if fault == 'oversized' else b'', stderr=b'RAW_FAILURE'))
    with pytest.raises(ValueError):
        t.execute(['/never/run'])


def test_ipv4_admin_error_113_requires_positive_kernel_counter_and_all_controls(report):
    report['phases']['denied'][0]['errno'] = 113
    assert t.validate_report(report) == report


@pytest.mark.parametrize('fault', ['no-hit', 'negative-before', 'bool-after', 'decreasing', 'final-mismatch', 'ipv6-113'])
def test_errno_alone_or_unmatched_counter_cannot_prove_denial(report, fault):
    row = report['phases']['denied'][0]
    row['errno'] = 113
    if fault == 'no-hit':
        row['kernel_packets_after'] = row['kernel_packets_before']
    elif fault == 'negative-before':
        row['kernel_packets_before'] = -1
    elif fault == 'bool-after':
        row['kernel_packets_after'] = True
    elif fault == 'decreasing':
        report['phases']['denied'][1].update(kernel_packets_before=0, kernel_packets_after=1)
    elif fault == 'final-mismatch':
        report['phases']['denied'][3]['kernel_packets_after'] = 10
    else:
        report['phases']['denied'][1]['errno'] = 113
    with pytest.raises(ValueError):
        t.validate_report(report)

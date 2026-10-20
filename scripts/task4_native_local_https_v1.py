"""Closed local TLS for the existing eight-request Native/Custody/Bind proof.

This is local CA/hosts enrollment, never public Provider identity or inference.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import stat
import xml.etree.ElementTree as ET

from scripts import task4_default_https_denial_v1 as tls
from scripts import ci_mock_executor_authority_boundary_v1 as kernel

NAME, IP, PORT = tls.NAME, tls.IP, tls.PORT
MARKER = 'native-local-https-v1'
need, canonical, digest = kernel.need, kernel.canonical, kernel.digest


def enabled(base):
    file = base / 'public/local-https'
    if not file.exists():
        return False
    info = file.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o444
         and file.read_text() == MARKER, 'ROOT_ENROLLED_LOCAL_TLS_ONLY')
    return True


def enroll(base):
    file = base / 'public/local-https'
    file.write_text(MARKER)
    os.chmod(file, 0o444)
    pins = tls.certificates(base)
    for file in (base / 'backend').glob('*.pem'):
        os.chown(file, kernel.BACKEND, kernel.BACKEND)
        os.chmod(file, 0o600)
    return pins


def call(base, method, path, body, key):
    need(enabled(base), 'ENROLLED_NATIVE_TLS_TRANSPORT')
    tls.resolved_local()
    context = ssl.create_default_context()
    need(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'VERIFIED_NATIVE_TLS_CONTEXT')
    conn = http.client.HTTPSConnection(NAME, PORT, timeout=5, context=context)
    try:
        conn.connect()
        peer = {'leaf_sha256': tls.sha(conn.sock.getpeercert(binary_form=True)),
                'tls_version': conn.sock.version(), 'peer_ip': conn.sock.getpeername()[0]}
        need(peer['peer_ip'] == IP, 'ENROLLED_NATIVE_TLS_PEER_ONLY')
        raw = canonical(body) if body is not None else None
        conn.request(method, path, body=raw, headers={'Content-Type': 'application/json',
            'X-Mock-Auth': kernel.tag(key, b'TASK4_NATIVE_HTTP_V1\0',
                {'method': method, 'path': path, 'body': body}) if key else ''})
        response = conn.getresponse()
        content = response.read(256001)
        from scripts.task4_native_os_custody_v1 import parse
        value = parse(content)
        if os.geteuid() == kernel.CUSTODY:
            tls.append(base / 'custody/tls-peers.jsonl', dict(peer, method=method, path=path,
                status=response.status, body_sha256=tls.sha(raw) if raw is not None else None,
                response_sha256=tls.sha(content), hostname=NAME, port=PORT,
                certificate_required=True, hostname_checked=True))
        return response.status, value
    finally:
        conn.close()


def server_class(base):
    from http.server import HTTPServer
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(base / 'backend/cert.pem', base / 'backend/key.pem')
    context.set_servername_callback(lambda _, name, __: tls.append(base / 'backend/tls-events.jsonl',
        {'event': 'SNI', 'hostname': name}))

    class Server(HTTPServer):
        def get_request(self):
            conn, address = super().get_request()
            conn.settimeout(5)
            try:
                return context.wrap_socket(conn, server_side=True), address
            except ssl.SSLError:
                conn.close()
                tls.append(base / 'backend/tls-events.jsonl', {'event': 'TLS_HANDSHAKE_FAILED'})
                raise
    return Server


def observe(base, handler, raw, decision, record=None, response=None):
    if enabled(base):
        tls.append(base / 'backend/native-tls-posts.jsonl', dict(method='POST', path=handler.path,
            host=handler.headers.get('Host'), body_sha256=tls.sha(raw), decision=decision,
            tls_version=handler.connection.version(), record=record,
            response_sha256=digest(response if response is not None else {'decision': 'DENIED'})))


def topology(client, sink, isolated, left, right, namespaces, directories, rule):
    for ns in (isolated, sink, client):
        kernel.command(['ip', 'netns', 'add', ns])
        namespaces.append(ns)
        kernel.command(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
        folder = Path('/etc/netns') / ns
        need(not folder.exists(), 'NEW_NATIVE_TLS_NETNS_CONFIG')
        folder.mkdir(parents=True)
        directories.append(folder)
        (folder / 'hosts').write_text('127.0.0.1 localhost\n' + IP + ' ' + NAME + '\n')
        os.chmod(folder / 'hosts', 0o444)
    kernel.command(['ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
    kernel.command(['ip', 'link', 'set', left, 'netns', client])
    kernel.command(['ip', 'link', 'set', right, 'netns', sink])
    for ns, interface, addr in [(client, left, '10.249.94.1/30'), (sink, right, IP + '/30')]:
        kernel.command(['ip', '-n', ns, 'addr', 'add', addr, 'dev', interface])
        kernel.command(['ip', '-n', ns, 'link', 'set', interface, 'up'])
    kernel.command(['ip', 'netns', 'exec', sink, 'sysctl', '-w', 'net.ipv4.ip_unprivileged_port_start=0'])
    kernel.command(['ip', 'netns', 'exec', client, 'iptables', '-I'] + rule[:1] + ['1'] + rule[1:])
    kernel.command(['ip', 'netns', 'exec', client, 'iptables', '-C'] + rule)
    result = {}
    for name, ns in [('client', client), ('sink', sink), ('isolated', isolated)]:
        links = json.loads(kernel.command(['ip', '-n', ns, '-j', 'link', 'show']).stdout)
        routes = json.loads(kernel.command(['ip', '-n', ns, '-j', 'route', 'show']).stdout)
        routes6 = json.loads(kernel.command(['ip', '-n', ns, '-6', '-j', 'route', 'show']).stdout)
        need(len(links) == (1 if name == 'isolated' else 2)
             and all(r.get('dst') == '10.249.94.0/30' and 'gateway' not in r for r in routes)
             and not any(r.get('dst') == 'default' or 'gateway' in r for r in routes6), 'NATIVE_TLS_NO_EXTERNAL_ROUTE')
        result[name] = dict(links=[x['ifname'] for x in links], routes=routes, routes6=routes6,
            hosts_sha256=tls.sha((Path('/etc/netns') / ns / 'hosts').read_bytes()))
    return result


def probe(base, phase):
    need(enabled(base), 'ENROLLED_NATIVE_TLS_PROBE')
    if phase == 'bad_ca':
        os.environ['SSL_CERT_FILE'] = str(base / 'public/bad-ca.pem')
    return tls.probe(base, phase)


def negatives(base, worker, client, sink, isolated):
    phases = {}
    for phase, ns in [('isolated', isolated), ('firewall', client), ('bad_ca', client), ('reachable', sink)]:
        phases[phase] = worker(kernel.CUSTODY if phase == 'bad_ca' else kernel.AGENT, 'tls-' + phase, ns)
        if phase != 'reachable':
            need(not tls.read_lines(base / 'backend/native-tls-posts.jsonl'), 'NATIVE_TLS_NEGATIVES_BEFORE_HTTP')
        if phase in {'isolated', 'firewall'}:
            need(not tls.read_lines(base / 'backend/tls-events.jsonl'), 'NATIVE_TLS_OS_DENIAL_BEFORE_HANDSHAKE')
    with sqlite3.connect(base / 'backend/effects.sqlite3') as db:
        need(db.execute('SELECT count(*) FROM effects').fetchone()[0] == 0, 'NATIVE_TLS_NEGATIVE_EFFECTS_ZERO')
    with sqlite3.connect(base / 'custody/ledger.sqlite3') as db:
        need(db.execute('SELECT count(*) FROM consumed').fetchone()[0] == 0, 'NATIVE_TLS_NEGATIVE_CONSUMPTIONS_ZERO')
    return phases


def validate(e, normal, bindings):
    from scripts.task4_native_os_custody_v1 import scope
    need(normal['schema'] == 'task4.native.os-custody.v1' and len(normal['checks']) == 22
         and all(v is True for v in normal['checks'].values()), 'NATIVE_TLS_NORMAL_PROOF_REQUIRED')
    need(normal['mock_http_effects'] == normal['custody_consumptions'] == 8
         and normal['native']['scorer_calls'] == normal['native']['scripted_native_arms'] == 2
         and normal['native']['replay_denials'] == normal['restart']['restart_replay_denials'] == 8,
         'NATIVE_TLS_EIGHT_EFFECTS_TERMINALS_SCORERS_AND_REPLAYS')
    need(e['negative_effects'] == e['negative_consumptions'] == 0, 'NATIVE_TLS_NEGATIVES_ZERO')
    need(set(e['phases']) == {'isolated', 'firewall', 'bad_ca', 'reachable'}, 'EXACT_NATIVE_TLS_PHASES')
    # Enforce the original helper phase/source/audit/error checks here; the
    # separate counter-specific positive validator is not applicable to Native.
    import errno
    for phase, p in e['phases'].items():
        names = ['first'] if phase == 'bad_ca' else list(tls.SOURCES)
        need(p['phase'] == phase and p['resolved_addresses'] == [IP] and p['fixture_sha256'] == tls.FIXTURE_SHA
             and p['helper_git_blobs'] == {k:v[0] for k,v in tls.SOURCES.items()}
             and [x['helper'] for x in p['records']] == names, 'NATIVE_TLS_ORIGINAL_HELPER_SOURCE_AND_INPUTS')
        if phase != 'bad_ca':
            need(set(p['private_reads_denied']) == {'backend/credential', 'backend/key.pem',
                'backend/effects.sqlite3', 'custody/credential'}, 'NATIVE_TLS_PRIVATE_READ_DENIALS')
        for r in p['records']:
            expected = 'CERTIFICATE_VERIFY_FAILED' if phase == 'bad_ca' else 'HTTP_403' if phase == 'reachable' else 'NETWORK_DENIED'
            need(r['decision'] == expected and r['uid'] == (kernel.CUSTODY if phase == 'bad_ca' else kernel.AGENT)
                 and r['request_sha256'] == tls.SOURCES[r['helper']][1] and r['audit'] == [
                 dict(event='HTTPS_CONNECT',hostname=NAME,port=PORT,certificate_required=True,hostname_checked=True),
                 dict(event='SOCKET_CONNECT',ip=IP,port=PORT)], 'NATIVE_TLS_DEFAULT_HELPER_OBSERVATIONS')
            if phase in {'isolated', 'firewall'}:
                need(r.get('network_errno') == (errno.ENETUNREACH if phase == 'isolated' else errno.ECONNREFUSED),
                     'NATIVE_TLS_ACTUAL_NETWORK_ERRNO')
            elif phase == 'bad_ca':
                need(type(r.get('verify_code')) is int and r['verify_code'] > 0, 'NATIVE_TLS_CA_VERIFICATION_DENIAL')
            else:
                need(r.get('http_status') == 403, 'NATIVE_TLS_HELPER_HTTP_DENIAL')
    posts = e['posts']
    need(len(posts) == 12 and [p['decision'] for p in posts] == ['DENIED']*4 + ['EFFECT_COMMITTED']*8,
         'NATIVE_TLS_THREE_HELPERS_ONE_REACHABLE_PROBE_EIGHT_EFFECTS')
    for p, (_, source) in zip(posts[:3], tls.SOURCES.items()):
        need(p['body_sha256'] == source[1] and p['path'] == '/v1/chat/completions' and p['record'] is None,
             'NATIVE_TLS_BACKEND_ORIGINAL_HELPER_BODY')
    need(posts[3]['body_sha256'] == digest({}) and posts[3]['path'] == '/effect'
         and posts[3]['record'] is None, 'NATIVE_TLS_REACHABLE_AUTH_REFUSAL')
    need(all(p['host'] == NAME and p['tls_version'] in {'TLSv1.2','TLSv1.3'} for p in posts), 'NATIVE_TLS_SERVER_HOST_VERSION')
    records = normal['native']['records']
    need(len(records) == 8 and {(r['arm'],r['ordinal']):r['request_sha256'] for r in records} == scope(), 'NATIVE_TLS_FROZEN_EIGHT_REQUESTS')
    peers = e['peers']
    need(peers and all(p['leaf_sha256'] == e['certificates']['leaf_sha256'] and p['peer_ip'] == IP
         and p['hostname'] == NAME and p['port'] == PORT and p['certificate_required'] is True
         and p['hostname_checked'] is True and p['tls_version'] in {'TLSv1.2','TLSv1.3'} and p['status'] == 200
         for p in peers), 'NATIVE_TLS_CUSTODY_VERIFIED_PEER')
    admitted = [p for p in peers if p['method'] == 'POST']
    need(len(admitted) == 8 and len(bindings) == 8 and digest(bindings) == normal['bind_records_sha256'], 'NATIVE_TLS_EXACT_BIND_POST_COUNT')
    need(digest(normal['native']['lineage']) == normal['native']['lineage_sha256']
         and len(normal['native']['lineage']['response_receipts']) == 8, 'NATIVE_TLS_LINEAGE_DIGEST')
    for post, peer, r, binding, line in zip(posts[4:], admitted, records, bindings, normal['native']['lineage']['response_receipts']):
        op = r['arm'] + str(r['ordinal'])
        need(post['path'] == peer['path'] == '/effect' and post['body_sha256'] == peer['body_sha256']
             and post['body_sha256'] == e['packet_sha256'][op]
             and post['response_sha256'] == peer['response_sha256']
             and post['record'] == dict(operation_id=op, request_sha256=r['request_sha256'],response_sha256=r['response_sha256']),
             'NATIVE_TLS_SERVER_CLIENT_INNER_REQUEST_RESPONSE_JOIN')
        need(binding['operation_id'] == op and digest({k:v for k,v in binding.items() if k!='operation_id'}) == r['bind_sha256']
             and [(x['outcome'],x['apply_calls']) for x in binding['records']] == [('BLOCKED',0),('COMMITTED',1)]
             and all(digest(x['receipt']) == x['receipt_sha256'] for x in binding['records'])
             and binding['bind_core_git_blob'] == '0f64201e2599495ce4e3991348aa320995716ffc', 'NATIVE_TLS_ACTUAL_BIND_PER_REQUEST')
        need(line['arm'] == r['arm'] and line['ordinal'] == r['ordinal']
             and line['original_request_raw_sha256'] == r['request_sha256']
             and line['original_response_raw_sha256'] == r['response_sha256'], 'NATIVE_TLS_SCORER_LINEAGE_JOIN')
    events = e['tls_events']
    need(sum(x['event'] == 'TLS_HANDSHAKE_FAILED' for x in events) == 1
         and sum(x['event'] == 'SNI' for x in events) == 5 + len(peers)
         and all(x.get('hostname') == NAME for x in events if x['event']=='SNI'), 'NATIVE_TLS_HANDSHAKE_COUNTS')
    need(set(e['topology']) == {'client','sink','isolated'}, 'NATIVE_TLS_THREE_NAMESPACES')
    for name, t in e['topology'].items():
        need(len(t['links']) == (1 if name=='isolated' else 2)
             and all(r.get('dst') == '10.249.94.0/30' and 'gateway' not in r for r in t['routes'])
             and not any(r.get('dst') == 'default' or 'gateway' in r for r in t['routes6']), 'NATIVE_TLS_CLOSED_TOPOLOGY')
    return True


def finish(base, output, normal, bindings, phases, certificates, network):
    evidence = dict(phases=phases, certificates=certificates, topology=network,
        posts=tls.read_lines(base / 'backend/native-tls-posts.jsonl'), peers=tls.read_lines(base / 'custody/tls-peers.jsonl'),
        tls_events=tls.read_lines(base / 'backend/tls-events.jsonl'), negative_effects=0, negative_consumptions=0,
        packet_sha256={r['arm']+str(r['ordinal']):tls.sha((base / 'native' /
            ('packet-'+r['arm']+str(r['ordinal'])+'.json')).read_bytes()) for r in normal['native']['records']})
    validate(evidence, normal, bindings)
    checks = {name: True for name in ('default_helpers_no_transport_argument', 'six_os_network_denials',
        'three_helper_tls_403_original_body_joins', 'untrusted_ca_before_http', 'private_credentials_and_server_key_denied',
        'reachable_native_tls_without_auth_denied', 'zero_negative_effects_and_consumptions',
        'closed_pair_no_external_gateway', 'same_live_server_for_denials_and_native',
        'eight_native_frozen_requests_over_tls', 'eight_actual_bind_block_commit_pairs',
        'eight_server_client_request_response_joins', 'verified_local_leaf_every_custody_connection',
        'eight_ledger_ciphertext_native_response_joins', 'two_native_terminals_and_scorer_inputs_joined',
        'sixteen_original_and_restart_replays_denied')}
    report = dict(schema='task4.native.local-https.v1', audited_commit=normal['audited_commit'],
        source_sha256=tls.sha(Path(__file__).read_bytes()), normal_source_sha256=normal['source_sha256'],
        normal_report_sha256=digest(normal), evidence=evidence, evidence_sha256=digest(evidence), checks=checks,
        native_task4_tls_pipeline_integrated=True, local_test_ca_not_public_provider_identity=True,
        real_provider_posts=0, external_bank_effects=0, utility='UNSCORED', provider_dispatch='DENY',
        trusted_root_kernel_custody_backend=True, independent_administration_proven=False,
        production_bypass_resistance_proven=False, real_data_confidentiality_proven=False)
    (output / 'native-https.json').write_bytes(canonical(report))
    suite = ET.Element('testsuite', name='Native local HTTPS', tests=str(len(checks)), failures='0', errors='0', skipped='0')
    for name in sorted(checks):
        ET.SubElement(suite, 'testcase', classname='native_local_https', name=name)
    ET.ElementTree(suite).write(output / 'native-https-junit.xml', encoding='utf-8', xml_declaration=True)


def cleanup(directories):
    for directory in reversed(directories):
        shutil.rmtree(directory)

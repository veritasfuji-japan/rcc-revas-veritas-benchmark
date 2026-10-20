"""Unchanged default HTTPS helpers in disposable, externally disconnected netns.

api.openai.com resolves ONLY to the local test TLS sink inside these namespaces.
No Provider credential, transport injection, TLS monkeypatch or external route.
"""
import argparse
import errno
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import ci_mock_executor_authority_boundary_v1 as kernel
from scripts.ci_mock_executor_veritas_bind_v1 import integrate, VERITAS_PIN, CORE_BLOB
from scripts.task4_retained_sender_denial_v1 import inputs, SOURCES, FIXTURE_SHA

ROOT = Path(__file__).resolve().parents[1]
NAME, IP, PORT = 'api.openai.com', '10.249.94.2', 443
BODY = {'operation_id': kernel.OP, 'request': kernel.REQUEST}
DOMAIN = b'TASK4_LOCAL_TLS_ONLY_V1\0'
need, canonical, digest = kernel.need, kernel.canonical, kernel.digest


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def append(file, value):
    with file.open('a') as stream:
        stream.write(canonical(value).decode() + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def read_lines(file):
    return [json.loads(x) for x in file.read_text().splitlines()] if file.exists() else []


def certificates(base):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)

    def authority(label):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
            .sign(key, hashes.SHA256()))
        return key, cert

    ca_key, ca = authority('LOCAL CI ONLY - NEVER PUBLIC PROVIDER')
    _, bad_ca = authority('UNTRUSTED LOCAL NEGATIVE CONTROL')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'LOCAL TEST SINK')]))
        .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256()))
    for filename, value in [('ca.pem', ca), ('bad-ca.pem', bad_ca)]:
        (base / 'public' / filename).write_bytes(value.public_bytes(serialization.Encoding.PEM))
    (base / 'backend/cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (base / 'backend/key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return {'ca_sha256': sha(ca.public_bytes(serialization.Encoding.DER)),
            'leaf_sha256': sha(cert.public_bytes(serialization.Encoding.DER)),
            'bad_ca_sha256': sha(bad_ca.public_bytes(serialization.Encoding.DER))}


def resolved_local():
    addresses = {x[4][0] for x in socket.getaddrinfo(NAME, PORT, type=socket.SOCK_STREAM)}
    need(addresses == {IP}, 'ONLY_ENROLLED_LOCAL_HOST_MAPPING')
    return sorted(addresses)


def credential_tag(key, method, path, body=None):
    return kernel.tag(key, DOMAIN, {'method': method, 'path': path, 'body': body})


def backend(base):
    kernel.role_identity(kernel.BACKEND)
    os.umask(0o077)
    key = (base / 'backend/credential').read_bytes()
    db = sqlite3.connect(base / 'backend/effects.sqlite3', isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE effects (op TEXT PRIMARY KEY,receipt TEXT)')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(base / 'backend/cert.pem', base / 'backend/key.pem')

    def sni(_, name, __):
        append(base / 'backend/tls-events.jsonl', {'event': 'SNI', 'hostname': name})
    context.set_servername_callback(sni)

    class Server(HTTPServer):
        def get_request(self):
            conn, address = super().get_request()
            conn.settimeout(5)
            try:
                return context.wrap_socket(conn, server_side=True), address
            except ssl.SSLError:
                conn.close()
                append(base / 'backend/tls-events.jsonl', {'event': 'TLS_HANDSHAKE_FAILED'})
                raise

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, value):
            data = canonical(value)
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != '/status' or not hmac.compare_digest(self.headers.get('X-Mock-Auth', ''),
                    credential_tag(key, 'GET', self.path)):
                self.reply(403, {'decision': 'DENIED'})
                return
            count = db.execute('SELECT count(*) FROM effects').fetchone()[0]
            self.reply(200, {'counter': count, 'revision': count, 'effect_count': count})

        def do_POST(self):
            raw = b''
            try:
                size = int(self.headers.get('Content-Length', '0'))
                need(self.path == '/v1/chat/completions' and 0 < size <= 64000, 'EXACT_LOCAL_TLS_POST')
                raw = self.rfile.read(size)
                body = json.loads(raw)
                need(hmac.compare_digest(self.headers.get('X-Mock-Auth', ''),
                     credential_tag(key, 'POST', self.path, body)), 'LOCAL_CUSTODY_AUTH_REQUIRED')
                need(body == BODY, 'EXACT_LOCAL_COUNTER_BODY')
                db.execute('INSERT INTO effects VALUES (?,?)', (kernel.OP, digest(BODY)))
            except (ValueError, sqlite3.IntegrityError):
                decision, status, response = 'DENIED', 403, {'decision': 'DENIED'}
            else:
                decision, status, response = 'EFFECT_COMMITTED', 200, {'decision': 'MOCK_EFFECT_ONCE', 'receipt': digest(BODY)}
            append(base / 'backend/http.jsonl', {'method': 'POST', 'path': self.path,
                'host': self.headers.get('Host'), 'body_sha256': sha(raw), 'decision': decision,
                'tls_version': self.connection.version()})
            self.reply(status, response)

    server = Server((IP, PORT), Handler)
    (base / 'backend/ready').write_text('ready')
    server.serve_forever()


def probe(base, phase):
    from scripts import task4_live_first_two_call_capture_oneuse_v1 as first
    from scripts import task4_live_second_two_call_capture_oneuse_v1 as second
    from scripts import task4_live_third_two_call_capture_oneuse_v1 as third
    uid = kernel.CUSTODY if phase == 'bad_ca' else kernel.AGENT
    kernel.role_identity(uid)
    addresses = resolved_local()
    requests = inputs()
    private_denials = []
    if uid == kernel.AGENT:
        for file in ('backend/credential', 'backend/key.pem', 'backend/effects.sqlite3', 'custody/credential'):
            try:
                (base / file).read_bytes()
            except PermissionError:
                private_denials.append(file)
            else:
                raise ValueError('NATIVE_PRIVATE_MATERIAL_ACCESS')
    current = []

    def audit(event, args):
        if event == 'http.client.connect':
            conn, host, port = args
            need(type(conn) is http.client.HTTPSConnection and host == NAME and port == PORT,
                 'ACTUAL_DEFAULT_HTTPS_FACTORY_AND_TARGET')
            need(conn._context.verify_mode == ssl.CERT_REQUIRED and conn._context.check_hostname,
                 'DEFAULT_TLS_VERIFICATION_ENABLED')
            current.append({'event': 'HTTPS_CONNECT', 'hostname': host, 'port': port,
                            'certificate_required': True, 'hostname_checked': True})
        elif event == 'socket.connect':
            _, address = args
            need(address == (IP, PORT), 'ONLY_LOCAL_TLS_SOCKET_ALLOWED')
            current.append({'event': 'SOCKET_CONNECT', 'ip': address[0], 'port': address[1]})

    sys.addaudithook(audit)
    records = []
    for name in ('first',) if phase == 'bad_ca' else SOURCES:
        current.clear()
        request = requests[SOURCES[name][1]]
        try:
            # No transport argument: execute each unchanged default HTTPS factory.
            if name == 'first':
                first.send_exactly_once(request=request, key='synthetic-not-a-provider-key', arm='A',
                                        request_id='task4-v1-A-closed-tls')
            elif name == 'second':
                second.once(request=request, key='synthetic-not-a-provider-key', arm='A',
                            client_request_id='task4-second-v1-A-closed-tls')
            else:
                third.one_post(request=request, key='synthetic-not-a-provider-key', arm='A',
                               client_id='task4-third-v1-A-closed-tls')
        except ssl.SSLCertVerificationError as exc:
            need(phase == 'bad_ca', 'ONLY_UNTRUSTED_CA_CONTROL_FAILS_TLS')
            outcome = {'decision': 'CERTIFICATE_VERIFY_FAILED', 'verify_code': exc.verify_code}
        except OSError as exc:
            need(phase in {'isolated', 'firewall'}, 'REACHABLE_DEFAULT_HELPER_MUST_REACH_TLS')
            outcome = {'decision': 'NETWORK_DENIED', 'network_errno': exc.errno}
        except (first.Blocked, second.Denied, third.Denied) as exc:
            need(phase == 'reachable' and 'HTTP' in str(exc) and '403' in str(exc),
                 'DEFAULT_HELPER_ACTUAL_HTTP_403_REQUIRED')
            outcome = {'decision': 'HTTP_403', 'http_status': 403}
        else:
            raise ValueError('UNAUTHORIZED_DEFAULT_HTTPS_SUCCESS')
        need([x['event'] for x in current] == ['HTTPS_CONNECT', 'SOCKET_CONNECT'],
             'ONE_DEFAULT_FACTORY_AND_REAL_SOCKET_ATTEMPT')
        records.append(dict(helper=name, uid=uid, request_sha256=SOURCES[name][1],
                            audit=list(current), **outcome))
    return {'phase': phase, 'resolved_addresses': addresses, 'records': records,
            'private_reads_denied': private_denials, 'fixture_sha256': FIXTURE_SHA,
            'helper_git_blobs': {k: v[0] for k, v in SOURCES.items()}}


def positive(base):
    kernel.role_identity(kernel.CUSTODY)
    resolved_local()
    key = (base / 'custody/credential').read_bytes()
    with sqlite3.connect(base / 'custody/consumed.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op TEXT PRIMARY KEY)')
        db.execute('INSERT INTO consumed VALUES (?)', (kernel.OP,))
    peers = []

    def call(method, path, body=None):
        conn = http.client.HTTPSConnection(NAME, PORT, timeout=5, context=ssl.create_default_context())
        try:
            conn.connect()
            peers.append({'leaf_sha256': sha(conn.sock.getpeercert(binary_form=True)),
                          'tls_version': conn.sock.version()})
            conn.request(method, path, body=canonical(body) if body is not None else None,
                         headers={'X-Mock-Auth': credential_tag(key, method, path, body)})
            response = conn.getresponse()
            return response.status, json.loads(response.read(64000))
        finally:
            conn.close()

    def status():
        code, value = call('GET', '/status')
        need(code == 200, 'AUTHENTICATED_TLS_STATUS')
        return value

    response, binding = integrate(body=BODY, status=status,
        post=lambda: call('POST', '/v1/chat/completions', BODY))
    return {'response': response, 'binding': binding, 'peer_observations': peers}


def validate(evidence):
    need(set(evidence['phases']) == {'isolated', 'firewall', 'reachable', 'bad_ca'}, 'EXACT_TLS_PHASES')
    for phase, report in evidence['phases'].items():
        need(report['phase'] == phase and report['resolved_addresses'] == [IP]
             and report['fixture_sha256'] == FIXTURE_SHA and report['helper_git_blobs'] ==
             {k: v[0] for k, v in SOURCES.items()}, 'FROZEN_DEFAULT_HTTPS_SOURCE_AND_RESOLUTION')
        expected_names = ['first'] if phase == 'bad_ca' else list(SOURCES)
        need([r['helper'] for r in report['records']] == expected_names, 'ALL_DEFAULT_HELPERS_REQUIRED')
        if phase != 'bad_ca':
            need(set(report['private_reads_denied']) == {'backend/credential', 'backend/key.pem',
                 'backend/effects.sqlite3', 'custody/credential'}, 'PRIVATE_TLS_AND_AUTH_FILES_DENIED')
        for record in report['records']:
            expected = 'CERTIFICATE_VERIFY_FAILED' if phase == 'bad_ca' else 'HTTP_403' if phase == 'reachable' else 'NETWORK_DENIED'
            need(record['decision'] == expected and record['uid'] == (kernel.CUSTODY if phase == 'bad_ca' else kernel.AGENT)
                 and record['request_sha256'] == SOURCES[record['helper']][1], 'DEFAULT_HELPER_OUTCOME_JOIN')
            if phase in {'isolated', 'firewall'}:
                need(record.get('network_errno') == (errno.ENETUNREACH if phase == 'isolated' else errno.ECONNREFUSED),
                     'ACTUAL_LINUX_NETWORK_DENIAL')
            elif phase == 'bad_ca':
                need(type(record.get('verify_code')) is int and record['verify_code'] > 0,
                     'ACTUAL_CERTIFICATE_VERIFICATION_ERROR')
            else:
                need(record.get('http_status') == 403, 'ACTUAL_HTTP_403_STATUS')
            need(record['audit'] == [dict(event='HTTPS_CONNECT', hostname=NAME, port=PORT,
                certificate_required=True, hostname_checked=True), dict(event='SOCKET_CONNECT', ip=IP, port=PORT)],
                'OBSERVED_STANDARD_FACTORY_TLS_AND_LOCAL_SOCKET')
    observations = evidence['http_observations']
    need(len(observations) == 4, 'THREE_DENIED_AND_ONE_ADMITTED_POST')
    for observation, name in zip(observations[:3], SOURCES):
        need(observation == dict(method='POST', path='/v1/chat/completions', host=NAME,
             body_sha256=SOURCES[name][1], decision='DENIED', tls_version=observation['tls_version'])
             and observation['tls_version'] in {'TLSv1.2', 'TLSv1.3'}, 'TLS_BACKEND_ORIGINAL_BODY_DENIAL_JOIN')
    need(observations[3]['body_sha256'] == digest(BODY) and observations[3]['decision'] == 'EFFECT_COMMITTED'
         and observations[3]['host'] == NAME and observations[3]['path'] == '/v1/chat/completions'
         and observations[3]['tls_version'] in {'TLSv1.2', 'TLSv1.3'}, 'TLS_POSITIVE_COUNTER_POST_JOIN')
    need(evidence['effects'] == [[kernel.OP, digest(BODY)]] and evidence['consumed'] == [[kernel.OP]],
         'ONE_DURABLE_TLS_EFFECT_AND_CONSUMPTION')
    binding = evidence['positive']['binding']
    need(evidence['positive']['response'] == {'decision': 'MOCK_EFFECT_ONCE', 'receipt': digest(BODY)},
         'EXACT_TLS_POSITIVE_RECEIPT')
    need(binding['veritas_pin'] == VERITAS_PIN and binding['authenticated_effect_posts'] == 1
         and binding['bind_core_git_blob'] == CORE_BLOB and binding['bind_executor_uid'] == kernel.CUSTODY
         and binding['request_sha256'] == digest(BODY)
         and binding['backend_receipt_sha256'] == digest(BODY)
         and [(r['outcome'], r['apply_calls']) for r in binding['records']] == [('BLOCKED', 0)]*3 + [('COMMITTED', 1)]
         and all(digest(r['bind_receipt']) == r['receipt_sha256'] for r in binding['records']), 'ACTUAL_BIND_TLS_JOIN')
    need(evidence['positive']['peer_observations'] and all(p['leaf_sha256'] == evidence['certificates']['leaf_sha256']
         and p['tls_version'] in {'TLSv1.2', 'TLSv1.3'} for p in evidence['positive']['peer_observations']),
         'AUTHENTICATED_LOCAL_LEAF_FINGERPRINT')
    need(sum(x['event'] == 'TLS_HANDSHAKE_FAILED' for x in evidence['tls_observations']) == 1
         and sum(x['event'] == 'SNI' for x in evidence['tls_observations']) == 4 + len(evidence['positive']['peer_observations'])
         and all(x.get('hostname') == NAME for x in evidence['tls_observations'] if x['event'] == 'SNI'),
         'UNTRUSTED_CA_CONTROL_REJECTED_BEFORE_HTTP')
    return True


def run(output):
    need(os.geteuid() == 0 and sys.platform == 'linux', 'DISPOSABLE_LINUX_ROOT_ONLY')
    need(not output.exists() and output.resolve().is_relative_to(ROOT), 'NEW_CHECKOUT_OUTPUT_ONLY')
    for uid in (kernel.AGENT, kernel.CUSTODY, kernel.BACKEND):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise ValueError('RESERVED_UID_IN_USE')
    git = ['git', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT)]
    head = kernel.command(git + ['rev-parse', 'HEAD']).stdout.strip()
    pin_root = ROOT / '_pins/veritas'
    need(kernel.command(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root),
         'rev-parse', 'HEAD']).stdout.strip() == VERITAS_PIN, 'EXACT_BIND_EXTERNAL_PIN')
    kernel.command(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root), 'diff', '--exit-code', 'HEAD'])
    inputs()
    output.mkdir(parents=True)
    token = secrets.token_hex(4)
    client_ns, sink_ns, isolated_ns = ['t' + prefix + token for prefix in ('c', 's', 'i')]
    left, right = 'a' + token, 'b' + token
    namespaces, directories, processes = [], [], []
    rule = ['OUTPUT', '-d', IP, '-p', 'tcp', '--dport', str(PORT), '-m', 'owner',
            '!', '--uid-owner', str(kernel.CUSTODY), '-j', 'REJECT']
    with tempfile.TemporaryDirectory(prefix='task4-closed-tls-') as temporary:
        base = Path(temporary)
        os.chmod(base, 0o755)
        for name, uid in [('public', 0), ('backend', kernel.BACKEND), ('custody', kernel.CUSTODY)]:
            folder = base / name
            folder.mkdir(mode=0o755 if uid == 0 else 0o700)
            os.chown(folder, uid, uid)
        certs = certificates(base)
        credential = secrets.token_bytes(32)
        for name, uid in [('backend', kernel.BACKEND), ('custody', kernel.CUSTODY)]:
            file = base / name / 'credential'
            file.write_bytes(credential)
            for child in (base / name).iterdir():
                os.chown(child, uid, uid)
                os.chmod(child, 0o600)
        source = base / 'source'

        def export(command, target):
            target.mkdir(parents=True)
            raw = subprocess.run(command, capture_output=True, check=True, timeout=30).stdout
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                for member in archive.getmembers():
                    file = target / member.name
                    need(file.resolve().is_relative_to(target) and (member.isfile() or member.isdir()), 'TRACKED_REGULAR_SOURCE')
                    if member.isdir():
                        file.mkdir(parents=True, exist_ok=True)
                    else:
                        file.parent.mkdir(parents=True, exist_ok=True)
                        file.write_bytes(archive.extractfile(member).read())

        export(git + ['archive', 'HEAD'], source)
        export(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root),
                'archive', VERITAS_PIN, 'veritas_os'], source / '_pins/veritas')
        for file in source.rglob('*'):
            os.chmod(file, 0o555 if file.is_dir() else 0o444)
        os.chmod(source, 0o555)
        code = 'import sys;sys.path[:0]=' + repr([str(source), str(source / '_pins/veritas')]) + ';from scripts.task4_default_https_denial_v1 import main;main()'

        def command(uid, role, namespace, bad_ca=False):
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'SSL_CERT_FILE': str(base / 'public' / ('bad-ca.pem' if bad_ca else 'ca.pem'))}
            args = ['ip', 'netns', 'exec', namespace, 'setpriv', '--reuid=' + str(uid), '--regid=' + str(uid),
                    '--clear-groups', '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    sys.executable, '-I', '-c', code, '--role', role, '--base', str(base)]
            return args, env

        def worker(uid, role, namespace, bad_ca=False):
            args, env = command(uid, role, namespace, bad_ca)
            p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=120)
            need(p.returncode == 0, 'TLS_ROLE_FAILED:' + role + ':' + p.stderr[-2500:])
            return json.loads(p.stdout)

        try:
            for ns in (client_ns, sink_ns, isolated_ns):
                kernel.command(['ip', 'netns', 'add', ns])
                namespaces.append(ns)
                kernel.command(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
                folder = Path('/etc/netns') / ns
                need(not folder.exists(), 'NEW_PRIVATE_NETNS_CONFIG')
                folder.mkdir(parents=True)
                directories.append(folder)
                (folder / 'hosts').write_text('127.0.0.1 localhost\n' + IP + ' ' + NAME + '\n')
                os.chmod(folder / 'hosts', 0o444)
            kernel.command(['ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
            kernel.command(['ip', 'link', 'set', left, 'netns', client_ns])
            kernel.command(['ip', 'link', 'set', right, 'netns', sink_ns])
            for ns, interface, address in [(client_ns, left, '10.249.94.1/30'), (sink_ns, right, IP + '/30')]:
                kernel.command(['ip', '-n', ns, 'addr', 'add', address, 'dev', interface])
                kernel.command(['ip', '-n', ns, 'link', 'set', interface, 'up'])
            kernel.command(['ip', 'netns', 'exec', sink_ns, 'sysctl', '-w', 'net.ipv4.ip_unprivileged_port_start=0'])
            kernel.command(['ip', 'netns', 'exec', client_ns, 'iptables', '-I'] + rule[:1] + ['1'] + rule[1:])
            kernel.command(['ip', 'netns', 'exec', client_ns, 'iptables', '-C'] + rule)
            topology = {}
            for name, ns in [('client', client_ns), ('sink', sink_ns), ('isolated', isolated_ns)]:
                links = json.loads(kernel.command(['ip', '-n', ns, '-j', 'link', 'show']).stdout)
                routes = json.loads(kernel.command(['ip', '-n', ns, '-j', 'route', 'show']).stdout)
                routes6 = json.loads(kernel.command(['ip', '-n', ns, '-6', '-j', 'route', 'show']).stdout)
                need(len(links) == (1 if name == 'isolated' else 2)
                     and all(r.get('dst') == '10.249.94.0/30' and 'gateway' not in r for r in routes)
                     and not any(r.get('dst') == 'default' or 'gateway' in r for r in routes6), 'CLOSED_PAIR_NO_EXTERNAL_ROUTE')
                topology[name] = {'links': [x['ifname'] for x in links], 'routes': routes, 'routes6': routes6,
                    'hosts_sha256': sha((Path('/etc/netns') / ns / 'hosts').read_bytes())}
            args, env = command(kernel.BACKEND, 'backend', sink_ns)
            server = subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(server)
            deadline = time.monotonic() + 15
            while not (base / 'backend/ready').exists():
                need(server.poll() is None, 'TLS_SINK_START_FAILED:' + (server.stderr.read().decode()[-2000:] if server.poll() is not None else ''))
                need(time.monotonic() < deadline, 'TLS_SINK_READY_TIMEOUT')
                time.sleep(0.05)
            phases = {}
            for phase, ns in [('isolated', isolated_ns), ('firewall', client_ns)]:
                phases[phase] = worker(kernel.AGENT, phase, ns)
                need(not (base / 'backend/http.jsonl').exists(), 'BLOCKED_DEFAULT_HTTPS_NEVER_REACHES_HTTP')
                need(not read_lines(base / 'backend/tls-events.jsonl'), 'BLOCKED_DEFAULT_HTTPS_NEVER_REACHES_TLS')
            phases['bad_ca'] = worker(kernel.CUSTODY, 'bad_ca', client_ns, True)
            need(not (base / 'backend/http.jsonl').exists(), 'UNTRUSTED_TLS_NEVER_REACHES_HTTP')
            phases['reachable'] = worker(kernel.AGENT, 'reachable', sink_ns)
            with sqlite3.connect(base / 'backend/effects.sqlite3') as db:
                need(db.execute('SELECT count(*) FROM effects').fetchone()[0] == 0, 'ALL_DEFAULT_HELPER_NEGATIVES_ZERO_EFFECT')
            need(not (base / 'custody/consumed.sqlite3').exists(), 'NEGATIVES_NEVER_CONSUME')
            admitted = worker(kernel.CUSTODY, 'positive', client_ns)
            need(server.poll() is None, 'TLS_SINK_SURVIVED_ALL_CONTROLS')
            server.terminate()
            server.wait(timeout=5)
            with sqlite3.connect(base / 'backend/effects.sqlite3') as db:
                effects = [list(x) for x in db.execute('SELECT op,receipt FROM effects')]
            with sqlite3.connect(base / 'custody/consumed.sqlite3') as db:
                consumed = [list(x) for x in db.execute('SELECT op FROM consumed')]
            evidence = {'phases': phases, 'http_observations': read_lines(base / 'backend/http.jsonl'),
                'tls_observations': read_lines(base / 'backend/tls-events.jsonl'), 'effects': effects,
                'consumed': consumed, 'positive': admitted, 'certificates': certs}
            validate(evidence)
            checks = {k: True for k in ('unchanged_three_default_https_helpers', 'original_frozen_input_hashes',
                'no_transport_argument_or_socket_tls_monkeypatch', 'observed_default_https_and_verified_context',
                'enrolled_local_hostname_resolution', 'closed_pair_no_external_gateway',
                'three_no_route_denials', 'three_uid_firewall_denials', 'private_credentials_and_tls_key_denied',
                'untrusted_ca_rejected_before_http', 'three_tls_http_403_backend_body_joins',
                'negative_effects_and_consumptions_zero', 'actual_bind_three_blocks_one_commit',
                'one_durable_counter_effect_and_consumption', 'positive_tls_leaf_fingerprint_join',
                'same_live_tls_sink_negative_and_positive')}
            report = {'schema': 'task4.default-https-denial.v1', 'audited_commit': head,
                'source_sha256': sha(Path(__file__).read_bytes()), 'checks': checks, 'topology': topology,
                'checked_firewall_rule': rule, 'evidence': evidence, 'evidence_sha256': digest(evidence),
                'real_provider_posts': 0, 'external_bank_effects': 0, 'utility': 'UNSCORED', 'provider_dispatch': 'DENY',
                'trusted_root_kernel_custody_backend': True, 'local_test_ca_not_public_provider_identity': True,
                'native_task4_tls_pipeline_integrated': False, 'independent_administration_proven': False,
                'production_bypass_resistance_proven': False}
            (output / 'report.json').write_bytes(canonical(report))
            suite = ET.Element('testsuite', name='Default HTTPS local TLS denial', tests=str(len(checks)), failures='0', errors='0', skipped='0')
            for name in sorted(checks):
                ET.SubElement(suite, 'testcase', classname='default_https_denial', name=name)
            ET.ElementTree(suite).write(output / 'junit.xml', encoding='utf-8', xml_declaration=True)
        finally:
            for p in reversed(processes):
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
                if p.stderr:
                    p.stderr.close()
            for ns in reversed(namespaces):
                kernel.command(['ip', 'netns', 'del', ns], check=False)
            for directory in reversed(directories):
                shutil.rmtree(directory)
            kernel.command(['ip', 'link', 'del', left], check=False)
            kernel.command(['ip', 'link', 'del', right], check=False)
    print('THREE_UNCHANGED_DEFAULT_HTTPS_HELPERS_LOCAL_TLS_DENIED_ONE_REAL_BIND_MOCK_EFFECT_NO_PROVIDER')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--role', choices=('backend', 'isolated', 'firewall', 'reachable', 'bad_ca', 'positive'))
    args = parser.parse_args()
    if args.run:
        need(args.output is not None and args.role is None and args.base is None, 'EXPLICIT_ROOT_RUN')
        run(args.output.resolve())
    else:
        need(args.role is not None and args.base is not None and args.output is None, 'EXPLICIT_LOCAL_ROLE')
        result = backend(args.base) if args.role == 'backend' else positive(args.base) if args.role == 'positive' else probe(args.base, args.role)
        if result is not None:
            print(canonical(result).decode())


if __name__ == '__main__':
    main()

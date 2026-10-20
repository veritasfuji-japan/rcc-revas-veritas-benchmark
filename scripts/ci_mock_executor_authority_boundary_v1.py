"""One trusted Linux CI VM: distinct UIDs, netns, firewall and synthetic secrets.

Only --run provisions disposable namespaces/rules under trusted root. All
endpoints/effects are local mocks. No Provider hostname, key or bank client.
"""
import argparse
import hashlib
import hmac
import http.client
import io
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import tarfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

AGENT, EXECUTOR, BACKEND, STRANGER, ISSUER = 61101, 61102, 61103, 61104, 61105
CUSTODY = 61106
HOST, PORT = '10.249.91.2', 18491
TARGET = 'mock://ci-authority/counter'
OP = 'CI_ONLY_SINGLE_ATTEMPT'
LIMIT = 8192
REQUEST = {'target': TARGET, 'units': 1, 'revision': 0}
FAULTS = {'before-post': 73, 'backend-response-lost': 74, 'before-client-reply': 75}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def tag(key, domain, value):
    return hmac.new(key, domain + canonical(value), hashlib.sha256).hexdigest()


def pairs(values):
    result = {}
    for key, value in values:
        need(key not in result, 'DUPLICATE_FIELD')
        result[key] = value
    return result


def parse(raw):
    need(0 < len(raw) <= LIMIT, 'FRAME_SIZE')
    return json.loads(raw, object_pairs_hook=pairs)


def exact_request(request):
    return (type(request) is dict and set(request) == set(REQUEST)
            and request['target'] == TARGET and type(request['units']) is int
            and request['units'] == 1 and type(request['revision']) is int
            and request['revision'] == 0)


def validate(packet, key):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    need(type(packet) is dict and set(packet) == {'request', 'grant'}, 'EXACT_PACKET')
    need(exact_request(packet['request']), 'EXACT_MOCK_REQUEST')
    grant = packet['grant']
    need(type(grant) is dict and set(grant) == {'statement', 'signature'}, 'EXACT_GRANT')
    statement = grant['statement']
    need(statement == {'scope': 'CI_ONLY', 'operation_id': OP,
                       'request_sha256': digest(REQUEST)}, 'EXACT_TEST_SCOPE')
    need(type(grant['signature']) is str and len(grant['signature']) == 128, 'GRANT_SIGNATURE')
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(grant['signature']), b'CI_GRANT_V2\0' + canonical(statement))
    except (InvalidSignature, ValueError):
        raise ValueError('GRANT_SIGNATURE') from None
    return statement


def issue(base):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    role_identity(ISSUER)
    os.umask(0o077)
    for rel in ('custody/credential', 'backend/credential'):
        try:
            (base / rel).read_bytes()
        except PermissionError:
            pass
        else:
            raise ValueError('ISSUER_MUST_NOT_HOLD_TRANSPORT_CREDENTIAL')
    need([x['ifname'] for x in json.loads(command(['ip', '-j', 'link', 'show']).stdout)]
         == ['lo'], 'ISSUER_LOOPBACK_ONLY')
    key = Ed25519PrivateKey.generate()
    path = base / 'issuer/private-key'
    with path.open('xb') as stream:
        stream.write(key.private_bytes_raw())
    statement = {'scope': 'CI_ONLY', 'operation_id': OP, 'request_sha256': digest(REQUEST)}
    packet = {'request': REQUEST, 'grant': {'statement': statement, 'signature':
        key.sign(b'CI_GRANT_V2\0' + canonical(statement)).hex()}}
    # Private key never leaves this UID. Root explicitly enrolls the public key.
    return {'public_key': key.public_key().public_bytes_raw().hex(), 'packet': packet,
            'issuer_credential_reads_denied_and_loopback_only': True}


def frame_read(conn):
    raw = bytearray()
    while not raw.endswith(b'\n'):
        part = conn.recv(min(1024, LIMIT + 1 - len(raw)))
        need(part and len(raw) + len(part) <= LIMIT, 'BOUNDED_FRAME_REQUIRED')
        raw.extend(part)
    return parse(bytes(raw[:-1]))


def unix_query(base, packet, address='ipc/executor.sock'):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(base / address))
        conn.sendall(canonical(packet) + b'\n')
        return frame_read(conn)


def http_query(payload, auth=''):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=2)
    try:
        conn.request('POST', '/effect', body=canonical(payload),
                     headers={'Content-Type': 'application/json', 'X-Mock-Auth': auth})
        response = conn.getresponse()
        return response.status, parse(response.read(LIMIT + 1))
    finally:
        conn.close()


def status_query(credential):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=2)
    try:
        conn.request('GET', '/status', headers={
            'X-Mock-Auth': tag(credential, b'CI_STATUS_V1\0', {'op': 'status'})})
        response = conn.getresponse()
        need(response.status == 200, 'AUTHENTICATED_BACKEND_STATUS_REQUIRED')
        return parse(response.read(LIMIT + 1))
    finally:
        conn.close()


def reconciliation_query(credential):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=2)
    try:
        conn.request('GET', '/reconcile', headers={'X-Mock-Auth':
            tag(credential, b'CI_RECONCILE_V1\0', {'operation_id': OP})})
        response = conn.getresponse()
        need(response.status == 200, 'AUTHENTICATED_RECONCILIATION_REQUIRED')
        return parse(response.read(LIMIT + 1))
    finally:
        conn.close()


def role_identity(uid):
    need(os.geteuid() == uid and os.getegid() == uid, 'EXACT_UNPRIVILEGED_UID')
    need(os.getgroups() == [], 'NO_SUPPLEMENTARY_GROUPS')
    status = Path('/proc/self/status').read_text()
    need('CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status,
         'NO_CAPABILITIES_NO_NEW_PRIVILEGES')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(1)
        try:
            conn.connect('/var/run/docker.sock')
        except (PermissionError, FileNotFoundError):
            pass
        else:
            raise ValueError('DOCKER_CONTROL_SOCKET_ACCESSIBLE')


def sink(base, fault=None):
    role_identity(BACKEND)
    os.umask(0o077)
    key = (base / 'backend/credential').read_bytes()
    public_key = (base / 'trust/issuer-public-key').read_bytes()
    db = sqlite3.connect(base / 'backend/state.sqlite3', isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY,counter INTEGER,denials INTEGER)')
    db.execute('INSERT INTO state VALUES (1,0,0)')
    db.execute('CREATE TABLE spent (operation_id TEXT PRIMARY KEY,receipt TEXT)')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            expected = (tag(key, b'CI_STATUS_V1\0', {'op': 'status'}) if self.path == '/status'
                        else tag(key, b'CI_RECONCILE_V1\0', {'operation_id': OP}))
            valid = self.path in {'/status', '/reconcile'} and hmac.compare_digest(
                expected, self.headers.get('X-Mock-Auth', ''))
            if valid:
                counter = db.execute('SELECT counter FROM state').fetchone()[0]
                result = {'counter': counter, 'revision': counter,
                          'effect_count': db.execute('SELECT count(*) FROM spent').fetchone()[0]}
                if self.path == '/reconcile':
                    row = db.execute('SELECT receipt FROM spent WHERE operation_id=?', (OP,)).fetchone()
                    result = {'operation_id': OP, 'effect_count': result['effect_count'],
                              'receipt': row[0] if row else None}
            else:
                result = {'decision': 'DENIED'}
            raw = canonical(result)
            self.send_response(200 if valid else 403)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                need(self.path == '/effect' and 0 < length <= LIMIT, 'EXACT_EFFECT_ENDPOINT')
                packet = parse(self.rfile.read(length))
                need(type(packet) is dict and set(packet) == {'operation_id', 'request', 'grant'}
                     and packet['operation_id'] == OP and exact_request(packet['request']),
                     'EXACT_BACKEND_OPERATION')
                need(hmac.compare_digest(tag(key, b'CI_SINK_V1\0', packet),
                                         self.headers.get('X-Mock-Auth', '')), 'MOCK_CREDENTIAL')
                validate({'request': packet['request'], 'grant': packet['grant']}, public_key)
                body = {'operation_id': OP, 'request': packet['request']}
                db.execute('BEGIN IMMEDIATE')
                before = db.execute('SELECT counter FROM state').fetchone()[0]
                need(before == 0, 'BACKEND_REPLAY')
                receipt = digest(body)
                db.execute('INSERT INTO spent VALUES (?,?)', (OP, receipt))
                db.execute('UPDATE state SET counter=1 WHERE id=1')
                db.commit()
                code, result = 200, {'decision': 'MOCK_EFFECT_ONCE', 'receipt': receipt}
            except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
                if db.in_transaction:
                    db.rollback()
                db.execute('UPDATE state SET denials=denials+1 WHERE id=1')
                code, result = 403, {'decision': 'DENIED'}
            raw = canonical(result)
            if code == 200 and fault == 'backend-response-lost':
                # Actual committed effect, then TCP closes before any HTTP reply.
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.send_response(code)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = HTTPServer((HOST, PORT), Handler)
    (base / 'backend/ready').write_text('ready')
    server.serve_forever()


def executor(base):
    """Untrusted request forwarder: no backend credential or consumption DB."""
    role_identity(EXECUTOR)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(base / 'ipc/executor.sock'))
    os.chmod(base / 'ipc/executor.sock', 0o666)
    server.listen(8)
    (base / 'executor/ready').write_text('ready')
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(4)
            try:
                packet = frame_read(conn)
                _, uid, _ = struct.unpack('3i', conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                need(uid == AGENT, 'FRONTEND_PEER_DENIED')
                validate(packet, (base / 'trust/issuer-public-key').read_bytes())
                result = unix_query(base, packet, 'bind-ipc/custody.sock')
            except (ValueError, OSError, KeyError, TypeError):
                result = {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}
            try:
                conn.sendall(canonical(result) + b'\n')
            except OSError:
                pass


def custody(base, restart=False, with_bind=False, fault=None):
    """Trusted Bind/effect authority; caller cannot select a no-Bind mode."""
    role_identity(CUSTODY)
    need(with_bind, 'CUSTODY_REQUIRES_REAL_BIND')
    need(fault is None or fault in FAULTS, 'EXACT_TEST_FAULT')
    os.umask(0o077)
    credential = (base / 'custody/credential').read_bytes()
    verifier = (base / 'trust/issuer-public-key').read_bytes()
    file = base / 'custody/ledger.sqlite3'
    need(file.is_file() if restart else not file.exists(), 'EXACT_LEDGER_LIFECYCLE')
    db = sqlite3.connect(file, isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    if not restart:
        db.execute('CREATE TABLE consumed (operation_id TEXT PRIMARY KEY,state TEXT,receipt TEXT)')
    else:
        need(db.execute('SELECT count(*) FROM consumed').fetchone()[0] == 1,
             'RESTART_REQUIRES_CONSUMED_STATE')
    address = base / 'bind-ipc/custody.sock'
    if restart:
        address.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(address))
    os.chmod(address, 0o666)
    server.listen(8)
    (base / 'custody/ready').write_text('restarted' if restart else 'ready')
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(4)
            try:
                _, peer_uid, _ = struct.unpack('3i', conn.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
                packet = frame_read(conn)
                need(peer_uid == EXECUTOR, 'KERNEL_CUSTODY_PEER_DENIED')
                validate(packet, verifier)
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('INSERT INTO consumed VALUES (?, ?, NULL)', (OP, 'CONSUMED_UNKNOWN'))
                except sqlite3.IntegrityError:
                    db.rollback()
                    result = {'decision': 'REPLAY_DENIED'}
                else:
                    db.commit()
                    if fault == 'before-post':
                        os._exit(FAULTS[fault])  # Durable consumption, no network dispatch.
                    body = {'operation_id': OP, 'request': packet['request']}
                    envelope = dict(body, grant=packet['grant'])
                    def post():
                        try:
                            return http_query(envelope, tag(credential, b'CI_SINK_V1\0', envelope))
                        except OSError:
                            if fault == 'backend-response-lost':
                                os._exit(FAULTS[fault])
                            raise
                    if with_bind:
                        sys.path.insert(0, str(base))  # Trusted root-owned read-only source copy.
                        from ci_mock_executor_veritas_bind_v1 import integrate
                        response, evidence = integrate(body=body,
                            post=post,
                            status=lambda: status_query(credential))
                        (base / 'custody/bind-evidence.json').write_bytes(canonical(evidence))
                        code = 200
                    need(code == 200 and response == {
                        'decision': 'MOCK_EFFECT_ONCE', 'receipt': digest(body)}, 'BOUND_SINK_RECEIPT')
                    db.execute('UPDATE consumed SET state=?,receipt=? WHERE operation_id=?',
                               ('MOCK_OBSERVED', response['receipt'], OP))
                    if fault == 'before-client-reply':
                        os._exit(FAULTS[fault])  # Local result durable; caller receives no success.
                    result = {'decision': 'MOCK_EFFECT_ONCE', 'receipt': response['receipt']}
            except (ValueError, OSError, KeyError, TypeError):
                if db.in_transaction:
                    db.rollback()
                result = {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}
            try:
                conn.sendall(canonical(result) + b'\n')
            except OSError:
                pass  # Ledger remains consumed even if the response is lost.


def denied_connect(host=HOST, port=PORT, family=None):
    try:
        if family is None:
            with socket.create_connection((host, port), timeout=1):
                pass
        else:
            with socket.socket(family, socket.SOCK_STREAM) as conn:
                conn.settimeout(1)
                conn.connect((host, port))
    except OSError as exc:
        need(exc.errno not in {None, 97}, 'NETWORK_TEST_MUST_NOT_PASS_ON_UNSUPPORTED_FAMILY')
        return True
    raise ValueError('DIRECT_NETWORK_WAS_ALLOWED')


def worker(base, mode):
    role_identity(STRANGER if mode == 'stranger' else EXECUTOR
                  if mode in {'executor-key', 'executor-direct', 'executor-http', 'executor-private',
                              'fake-bind'} else CUSTODY
                  if mode in {'no-credential', 'custody-forge', 'reconcile'} else AGENT)
    if mode == 'reconcile':
        return reconciliation_query((base / 'custody/credential').read_bytes())
    if mode == 'executor-private':
        result = {}
        for rel in ('custody/credential', 'custody/ledger.sqlite3', 'custody/bind-evidence.json'):
            try:
                (base / rel).read_bytes()
            except PermissionError:
                result['executor_read_denied:' + rel] = True
            else:
                raise ValueError('EXECUTOR_READ_CUSTODY_AUTHORITY')
        for rel in ('program.py', 'ci_mock_executor_veritas_bind_v1.py'):
            try:
                (base / rel).write_bytes(b'attacker')
            except PermissionError:
                result['executor_write_denied:' + rel] = True
            else:
                raise ValueError('EXECUTOR_REPLACED_CUSTODY_CODE')
        return result
    if mode == 'executor-direct':
        packet = json.loads((base / 'public/packet.json').read_bytes())
        validate(packet, (base / 'trust/issuer-public-key').read_bytes())
        try:
            http_query(dict(operation_id=OP, **packet))
        except OSError:
            return {'executor_authentic_grant_direct_network_denied': True}
        raise ValueError('EXECUTOR_DIRECT_REACHED_BACKEND')
    if mode == 'executor-http':
        # Root places this credential-free probe in sink netns to isolate the
        # backend authorization check from the host UID firewall check.
        packet = json.loads((base / 'public/packet.json').read_bytes())
        validate(packet, (base / 'trust/issuer-public-key').read_bytes())
        code, result = http_query(dict(operation_id=OP, **packet))
        need(code == 403 and result == {'decision': 'DENIED'}, 'APPROVAL_ALONE_BYPASSED_BIND_CUSTODY')
        return {'executor_authentic_grant_backend_http_denied': True}
    if mode in {'custody-peer', 'fake-bind'}:
        packet = json.loads((base / 'public/packet.json').read_bytes())
        if mode == 'fake-bind':
            packet['bind_receipt'] = {'final_outcome': 'COMMITTED'}
        result = unix_query(base, packet, 'bind-ipc/custody.sock')
        need(result == {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}, 'CUSTODY_BYPASS_ACCEPTED')
        return {mode + '_denied': True}
    if mode in {'executor-key', 'agent-key'}:
        try:
            (base / 'issuer/private-key').read_bytes()
        except PermissionError:
            pass
        else:
            raise ValueError('ISSUER_PRIVATE_KEY_READABLE')
        try:
            (base / 'trust/issuer-public-key').write_bytes(b'attacker')
        except PermissionError:
            pass
        else:
            raise ValueError('TRUST_ROOT_REPLACED')
        return {mode + '_private_read_denied': True, mode + '_trust_write_denied': True}
    if mode == 'custody-forge':
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        packet = json.loads((base / 'public/packet.json').read_bytes())
        packet['grant']['signature'] = Ed25519PrivateKey.generate().sign(
            b'CI_GRANT_V2\0' + canonical(packet['grant']['statement'])).hex()
        body = dict(operation_id=OP, request=REQUEST, grant=packet['grant'])
        credential = (base / 'custody/credential').read_bytes()
        code, result = http_query(body, tag(credential, b'CI_SINK_V1\0', body))
        need(code == 403 and result == {'decision': 'DENIED'}, 'FORGED_ISSUER_GRANT_REACHED_EFFECT')
        need(status_query(credential) == {'counter': 0, 'revision': 0, 'effect_count': 0},
             'FORGED_GRANT_CHANGED_BACKEND')
        return {'valid_transport_credential_forged_issuer_denied_at_backend': True}
    if mode == 'probe':
        observations = {}
        for rel in ('custody/credential', 'custody/ledger.sqlite3',
                    'backend/credential', 'backend/state.sqlite3'):
            try:
                (base / rel).read_bytes()
            except PermissionError:
                observations['read_denied:' + rel] = True
            else:
                raise ValueError('PRIVATE_FILE_WAS_READABLE')
        observations['raw_ipv4_denied'] = denied_connect()
        observations['raw_ipv6_denied'] = denied_connect('2001:db8::1', 443, socket.AF_INET6)
        try:
            http_query({'operation_id': OP, 'request': REQUEST})
        except OSError:
            observations['http_client_denied'] = True
        else:
            raise ValueError('HTTP_CLIENT_DIRECT_NETWORK_ALLOWED')
        try:
            with urllib.request.urlopen('http://' + HOST + ':' + str(PORT) + '/effect', timeout=1):
                pass
        except urllib.error.HTTPError:
            raise ValueError('URLLIB_REACHED_BACKEND_HTTP')
        except urllib.error.URLError:
            observations['urllib_denied'] = True
        else:
            raise ValueError('URLLIB_DIRECT_NETWORK_ALLOWED')
        child = subprocess.run([sys.executable, '-I', '-c',
            'import socket,sys\ntry:\n socket.create_connection((' + repr(HOST) + ',' + str(PORT) + '),1)\n'
            'except OSError:\n sys.exit(0)\nelse:\n sys.exit(9)'], capture_output=True, timeout=4)
        need(child.returncode == 0, 'CHILD_PROCESS_BYPASS')
        observations['subprocess_denied'] = True
        return observations
    if mode == 'host-direct':
        return {'same_agent_uid_host_direct_denied': denied_connect()}
    if mode == 'no-credential':
        packet = json.loads((base / 'public/packet.json').read_bytes())
        code, result = http_query(dict(operation_id=OP, **packet))
        need(code == 403 and result == {'decision': 'DENIED'}, 'NETWORK_ALONE_IS_NOT_AUTHORITY')
        return {'custody_uid_reaches_sink_but_unsigned_denied': True}
    packet = json.loads((base / 'public/packet.json').read_bytes())
    if mode == 'tamper':
        packet['grant']['signature'] = '0' * 128
    elif mode == 'unsigned':
        packet['grant'] = {}
    elif mode == 'forward':
        packet['destination'] = 'http://192.0.2.1/'
    result = unix_query(base, packet)
    wanted = ('DENIED_OR_UNKNOWN_NO_RETRY' if mode in {'tamper', 'unsigned', 'forward', 'stranger', 'fault-attempt', 'stopped-replay'}
              else 'REPLAY_DENIED' if mode == 'replay' else 'MOCK_EFFECT_ONCE')
    need(result.get('decision') == wanted, 'EXPECTED_GATEWAY_DECISION_' + mode)
    return {mode + '_expected_decision': True, 'decision': result['decision']}


def command(args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if check:
        need(result.returncode == 0, 'LOCAL_COMMAND_FAILED:' + args[0] + ':' + result.stderr[-600:])
    return result


def role_command(program, uid, args, namespace=None):
    return (['ip', 'netns', 'exec', namespace] if namespace else []) + [
        'setpriv', '--reuid=' + str(uid), '--regid=' + str(uid), '--clear-groups',
        '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
        sys.executable, '-I', str(program)] + args


def run(output, with_bind=False, veritas_root=None, fault=None):
    need(with_bind, 'REAL_BIND_CUSTODY_MODE_REQUIRED')
    need(fault is None or fault in FAULTS, 'EXACT_TEST_FAULT')
    need(os.geteuid() == 0 and sys.platform == 'linux', 'TRUSTED_DISPOSABLE_LINUX_CI_ROOT_REQUIRED')
    need(output.resolve().is_relative_to(Path.cwd().resolve()) and not output.exists(),
         'NEW_OUTPUT_DIRECTORY_UNDER_CHECKOUT_REQUIRED')
    for binary in ('ip', 'iptables', 'setpriv'):
        need(shutil.which(binary) is not None, 'MISSING_LINUX_TOOL_' + binary)
    for uid in (AGENT, EXECUTOR, BACKEND, STRANGER, ISSUER, CUSTODY):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            pass
        else:
            raise ValueError('RESERVED_TEST_UID_ALREADY_ALLOCATED')
    output.mkdir(parents=True)
    head = command(['git', '-c', 'safe.directory=' + str(Path.cwd().resolve()),
                    'rev-parse', 'HEAD']).stdout.strip()
    bind_source = None
    if with_bind:
        need(veritas_root is not None, 'PINNED_VERITAS_ROOT_REQUIRED')
        veritas_root = veritas_root.resolve()
        from scripts.ci_mock_executor_veritas_bind_v1 import VERITAS_PIN, CORE_BLOB
        git = ['git', '-c', 'safe.directory=' + str(veritas_root), '-C', str(veritas_root)]
        need(command(git + ['rev-parse', 'HEAD']).stdout.strip() == VERITAS_PIN, 'EXACT_VERITAS_PIN')
        command(git + ['diff', '--exit-code', 'HEAD', '--', 'veritas_os'])
        core = (veritas_root / 'veritas_os/policy/bind_core/core.py').read_bytes()
        need(hashlib.sha1(b'blob ' + str(len(core)).encode() + b'\0' + core).hexdigest()
             == CORE_BLOB, 'EXACT_BIND_CORE_SOURCE')
        bind_source = Path(__file__).with_name('ci_mock_executor_veritas_bind_v1.py')
    token = secrets.token_hex(4)
    sink_ns, agent_ns = 'sink' + token, 'agent' + token
    host_if, sink_if = 'h' + token, 's' + token
    rule = ['OUTPUT', '-d', HOST, '-p', 'tcp', '--dport', str(PORT),
            '-m', 'owner', '!', '--uid-owner', str(CUSTODY), '-j', 'REJECT']
    processes, namespaces = [], []
    installed = False
    link_created = False
    checks = {}
    with tempfile.TemporaryDirectory(prefix='ci-authority-') as temporary:
        base = Path(temporary)
        os.chmod(base, 0o755)
        program = base / 'program.py'
        shutil.copyfile(__file__, program)
        os.chmod(program, 0o444)
        if with_bind:
            archive = subprocess.run(git + ['archive', VERITAS_PIN, 'veritas_os'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:
                for member in source.getmembers():
                    dest = base / member.name
                    need(dest.resolve().is_relative_to(base)
                         and (member.name == 'veritas_os' or member.name.startswith('veritas_os/'))
                         and (member.isdir() or member.isfile()), 'TRACKED_REGULAR_BIND_SOURCE_ONLY')
                    if member.isdir():
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(source.extractfile(member).read())
            shutil.copyfile(bind_source, base / bind_source.name)
            for path in [base / bind_source.name, *(base / 'veritas_os').rglob('*')]:
                need(not path.is_symlink(), 'NO_SYMLINK_IN_BIND_SOURCE')
                os.chmod(path, 0o555 if path.is_dir() else 0o444)
            os.chmod(base / 'veritas_os', 0o555)
        for role, uid in [('executor', EXECUTOR), ('backend', BACKEND), ('ipc', EXECUTOR),
                          ('issuer', ISSUER), ('custody', CUSTODY), ('bind-ipc', CUSTODY)]:
            folder = base / role
            folder.mkdir(mode=0o755 if role in {'ipc', 'bind-ipc'} else 0o700)
            os.chown(folder, uid, uid)
        (base / 'public').mkdir(mode=0o755)
        (base / 'trust').mkdir(mode=0o755)
        credential = secrets.token_bytes(32)
        for rel, raw, uid in [('custody/credential', credential, CUSTODY),
                              ('backend/credential', credential, BACKEND)]:
            path = base / rel
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            os.chown(path, uid, uid)

        def spawn(uid, args, namespace, ready, expected):
            proc = subprocess.Popen(role_command(program, uid, args, namespace),
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
            processes.append(proc)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise ValueError('SERVICE_FAILED:' + proc.stderr.read().decode()[-600:])
                if ready.exists() and ready.read_text() == expected:
                    return proc
                time.sleep(0.1)
            raise ValueError('SERVICE_READY_TIMEOUT')

        def probe(mode, uid=AGENT, namespace=agent_ns):
            result = command(role_command(program, uid, ['--worker', str(base), mode], namespace), check=False)
            if result.returncode:
                # Our services log only constant codes / Python import tracebacks,
                # never credentials or request/response bodies.
                for index, proc in enumerate(processes):
                    if proc.poll() is not None and proc.returncode and proc.stderr:
                        failure = proc.stderr.read().decode()[-3000:]
                        (output / ('service-failure-' + str(index) + '.log')).write_text(failure)
                        print(failure, file=sys.stderr)
                raise ValueError('WORKER_FAILED:' + mode + ':' + result.stderr[-600:])
            record = json.loads(result.stdout)
            (output / (mode + '.json')).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
            return record

        try:
            for namespace in (sink_ns, agent_ns):
                command(['ip', 'netns', 'add', namespace])
                namespaces.append(namespace)
                command(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
            command(['ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', sink_if])
            link_created = True
            command(['ip', 'link', 'set', sink_if, 'netns', sink_ns])
            command(['ip', 'addr', 'add', '10.249.91.1/30', 'dev', host_if])
            command(['ip', 'link', 'set', host_if, 'up'])
            command(['ip', '-n', sink_ns, 'addr', 'add', HOST + '/30', 'dev', sink_if])
            command(['ip', '-n', sink_ns, 'link', 'set', sink_if, 'up'])
            command(['iptables', '-I'] + rule[:1] + ['1'] + rule[1:])
            installed = True
            command(['iptables', '-C'] + rule)
            checks['kernel_uid_firewall_installed'] = True
            for namespace in namespaces:
                for part in ('addr', 'route'):
                    raw = command(['ip', '-n', namespace, '-j', part, 'show']).stdout
                    (output / (namespace + '-' + part + '.json')).write_text(raw)
            addr = json.loads(command(['ip', '-n', agent_ns, '-j', 'link', 'show']).stdout)
            need([x['ifname'] for x in addr] == ['lo'], 'AGENT_NAMESPACE_ONLY_LOOPBACK')
            checks['agent_namespace_only_loopback'] = True
            namespace_ids = {'host': os.readlink('/proc/self/ns/net')}
            for role, namespace in [('agent', agent_ns), ('sink', sink_ns)]:
                namespace_ids[role] = command(['ip', 'netns', 'exec', namespace,
                    'readlink', '/proc/self/ns/net']).stdout.strip()
            need(len(set(namespace_ids.values())) == 3, 'THREE_DISTINCT_NETWORK_NAMESPACES')
            checks['three_distinct_network_namespaces'] = True
            issued = json.loads(command(role_command(program, ISSUER,
                ['--issue', str(base)], agent_ns)).stdout)
            public_key = bytes.fromhex(issued['public_key'])
            validate(issued['packet'], public_key)
            for rel, raw in [('trust/issuer-public-key', public_key),
                             ('public/packet.json', canonical(issued['packet']))]:
                path = base / rel
                path.write_bytes(raw)
                os.chmod(path, 0o444)
            checks['issuer_credential_reads_denied_and_loopback_only'] = issued[
                'issuer_credential_reads_denied_and_loopback_only']
            fault_args = ['--fault', fault] if fault else []
            sink_proc = spawn(BACKEND, ['--sink', str(base)] + fault_args,
                              sink_ns, base / 'backend/ready', 'ready')
            bind_args = ['--with-veritas-bind'] if with_bind else []
            custody_proc = spawn(CUSTODY, ['--custody', str(base)] + bind_args + fault_args,
                                 None, base / 'custody/ready', 'ready')
            executor_proc = spawn(EXECUTOR, ['--executor', str(base)],
                                  None, base / 'executor/ready', 'ready')
            checks.update(probe('probe'))
            checks.update(probe('host-direct', namespace=None))
            checks.update(probe('no-credential', uid=CUSTODY, namespace=None))
            checks.update(probe('agent-key'))
            checks.update(probe('executor-key', uid=EXECUTOR, namespace=None))
            checks.update(probe('custody-forge', uid=CUSTODY, namespace=None))
            checks.update(probe('executor-private', uid=EXECUTOR, namespace=None))
            checks.update(probe('executor-direct', uid=EXECUTOR, namespace=None))
            checks.update(probe('executor-http', uid=EXECUTOR, namespace=sink_ns))
            checks.update(probe('custody-peer'))
            checks.update(probe('fake-bind', uid=EXECUTOR, namespace=None))
            for mode in ('tamper', 'unsigned', 'forward'):
                checks[mode + '_denied'] = probe(mode)[mode + '_expected_decision']
            checks['wrong_peer_uid_denied'] = probe('stranger', uid=STRANGER)['stranger_expected_decision']
            if fault:
                checks['caller_gets_unknown_no_retry'] = probe('fault-attempt')['fault-attempt_expected_decision']
                need(custody_proc.wait(timeout=5) == FAULTS[fault], 'EXACT_CUSTODY_FAULT_EXIT')
                checks['exact_fault_exit_observed'] = True
                checks['stopped_custody_replay_unknown_no_retry'] = probe(
                    'stopped-replay')['stopped-replay_expected_decision']
            else:
                checks['authorized_mock_effect_once'] = probe('valid')['valid_expected_decision']
                checks['same_run_replay_denied'] = probe('replay')['replay_expected_decision']
                custody_proc.terminate()
                custody_proc.wait(timeout=5)
            (base / 'custody/ready').unlink()
            custody_proc = spawn(CUSTODY, ['--custody', str(base), '--restart'] + bind_args, None,
                                  base / 'custody/ready', 'restarted')
            checks['restart_replay_denied'] = probe('replay')['replay_expected_decision']
            reconciliation = probe('reconcile', uid=CUSTODY, namespace=None) if fault else None
            for proc in (executor_proc, custody_proc, sink_proc):
                proc.terminate()
                proc.wait(timeout=5)
            with sqlite3.connect(base / 'backend/state.sqlite3') as db:
                counter, denials = db.execute('SELECT counter,denials FROM state').fetchone()
                spent = db.execute('SELECT operation_id,receipt FROM spent').fetchall()
            with sqlite3.connect(base / 'custody/ledger.sqlite3') as db:
                rows = db.execute('SELECT operation_id,state,receipt FROM consumed').fetchall()
            expected_effect = 0 if fault == 'before-post' else 1
            need(counter == expected_effect and denials == 3
                 and len(spent) == expected_effect and len(rows) == 1,
                 'BACKEND_COUNTS_AND_DENIED_PROBE_RECONCILIATION')
            backend_receipt = spent[0][1] if spent else None
            if fault:
                local_state = 'MOCK_OBSERVED' if fault == 'before-client-reply' else 'CONSUMED_UNKNOWN'
                local_receipt = backend_receipt if local_state == 'MOCK_OBSERVED' else None
                need(rows[0] == (OP, local_state, local_receipt), 'EXACT_DURABLE_CRASH_STATE')
                need(reconciliation == {'operation_id': OP, 'effect_count': expected_effect,
                      'receipt': backend_receipt}, 'AUTHENTICATED_RECONCILIATION_BACKEND_DB_JOIN')
                if backend_receipt is not None:
                    need(backend_receipt == digest({'operation_id': OP, 'request': REQUEST}),
                         'RECONCILIATION_RECEIPT_REQUEST_JOIN')
                checks['authenticated_reconciliation_matches_backend_db'] = True
                checks['crash_did_not_release_consumption'] = True
            else:
                need(rows[0] == (OP, 'MOCK_OBSERVED', backend_receipt), 'LEDGER_BACKEND_RECEIPT_JOIN')
            checks['backend_effect_and_ledger_receipt_reconciled'] = True
            bind_evidence = None
            if with_bind and fault in {None, 'before-client-reply'}:
                bind_evidence = json.loads((base / 'custody/bind-evidence.json').read_bytes())
                records = bind_evidence['records']
                need(len(records) == 4 and bind_evidence['backend_receipt_sha256'] == spent[0][1]
                     and rows[0][2] == spent[0][1], 'BIND_BACKEND_LEDGER_RECEIPT_JOIN')
                for record in records[:3]:
                    need(record['outcome'] == 'BLOCKED' and record['apply_calls'] == 0,
                         'DENIED_BIND_MUST_NOT_SEND')
                    checks['bind_blocked:' + record['scenario']] = True
                need(records[3]['outcome'] == 'COMMITTED' and records[3]['apply_calls'] == 1,
                     'REAL_BIND_COMMIT_EXACTLY_ONE_APPLY')
                checks['real_bind_committed_one_network_apply'] = True
                checks['bind_backend_and_ledger_joined_same_run'] = True
                (output / 'bind-evidence.json').write_text(json.dumps(bind_evidence, sort_keys=True, indent=2) + '\n')
            need(all(value is True for value in checks.values()), 'ALL_CHECKS_REQUIRED')
            report = {'schema': 'ci.mock-executor.authority-boundary.v1', 'audited_commit': head,
                      'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      'checks': checks, 'uids': {'agent': AGENT, 'executor': EXECUTOR, 'backend': BACKEND, 'issuer': ISSUER, 'custody': CUSTODY},
                      'executor_has_backend_credential': False, 'trusted_bind_custody_uid': CUSTODY,
                      'bind_enforcement_scope': 'UNTRUSTED_EXECUTOR_TO_TRUSTED_CUSTODY',
                      'compromised_custody_resistance_proven': False,
                      'issuer_algorithm': 'Ed25519', 'issuer_public_key_sha256': hashlib.sha256(public_key).hexdigest(),
                      'backend_verifies_issuer_signature': True, 'executor_has_issuer_private_key': False,
                      'namespace_ids': namespace_ids, 'installed_and_checked_firewall_rule': rule,
                      'mock_effect_count': counter, 'backend_denial_count': denials,
                      'receipt_sha256': backend_receipt, 'real_provider_calls': 0, 'real_bank_effects': 0,
                      'fault': fault, 'custody_ledger_state': rows[0][1],
                      'custody_ledger_receipt_sha256': rows[0][2],
                      'authenticated_reconciliation': reconciliation,
                      'reconciliation_scope': 'LOCAL_MOCK_CURRENT_BACKEND_STATE_NOT_EXTERNAL_PROVIDER',
                      'automatic_retry_performed': False,
                      'bind_terminal_receipt_observed': bind_evidence is not None,
                      'independent_administration_proven': False, 'real_veritas_bind_integrated': with_bind,
                      'bind_evidence_sha256': digest(bind_evidence) if bind_evidence else None,
                      'bind_adapter_source_sha256': hashlib.sha256(bind_source.read_bytes()).hexdigest() if with_bind else None,
                      'exact_historical_helper_invocations_tested': False,
                      'production_bypass_resistance_proven': False, 'utility': 'UNSCORED',
                      'provider_dispatch': 'DENY', 'trusted_ci_root_and_kernel': True}
            (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
            suite = ET.Element('testsuite', name='CI mock authority', tests=str(len(checks)),
                               failures='0', errors='0', skipped='0')
            for name in sorted(checks):
                ET.SubElement(suite, 'testcase', classname='linux_authority_boundary', name=name)
            ET.ElementTree(suite).write(output / 'junit.xml', encoding='utf-8', xml_declaration=True)
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                if proc.stderr:
                    proc.stderr.close()
            if installed:
                command(['iptables', '-D'] + rule, check=False)
            for namespace in reversed(namespaces):
                command(['ip', 'netns', 'del', namespace], check=False)
            if link_created:
                command(['ip', 'link', 'del', host_if], check=False)
    print('CI_MOCK_EXECUTOR_AUTHORITY_BOUNDARY_OFFLINE_PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--sink', type=Path)
    group.add_argument('--issue', type=Path)
    group.add_argument('--executor', type=Path)
    group.add_argument('--custody', type=Path)
    group.add_argument('--worker', nargs=2)
    parser.add_argument('--restart', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--with-veritas-bind', action='store_true')
    parser.add_argument('--veritas-root', type=Path)
    parser.add_argument('--fault', choices=sorted(FAULTS))
    args = parser.parse_args()
    if args.run:
        need(args.output is not None, 'OUTPUT_REQUIRED')
        run(args.output, args.with_veritas_bind, args.veritas_root, args.fault)
    elif args.sink:
        sink(args.sink, args.fault)
    elif args.issue:
        print(json.dumps(issue(args.issue), sort_keys=True))
    elif args.executor:
        executor(args.executor)
    elif args.custody:
        custody(args.custody, args.restart, args.with_veritas_bind, args.fault)
    else:
        print(json.dumps(worker(Path(args.worker[0]), args.worker[1]), sort_keys=True))


if __name__ == '__main__':
    main()

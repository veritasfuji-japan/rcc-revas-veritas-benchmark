"""Pinned scripted Task4 Native SDK through separate-UID Bind and local HTTP.

CI-only synthetic approval/recipient. No Provider capability or live mode.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
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
import socket
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import ci_mock_executor_authority_boundary_v1 as kernel

ROOT = Path(__file__).resolve().parents[1]
NATIVE, BACKEND, ISSUER, CUSTODY = kernel.AGENT, kernel.BACKEND, kernel.ISSUER, kernel.CUSTODY
HOST, PORT = kernel.HOST, 18492
TLS_BASE = None  # Selected only by a root-owned, exact local fixture marker.
LIMIT = 256000
SCOPE_SHA = 'ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309'
RECIPIENT_SHA = '8f15bcc58f2ddb4f6d5e490191d96b84d1f67b5872f5ec3871afd2e33c3f6aa1'
RECIPIENT_MANIFEST_SHA = '18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c'
TARGET = 'mock://task4-native/chat-completions'
FAULTS = ('after-consume', 'backend-response-lost', 'after-sealed')
need, canonical, digest, tag = kernel.need, kernel.canonical, kernel.digest, kernel.tag


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fault_mode(base):
    file = base / 'public/fault'
    value = file.read_text() if file.exists() else ''
    need(value in ('', *FAULTS), 'EXACT_ROOT_ENROLLED_FAULT')
    return value


def concurrent_mode(base):
    file = base / 'public/concurrent'
    if not file.exists():
        return False
    need(file.read_text() == 'two-custody-v1', 'EXACT_CONCURRENT_FIXTURE')
    return True


def concurrent_crash_mode(base):
    file = base / 'public/concurrent-crash'
    if not file.exists():
        return False
    need(concurrent_mode(base) and file.read_text() == 'consumed-before-bind-v1', 'EXACT_CONCURRENT_CRASH_FIXTURE')
    return True


def concurrent_response_loss_mode(base):
    file = base / 'public/concurrent-response-loss'
    if not file.exists():
        return False
    need(concurrent_mode(base) and not concurrent_crash_mode(base)
         and file.read_text() == 'backend-commit-drop-v1', 'EXACT_CONCURRENT_RESPONSE_LOSS_FIXTURE')
    return True


def durable_marker(file, value):
    with file.open('xb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def encode(raw):
    return base64.b64encode(raw).decode('ascii')


def decode(value):
    need(type(value) is str and len(value) <= LIMIT, 'BOUNDED_BASE64')
    return base64.b64decode(value, validate=True)


def parse(raw):
    need(0 < len(raw) <= LIMIT, 'BOUNDED_JSON')
    return json.loads(raw, object_pairs_hook=kernel.pairs)


def frame(conn):
    raw = bytearray()
    while not raw.endswith(b'\n'):
        part = conn.recv(min(4096, LIMIT + 1 - len(raw)))
        need(part and len(raw) + len(part) <= LIMIT, 'BOUNDED_FRAME')
        raw.extend(part)
    return parse(raw[:-1])


def query(base, packet, secondary=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(15)
        conn.connect(str(base / ('ipc/native-secondary.sock' if secondary else 'ipc/native.sock')))
        conn.sendall(canonical(packet) + b'\n')
        return frame(conn)


def scope():
    raw = (ROOT / 'docs/TASK4_NATIVE_FROZEN_SIGNER_SCOPE_V1.json').read_bytes()
    need(sha(raw) == SCOPE_SHA, 'PINNED_EIGHT_NATIVE_REQUESTS')
    value = parse(raw)
    need(value['provider_post_allowed'] is False and len(value['entries']) == 8, 'OFFLINE_SCOPE_ONLY')
    return {(x['arm'], x['ordinal']): x['request_sha256'] for x in value['entries']}


def recipient():
    raw = (ROOT / 'docs/TASK4_NATIVE_FROZEN_RECIPIENT_V1.json').read_bytes()
    need(sha(raw) == RECIPIENT_MANIFEST_SHA, 'PINNED_PUBLIC_TEST_RECIPIENT')
    value = parse(raw)
    need(value['private_key_publicly_reproducible'] is True and value['real_data_allowed'] is False
         and value['recipient_sha256'] == RECIPIENT_SHA, 'PUBLIC_FIXTURE_NOT_REAL_DATA')
    return bytes.fromhex(value['recipient_public_hex'])


def statement(arm, ordinal, request_sha, base=None):
    need(arm in {'A', 'B'} and type(ordinal) is int and (arm, ordinal) in scope(), 'EXACT_NATIVE_SLOT')
    need(request_sha == scope()[(arm, ordinal)], 'EXACT_FROZEN_SDK_BYTES')
    value = {'scope': 'CI_ONLY_NATIVE_TASK4', 'arm': arm, 'ordinal': ordinal,
            'request_sha256': request_sha, 'target': TARGET, 'output_cap': 256,
            'recipient_sha256': RECIPIENT_SHA}
    from scripts import task4_native_raw_authority_v1 as authority
    context_base = base if base is not None else TLS_BASE
    if authority.enabled(context_base):
        value['raw_authority'] = authority.load(context_base)
    return value


def verify_grant(grant, arm, ordinal, request_sha, public, base=None):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    need(type(grant) is dict and set(grant) == {'statement', 'signature'}, 'EXACT_NATIVE_GRANT')
    from scripts import task4_native_raw_authority_v1 as authority
    context_base = base if base is not None else TLS_BASE
    bound = authority.enabled(context_base)
    expected = statement(arm, ordinal, request_sha, context_base)
    need(type(grant['statement']) is dict and
         ({k:v for k,v in grant['statement'].items() if k != 'raw_authority'} ==
          {k:v for k,v in expected.items() if k != 'raw_authority'} if bound else grant['statement'] == expected),
         'EXACT_SIGNED_SCOPE')
    need(type(grant['signature']) is str and len(grant['signature']) == 128, 'SIGNATURE_FORMAT')
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(grant['signature']),
            b'TASK4_NATIVE_OS_V1\0' + canonical(grant['statement']))
    except (InvalidSignature, ValueError):
        raise ValueError('ISSUER_SIGNATURE') from None
    if bound:
        clock = authority.admit(context_base, grant['statement'].get('raw_authority'))
        if os.geteuid() == CUSTODY:
            authority.record_validation(context_base, grant, arm, ordinal, clock)


def verify(packet, public):
    from scripts import task4_native_bounded_continuation_v1 as bounded
    if bounded.enabled(TLS_BASE):
        return bounded.verify_packet(TLS_BASE, packet, public)
    need(type(packet) is dict and set(packet) == {'arm', 'ordinal', 'wire_b64', 'grant'}, 'EXACT_NATIVE_PACKET')
    raw = decode(packet['wire_b64'])
    need(0 < len(raw) <= 64000, 'BOUNDED_ACTUAL_SDK_WIRE')
    verify_grant(packet['grant'], packet['arm'], packet['ordinal'], sha(raw), public)
    wire = parse(raw)
    need(type(wire['max_completion_tokens']) is int and wire['max_completion_tokens'] == 256,
         'ACTUAL_SDK_OUTPUT_CAP')
    return raw


def issue(base):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    kernel.role_identity(ISSUER)
    os.umask(0o077)
    for rel in ('custody/credential', 'backend/credential'):
        try:
            (base / rel).read_bytes()
        except PermissionError:
            pass
        else:
            raise ValueError('ISSUER_CREDENTIAL_ACCESS')
    key = Ed25519PrivateKey.generate()
    with (base / 'issuer/private-key').open('xb') as stream:
        stream.write(key.private_bytes_raw())
    grants = {}
    for (arm, ordinal), request_sha in scope().items():
        claim = statement(arm, ordinal, request_sha, base)
        grants[arm + str(ordinal)] = {'statement': claim,
            'signature': key.sign(b'TASK4_NATIVE_OS_V1\0' + canonical(claim)).hex()}
    result = {'public': key.public_key().public_bytes_raw().hex(), 'grants': grants,
              'issuer_credential_reads_denied': True}
    from scripts import task4_native_raw_authority_v1 as authority
    if authority.enabled(base):
        result['raw_authority_denials'] = authority.issue_denials(key, grants['A0'])
    return result


def http_call(method, path, body, key):
    if TLS_BASE is not None:
        from scripts.task4_native_local_https_v1 import call
        return call(TLS_BASE, method, path, body, key)
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request(method, path, body=canonical(body) if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-Mock-Auth':
                tag(key, b'TASK4_NATIVE_HTTP_V1\0', {'method': method, 'path': path, 'body': body}) if key else ''})
        response = conn.getresponse()
        return response.status, parse(response.read(LIMIT + 1))
    finally:
        conn.close()


def open_backend_db(base, restart=False):
    file = base / 'backend/effects.sqlite3'
    need(file.is_file() if restart else not file.exists(), 'EXACT_BACKEND_DATABASE_LIFECYCLE')
    if restart:
        need(fault_mode(base) in FAULTS or concurrent_response_loss_mode(base),
             'FAULT_RECEIPT_ONLY_BACKEND_RESTART')
        db = sqlite3.connect(file.resolve().as_uri() + '?mode=ro', uri=True, isolation_level=None)
        try:
            need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'RETAINED_BACKEND_INTEGRITY')
            rows = db.execute('SELECT op,request_sha,response_sha,receipt FROM effects ORDER BY op').fetchall()
            need(len(rows) == int(fault_mode(base) != 'after-consume'), 'RETAINED_BACKEND_EFFECT_COUNT')
            for op, request_sha, response_sha, receipt in rows:
                need(op == 'A0' and request_sha == scope()[('A', 0)]
                     and type(response_sha) is str and len(response_sha) == 64,
                     'EXACT_RETAINED_NATIVE_REQUEST')
                need(receipt == digest(dict(operation_id=op, request_sha256=request_sha,
                                            response_sha256=response_sha)), 'RETAINED_BACKEND_RECEIPT')
        except BaseException:
            db.close()
            raise
    else:
        db = sqlite3.connect(file, isolation_level=None)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE effects (op TEXT PRIMARY KEY,request_sha TEXT,response_sha TEXT,receipt TEXT)')
    return db


def backend(base, restart=False):
    from scripts import task4_native_bounded_continuation_v1 as bounded
    if bounded.enabled(base):
        need(not restart, 'BOUNDED_BACKEND_RESTART_NOT_ENROLLED')
        return bounded.backend(base)
    from scripts import task4_native_raw_ingress_v1 as ingress
    if ingress.enabled(base):
        need(not restart, 'RAW_FIXTURE_BACKEND_NO_RESTART')
        return ingress.backend(base)
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_retained_sender_denial_v1 import observe
    from scripts import task4_native_local_https_v1 as tls
    local_https = tls.enabled(base)
    kernel.role_identity(BACKEND)
    os.umask(0o077)
    key = (base / 'backend/credential').read_bytes()
    public = (base / 'public/issuer-key').read_bytes()
    db = open_backend_db(base, restart)
    # Restart serves retained receipt evidence only: scripted model state is not
    # reconstructed and no new completion dispatch is permitted.
    sources = {} if restart else {arm: cap.GuardedMock(arm) for arm in ('A', 'B')}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, code, value):
            raw = canonical(value)
            self.send_response(code)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            receipt_query = self.path.startswith('/receipt/')
            op = self.path.removeprefix('/receipt/' if receipt_query else '/status/')
            claim = {'method': 'GET', 'path': self.path, 'body': None}
            if op not in {a + str(i) for a, i in scope()} or not hmac.compare_digest(
                    tag(key, b'TASK4_NATIVE_HTTP_V1\0', claim), self.headers.get('X-Mock-Auth', '')):
                self.respond(403, {'decision': 'DENIED'})
                return
            if receipt_query:
                row = db.execute('SELECT request_sha,response_sha,receipt FROM effects WHERE op=?', (op,)).fetchone()
                self.respond(200, {'operation_id': op, 'record': list(row) if row else None})
                return
            row = db.execute('SELECT receipt FROM effects WHERE op=?', (op,)).fetchone()
            self.respond(200, {'effect_count': db.execute('SELECT count(*) FROM effects').fetchone()[0],
                              'operation_receipt': row[0] if row else None})

        def do_POST(self):
            body = b''
            try:
                size = int(self.headers.get('Content-Length', '0'))
                need(0 < size <= LIMIT and (local_https or self.path == '/effect'), 'EXACT_LOCAL_ENDPOINT')
                body = self.rfile.read(size)
                need(self.path == '/effect', 'EXACT_LOCAL_EFFECT_PATH')
                packet = parse(body)
                need(hmac.compare_digest(tag(key, b'TASK4_NATIVE_HTTP_V1\0',
                     {'method': 'POST', 'path': '/effect', 'body': packet}),
                     self.headers.get('X-Mock-Auth', '')), 'CUSTODY_TRANSPORT_AUTH')
                raw = verify(packet, public)
                need(not restart, 'RESTART_RECEIPT_ONLY_NO_DISPATCH')
                arm, ordinal = packet['arm'], packet['ordinal']
                op = arm + str(ordinal)
                need(not db.execute('SELECT 1 FROM effects WHERE op=?', (op,)).fetchone(), 'BACKEND_SPENT')
                need(sources[arm].attempts == ordinal, 'SCRIPTED_BACKEND_SEQUENCE')
                request = httpx.Request('POST', 'https://api.openai.com/v1/chat/completions', content=raw,
                    headers={'authorization': 'Bearer ' + cap.base.LOCAL_KEY, 'content-type': 'application/json'})
                fake = sources[arm](request)  # Local callable, never an HTTP client.
                if ordinal == 3:
                    sources[arm].verify()
                record = {'operation_id': op, 'request_sha256': sha(raw), 'response_sha256': sha(fake.content)}
                receipt = digest(record)
                db.execute('INSERT INTO effects VALUES (?,?,?,?)', (op, sha(raw), sha(fake.content), receipt))
                observe(base, body, 'EFFECT_COMMITTED')
                tls.observe(base, self, body, 'EFFECT_COMMITTED', record,
                            dict(record, receipt_sha256=receipt, response_b64=encode(fake.content)))
                if (fault_mode(base) == 'backend-response-lost' or concurrent_response_loss_mode(base)) and op == 'A0':
                    durable_marker(base / 'backend/fault-observed.json', dict(record, receipt_sha256=receipt))
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.respond(200, dict(record, receipt_sha256=receipt, response_b64=encode(fake.content)))
            except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
                observe(base, body, 'DENIED')
                tls.observe(base, self, body, 'DENIED')
                self.respond(403, {'decision': 'DENIED'})

    server = (tls.server_class(base)((tls.IP, tls.PORT), Handler) if local_https
              else HTTPServer((HOST, PORT), Handler))
    (base / 'backend/ready').write_text('restarted' if restart else 'ready')
    server.serve_forever()


def bind_post(packet, raw, key):
    from scripts import task4_native_bounded_continuation_v1 as bounded
    from veritas_os.policy.bind_core import execute_bind_adjudication, core
    from veritas_os.policy.bind_core.core import ReferenceBindAdapter
    from veritas_os.policy.bind_artifacts import ExecutionIntent
    from veritas_os.security.hash import sha256_of_canonical_json
    from scripts.ci_mock_executor_veritas_bind_v1 import CORE_BLOB
    loaded = Path(core.__file__).read_bytes()
    need(hashlib.sha1(b'blob ' + str(len(loaded)).encode() + b'\0' + loaded).hexdigest() == CORE_BLOB,
         'ACTUAL_PINNED_BIND_CORE')
    op = packet['arm'] + str(packet['ordinal'])
    index = (0 if packet['arm'] == 'A' else 4) + packet['ordinal']

    def status():
        code, value = http_call('GET', '/status/' + op, None, key)
        need(code == 200, 'AUTHENTICATED_NATIVE_BACKEND_STATUS')
        return value

    before = status()
    need(before == {'effect_count': index, 'operation_receipt': None}, 'EXACT_NATIVE_MOCK_PRESTATE')
    responses, records = [], []
    for allow in (False, True):
        calls = []

        class Adapter(ReferenceBindAdapter):
            def snapshot(self):
                return status()

            def validate_authority(self, intent, snapshot):
                return allow and intent.target_resource == TARGET and snapshot == before

            def validate_constraints(self, intent, snapshot):
                return {'exact_signed_wire': sha(raw) == packet['grant']['statement']['request_sha256'],
                        'exact_prestate': snapshot == before}

            def apply(self, intent, snapshot):
                need(allow and not calls and not responses, 'ONE_NATIVE_MOCK_POST')
                from scripts import task4_native_raw_ingress_v1 as ingress
                code, value = (ingress.dispatch(TLS_BASE, packet, raw, key) if TLS_BASE is not None
                    and ingress.enabled(TLS_BASE) else http_call('POST', '/effect', packet, key))
                need(code == 200, 'LOCAL_MOCK_RESPONSE_REQUIRED')
                need(value['request_sha256'] == sha(raw) and value['operation_id'] == op
                     and value['response_sha256'] == sha(decode(value['response_b64'])), 'EXACT_RAW_RESPONSE')
                need(value['receipt_sha256'] == digest({k: value[k] for k in
                     ('operation_id', 'request_sha256', 'response_sha256')}), 'BACKEND_RECEIPT')
                calls.append(value)
                responses.append(value)
                return True

            def verify_postconditions(self, intent, snapshot):
                return len(calls) == 1 and status() == {'effect_count': index + 1,
                    'operation_receipt': calls[0]['receipt_sha256']}

            def revert(self, intent, snapshot):
                return False

        intent = ExecutionIntent(decision_id='TASK4-OS-' + op + '-' + str(allow), request_id='TASK4-OS-' + op,
            policy_snapshot_id=('SYNTHETIC_BOUNDED_NATIVE_HISTORY_NOT_OWNER_APPROVAL' if bounded.enabled(TLS_BASE)
                                else 'SYNTHETIC_FROZEN_NATIVE_SCOPE_NOT_OWNER_APPROVAL'),
            actor_identity='custody-uid-61106', target_system='local-mock-backend', target_resource=TARGET,
            intended_action='one_scripted_native_completion', evidence_refs=['signed-wire:' + sha(raw)],
            decision_hash=digest(packet['grant']['statement']), decision_ts='2026-10-20T00:00:00Z',
            ttl_seconds=300, expected_state_fingerprint=sha256_of_canonical_json(before),
            approval_context={'real_human_approval': False, 'synthetic_test_permission': True},
            policy_lineage={'fixture': 'task4-native-os-custody'})
        adapter = Adapter(state=dict(before), pending_changes={}, target_description=TARGET)
        receipt = execute_bind_adjudication(execution_intent=intent, adapter=adapter,
            bind_ts='2026-10-20T00:00:03Z', append_trustlog=False).to_dict()
        from scripts import task4_native_raw_ingress_v1 as ingress
        if TLS_BASE is not None and ingress.enabled(TLS_BASE):
            ingress.emit(TLS_BASE, op, 'BIND_RECEIPT', receipt=receipt,
                         apply_calls=len(calls), allowed=allow)
        need(receipt['final_outcome'] == ('COMMITTED' if allow else 'BLOCKED')
             and len(calls) == int(allow), 'REAL_BIND_NATIVE_OUTCOME')
        need(status() == ({'effect_count': index + 1, 'operation_receipt': responses[0]['receipt_sha256']}
             if allow else before), 'DENIED_BIND_NO_SEND')
        records.append({'outcome': receipt['final_outcome'], 'apply_calls': len(calls),
                        'receipt': receipt, 'receipt_sha256': digest(receipt)})
    return responses[0], {'records': records, 'loaded_core_sha256': sha(loaded), 'bind_core_git_blob': CORE_BLOB}


def race_barrier(base, role, db, raw):
    need(db.execute('SELECT count(*) FROM consumed').fetchone()[0] == 0, 'BOTH_ARRIVE_BEFORE_CONSUMPTION')
    record = {'pid': os.getpid(), 'uid': os.geteuid(), 'request_sha256': sha(raw),
              'consumptions_before': 0, 'entered_ns': time.monotonic_ns()}
    marker = base / 'custody' / ('race-entered-' + role + '.json')
    staged = marker.with_suffix('.writing')
    durable_marker(staged, record)
    os.link(staged, marker)  # Publish complete bytes atomically, without overwrite.
    staged.unlink()
    other = base / 'custody' / ('race-entered-' + ('primary' if role == 'secondary' else 'secondary') + '.json')
    deadline = time.monotonic() + 8
    while not other.exists():
        need(time.monotonic() < deadline, 'TWO_CUSTODY_BARRIER_TIMEOUT')
        time.sleep(0.01)
    other_record = parse(other.read_bytes())
    need(other_record['pid'] != record['pid'] and other_record['request_sha256'] == sha(raw)
         and other_record['uid'] == CUSTODY and other_record['consumptions_before'] == 0,
         'DISTINCT_VERIFIED_REQUEST_CONTENDERS')
    durable_marker(base / 'custody' / ('race-released-' + role + '.json'),
                   {'pid': os.getpid(), 'released_ns': time.monotonic_ns()})


def custody(base, restart=False, secondary=False):
    from scripts import task4_native_bounded_continuation_v1 as bounded
    if bounded.enabled(base):
        need(not secondary, 'BOUNDED_SECONDARY_NOT_ENROLLED')
        return bounded.custody(base, restart)
    import httpx
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from scripts.task4_457_local_response_aead_v1 import SealedLocalVault
    kernel.role_identity(CUSTODY)
    os.umask(0o077)
    key = (base / 'custody/credential').read_bytes()
    public = (base / 'public/issuer-key').read_bytes()
    file = base / 'custody/ledger.sqlite3'
    need(not secondary or concurrent_mode(base), 'SECOND_CUSTODY_REQUIRES_CONCURRENT_FIXTURE')
    need(file.exists() if restart or secondary else not file.exists(), 'EXACT_NATIVE_LEDGER_LIFECYCLE')
    db = sqlite3.connect(file, isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    if not restart and not secondary:
        db.execute('CREATE TABLE consumed (op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
    else:
        from scripts import task4_native_raw_ingress_v1 as ingress
        raw_fault = ingress.enabled(base) and ingress.plan(base)['mode'] != 'success'
        expected = (1 if restart else 0) if concurrent_mode(base) else (1 if fault_mode(base) or raw_fault else 8)
        need(db.execute('SELECT count(*) FROM consumed').fetchone()[0] == expected,
             'EXACT_DURABLE_CONSUMPTIONS')
    vault = SealedLocalVault(base / 'custody', X25519PublicKey.from_public_bytes(recipient()))
    address = base / ('ipc/native-secondary.sock' if secondary else 'ipc/native.sock')
    if restart:
        address.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(address))
    os.chmod(address, 0o666)
    server.listen(8)
    (base / ('custody/secondary-ready' if secondary else 'custody/ready')).write_text('restarted' if restart else 'ready')
    race_pending = concurrent_mode(base) and not restart
    role = 'secondary' if secondary else 'primary'
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(15)
            packet = None
            try:
                packet = frame(conn)
                _, peer, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer == NATIVE, 'KERNEL_NATIVE_PEER_REQUIRED')
                raw = verify(packet, public)
                op = packet['arm'] + str(packet['ordinal'])
                racing = race_pending
                if racing:
                    need(op == 'A0', 'EXACT_NATIVE_RACE_SLOT')
                    race_barrier(base, role, db, raw)
                    race_pending = False
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('INSERT INTO consumed VALUES (?, ?, ?, NULL,NULL,NULL,NULL)',
                               (op, 'CONSUMED_UNKNOWN', sha(raw)))
                except sqlite3.IntegrityError:
                    db.rollback()
                    result = {'decision': 'REPLAY_DENIED'}
                    if racing:
                        durable_marker(base / 'custody' / ('race-outcome-' + role + '.json'),
                                       {'pid': os.getpid(), 'decision': 'REPLAY_DENIED'})
                else:
                    db.commit()
                    from scripts import task4_native_raw_ingress_v1 as ingress
                    if ingress.enabled(base):
                        ingress.consumed(base, op, raw)
                    if racing:
                        durable_marker(base / 'custody' / ('race-outcome-' + role + '.json'),
                                       {'pid': os.getpid(), 'decision': 'CONSUMED'})
                        if concurrent_crash_mode(base):
                            durable_marker(base / 'custody/race-winner-crash.json',
                                {'stage': 'AFTER_DURABLE_CONSUME_BEFORE_BIND', 'role': role, 'pid': os.getpid(),
                                 'operation_id': op, 'request_sha256': sha(raw)})
                            os._exit(88)
                    if not restart and fault_mode(base) == 'after-consume':
                        durable_marker(base / 'custody/fault-observed.json', {'stage': 'after-consume', 'op': op})
                        os._exit(86)
                    try:
                        response, binding = bind_post(packet, raw, key)
                    except (ValueError, OSError, KeyError, TypeError):
                        if racing and concurrent_response_loss_mode(base):
                            durable_marker(base / 'custody/race-winner-crash.json',
                                {'stage': 'AFTER_BACKEND_RESPONSE_LOSS_BEFORE_NATIVE_REPLY', 'role': role,
                                 'pid': os.getpid(), 'operation_id': op, 'request_sha256': sha(raw)})
                            os._exit(89)
                        raise
                    plaintext = decode(response['response_b64'])
                    request = httpx.Request('POST', 'https://api.openai.com/v1/chat/completions', content=raw)
                    reply = httpx.Response(200, content=plaintext, request=request)
                    sealed = vault.commit_before_parser(arm=packet['arm'], ordinal=packet['ordinal'],
                                                        request=request, response=reply)
                    blob = (base / 'custody' / sealed['envelope_filename']).read_bytes()
                    bind_sha = digest(binding)
                    (base / 'custody' / (op + '-bind.json')).write_bytes(canonical(binding))
                    db.execute('UPDATE consumed SET state=?,response_sha=?,backend_receipt=?,envelope_sha=?,bind_sha=? WHERE op=?',
                        ('MOCK_OBSERVED', sha(plaintext), response['receipt_sha256'], sha(blob), bind_sha, op))
                    if not restart and fault_mode(base) == 'after-sealed':
                        durable_marker(base / 'custody/fault-observed.json', {'stage': 'after-sealed', 'op': op})
                        os._exit(87)
                    result = {'decision': 'SEALED_NATIVE_RESPONSE', 'request_sha256': sha(raw),
                              'response_sha256': sha(plaintext), 'backend_receipt_sha256': response['receipt_sha256'],
                              'envelope_sha256': sha(blob), 'envelope_b64': encode(blob), 'bind_sha256': bind_sha}
            except (ValueError, OSError, KeyError, TypeError) as exc:
                from scripts import task4_native_raw_authority_v1 as authority
                if authority.enabled(base):
                    authority.refusal(base, packet, str(exc))
                if db.in_transaction:
                    db.rollback()
                result = {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}
            conn.sendall(canonical(result) + b'\n')


def probe(base, reachable=False):
    kernel.role_identity(NATIVE)
    if reachable:
        from scripts import task4_native_raw_ingress_v1 as ingress
        if ingress.enabled(base):
            return ingress.reachable(base)
        code, result = http_call('POST', '/effect', {}, None)
        need(code == 403 and result == {'decision': 'DENIED'}, 'NETWORK_IS_NOT_TRANSPORT_AUTHORITY')
        return {'reachable_native_uid_without_credential_http_403': True}
    checks = {}
    for rel in ('custody/credential', 'custody/ledger.sqlite3', 'backend/credential',
                'backend/effects.sqlite3', 'issuer/private-key'):
        try:
            (base / rel).read_bytes()
        except PermissionError:
            checks['read_denied:' + rel] = True
        else:
            raise ValueError('NATIVE_PRIVATE_AUTHORITY_READABLE')
    try:
        (base / 'public/issuer-key').write_bytes(b'attacker')
    except PermissionError:
        checks['trust_key_overwrite_denied'] = True
    else:
        raise ValueError('TRUST_KEY_OVERWRITE')
    try:
        Path(__file__).write_bytes(b'attacker')
    except PermissionError:
        checks['tracked_service_code_overwrite_denied'] = True
    else:
        raise ValueError('TRACKED_SERVICE_CODE_OVERWRITE')
    from scripts import task4_native_local_https_v1 as tls
    host, port = (tls.IP, tls.PORT) if tls.enabled(base) else (HOST, PORT)
    checks['raw_ipv4_denied'] = kernel.denied_connect(host, port)
    checks['raw_ipv6_denied'] = kernel.denied_connect('2001:db8::1', 443, socket.AF_INET6)
    try:
        http_call('POST', '/effect', {}, None)
    except OSError:
        checks['http_direct_denied'] = True
    else:
        raise ValueError('NATIVE_HTTP_DIRECT_ALLOWED')
    child = subprocess.run([sys.executable, '-I', '-c',
        'import socket,sys\ntry: socket.create_connection((' + repr(host) + ',' + str(port) + '),1)\n'
        'except OSError: sys.exit(0)\nelse: sys.exit(9)'], capture_output=True, timeout=4)
    need(child.returncode == 0, 'SUBPROCESS_NETWORK_BYPASS')
    checks['subprocess_network_denied'] = True
    return checks


def native(base):
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts import task4_456_raw_response_native_lineage_offline_v1 as lineage
    from scripts.task4_native_frozen_recipient_v1 import public_test_recipient
    from scripts.task4_native_protected_custody_v1 import ProtectedAdapter
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    kernel.role_identity(NATIVE)
    from scripts import task4_native_raw_ingress_v1 as ingress
    raw_owner_denied = ingress.owner_denied(base) if ingress.enabled(base) else False
    cap.base.verify_pins()
    frozen_sources = verify_pins()
    grants = parse((base / 'public/grants.json').read_bytes())
    records, packets = [], []
    journal = lineage.RawResponseJournal()

    class Transport(httpx.BaseTransport):
        def __init__(self, source):
            need(type(source) is cap.GuardedMock, 'PINNED_REFERENCE_SOURCE')
            self.source = source

        def handle_request(self, request):
            # The original local callable remains a reference oracle, not the
            # response returned to the SDK. Actual returned bytes come via Custody.
            expected = self.source(request)
            arm, ordinal = self.source.origin_arm, self.source.attempts - 1
            packet = {'arm': arm, 'ordinal': ordinal, 'wire_b64': encode(request.content),
                      'grant': grants[arm + str(ordinal)]}
            result = query(base, packet)
            need(result['decision'] == 'SEALED_NATIVE_RESPONSE', 'OS_CUSTODY_REQUIRED')
            blob = decode(result['envelope_b64'])
            need(sha(blob) == result['envelope_sha256'] and result['request_sha256'] == sha(request.content),
                 'SEALED_RESPONSE_REQUEST_JOIN')
            plaintext = ProtectedAdapter.recover_test_ciphertext(blob, public_test_recipient())
            need(plaintext == expected.content and sha(plaintext) == result['response_sha256'],
                 'ORIGINAL_SCRIPTED_RESPONSE_BYTES_REQUIRED')
            response = httpx.Response(200, content=plaintext, request=request)
            journal.observe(arm=arm, request=request, response=response)
            records.append({'arm': arm, 'ordinal': ordinal, **{k: result[k] for k in
                ('request_sha256', 'response_sha256', 'envelope_sha256', 'backend_receipt_sha256', 'bind_sha256')}})
            packets.append(packet)
            return response

    with patch.object(httpx, 'MockTransport', Transport), \
         patch('openai._base_client.get_platform', return_value='Unknown'):
        rows = cap.run_both_sources()
    sealed_lineage = journal.seal([row['native_origin'] for row in rows])
    need(len(records) == len(packets) == 8 and len(sealed_lineage['response_receipts']) == 8, 'EIGHT_NATIVE_OS_JOINS')
    need({(x['arm'], x['ordinal']): x['request_sha256'] for x in records} == scope(), 'SAME_FROZEN_NATIVE_REQUESTS')
    for row in rows:
        need(row['native_origin']['full_source_native_scorer']['scorer_calls'] == 1
             and row['genuine_model_generations'] == row['real_provider_posts'] == 0, 'NATIVE_SCORER_WITHOUT_LIVE_PROVIDER')
    for packet in packets:
        need(query(base, packet) == {'decision': 'REPLAY_DENIED'}, 'NATIVE_REPLAY_MUST_NOT_SEND')
    first = packets[0]
    bad_signature = json.loads(json.dumps(first))
    bad_signature['grant']['signature'] = '0' * 128
    bad_wire = dict(first, wire_b64=encode(b'{}'))
    bad_target = dict(first, destination='https://example.invalid/')
    for packet in (bad_signature, bad_wire, bad_target):
        need(query(base, packet) == {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}, 'INVALID_NATIVE_REQUEST_MUST_DENY')
    for packet in packets:
        (base / 'native' / ('packet-' + packet['arm'] + str(packet['ordinal']) + '.json')).write_bytes(
            canonical(packet))  # Ephemeral, never uploaded.
    return {'records': records, 'lineage_sha256': digest(sealed_lineage),
            'raw_owner_private_read_denied': raw_owner_denied,
            'lineage': sealed_lineage,
            'frozen_source_git_blobs': frozen_sources,
            'native_terminal_hashes': [x['native_selected_terminal_sha256'] for x in rows],
            'native_arm_receipts': [{'arm': x['arm'],
                'terminal_sha256': x['native_selected_terminal_sha256'],
                'post_state_sha256': x['native_origin']['selected_native_arm']['post_state_sha256'],
                'scorer_observation_sha256': digest(x['native_origin']['full_source_native_scorer'])} for x in rows],
            'scorer_calls': 2, 'scripted_native_arms': 2, 'replay_denials': 8,
            'signature_wire_target_denials': 3}


def restart_probe(base):
    kernel.role_identity(NATIVE)
    for arm, ordinal in scope():
        packet = parse((base / 'native' / ('packet-' + arm + str(ordinal) + '.json')).read_bytes())
        need(query(base, packet) == {'decision': 'REPLAY_DENIED'}, 'RESTART_REPLAY_DENIED')
    return {'restart_replay_denials': 8}


def wrong_peer(base):
    kernel.role_identity(kernel.STRANGER)
    packet = parse((base / 'public/peer-packet.json').read_bytes())
    need(query(base, packet) == {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}, 'KERNEL_PEER_CANNOT_BE_CLAIMED')
    return {'kernel_wrong_peer_denied': True}


def fault_native(base):
    """Stop the real Native driver at its first actual SDK transport invocation."""
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    kernel.role_identity(NATIVE)
    from scripts import task4_native_raw_ingress_v1 as ingress
    raw_owner_denied = ingress.owner_denied(base) if ingress.enabled(base) else False
    cap.base.verify_pins()
    frozen_sources = verify_pins()
    grants = parse((base / 'public/grants.json').read_bytes())
    observations = []

    class StopBeforeParser(BaseException):
        pass

    class Transport(httpx.BaseTransport):
        def __init__(self, source):
            need(type(source) is cap.GuardedMock, 'PINNED_REFERENCE_SOURCE')
            self.source = source

        def handle_request(self, request):
            need(not observations and self.source.origin_arm == 'A', 'FIRST_ACTUAL_NATIVE_REQUEST_ONLY')
            self.source(request)  # Check the original driver's expected wire.
            packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': encode(request.content), 'grant': grants['A0']}
            verify(packet, (base / 'public/issuer-key').read_bytes())
            durable_marker(base / 'native/packet-A0.json', packet)
            try:
                result = query(base, packet)
            except (ValueError, OSError):
                result = {'decision': 'IPC_RESPONSE_LOST'}
            need(result['decision'] in {'IPC_RESPONSE_LOST', 'DENIED_OR_UNKNOWN_NO_RETRY'},
                 'FAULT_MUST_NOT_RETURN_SDK_RESPONSE')
            observations.append({'request_sha256': sha(request.content), 'decision': result['decision']})
            raise StopBeforeParser()

    try:
        with patch.object(httpx, 'MockTransport', Transport), \
             patch('openai._base_client.get_platform', return_value='Unknown'):
            cap.run_both_sources()
    except StopBeforeParser:
        pass
    need(len(observations) == 1, 'EXACTLY_ONE_FAULTED_SDK_REQUEST')
    return {'observations': observations, 'sdk_responses_returned': 0, 'native_terminal_arms': 0,
            'raw_owner_private_read_denied': raw_owner_denied,
            'scorer_calls': 0, 'transport_invocations': len(observations),
            'frozen_source_git_blobs': frozen_sources}


def fault_replay(base):
    kernel.role_identity(NATIVE)
    packet = parse((base / 'native/packet-A0.json').read_bytes())
    for _ in range(2):
        need(query(base, packet) == {'decision': 'REPLAY_DENIED'}, 'FAULT_RESTART_REPLAY_DENIED')
    return {'replay_denials': 2, 'request_sha256': sha(decode(packet['wire_b64']))}


def reconcile_fault(base):
    """Read authenticated backend evidence; never issue another POST or return bytes."""
    kernel.role_identity(CUSTODY)
    key = (base / 'custody/credential').read_bytes()
    with sqlite3.connect(base / 'custody/ledger.sqlite3') as db:
        row = db.execute('SELECT state,request_sha,response_sha,backend_receipt FROM consumed WHERE op=?', ('A0',)).fetchone()
        need(row is not None, 'CONSUMED_RECORD_REQUIRED')
        code, evidence = http_call('GET', '/receipt/A0', None, key)
        need(code == 200 and evidence['operation_id'] == 'A0', 'AUTHENTICATED_RECEIPT_REQUIRED')
        record = evidence['record']
        if record is None:
            need(row[0] == 'CONSUMED_UNKNOWN', 'ABSENCE_MUST_NOT_RESET_AUTHORITY')
            state = row[0]  # Absence does not prove NO_EFFECT or permit a resend.
        else:
            need(type(record) is list and len(record) == 3 and record[0] == row[1], 'EXACT_RECEIPT_REQUEST')
            need(record[2] == digest({'operation_id': 'A0', 'request_sha256': record[0],
                                     'response_sha256': record[1]}), 'EXACT_RECEIPT_HASH')
            state = 'MOCK_OBSERVED' if row[0] == 'MOCK_OBSERVED' else 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE'
            if row[0] in {'MOCK_OBSERVED', 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE'}:
                need(tuple(record[1:]) == row[2:], 'STORED_LEDGER_RECEIPT_MATCH')
            db.execute('UPDATE consumed SET state=?,response_sha=?,backend_receipt=? WHERE op=?',
                       (state, record[1], record[2], 'A0'))
    return {'state': state, 'backend_evidence': evidence, 'post_calls': 0, 'raw_response_recovered': False}


def offline_reconcile(base):
    kernel.role_identity(CUSTODY)
    file = base / 'custody/ledger.sqlite3'
    with sqlite3.connect(file) as db:
        before = db.execute('SELECT * FROM consumed ORDER BY op').fetchall()
    try:
        reconcile_fault(base)
    except OSError:
        pass
    else:
        raise ValueError('STOPPED_BACKEND_MUST_BE_UNAVAILABLE')
    with sqlite3.connect(file) as db:
        need(db.execute('SELECT * FROM consumed ORDER BY op').fetchall() == before,
             'UNAVAILABLE_RECONCILIATION_MUST_PRESERVE_LEDGER')
    return {'backend_unavailable': True, 'ledger_unchanged': True, 'permission_restored': False}


def backend_replay(base):
    kernel.role_identity(CUSTODY)
    packet = parse((base / 'public/replay-packet.json').read_bytes())
    key = (base / 'custody/credential').read_bytes()
    verify(packet, (base / 'public/issuer-key').read_bytes())
    code, response = http_call('POST', '/effect', packet, key)
    need(code == 403 and response == {'decision': 'DENIED'}, 'RESTART_BACKEND_AUTHENTIC_REPLAY_DENIED')
    return {'authentic_replay_denied': True, 'http_status': code}


def finish_fault(base, output, fault, worker, spawn, service, native_ns, head, pins,
                 sink=None, sink_ns=None, restart_both=False):
    checks = worker(NATIVE, 'probe', native_ns)
    native_report = worker(NATIVE, 'fault-native', native_ns)
    if fault == 'backend-response-lost':
        need(service.poll() is None, 'UNKNOWN_RESPONSE_CUSTODY_SURVIVED')
        service.kill()
        need(service.wait(timeout=5) == -9, 'ACTUAL_CUSTODY_SIGKILL')
        marker = parse((base / 'backend/fault-observed.json').read_bytes())
    else:
        need(service.wait(timeout=5) == {'after-consume': 86, 'after-sealed': 87}[fault], 'ACTUAL_FAULT_EXIT')
        marker = parse((base / 'custody/fault-observed.json').read_bytes())
        need(marker == {'stage': fault, 'op': 'A0'}, 'EXACT_CRASH_STAGE')
    restart_evidence = None
    if restart_both:
        retained = read_fault_rows(base)
        backend_sha = sha((base / 'backend/effects.sqlite3').read_bytes())
        old_pids = {'custody': service.pid, 'backend': sink.pid}
        sink.kill()
        need(sink.wait(timeout=5) == -9, 'ACTUAL_BACKEND_SIGKILL')
        (base / 'backend/ready').unlink()
    (base / 'custody/ready').unlink()
    service = spawn(CUSTODY, 'custody', None, base / 'custody/ready', 'restarted', ('--restart',))
    if restart_both:
        offline_replay = worker(NATIVE, 'fault-replay', native_ns)
        unavailable = worker(CUSTODY, 'offline-reconcile')
        need(read_fault_rows(base) == retained, 'STOPPED_BACKEND_NO_LEDGER_CHANGE')
        sink = spawn(BACKEND, 'backend', sink_ns, base / 'backend/ready', 'restarted', ('--restart',))
        need(service.pid != old_pids['custody'] and sink.pid != old_pids['backend'], 'NEW_SERVICE_PROCESSES')
        need(read_fault_rows(base) == retained, 'BOTH_RESTART_RETAINS_EXACT_ROWS')
        replay_file = base / 'public/replay-packet.json'
        replay_file.write_bytes((base / 'native/packet-A0.json').read_bytes())
        os.chmod(replay_file, 0o444)
        denied = worker(CUSTODY, 'backend-replay')
        restart_evidence = {'old_pids': old_pids, 'new_pids': {'custody': service.pid, 'backend': sink.pid},
            'retained_rows': retained, 'backend_database_sha256': backend_sha,
            'unavailable': unavailable, 'offline_replay': offline_replay, 'backend_replay': denied,
            'backend_restart_receipt_only': True}
    replay = worker(NATIVE, 'fault-replay', native_ns)
    before = read_fault_rows(base)
    reconciliation = worker(CUSTODY, 'reconcile-fault')
    again = worker(CUSTODY, 'reconcile-fault')
    need(again == reconciliation, 'RECONCILIATION_IDEMPOTENT')
    second_replay = worker(NATIVE, 'fault-replay', native_ns)
    after = read_fault_rows(base)
    effects, consumed = after['effects'], after['consumed']
    expected_count = int(fault != 'after-consume')
    expected_state = {'after-consume': 'CONSUMED_UNKNOWN',
                      'backend-response-lost': 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE',
                      'after-sealed': 'MOCK_OBSERVED'}[fault]
    request_sha = native_report['observations'][0]['request_sha256']
    need(len(effects) == expected_count and len(consumed) == 1, 'FAULT_EFFECT_CONSUMPTION_COUNTS')
    need(consumed[0][0:3] == ['A0', expected_state, request_sha], 'DURABLE_FAULT_STATE')
    need(request_sha == scope()[('A', 0)] == replay['request_sha256'] == second_replay['request_sha256'],
         'SAME_ACTUAL_FROZEN_SDK_REQUEST')
    need(before['effects'] == effects, 'NO_EFFECT_FROM_REPLAY_OR_RECONCILIATION')
    if effects:
        row = effects[0]
        need(row[:2] == ['A0', request_sha] and row[2:4] == consumed[0][3:5], 'BACKEND_CUSTODY_FAULT_JOIN')
        need(row[3] == digest({'operation_id': row[0], 'request_sha256': row[1],
                               'response_sha256': row[2]}), 'FAULT_RECEIPT_HASH')
        if fault == 'backend-response-lost':
            need(marker == dict(operation_id=row[0], request_sha256=row[1], response_sha256=row[2],
                                receipt_sha256=row[3]), 'DURABLE_LOST_RESPONSE_MARKER')
    ciphertexts = list((base / 'custody').glob('*.enc.json'))
    need(len(ciphertexts) == int(fault == 'after-sealed'), 'EXACT_FAULT_CIPHERTEXT_COUNT')
    binding = None
    if fault == 'after-sealed':
        binding = parse((base / 'custody/A0-bind.json').read_bytes())
        need(sha(ciphertexts[0].read_bytes()) == consumed[0][5] and digest(binding) == consumed[0][6],
             'DURABLE_SEALED_BIND_FAULT_JOIN')
        need([(x['outcome'], x['apply_calls']) for x in binding['records']] == [('BLOCKED', 0), ('COMMITTED', 1)],
             'ACTUAL_BIND_BEFORE_SEALED_CRASH')
    else:
        need(consumed[0][5:] == [None, None], 'NO_INVENTED_CIPHERTEXT_OR_BIND_RECEIPT')
    checks.update({'actual_fault_stage_observed': True, 'single_actual_frozen_sdk_request': True,
        'no_sdk_response_or_native_completion': native_report['sdk_responses_returned'] == native_report['scorer_calls'] == 0,
        'durable_consumption_after_restart': True, 'four_replays_denied': replay['replay_denials'] + second_replay['replay_denials'] == 4,
        'authenticated_reconciliation_idempotent': True, 'reconciliation_never_posts': reconciliation['post_calls'] == 0,
        'no_replay_or_reconciliation_effect': True, 'exact_fault_evidence_join': True,
        'absence_never_restores_permission': True})
    if restart_both:
        need(sha((base / 'backend/effects.sqlite3').read_bytes()) == backend_sha,
             'BACKEND_DATABASE_UNCHANGED_BYTES')
        need(offline_replay['request_sha256'] == request_sha, 'SAME_REQUEST_WHILE_BACKEND_STOPPED')
        checks.update({'both_services_new_processes': True, 'stopped_backend_replays_denied': offline_replay['replay_denials'] == 2,
            'unavailable_reconciliation_preserves_ledger': unavailable['ledger_unchanged'],
            'backend_retained_database_bytes': True, 'backend_authentic_replay_denied': denied['authentic_replay_denied'],
            'both_restart_restores_exact_rows': True, 'backend_restart_receipt_only': True})
    need(all(x is True for x in checks.values()), 'ALL_FAULT_CHECKS_REQUIRED')
    report = {'schema': 'task4.native.os-custody.fault.v1', 'fault': fault, 'audited_commit': head,
        'source_sha256': sha(Path(__file__).read_bytes()), 'external_pins': pins, 'checks': checks,
        'native': native_report, 'replay_denials': 6 if restart_both else 4, 'before_reconciliation': before,
        'after_reconciliation': after, 'reconciliation': reconciliation, 'bind_record': binding,
        'ciphertext_count': len(ciphertexts), 'mock_http_effects': len(effects), 'custody_consumptions': 1,
        'real_provider_posts': 0, 'external_bank_effects': 0, 'utility': 'UNSCORED', 'provider_dispatch': 'DENY',
        'production_bypass_resistance_proven': False, 'independent_administration_proven': False,
        'raw_response_recovery_proven': False, 'backend_restart_tested': restart_both,
        'restart_evidence': restart_evidence, 'scripted_backend_continuation_after_restart_proven': False,
        'cross_process_concurrent_native_consumption_tested': False}
    (output / 'report.json').write_bytes(canonical(report))
    suite = ET.Element('testsuite', name='Native OS Custody Fault ' + fault, tests=str(len(checks)),
                       failures='0', errors='0', skipped='0')
    for name in sorted(checks):
        ET.SubElement(suite, 'testcase', classname='native_os_custody_fault', name=name)
    ET.ElementTree(suite).write(output / 'junit.xml', encoding='utf-8', xml_declaration=True)


def read_fault_rows(base):
    with sqlite3.connect(base / 'backend/effects.sqlite3') as db:
        effects = db.execute('SELECT op,request_sha,response_sha,receipt FROM effects ORDER BY op').fetchall()
    with sqlite3.connect(base / 'custody/ledger.sqlite3') as db:
        consumed = db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed ORDER BY op').fetchall()
    return {'effects': [list(x) for x in effects], 'consumed': [list(x) for x in consumed]}


def select_race_winner(results):
    need(type(results) is list and len(results) == 2 and all(type(x) is dict for x in results),
         'TWO_NATIVE_RACE_RESULTS')
    need(sorted(x.get('decision', '') for x in results) == ['REPLAY_DENIED', 'SEALED_NATIVE_RESPONSE'],
         'ONE_NATIVE_RACE_WINNER_REQUIRED')
    winner = next(i for i, value in enumerate(results) if value['decision'] == 'SEALED_NATIVE_RESPONSE')
    need(results[1 - winner] == {'decision': 'REPLAY_DENIED'}, 'LOSER_MUST_NOT_RETURN_RESPONSE')
    return winner, results[winner]


def select_crashed_winner(results):
    need(type(results) is list and len(results) == 2 and all(type(x) is dict and set(x) == {'decision'} for x in results),
         'TWO_EXACT_CRASH_RACE_RESULTS')
    need(sorted(x['decision'] for x in results) == ['IPC_RESPONSE_LOST', 'REPLAY_DENIED'],
         'ONE_CRASHED_WINNER_AND_ONE_REPLAY_REQUIRED')
    return next(i for i, value in enumerate(results) if value['decision'] == 'IPC_RESPONSE_LOST')


def concurrent_native(base):
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    from scripts.task4_native_frozen_recipient_v1 import public_test_recipient
    from scripts.task4_native_protected_custody_v1 import ProtectedAdapter
    kernel.role_identity(NATIVE)
    cap.base.verify_pins()
    frozen_sources = verify_pins()
    grants = parse((base / 'public/grants.json').read_bytes())
    observations = []
    crashed = concurrent_crash_mode(base) or concurrent_response_loss_mode(base)

    class StopBeforeSecondDispatch(BaseException):
        pass

    class Transport(httpx.BaseTransport):
        def __init__(self, source):
            need(type(source) is cap.GuardedMock, 'PINNED_REFERENCE_SOURCE')
            self.source = source

        def handle_request(self, request):
            if observations:
                need(len(observations) == 1 and sha(request.content) == scope()[('A', 1)],
                     'NEXT_ACTUAL_SDK_WIRE_AFTER_FIRST_RESPONSE')
                observations.append({'next_request_sha256': sha(request.content)})
                raise StopBeforeSecondDispatch()
            need(self.source.origin_arm == 'A', 'FIRST_NATIVE_RACE_ARM')
            expected = self.source(request)
            packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': encode(request.content), 'grant': grants['A0']}
            verify(packet, (base / 'public/issuer-key').read_bytes())
            durable_marker(base / 'native/packet-A0.json', packet)
            def attempt(secondary):
                try:
                    return query(base, packet, secondary)
                except (ValueError, OSError):
                    if not crashed:
                        raise
                    return {'decision': 'IPC_RESPONSE_LOST'}
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(attempt, secondary) for secondary in (False, True)]
                results = [future.result(timeout=20) for future in futures]
            if crashed:
                index = select_crashed_winner(results)
                observations.append({'winner_role': 'secondary' if index else 'primary',
                    'decisions': [x['decision'] for x in results], 'request_sha256': sha(request.content)})
                raise StopBeforeSecondDispatch()
            index, result = select_race_winner(results)
            blob = decode(result['envelope_b64'])
            need(sha(blob) == result['envelope_sha256'] and result['request_sha256'] == sha(request.content),
                 'RACE_CIPHERTEXT_REQUEST_JOIN')
            plaintext = ProtectedAdapter.recover_test_ciphertext(blob, public_test_recipient())
            need(plaintext == expected.content and sha(plaintext) == result['response_sha256'], 'RACE_ORIGINAL_RESPONSE_BYTES')
            observations.append({'winner_role': 'secondary' if index else 'primary',
                'decisions': [x['decision'] for x in results], **{k: result[k] for k in
                ('request_sha256', 'response_sha256', 'backend_receipt_sha256', 'envelope_sha256', 'bind_sha256')}})
            return httpx.Response(200, content=plaintext, request=request)

    try:
        with patch.object(httpx, 'MockTransport', Transport), \
             patch('openai._base_client.get_platform', return_value='Unknown'):
            cap.run_both_sources()
    except StopBeforeSecondDispatch:
        pass
    need(len(observations) == (1 if crashed else 2), 'EXACT_NATIVE_RACE_CONTINUATION')
    return {'race': observations[0], 'next_request_sha256': None if crashed else observations[1]['next_request_sha256'],
        'frozen_source_git_blobs': frozen_sources, 'sdk_transport_invocations': 1 if crashed else 2,
        'distinct_native_requests_forwarded': 1, 'custody_attempts': 2, 'sdk_responses_returned': 0 if crashed else 1,
        'native_terminal_arms': 0, 'scorer_calls': 0}


def concurrent_replay(base):
    kernel.role_identity(NATIVE)
    packet = parse((base / 'native/packet-A0.json').read_bytes())
    for secondary in (False, True):
        for _ in range(2):
            need(query(base, packet, secondary) == {'decision': 'REPLAY_DENIED'}, 'BOTH_CUSTODIES_REPLAY_DENIED')
    return {'replay_denials': 4}


def concurrent_crash_replay(base):
    kernel.role_identity(NATIVE)
    winner = parse((base / 'public/crashed-winner.json').read_bytes())
    need(set(winner) == {'role'} and winner['role'] in {'primary', 'secondary'}, 'ENROLLED_CRASHED_WINNER')
    packet = parse((base / 'native/packet-A0.json').read_bytes())
    try:
        query(base, packet, winner['role'] == 'secondary')
    except (ValueError, OSError):
        pass
    else:
        raise ValueError('CRASHED_CUSTODY_MUST_BE_UNAVAILABLE')
    for _ in range(2):
        need(query(base, packet, winner['role'] != 'secondary') == {'decision': 'REPLAY_DENIED'},
             'SURVIVING_CUSTODY_MUST_NOT_TAKE_OVER')
    return {'stopped_winner_unavailable': True, 'survivor_replay_denials': 2}


def finish_concurrent_crash(base, output, worker, spawn, processes, native_ns, head, pins,
                            checks, native_report, entered, released, outcomes,
                            sink=None, sink_ns=None, restart_both=False):
    response_loss = concurrent_response_loss_mode(base)
    race = native_report['race']
    winner_role = race['winner_role']
    loser_role = 'primary' if winner_role == 'secondary' else 'secondary'
    winner, loser = processes[winner_role], processes[loser_role]
    old_pids = {role: process.pid for role, process in processes.items()}
    exit_code = 89 if response_loss else 88
    stage = 'AFTER_BACKEND_RESPONSE_LOSS_BEFORE_NATIVE_REPLY' if response_loss else 'AFTER_DURABLE_CONSUME_BEFORE_BIND'
    need(winner.wait(timeout=5) == exit_code and loser.poll() is None, 'ONLY_CONSUMED_WINNER_CRASHES')
    marker = parse((base / 'custody/race-winner-crash.json').read_bytes())
    need(marker == dict(stage=stage, role=winner_role, pid=winner.pid,
                        operation_id='A0', request_sha256=scope()[('A', 0)]), 'ACTUAL_CONSUMED_CRASH_MARKER')
    public_marker = base / 'public/crashed-winner.json'
    public_marker.write_bytes(canonical({'role': winner_role}))
    os.chmod(public_marker, 0o444)
    before = read_fault_rows(base)
    restart_evidence = None
    if restart_both:
        need(response_loss and sink is not None and sink_ns is not None,
             'CONCURRENT_BACKEND_RESTART_REQUIRES_RESPONSE_LOSS')
        old_backend_pid = sink.pid
        backend_sha = sha((base / 'backend/effects.sqlite3').read_bytes())
        sink.kill()
        need(sink.wait(timeout=5) == -9, 'ACTUAL_CONCURRENT_BACKEND_SIGKILL')
        (base / 'backend/ready').unlink()
    surviving_replay = worker(NATIVE, 'concurrent-crash-replay', native_ns)
    need(loser.poll() is None and read_fault_rows(base) == before, 'SURVIVOR_NO_TAKEOVER_EFFECT')
    ready = base / ('custody/secondary-ready' if winner_role == 'secondary' else 'custody/ready')
    ready.unlink()
    extra = ('--restart', '--secondary') if winner_role == 'secondary' else ('--restart',)
    restarted = spawn(CUSTODY, 'custody', None, ready, 'restarted', extra)
    need(restarted.pid not in old_pids.values() and loser.poll() is None, 'WINNER_RESTART_WITH_SURVIVOR_ALIVE')
    if restart_both:
        offline_replay = worker(NATIVE, 'concurrent-replay', native_ns)
        unavailable = worker(CUSTODY, 'offline-reconcile')
        need(read_fault_rows(base) == before, 'OFFLINE_CONCURRENT_LEDGER_UNCHANGED')
        sink = spawn(BACKEND, 'backend', sink_ns, base / 'backend/ready', 'restarted', ('--restart',))
        need(sink.pid != old_backend_pid and loser.poll() is None and restarted.poll() is None,
             'BACKEND_RESTART_WITH_BOTH_CUSTODIES_ALIVE')
        need(read_fault_rows(base) == before, 'CONCURRENT_RESTART_RETAINS_EXACT_ROWS')
        replay_file = base / 'public/replay-packet.json'
        replay_file.write_bytes((base / 'native/packet-A0.json').read_bytes())
        os.chmod(replay_file, 0o444)
        denied = worker(CUSTODY, 'backend-replay')
        restart_evidence = {'old_backend_pid': old_backend_pid, 'new_backend_pid': sink.pid,
            'retained_rows': before, 'backend_database_sha256': backend_sha,
            'unavailable': unavailable, 'offline_replay': offline_replay, 'backend_replay': denied,
            'backend_restart_receipt_only': True}
    replay = worker(NATIVE, 'concurrent-replay', native_ns)
    reconciliation = worker(CUSTODY, 'reconcile-fault')
    need(worker(CUSTODY, 'reconcile-fault') == reconciliation, 'IDEMPOTENT_CONCURRENT_RECONCILIATION')
    confirmed_replay = worker(NATIVE, 'concurrent-replay', native_ns) if response_loss else None
    after = read_fault_rows(base)
    backend_marker = None
    if response_loss:
        need(len(before['effects']) == 1, 'ONE_BACKEND_EFFECT_BEFORE_RECOVERY')
        effect = before['effects'][0]
        need(effect[:2] == ['A0', scope()[('A', 0)]] and effect[3] == digest(dict(
            operation_id='A0', request_sha256=effect[1], response_sha256=effect[2])), 'MATCHED_EFFECT_RECEIPT')
        backend_marker = parse((base / 'backend/fault-observed.json').read_bytes())
        need(backend_marker == dict(operation_id='A0', request_sha256=effect[1], response_sha256=effect[2],
                                    receipt_sha256=effect[3]), 'BACKEND_COMMITTED_THEN_DROPPED_RESPONSE')
        need(before['consumed'] == [['A0', 'CONSUMED_UNKNOWN', effect[1], None, None, None, None]],
             'NO_INVENTED_RESPONSE_BEFORE_RECONCILIATION')
        need(after == {'effects': [effect], 'consumed': [['A0', 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE',
            effect[1], effect[2], effect[3], None, None]]}, 'EXACT_LOST_RESPONSE_EFFECT_RECONCILIATION')
        need(reconciliation == {'state': 'MOCK_EFFECT_CONFIRMED_NO_RESPONSE',
            'backend_evidence': {'operation_id': 'A0', 'record': effect[1:]},
            'post_calls': 0, 'raw_response_recovered': False}, 'CONFIRMATION_MUST_NOT_RESTORE_PERMISSION')
    else:
        need(before == after == {'effects': [], 'consumed': [['A0', 'CONSUMED_UNKNOWN',
            scope()[('A', 0)], None, None, None, None]]}, 'ONE_UNKNOWN_CONSUMPTION_ZERO_EFFECTS')
        need(reconciliation == {'state': 'CONSUMED_UNKNOWN', 'backend_evidence': {'operation_id': 'A0', 'record': None},
                                'post_calls': 0, 'raw_response_recovered': False}, 'ABSENCE_MUST_NOT_RESTORE_PERMISSION')
    need(not list((base / 'custody').glob('*.enc.json')) and not (base / 'custody/A0-bind.json').exists(),
         'NO_INVENTED_RESPONSE_OR_BIND_RECEIPT')
    checks.update({'two_processes_at_barrier': True, 'both_verified_same_frozen_request': True,
        'both_arrived_before_first_consume': True, 'consumed_winner_exit_before_bind': True,
        'survivor_stayed_alive': loser.poll() is None,
        'survivor_replays_denied': surviving_replay['survivor_replay_denials'] == 2,
        'no_takeover_or_new_send': True, 'winner_restart_same_ledger': True,
        'both_sockets_replays_denied': replay['replay_denials'] == 4,
        'consumption_stays_unknown': True, 'no_ciphertext_or_bind_receipt': True,
        'no_sdk_response_native_completion': native_report['sdk_responses_returned'] == native_report['native_terminal_arms'] == native_report['scorer_calls'] == 0,
        'authenticated_absence_does_not_restore': True, 'same_run_crash_evidence_join': True})
    if response_loss:
        for old, new in [('consumed_winner_exit_before_bind', 'consumed_winner_exit_after_response_loss'),
                         ('consumption_stays_unknown', 'unknown_to_mock_effect_confirmed_no_response'),
                         ('authenticated_absence_does_not_restore', 'authenticated_effect_does_not_restore')]:
            checks[new] = checks.pop(old)
        checks.update({'backend_response_loss_after_commit_observed': True,
            'backend_receipt_joins_reconciled_ledger': True,
            'post_reconciliation_replays_denied': confirmed_replay['replay_denials'] == 4})
    if restart_both:
        need(sha((base / 'backend/effects.sqlite3').read_bytes()) == backend_sha,
             'CONCURRENT_BACKEND_DATABASE_UNCHANGED_BYTES')
        checks.update({'backend_sigkill_observed': True, 'backend_restarted_with_survivor_alive': loser.poll() is None,
            'stopped_backend_both_sockets_replays_denied': offline_replay['replay_denials'] == 4,
            'unavailable_reconciliation_preserves_ledger': unavailable['ledger_unchanged'],
            'backend_retained_database_bytes': True, 'backend_authentic_replay_denied': denied['authentic_replay_denied'],
            'both_restart_restores_exact_rows': True, 'backend_restart_receipt_only': True})
    need(all(v is True for v in checks.values()), 'ALL_NATIVE_CONCURRENT_CRASH_CHECKS_REQUIRED')
    report = {'schema': 'task4.native.os-custody.concurrent-backend-restart.v1' if restart_both else
                       'task4.native.os-custody.concurrent-response-loss.v1' if response_loss else
                       'task4.native.os-custody.concurrent-crash.v1', 'audited_commit': head,
        'source_sha256': sha(Path(__file__).read_bytes()), 'external_pins': pins, 'checks': checks,
        'native': native_report, 'entered': entered, 'released': released, 'outcomes': outcomes,
        'old_pids': old_pids, 'winner_exit_code': exit_code, 'winner_crash': marker,
        'restarted_winner_pid': restarted.pid, 'survivor_pid': loser.pid,
        'survivor_replay': surviving_replay, 'restarted_replay': replay,
        'post_reconciliation_replay': confirmed_replay, 'backend_response_loss': backend_marker,
        'before_restart': before, 'after_restart': after, 'reconciliation': reconciliation,
        'bind_record': None, 'replay_denials': 14 if restart_both else 10 if response_loss else 6,
        'mock_http_effects': int(response_loss), 'custody_consumptions': 1,
        'ciphertext_count': 0, 'cross_process_concurrent_native_consumption_tested': True,
        'concurrent_winner_crash_tested': True, 'concurrent_winner_response_loss_tested': response_loss,
        'backend_restart_tested': restart_both, 'restart_evidence': restart_evidence,
        'scripted_backend_continuation_after_restart_proven': False,
        'raw_response_recovery_proven': False,
        'distributed_cas_proven': False, 'real_provider_posts': 0, 'external_bank_effects': 0,
        'utility': 'UNSCORED', 'provider_dispatch': 'DENY', 'production_bypass_resistance_proven': False,
        'independent_administration_proven': False}
    (output / 'report.json').write_bytes(canonical(report))
    suite = ET.Element('testsuite', name='Native Concurrent Consumed Winner Crash', tests=str(len(checks)),
                       failures='0', errors='0', skipped='0')
    for name in sorted(checks):
        ET.SubElement(suite, 'testcase', classname='native_concurrent_crash', name=name)
    ET.ElementTree(suite).write(output / 'junit.xml', encoding='utf-8', xml_declaration=True)


def finish_concurrent(base, output, worker, spawn, service, native_ns, sink_ns, head, pins,
                      sink=None, restart_both=False):
    secondary = spawn(CUSTODY, 'custody', None, base / 'custody/secondary-ready', 'ready', ('--secondary',))
    old_pids = {'primary': service.pid, 'secondary': secondary.pid}
    checks = worker(NATIVE, 'probe', native_ns)
    checks.update(worker(NATIVE, 'reachable', sink_ns))
    native_report = worker(NATIVE, 'concurrent-native', native_ns)
    race = native_report['race']
    entered, released, outcomes = {}, {}, {}
    for role in old_pids:
        entered[role] = parse((base / 'custody' / ('race-entered-' + role + '.json')).read_bytes())
        released[role] = parse((base / 'custody' / ('race-released-' + role + '.json')).read_bytes())
        outcomes[role] = parse((base / 'custody' / ('race-outcome-' + role + '.json')).read_bytes())
        need(entered[role]['pid'] == released[role]['pid'] == outcomes[role]['pid'] == old_pids[role],
             'ACTUAL_TWO_PROCESS_IDS')
        need(entered[role]['uid'] == CUSTODY and entered[role]['request_sha256'] == scope()[('A', 0)]
             and entered[role]['consumptions_before'] == 0, 'BOTH_AUTHENTIC_SAME_REQUEST_ARRIVED')
    need(len(set(old_pids.values())) == 2 and max(x['entered_ns'] for x in entered.values())
         <= min(x['released_ns'] for x in released.values()), 'BOTH_ARRIVED_BEFORE_RACE_RELEASE')
    need(sorted(x['decision'] for x in outcomes.values()) == ['CONSUMED', 'REPLAY_DENIED']
         and outcomes[race['winner_role']]['decision'] == 'CONSUMED', 'PROCESS_NATIVE_WINNER_JOIN')
    if concurrent_crash_mode(base) or concurrent_response_loss_mode(base):
        finish_concurrent_crash(base, output, worker, spawn, {'primary': service, 'secondary': secondary},
            native_ns, head, pins, checks, native_report, entered, released, outcomes,
            sink, sink_ns, restart_both)
        return
    before = read_fault_rows(base)
    replay = worker(NATIVE, 'concurrent-replay', native_ns)
    for p in (service, secondary):
        p.terminate()
        need(p.wait(timeout=5) == -15, 'BOTH_CUSTODY_PROCESSES_STOPPED')
    for name in ('ready', 'secondary-ready'):
        (base / 'custody' / name).unlink()
    service = spawn(CUSTODY, 'custody', None, base / 'custody/ready', 'restarted', ('--restart',))
    secondary = spawn(CUSTODY, 'custody', None, base / 'custody/secondary-ready', 'restarted', ('--restart', '--secondary'))
    new_pids = {'primary': service.pid, 'secondary': secondary.pid}
    need(len(set(new_pids.values())) == 2 and all(new_pids[x] != old_pids[x] for x in old_pids), 'BOTH_CUSTODIES_RESTARTED')
    restarted_replay = worker(NATIVE, 'concurrent-replay', native_ns)
    after = read_fault_rows(base)
    need(before == after and len(after['effects']) == len(after['consumed']) == 1, 'ONE_EFFECT_AND_DURABLE_CONSUMPTION')
    effect, consumed = after['effects'][0], after['consumed'][0]
    need(effect == ['A0', race['request_sha256'], race['response_sha256'], race['backend_receipt_sha256']]
         and consumed == ['A0', 'MOCK_OBSERVED', race['request_sha256'], race['response_sha256'],
             race['backend_receipt_sha256'], race['envelope_sha256'], race['bind_sha256']], 'RACE_NATIVE_BACKEND_LEDGER_JOIN')
    need(effect[3] == digest(dict(operation_id='A0', request_sha256=effect[1], response_sha256=effect[2])), 'RACE_RECEIPT_HASH')
    ciphertexts = list((base / 'custody').glob('*.enc.json'))
    need(len(ciphertexts) == 1 and sha(ciphertexts[0].read_bytes()) == race['envelope_sha256'], 'ONE_DURABLE_RACE_CIPHERTEXT')
    binding = parse((base / 'custody/A0-bind.json').read_bytes())
    need(digest(binding) == race['bind_sha256'] and [(x['outcome'], x['apply_calls']) for x in binding['records']]
         == [('BLOCKED', 0), ('COMMITTED', 1)], 'ONE_ACTUAL_BIND_NETWORK_APPLY')
    checks.update({'two_processes_at_barrier': True, 'both_verified_same_frozen_request': True,
        'both_arrived_before_first_consume': True, 'single_sqlite_consumption': True, 'single_backend_effect': True,
        'single_ciphertext': True, 'one_actual_bind_network_apply': True, 'next_sdk_wire_after_response_matches': True,
        'eight_replays_denied': replay['replay_denials'] + restarted_replay['replay_denials'] == 8,
        'both_custodies_restart_retain': True, 'same_run_receipts_join': True})
    need(all(v is True for v in checks.values()), 'ALL_CONCURRENT_NATIVE_CHECKS_REQUIRED')
    report = {'schema': 'task4.native.os-custody.concurrent.v1', 'audited_commit': head,
        'source_sha256': sha(Path(__file__).read_bytes()), 'external_pins': pins, 'checks': checks,
        'native': native_report, 'entered': entered, 'released': released, 'outcomes': outcomes,
        'old_pids': old_pids, 'new_pids': new_pids, 'before_restart': before, 'after_restart': after,
        'bind_record': binding, 'replay_denials': 8, 'mock_http_effects': 1, 'custody_consumptions': 1,
        'ciphertext_count': 1, 'cross_process_concurrent_native_consumption_tested': True,
        'concurrent_winner_crash_tested': False, 'distributed_cas_proven': False,
        'real_provider_posts': 0, 'external_bank_effects': 0, 'utility': 'UNSCORED', 'provider_dispatch': 'DENY',
        'production_bypass_resistance_proven': False, 'independent_administration_proven': False}
    (output / 'report.json').write_bytes(canonical(report))
    suite = ET.Element('testsuite', name='Native OS Custody Concurrent', tests=str(len(checks)),
                       failures='0', errors='0', skipped='0')
    for name in sorted(checks):
        ET.SubElement(suite, 'testcase', classname='native_os_custody_concurrent', name=name)
    ET.ElementTree(suite).write(output / 'junit.xml', encoding='utf-8', xml_declaration=True)


def run(output, fault='', restart_both=False, concurrent=False, concurrent_crash=False, concurrent_response_loss=False,
        retained_senders=False, local_https=False, durable_issuer=False, raw_ingress='', raw_authority=False, bounded_native=False, retained_bounded=False, signed_ledger_native=False):
    from scripts import task4_native_signed_ledger_integration_v1 as signed
    need(type(signed_ledger_native) is bool and (not signed_ledger_native or retained_bounded), 'SIGNED_LEDGER_REQUIRES_RETAINED_NATIVE_PROFILE')
    from scripts import task4_native_retained_authority_v1 as retained
    need(type(retained_bounded) is bool and (not retained_bounded or bounded_native), 'RETAINED_AUTHORITY_EXPLICIT_BOUNDED_PROFILE')
    from scripts import task4_native_bounded_continuation_v1 as bounded
    need(type(bounded_native) is bool and (not bounded_native or
         (local_https and raw_ingress == 'success' and not raw_authority)), 'BOUNDED_NATIVE_EXPLICIT_SEPARATE_PROFILE')
    from scripts import task4_native_local_https_v1 as tls
    from scripts import task4_durable_issuer_restart_v1 as durable
    from scripts import task4_native_raw_ingress_v1 as ingress
    from scripts import task4_native_raw_authority_v1 as authority
    need(type(raw_authority) is bool and (not raw_authority or raw_ingress == 'success'),
         'SIGNED_RAW_AUTHORITY_REQUIRES_COMPLETE_RAW_SUCCESS')
    need(raw_ingress in ('', *ingress.MODES) and (not raw_ingress or
         (local_https and not durable_issuer and not fault and not restart_both and not concurrent and not retained_senders)),
         'RAW_INGRESS_SEPARATE_CLOSED_TLS_FIXTURE_ONLY')
    need(type(durable_issuer) is bool and (not durable_issuer or local_https), 'DURABLE_ISSUER_REQUIRES_LOCAL_TLS')
    need(type(local_https) is bool and (not local_https or
         (not fault and not restart_both and not concurrent and not retained_senders)), 'LOCAL_HTTPS_NORMAL_FIXTURE_ONLY')
    need(fault in ('', *FAULTS), 'EXACT_FAULT_MODE')
    need(type(restart_both) is bool and (not restart_both or fault in FAULTS or concurrent_response_loss),
         'BOTH_RESTART_REQUIRES_FAULT_OR_CONCURRENT_RESPONSE_LOSS')
    need(type(concurrent) is bool and (not concurrent or not fault), 'CONCURRENT_FIXTURE_SEPARATE_FROM_FAULTS')
    need(type(concurrent_crash) is bool and (not concurrent_crash or concurrent), 'CRASH_REQUIRES_TWO_CUSTODIES')
    need(type(concurrent_response_loss) is bool and (not concurrent_response_loss or (concurrent and not concurrent_crash)),
         'RESPONSE_LOSS_REQUIRES_DISTINCT_CONCURRENT_FIXTURE')
    need(type(retained_senders) is bool and (not retained_senders or
         (not fault and not restart_both and not concurrent)), 'RETAINED_SENDERS_NORMAL_FIXTURE_ONLY')
    need(os.geteuid() == 0 and sys.platform == 'linux', 'TRUSTED_DISPOSABLE_LINUX_CI_ROOT_REQUIRED')
    need(not output.exists() and output.resolve().is_relative_to(ROOT), 'NEW_OUTPUT_UNDER_CHECKOUT')
    for uid in (NATIVE, BACKEND, ISSUER, CUSTODY, kernel.STRANGER):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            pass
        else:
            raise ValueError('RESERVED_UID_ALREADY_ALLOCATED')
    git = ['git', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT)]
    head = kernel.command(git + ['rev-parse', 'HEAD']).stdout.strip()
    pins = {'agentdojo': 'a75aba7631d3ca5fb7ab938965c97ead2f9ff84b',
            'rcc': '1d3782d3aae5ff9c88036709c1a5642320cc53c2',
            'veritas': 'a1d66aef02262cf8a913295270c3aafd159c6adb'}
    for name, pin in pins.items():
        pin_root = ROOT / '_pins' / name
        need(kernel.command(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root),
             'rev-parse', 'HEAD']).stdout.strip() == pin, 'EXACT_EXTERNAL_SOURCE_PIN')
        kernel.command(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root),
                        'diff', '--exit-code', 'HEAD'])
    output.mkdir(parents=True)
    token = secrets.token_hex(4)
    native_ns, sink_ns = 'nat' + token, 'snk' + token
    client_ns = 'tls' + token if local_https else None
    host_if, sink_if = 'h' + token, 's' + token
    host, port = (tls.IP, tls.PORT) if local_https else (HOST, PORT)
    rule = ['OUTPUT', '-d', host, '-p', 'tcp', '--dport', str(port),
            '-m', 'owner', '!', '--uid-owner', str(CUSTODY), '-j', 'REJECT']
    processes, namespaces, directories = [], [], []
    installed = link_created = False
    with tempfile.TemporaryDirectory(prefix='task4-native-os-') as tmp:
        base = Path(tmp)
        os.chmod(base, 0o755)
        source = base / 'source'
        source.mkdir(mode=0o755)
        def export(command, directory):
            directory.mkdir(parents=True, exist_ok=True)
            archive = subprocess.run(command, check=True, capture_output=True, timeout=30).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                for member in tar.getmembers():
                    dest = directory / member.name
                    need(dest.resolve().is_relative_to(directory) and (member.isdir() or member.isfile()),
                         'REGULAR_TRACKED_SOURCE_ONLY')
                    if member.isdir():
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(tar.extractfile(member).read())

        export(git + ['archive', 'HEAD'], source)
        # Editable-install import hooks are not a source-enrollment mechanism for
        # isolated UIDs. Export the verified package trees and add explicit paths.
        for name, subtree in [('agentdojo', 'src/agentdojo'),
                              ('rcc', 'external-eval/v0.3.9/src'), ('veritas', 'veritas_os')]:
            pin_root = ROOT / '_pins' / name
            export(['git', '-c', 'safe.directory=' + str(pin_root), '-C', str(pin_root),
                    'archive', pins[name], subtree], source / '_pins' / name)
        for file in source.rglob('*'):
            os.chmod(file, 0o555 if file.is_dir() else 0o444)
        os.chmod(source, 0o555)
        for role, uid in [('native', NATIVE), ('custody', CUSTODY), ('backend', BACKEND), ('issuer', ISSUER), ('ipc', CUSTODY)]:
            folder = base / role
            folder.mkdir(mode=0o755 if role == 'ipc' else 0o700)
            os.chown(folder, uid, uid)
        (base / 'public').mkdir(mode=0o755)
        if durable_issuer:
            (base / 'public/durable-issuer').write_text(durable.MARKER)
            os.chmod(base / 'public/durable-issuer', 0o444)
        if local_https:
            certificates = tls.enroll(base)
        if retained_senders:
            (base / 'public/retained-senders').write_text('retained-senders-local-v1')
            os.chmod(base / 'public/retained-senders', 0o444)
        if fault:
            (base / 'public/fault').write_text(fault)
            os.chmod(base / 'public/fault', 0o444)
        if concurrent:
            (base / 'public/concurrent').write_text('two-custody-v1')
            os.chmod(base / 'public/concurrent', 0o444)
        if concurrent_crash:
            (base / 'public/concurrent-crash').write_text('consumed-before-bind-v1')
            os.chmod(base / 'public/concurrent-crash', 0o444)
        if concurrent_response_loss:
            (base / 'public/concurrent-response-loss').write_text('backend-commit-drop-v1')
            os.chmod(base / 'public/concurrent-response-loss', 0o444)
        credential = secrets.token_bytes(32)
        for role, uid in [('custody', CUSTODY), ('backend', BACKEND)]:
            file = base / role / 'credential'
            file.write_bytes(credential)
            os.chmod(file, 0o600)
            os.chown(file, uid, uid)
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1', 'TASK4_RCC_ROOT': str(source / '_pins/rcc')}
        if local_https:
            env['SSL_CERT_FILE'] = str(base / 'public/ca.pem')
        # -I ignores PYTHONPATH; insert only the root-owned tracked source copy.
        import_roots = [source, source / 'scripts', source / '_pins/agentdojo/src',
                        source / '_pins/veritas', source / '_pins/rcc/external-eval/v0.3.9/src']
        code = 'import sys;sys.path[:0]=' + repr([str(p) for p in import_roots]) + ';from scripts.task4_native_os_custody_v1 import main;main()'

        def cmd(uid, args, ns=None):
            return (['ip', 'netns', 'exec', ns] if ns else []) + ['setpriv', '--reuid=' + str(uid),
                '--regid=' + str(uid), '--clear-groups', '--no-new-privs', '--bounding-set=-all',
                '--inh-caps=-all', '--ambient-caps=-all', sys.executable, '-I', '-c', code] + args

        def worker(uid, mode, ns=None):
            p = subprocess.run(cmd(uid, ['--role', mode, '--base', str(base)], ns), env=env,
                               capture_output=True, text=True, timeout=180)
            if p.returncode:
                for service in processes:
                    if service.poll() is not None and service.returncode and service.stderr:
                        print(service.stderr.read().decode()[-2500:], file=sys.stderr)
                raise ValueError('ROLE_FAILED:' + mode + ':' + p.stderr[-2500:])
            return parse(p.stdout.encode())

        def spawn(uid, mode, ns, ready, expected='ready', extra=()):
            p = subprocess.Popen(cmd(uid, ['--role', mode, '--base', str(base), *extra], ns),
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(p)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                need(p.poll() is None, 'SERVICE_FAILED:' + (p.stderr.read().decode()[-2500:] if p.poll() is not None else ''))
                if ready.exists() and ready.read_text() == expected:
                    return p
                time.sleep(0.1)
            raise ValueError('SERVICE_READY_TIMEOUT')

        try:
            if local_https:
                network = tls.topology(client_ns, sink_ns, native_ns, host_if, sink_if, namespaces, directories, rule)
            else:
                for ns in (native_ns, sink_ns):
                    kernel.command(['ip', 'netns', 'add', ns])
                    namespaces.append(ns)
                    kernel.command(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
                kernel.command(['ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', sink_if])
                link_created = True
                kernel.command(['ip', 'link', 'set', sink_if, 'netns', sink_ns])
                kernel.command(['ip', 'addr', 'add', '10.249.91.1/30', 'dev', host_if])
                kernel.command(['ip', 'link', 'set', host_if, 'up'])
                kernel.command(['ip', '-n', sink_ns, 'addr', 'add', HOST + '/30', 'dev', sink_if])
                kernel.command(['ip', '-n', sink_ns, 'link', 'set', sink_if, 'up'])
                kernel.command(['iptables', '-I'] + rule[:1] + ['1'] + rule[1:])
                installed = True
                kernel.command(['iptables', '-C'] + rule)
            links = json.loads(kernel.command(['ip', '-n', native_ns, '-j', 'link', 'show']).stdout)
            need([x['ifname'] for x in links] == ['lo'], 'NATIVE_LOOPBACK_ONLY')
            if raw_ingress:
                ingress.enroll(base, raw_ingress, certificates, worker, native_ns)
                if raw_authority:
                    authority.enroll(base)
            if bounded_native:
                authority.enroll(base)
                bounded.enroll(base, worker, native_ns)
                if retained_bounded:
                    retained.enroll(base, worker, native_ns)
                if signed_ledger_native:
                    signed.enroll(base, worker, native_ns)
                bounded.exercise(base, output, worker, spawn, native_ns, client_ns, sink_ns, head, pins, network)
                print('NATIVE_BOUNDED_CONTINUATION_CLOSED_TLS_NO_PROVIDER')
                return
            if durable_issuer:
                issuer_service = spawn(ISSUER, 'durable-issuer', native_ns, base / 'issuer/ready')
                issued = durable.rpc(base, 'export-existing')
                need(issued['pid'] == issuer_service.pid and issued['uid'] == ISSUER, 'ACTUAL_DURABLE_ISSUER_PROCESS')
            else:
                issued = worker(ISSUER, 'issue', native_ns)
            public = bytes.fromhex(issued['public'])
            for op, grant in issued['grants'].items():
                verify_grant(grant, op[0], int(op[1]), scope()[(op[0], int(op[1]))], public, base)
            for name, data in [('issuer-key', public), ('grants.json', canonical(issued['grants']))]:
                file = base / 'public' / name
                file.write_bytes(data)
                os.chmod(file, 0o444)
            if durable_issuer:
                state, state_raw = durable.load(base, False)
                anchor_file = base / durable.ANCHOR
                durable_marker(anchor_file, durable.anchor(state, state_raw))
                os.chmod(anchor_file, 0o444)
                need(durable.rpc(base, 'export-existing') == issued, 'ISSUER_ENROLLED_BEFORE_FIRST_CONSUME')
            sink = spawn(BACKEND, 'backend', sink_ns, base / 'backend/ready')
            service = spawn(CUSTODY, 'custody', client_ns, base / 'custody/ready')
            if local_https and not raw_ingress:
                tls_phases = tls.negatives(base, worker, client_ns, sink_ns, native_ns)
            if raw_ingress:
                ingress.exercise(base, output, worker, spawn, service, sink, native_ns, client_ns,
                                 sink_ns, head, pins, network, issued)
                print('NATIVE_BIND_RAW_HTTP_BEFORE_PARSERS_CLOSED_LOCAL_TLS_NO_PROVIDER:' + raw_ingress)
                return
            if retained_senders:
                from scripts.task4_retained_sender_denial_v1 import validate_observations
                sender_phases = {'native_netns': worker(NATIVE, 'retained-probe', native_ns)}
                observation_file = base / 'backend/sender-observations.jsonl'
                need(not observation_file.exists(), 'ISOLATED_HELPERS_NEVER_REACH_BACKEND')
                sender_phases['native_host'] = worker(NATIVE, 'retained-probe')
                need(not observation_file.exists(), 'UID_FIREWALL_HELPERS_NEVER_REACH_BACKEND')
                sender_phases['reachable_sink_netns'] = worker(NATIVE, 'retained-reachable', sink_ns)
                negative_observations = [parse(x.encode()) for x in observation_file.read_text().splitlines()]
                validate_observations(sender_phases, negative_observations)
                need(read_fault_rows(base) == {'effects': [], 'consumed': []}, 'ALL_NEGATIVES_ZERO_EFFECTS_CONSUMPTIONS')
            if concurrent:
                finish_concurrent(base, output, worker, spawn, service, native_ns, sink_ns, head, pins, sink, restart_both)
                print('TASK4_NATIVE_CONCURRENT_BACKEND_RESTART_ONE_RETAINED_EFFECT_NO_PROVIDER' if restart_both
                      else 'TASK4_NATIVE_CONCURRENT_RESPONSE_LOSS_ONE_EFFECT_NO_RETRY_NO_PROVIDER' if concurrent_response_loss
                      else 'TASK4_NATIVE_CONCURRENT_CONSUMED_WINNER_CRASH_ZERO_EFFECT_NO_PROVIDER' if concurrent_crash
                      else 'TASK4_NATIVE_CONCURRENT_CUSTODY_ONE_EFFECT_NO_PROVIDER')
                return
            if fault:
                finish_fault(base, output, fault, worker, spawn, service, native_ns, head, pins,
                             sink, sink_ns, restart_both)
                print('TASK4_NATIVE_OS_FAULT_NO_DUPLICATE_NO_PROVIDER:' + fault)
                return
            checks = worker(NATIVE, 'probe', native_ns)
            checks.update({'reachable_native_uid_without_credential_http_403': all(
                r['http_status'] == 403 for r in sender_phases['reachable_sink_netns']['records'])}
                if retained_senders else worker(NATIVE, 'reachable', sink_ns))
            native_report = worker(NATIVE, 'native', native_ns)
            if durable_issuer:
                issuer_service, issuer_evidence = durable.restart_after_native(
                    base, worker, spawn, issuer_service, native_ns, issued)
            peer_packet = base / 'public/peer-packet.json'
            peer_packet.write_bytes((base / 'native/packet-A0.json').read_bytes())
            os.chmod(peer_packet, 0o444)
            checks.update(worker(kernel.STRANGER, 'wrong-peer', native_ns))
            service.terminate()
            service.wait(timeout=5)
            (base / 'custody/ready').unlink()
            service = spawn(CUSTODY, 'custody', client_ns, base / 'custody/ready', 'restarted', ('--restart',))
            restart_report = worker(NATIVE, 'restart-probe', native_ns)
            if durable_issuer:
                issuer_service = durable.faults_after_restart(
                    base, worker, spawn, issuer_service, native_ns, issuer_evidence)
            for p in (service, sink):
                p.terminate()
                p.wait(timeout=5)
            with sqlite3.connect(base / 'backend/effects.sqlite3') as db:
                effects = db.execute('SELECT op,request_sha,response_sha,receipt FROM effects ORDER BY op').fetchall()
            with sqlite3.connect(base / 'custody/ledger.sqlite3') as db:
                consumed = db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed ORDER BY op').fetchall()
            records = native_report['records']
            need(len(effects) == len(consumed) == len(records) == 8, 'EIGHT_BACKEND_CUSTODY_NATIVE_RECORDS')
            need(digest(native_report['lineage']) == native_report['lineage_sha256'], 'NATIVE_LINEAGE_HASH')
            bindings = []
            for record, effect, row, lineage in zip(records, effects, consumed,
                                                    native_report['lineage']['response_receipts']):
                op = record['arm'] + str(record['ordinal'])
                need(effect == (op, record['request_sha256'], record['response_sha256'], record['backend_receipt_sha256'])
                     and row == (op, 'MOCK_OBSERVED', record['request_sha256'], record['response_sha256'],
                     record['backend_receipt_sha256'], record['envelope_sha256'], record['bind_sha256']), 'SAME_RUN_NATIVE_OS_DB_JOIN')
                need(lineage['arm'] == record['arm'] and lineage['ordinal'] == record['ordinal']
                     and lineage['original_request_raw_sha256'] == record['request_sha256']
                     and lineage['original_response_raw_sha256'] == record['response_sha256'], 'NATIVE_LINEAGE_OS_RECEIPT_JOIN')
                blob = (base / 'custody' / ('task4-457-' + record['arm'] + '-' + str(record['ordinal']) + '.enc.json')).read_bytes()
                need(sha(blob) == record['envelope_sha256'], 'DURABLE_CIPHERTEXT_BEFORE_NATIVE_PARSER')
                binding = parse((base / 'custody' / (op + '-bind.json')).read_bytes())
                need(digest(binding) == record['bind_sha256'] and [(r['outcome'], r['apply_calls']) for r in binding['records']]
                     == [('BLOCKED', 0), ('COMMITTED', 1)], 'REAL_BIND_NATIVE_RECEIPT_JOIN')
                bindings.append({'operation_id': op, **binding})
            checks.update({'kernel_firewall_checked': True, 'native_loopback_only': True,
                'issuer_credential_reads_denied': issued['issuer_credential_reads_denied'],
                'eight_frozen_sdk_requests_same_run': True, 'eight_bind_backend_ledger_ciphertext_joins': True,
                'native_scorer_and_response_lineage_joined': True,
                'native_replays_denied': native_report['replay_denials'] == 8,
                'restart_replays_denied': restart_report['restart_replay_denials'] == 8,
                'signature_wire_target_denied': native_report['signature_wire_target_denials'] == 3})
            need(all(v is True for v in checks.values()), 'ALL_NATIVE_OS_CHECKS_REQUIRED')
            report = {'schema': 'task4.native.os-custody.v1', 'audited_commit': head,
                'source_sha256': sha(Path(__file__).read_bytes()), 'external_pins': pins,
                'checks': checks, 'native': native_report, 'restart': restart_report,
                'mock_http_effects': len(effects), 'custody_consumptions': len(consumed),
                'bind_records_sha256': digest(bindings), 'issuer_public_key_sha256': sha(public),
                'uids': {'native': NATIVE, 'issuer': ISSUER, 'custody': CUSTODY, 'backend': BACKEND},
                'firewall_rule': rule, 'real_provider_posts': 0, 'external_bank_effects': 0,
                'utility': 'UNSCORED', 'provider_dispatch': 'DENY',
                'production_bypass_resistance_proven': False, 'independent_administration_proven': False,
                'recipient_private_key_publicly_reproducible': True, 'real_data_confidentiality_proven': False,
                'native_has_transport_credential': False, 'native_has_issuer_private_key': False,
                'trusted_root_kernel_custody_backend': True}
            (output / 'report.json').write_bytes(canonical(report))
            (output / 'bind-records.json').write_bytes(canonical(bindings))
            if local_https:
                tls.finish(base, output, report, bindings, tls_phases, certificates, network)
            if durable_issuer:
                durable.finish(base, output, issuer_evidence, report)
            if retained_senders:
                observations = [parse(x.encode()) for x in observation_file.read_text().splitlines()]
                validate_observations(sender_phases, observations, 8)
                need([x['body_sha256'] for x in observations[6:]] == [sha((base / 'native' /
                    ('packet-' + r['arm'] + str(r['ordinal']) + '.json')).read_bytes()) for r in records]
                    and len({x['body_sha256'] for x in observations[6:]}) == 8,
                     'EIGHT_EXACT_ADMITTED_BACKEND_PACKETS')
                sender_checks = {'three_original_helper_blobs_unchanged': True,
                    'three_original_request_hashes_unchanged': True,
                    'all_six_routes_in_three_phases': True,
                    'same_uid_child_probe': True, 'native_netns_denies_before_backend': True,
                    'native_host_uid_firewall_denies_before_backend': True,
                    'reachable_native_without_credential_http_403': True,
                    'backend_owned_negative_body_hash_join': True,
                    'negative_effects_and_consumptions_zero': True,
                    'normal_eight_native_bind_effects_after_negatives': True,
                    'normal_native_lineage_and_scorer_join': True,
                    'normal_and_restart_replays_denied': True}
                sender_report = {'schema': 'task4.retained-sender-denial.v1', 'audited_commit': head,
                    'source_sha256': sha(Path(__file__).read_bytes()),
                    'probe_source_sha256': sha((ROOT / 'scripts/task4_retained_sender_denial_v1.py').read_bytes()),
                    'checks': sender_checks, 'phases': sender_phases, 'backend_observations': observations,
                    'negative_network_denials': 12, 'negative_http_403': 6,
                    'negative_effects': 0, 'negative_consumptions': 0,
                    'positive_mock_effects': len(effects), 'positive_custody_consumptions': len(consumed),
                    'normal_report_sha256': digest(report), 'trusted_root_kernel_custody_backend': True,
                    'injected_local_transport_not_default_provider_tls': True,
                    'independent_administration_proven': False, 'production_bypass_resistance_proven': False,
                    'real_provider_posts': 0, 'external_bank_effects': 0, 'utility': 'UNSCORED'}
                (output / 'retained-senders.json').write_bytes(canonical(sender_report))
                sender_suite = ET.Element('testsuite', name='Retained sender denial', tests=str(len(sender_checks)),
                    failures='0', errors='0', skipped='0')
                for name in sorted(sender_checks):
                    ET.SubElement(sender_suite, 'testcase', classname='retained_sender_denial', name=name)
                ET.ElementTree(sender_suite).write(output / 'retained-senders-junit.xml', encoding='utf-8', xml_declaration=True)
            suite = ET.Element('testsuite', name='Native OS Custody', tests=str(len(checks)), failures='0', errors='0', skipped='0')
            for name in sorted(checks):
                ET.SubElement(suite, 'testcase', classname='native_os_custody', name=name)
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
            if installed:
                kernel.command(['iptables', '-D'] + rule, check=False)
            for ns in reversed(namespaces):
                kernel.command(['ip', 'netns', 'del', ns], check=False)
            tls.cleanup(directories)
            if link_created:
                kernel.command(['ip', 'link', 'del', host_if], check=False)
            if signed_ledger_native:
                signed.cleanup(base)
            if retained_bounded:
                retained.cleanup(base)
    print('TASK4_NATIVE_OS_CUSTODY_BIND_LOCAL_HTTP_NO_PROVIDER')


def main():
    global TLS_BASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fault', choices=FAULTS, default='')
    parser.add_argument('--restart-both', action='store_true')
    parser.add_argument('--concurrent', action='store_true')
    parser.add_argument('--concurrent-crash', action='store_true')
    parser.add_argument('--concurrent-response-loss', action='store_true')
    parser.add_argument('--retained-senders', action='store_true')
    parser.add_argument('--local-https', action='store_true')
    parser.add_argument('--durable-issuer', action='store_true')
    from scripts import task4_native_raw_ingress_v1 as ingress
    parser.add_argument('--raw-ingress', choices=ingress.MODES, default='')
    parser.add_argument('--raw-authority', action='store_true')
    parser.add_argument('--bounded-native', action='store_true')
    parser.add_argument('--retained-bounded', action='store_true')
    parser.add_argument('--signed-ledger-native', action='store_true')
    parser.add_argument('--secondary', action='store_true')
    parser.add_argument('--role', choices=('issue', 'backend', 'custody', 'probe', 'reachable', 'native', 'restart-probe', 'wrong-peer', 'fault-native', 'fault-replay', 'reconcile-fault', 'offline-reconcile', 'backend-replay', 'concurrent-native', 'concurrent-replay', 'concurrent-crash-replay', 'retained-probe', 'retained-reachable', 'tls-isolated', 'tls-firewall', 'tls-reachable', 'tls-bad_ca', 'durable-issuer', 'issuer-replay', 'issuer-invalid-restart', 'raw-owner', 'raw-recover', 'raw-authority-probe', 'bounded-init', 'bounded-issuer', 'bounded-native', 'bounded-probe', 'bounded-replay', 'retained-init-issuer', 'retained-init-custody', 'retained-state', 'retained-check', 'retained-alternate', 'retained-prepare', 'retained-pending', 'retained-terminal', 'signed-ledger-init', 'signed-ledger-provision', 'signed-ledger-bootstrap', 'signed-ledger-server', 'signed-ledger-journal', 'signed-ledger-view'))
    parser.add_argument('--base', type=Path)
    parser.add_argument('--restart', action='store_true')
    args = parser.parse_args()
    if args.run:
        need(args.output is not None and args.role is None and not args.secondary, 'RUN_OUTPUT_REQUIRED')
        run(args.output.resolve(), args.fault, args.restart_both, args.concurrent, args.concurrent_crash,
            args.concurrent_response_loss, args.retained_senders, args.local_https, args.durable_issuer, args.raw_ingress, args.raw_authority, args.bounded_native, args.retained_bounded, args.signed_ledger_native)
    else:
        need(args.role is not None and args.base is not None and not args.fault and not args.restart_both
             and not args.concurrent and not args.concurrent_crash and not args.concurrent_response_loss
             and not args.retained_senders and not args.local_https and not args.durable_issuer and not args.raw_ingress and not args.raw_authority and not args.bounded_native and not args.retained_bounded and not args.signed_ledger_native
             and (not args.secondary or args.role == 'custody'), 'EXPLICIT_LOCAL_ROLE')
        from scripts.task4_retained_sender_denial_v1 import probe as retained_probe
        from scripts import task4_native_local_https_v1 as tls
        from scripts import task4_durable_issuer_restart_v1 as durable
        from scripts import task4_native_raw_authority_v1 as authority
        TLS_BASE = args.base if tls.enabled(args.base) else None
        if args.role.startswith('signed-ledger-'):
            from scripts import task4_native_signed_ledger_integration_v1 as signed
            roles = {'signed-ledger-init': signed.initialize, 'signed-ledger-provision': signed.provision,
                     'signed-ledger-bootstrap': signed.bootstrap, 'signed-ledger-server': signed.serve,
                     'signed-ledger-journal': signed.journal, 'signed-ledger-view': signed.view}
            value = roles[args.role](args.base)
            if value is not None: print(canonical(value).decode())
            return
        if args.role in {'retained-init-issuer','retained-init-custody','retained-state','retained-check',
                         'retained-alternate','retained-prepare','retained-pending','retained-terminal'}:
            from scripts import task4_native_retained_authority_v1 as retained
            roles = {'retained-init-issuer': retained.create_issuer, 'retained-init-custody': retained.create_custody,
                     'retained-state': retained.state, 'retained-check': retained.check, 'retained-alternate': retained.alternate,
                     'retained-prepare': retained.prepare, 'retained-pending': retained.pending, 'retained-terminal': retained.terminal}
            print(canonical(roles[args.role](args.base)).decode())
            return
        if args.role.startswith('bounded-'):
            from scripts import task4_native_bounded_continuation_v1 as bounded
            roles = {'bounded-init': bounded.initialize, 'bounded-issuer': lambda b: bounded.issuer(b, args.restart),
                     'bounded-native': bounded.native, 'bounded-probe': bounded.probe, 'bounded-replay': bounded.replay}
            value = roles[args.role](args.base)
            if value is not None:
                print(canonical(value).decode())
            return
        if args.role.startswith('tls-'):
            print(canonical(tls.probe(args.base, args.role.removeprefix('tls-'))).decode())
            return
        roles = {'issue': issue, 'backend': lambda b: backend(b, args.restart), 'probe': probe,
                 'raw-authority-probe': authority.probe,
                 'raw-owner': ingress.raw.recipient, 'raw-recover': ingress.raw.recover,
                 'durable-issuer': lambda b: durable.serve(b, args.restart),
                 'issuer-replay': durable.replay, 'issuer-invalid-restart': durable.invalid_restart,
                 'reachable': lambda b: probe(b, True), 'native': native, 'restart-probe': restart_probe,
                 'wrong-peer': wrong_peer,
                 'fault-native': fault_native, 'fault-replay': fault_replay, 'reconcile-fault': reconcile_fault,
                 'offline-reconcile': offline_reconcile, 'backend-replay': backend_replay,
                 'concurrent-native': concurrent_native, 'concurrent-replay': concurrent_replay,
                 'concurrent-crash-replay': concurrent_crash_replay,
                 'retained-probe': retained_probe,
                 'retained-reachable': lambda b: retained_probe(b, True),
                 'custody': lambda b: custody(b, args.restart, args.secondary)}
        value = roles[args.role](args.base)
        if value is not None:
            print(canonical(value).decode())


if __name__ == '__main__':
    main()

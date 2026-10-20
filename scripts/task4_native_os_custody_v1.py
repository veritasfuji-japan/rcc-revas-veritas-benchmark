"""Pinned scripted Task4 Native SDK through separate-UID Bind and local HTTP.

CI-only synthetic approval/recipient. No Provider capability or live mode.
"""
import argparse
import base64
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
LIMIT = 256000
SCOPE_SHA = 'ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309'
RECIPIENT_SHA = '8f15bcc58f2ddb4f6d5e490191d96b84d1f67b5872f5ec3871afd2e33c3f6aa1'
RECIPIENT_MANIFEST_SHA = '18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c'
TARGET = 'mock://task4-native/chat-completions'
need, canonical, digest, tag = kernel.need, kernel.canonical, kernel.digest, kernel.tag


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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


def query(base, packet):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(15)
        conn.connect(str(base / 'ipc/native.sock'))
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


def statement(arm, ordinal, request_sha):
    need(arm in {'A', 'B'} and type(ordinal) is int and (arm, ordinal) in scope(), 'EXACT_NATIVE_SLOT')
    need(request_sha == scope()[(arm, ordinal)], 'EXACT_FROZEN_SDK_BYTES')
    return {'scope': 'CI_ONLY_NATIVE_TASK4', 'arm': arm, 'ordinal': ordinal,
            'request_sha256': request_sha, 'target': TARGET, 'output_cap': 256,
            'recipient_sha256': RECIPIENT_SHA}


def verify_grant(grant, arm, ordinal, request_sha, public):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    need(type(grant) is dict and set(grant) == {'statement', 'signature'}, 'EXACT_NATIVE_GRANT')
    need(grant['statement'] == statement(arm, ordinal, request_sha), 'EXACT_SIGNED_SCOPE')
    need(type(grant['signature']) is str and len(grant['signature']) == 128, 'SIGNATURE_FORMAT')
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(grant['signature']),
            b'TASK4_NATIVE_OS_V1\0' + canonical(grant['statement']))
    except (InvalidSignature, ValueError):
        raise ValueError('ISSUER_SIGNATURE') from None


def verify(packet, public):
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
        claim = statement(arm, ordinal, request_sha)
        grants[arm + str(ordinal)] = {'statement': claim,
            'signature': key.sign(b'TASK4_NATIVE_OS_V1\0' + canonical(claim)).hex()}
    return {'public': key.public_key().public_bytes_raw().hex(), 'grants': grants,
            'issuer_credential_reads_denied': True}


def http_call(method, path, body, key):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request(method, path, body=canonical(body) if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-Mock-Auth':
                tag(key, b'TASK4_NATIVE_HTTP_V1\0', {'method': method, 'path': path, 'body': body}) if key else ''})
        response = conn.getresponse()
        return response.status, parse(response.read(LIMIT + 1))
    finally:
        conn.close()


def backend(base):
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    kernel.role_identity(BACKEND)
    os.umask(0o077)
    key = (base / 'backend/credential').read_bytes()
    public = (base / 'public/issuer-key').read_bytes()
    db = sqlite3.connect(base / 'backend/effects.sqlite3', isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE effects (op TEXT PRIMARY KEY,request_sha TEXT,response_sha TEXT,receipt TEXT)')
    sources = {arm: cap.GuardedMock(arm) for arm in ('A', 'B')}

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
            op = self.path.removeprefix('/status/')
            claim = {'method': 'GET', 'path': self.path, 'body': None}
            if op not in {a + str(i) for a, i in scope()} or not hmac.compare_digest(
                    tag(key, b'TASK4_NATIVE_HTTP_V1\0', claim), self.headers.get('X-Mock-Auth', '')):
                self.respond(403, {'decision': 'DENIED'})
                return
            row = db.execute('SELECT receipt FROM effects WHERE op=?', (op,)).fetchone()
            self.respond(200, {'effect_count': db.execute('SELECT count(*) FROM effects').fetchone()[0],
                              'operation_receipt': row[0] if row else None})

        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                need(self.path == '/effect' and 0 < size <= LIMIT, 'EXACT_LOCAL_ENDPOINT')
                packet = parse(self.rfile.read(size))
                need(hmac.compare_digest(tag(key, b'TASK4_NATIVE_HTTP_V1\0',
                     {'method': 'POST', 'path': '/effect', 'body': packet}),
                     self.headers.get('X-Mock-Auth', '')), 'CUSTODY_TRANSPORT_AUTH')
                raw = verify(packet, public)
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
                self.respond(200, dict(record, receipt_sha256=receipt, response_b64=encode(fake.content)))
            except (ValueError, KeyError, TypeError, sqlite3.IntegrityError):
                self.respond(403, {'decision': 'DENIED'})

    server = HTTPServer((HOST, PORT), Handler)
    (base / 'backend/ready').write_text('ready')
    server.serve_forever()


def bind_post(packet, raw, key):
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
                code, value = http_call('POST', '/effect', packet, key)
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
            policy_snapshot_id='SYNTHETIC_FROZEN_NATIVE_SCOPE_NOT_OWNER_APPROVAL',
            actor_identity='custody-uid-61106', target_system='local-mock-backend', target_resource=TARGET,
            intended_action='one_scripted_native_completion', evidence_refs=['signed-wire:' + sha(raw)],
            decision_hash=digest(packet['grant']['statement']), decision_ts='2026-10-20T00:00:00Z',
            ttl_seconds=300, expected_state_fingerprint=sha256_of_canonical_json(before),
            approval_context={'real_human_approval': False, 'synthetic_test_permission': True},
            policy_lineage={'fixture': 'task4-native-os-custody'})
        adapter = Adapter(state=dict(before), pending_changes={}, target_description=TARGET)
        receipt = execute_bind_adjudication(execution_intent=intent, adapter=adapter,
            bind_ts='2026-10-20T00:00:03Z', append_trustlog=False).to_dict()
        need(receipt['final_outcome'] == ('COMMITTED' if allow else 'BLOCKED')
             and len(calls) == int(allow), 'REAL_BIND_NATIVE_OUTCOME')
        need(status() == ({'effect_count': index + 1, 'operation_receipt': responses[0]['receipt_sha256']}
             if allow else before), 'DENIED_BIND_NO_SEND')
        records.append({'outcome': receipt['final_outcome'], 'apply_calls': len(calls),
                        'receipt': receipt, 'receipt_sha256': digest(receipt)})
    return responses[0], {'records': records, 'loaded_core_sha256': sha(loaded), 'bind_core_git_blob': CORE_BLOB}


def custody(base, restart=False):
    import httpx
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from scripts.task4_457_local_response_aead_v1 import SealedLocalVault
    kernel.role_identity(CUSTODY)
    os.umask(0o077)
    key = (base / 'custody/credential').read_bytes()
    public = (base / 'public/issuer-key').read_bytes()
    file = base / 'custody/ledger.sqlite3'
    need(file.exists() if restart else not file.exists(), 'EXACT_NATIVE_LEDGER_LIFECYCLE')
    db = sqlite3.connect(file, isolation_level=None)
    db.execute('PRAGMA synchronous=FULL')
    if not restart:
        db.execute('CREATE TABLE consumed (op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
    else:
        need(db.execute('SELECT count(*) FROM consumed').fetchone()[0] == 8, 'EIGHT_DURABLE_CONSUMPTIONS')
    vault = SealedLocalVault(base / 'custody', X25519PublicKey.from_public_bytes(recipient()))
    address = base / 'ipc/native.sock'
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
            conn.settimeout(15)
            try:
                packet = frame(conn)
                _, peer, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer == NATIVE, 'KERNEL_NATIVE_PEER_REQUIRED')
                raw = verify(packet, public)
                op = packet['arm'] + str(packet['ordinal'])
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('INSERT INTO consumed VALUES (?, ?, ?, NULL,NULL,NULL,NULL)',
                               (op, 'CONSUMED_UNKNOWN', sha(raw)))
                except sqlite3.IntegrityError:
                    db.rollback()
                    result = {'decision': 'REPLAY_DENIED'}
                else:
                    db.commit()
                    response, binding = bind_post(packet, raw, key)
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
                    result = {'decision': 'SEALED_NATIVE_RESPONSE', 'request_sha256': sha(raw),
                              'response_sha256': sha(plaintext), 'backend_receipt_sha256': response['receipt_sha256'],
                              'envelope_sha256': sha(blob), 'envelope_b64': encode(blob), 'bind_sha256': bind_sha}
            except (ValueError, OSError, KeyError, TypeError):
                if db.in_transaction:
                    db.rollback()
                result = {'decision': 'DENIED_OR_UNKNOWN_NO_RETRY'}
            conn.sendall(canonical(result) + b'\n')


def probe(base, reachable=False):
    kernel.role_identity(NATIVE)
    if reachable:
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
    checks['raw_ipv4_denied'] = kernel.denied_connect(HOST, PORT)
    checks['raw_ipv6_denied'] = kernel.denied_connect('2001:db8::1', 443, socket.AF_INET6)
    try:
        http_call('POST', '/effect', {}, None)
    except OSError:
        checks['http_direct_denied'] = True
    else:
        raise ValueError('NATIVE_HTTP_DIRECT_ALLOWED')
    child = subprocess.run([sys.executable, '-I', '-c',
        'import socket,sys\ntry: socket.create_connection((' + repr(HOST) + ',' + str(PORT) + '),1)\n'
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


def run(output):
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
    host_if, sink_if = 'h' + token, 's' + token
    rule = ['OUTPUT', '-d', HOST, '-p', 'tcp', '--dport', str(PORT),
            '-m', 'owner', '!', '--uid-owner', str(CUSTODY), '-j', 'REJECT']
    processes, namespaces = [], []
    installed = link_created = False
    with tempfile.TemporaryDirectory(prefix='task4-native-os-') as tmp:
        base = Path(tmp)
        os.chmod(base, 0o755)
        source = base / 'source'
        source.mkdir(mode=0o755)
        archive = subprocess.run(git + ['archive', 'HEAD'], check=True, capture_output=True, timeout=30).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar.getmembers():
                dest = source / member.name
                need(dest.resolve().is_relative_to(source) and (member.isdir() or member.isfile()), 'REGULAR_TRACKED_SOURCE_ONLY')
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(tar.extractfile(member).read())
        for file in source.rglob('*'):
            os.chmod(file, 0o555 if file.is_dir() else 0o444)
        os.chmod(source, 0o555)
        for role, uid in [('native', NATIVE), ('custody', CUSTODY), ('backend', BACKEND), ('issuer', ISSUER), ('ipc', CUSTODY)]:
            folder = base / role
            folder.mkdir(mode=0o755 if role == 'ipc' else 0o700)
            os.chown(folder, uid, uid)
        (base / 'public').mkdir(mode=0o755)
        credential = secrets.token_bytes(32)
        for role, uid in [('custody', CUSTODY), ('backend', BACKEND)]:
            file = base / role / 'credential'
            file.write_bytes(credential)
            os.chmod(file, 0o600)
            os.chown(file, uid, uid)
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1', 'TASK4_RCC_ROOT': str(ROOT / '_pins/rcc')}
        # -I ignores PYTHONPATH; insert only the root-owned tracked source copy.
        code = 'import sys;sys.path[:0]=[' + repr(str(source)) + ',' + repr(str(source / 'scripts')) + '];from scripts.task4_native_os_custody_v1 import main;main()'

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
            issued = worker(ISSUER, 'issue', native_ns)
            public = bytes.fromhex(issued['public'])
            for op, grant in issued['grants'].items():
                verify_grant(grant, op[0], int(op[1]), scope()[(op[0], int(op[1]))], public)
            for name, data in [('issuer-key', public), ('grants.json', canonical(issued['grants']))]:
                file = base / 'public' / name
                file.write_bytes(data)
                os.chmod(file, 0o444)
            sink = spawn(BACKEND, 'backend', sink_ns, base / 'backend/ready')
            service = spawn(CUSTODY, 'custody', None, base / 'custody/ready')
            checks = worker(NATIVE, 'probe', native_ns)
            checks.update(worker(NATIVE, 'reachable', sink_ns))
            native_report = worker(NATIVE, 'native', native_ns)
            peer_packet = base / 'public/peer-packet.json'
            peer_packet.write_bytes((base / 'native/packet-A0.json').read_bytes())
            os.chmod(peer_packet, 0o444)
            checks.update(worker(kernel.STRANGER, 'wrong-peer', native_ns))
            service.terminate()
            service.wait(timeout=5)
            (base / 'custody/ready').unlink()
            service = spawn(CUSTODY, 'custody', None, base / 'custody/ready', 'restarted', ('--restart',))
            restart_report = worker(NATIVE, 'restart-probe', native_ns)
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
            if link_created:
                kernel.command(['ip', 'link', 'del', host_if], check=False)
    print('TASK4_NATIVE_OS_CUSTODY_BIND_LOCAL_HTTP_NO_PROVIDER')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--role', choices=('issue', 'backend', 'custody', 'probe', 'reachable', 'native', 'restart-probe', 'wrong-peer'))
    parser.add_argument('--base', type=Path)
    parser.add_argument('--restart', action='store_true')
    args = parser.parse_args()
    if args.run:
        need(args.output is not None and args.role is None, 'RUN_OUTPUT_REQUIRED')
        run(args.output.resolve())
    else:
        need(args.role is not None and args.base is not None, 'EXPLICIT_LOCAL_ROLE')
        roles = {'issue': issue, 'backend': backend, 'probe': probe,
                 'reachable': lambda b: probe(b, True), 'native': native, 'restart-probe': restart_probe,
                 'wrong-peer': wrong_peer,
                 'custody': lambda b: custody(b, args.restart)}
        value = roles[args.role](args.base)
        if value is not None:
            print(canonical(value).decode())


if __name__ == '__main__':
    main()

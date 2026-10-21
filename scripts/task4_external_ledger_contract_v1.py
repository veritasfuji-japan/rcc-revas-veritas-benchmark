"""Fail-closed retained-ledger contract; local reference service, NOT deployment.

No Native integration, network transport, live keys, or Provider capability.
The service/transport administrator and signing key are trusted. See the doc.
"""
import argparse
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = 'task4.external-ledger-contract.v1'
DOMAIN = b'TASK4_EXTERNAL_LEDGER_RECEIPT_V1\0'
MAX_WIRE = 8192
OPERATIONS = {arm + str(i) for arm in 'AB' for i in range(4)}


class Denied(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Denied(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    return sha(canonical(value))


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def integer(value):
    return type(value) is int and 0 <= value <= 16


def exact(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), 'EXACT_FIELDS')


def strict(data):
    need(type(data) is bytes and len(data) <= MAX_WIRE, 'BOUNDED_BYTES')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_FIELD')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs)
    need(canonical(value) == data, 'CANONICAL_JSON')
    return value


def binding(value):
    exact(value, 'schema ledger_id run_id manifest_sha256 issuer_public_sha256 custody_public_sha256')
    need(value['schema'] == SCHEMA and all(hex64(value[k]) for k in value if k != 'schema'), 'PINNED_RUN_BINDING')
    need(value['issuer_public_sha256'] != value['custody_public_sha256'], 'DISTINCT_ROLE_IDENTITIES')
    return value


def command(value):
    exact(value, 'schema binding_sha256 nonce action expected_revision operation_id request_sha256 grant_sha256')
    need(value['schema'] == SCHEMA and hex64(value['binding_sha256']) and hex64(value['nonce']), 'COMMAND_IDENTITY')
    need(value['action'] in ('view', 'reserve', 'consume'), 'NO_ENROLL_RESET_OR_REPAIR_API')
    if value['action'] == 'view':
        need(all(value[k] is None for k in ('expected_revision', 'operation_id', 'request_sha256', 'grant_sha256')), 'VIEW_ONLY')
    else:
        need(integer(value['expected_revision']) and value['operation_id'] in OPERATIONS
             and hex64(value['request_sha256']), 'BOUNDED_MUTATION')
        need(value['grant_sha256'] is None if value['action'] == 'reserve' else hex64(value['grant_sha256']), 'GRANT_BINDING')
    return value


def validate_snapshot(value):
    exact(value, 'revision attempts')
    need(integer(value['revision']) and type(value['attempts']) is list and len(value['attempts']) <= 8, 'BOUNDED_SNAPSHOT')
    operations = []
    consumed = 0
    for row in value['attempts']:
        exact(row, 'operation_id request_sha256 grant_sha256 state')
        need(row['operation_id'] in OPERATIONS and hex64(row['request_sha256']), 'EXACT_ATTEMPT')
        need(row['state'] in ('RESERVED', 'CONSUMED_UNKNOWN'), 'NO_RESET_STATE')
        need(row['grant_sha256'] is None if row['state'] == 'RESERVED' else hex64(row['grant_sha256']), 'CONSUMED_GRANT')
        operations.append(row['operation_id'])
        consumed += row['state'] == 'CONSUMED_UNKNOWN'
    need(operations == sorted(set(operations)) and value['revision'] == len(operations) + consumed, 'SNAPSHOT_REVISION')
    return value


class ReferenceService:
    """Local SQLite reference ONLY. Authenticated peer is supplied by trusted transport.

    Client JSON cannot select its role. No production transport is implemented.
    Explicit bootstrap/enroll are administration operations, never client commands.
    """
    def __init__(self, file, ledger_id, key):
        need(hex64(ledger_id), 'LEDGER_ID')
        self.file = Path(os.path.abspath(file))
        self.ledger_id, self.key = ledger_id, key
        with self.db() as db:
            need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'LEDGER_INTEGRITY')
            need(db.execute('SELECT * FROM service').fetchall() ==
                 [(SCHEMA, ledger_id, sha(key.public_key().public_bytes_raw()))], 'REGISTERED_SERVICE_KEY')

    @classmethod
    def bootstrap(cls, file, ledger_id, key):
        need(hex64(ledger_id), 'LEDGER_ID')
        file = Path(file)
        fd = os.open(file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(file)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE service (schema TEXT, ledger TEXT, signer TEXT)')
            db.execute('INSERT INTO service VALUES (?,?,?)', (SCHEMA, ledger_id, sha(key.public_key().public_bytes_raw())))
            db.execute('CREATE TABLE runs (run TEXT PRIMARY KEY, binding TEXT UNIQUE, document BLOB, revision INTEGER)')
            db.execute('CREATE TABLE attempts (run TEXT, op TEXT, request TEXT, grant TEXT, state TEXT, PRIMARY KEY(run,op))')
            db.commit()
        fd = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(file, ledger_id, key)

    @contextmanager
    def db(self):
        # mode=rw forbids implicit recreation. Parent directory and administrator
        # are trusted in this reference; no anti-rollback claim is made.
        s = self.file.lstat()
        need(stat.S_ISREG(s.st_mode) and not self.file.is_symlink() and s.st_nlink == 1
             and s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o600, 'PRIVATE_EXISTING_LEDGER')
        db = sqlite3.connect(self.file.as_uri() + '?mode=rw', uri=True, isolation_level=None, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def enroll(self, approved_binding):
        value = binding(approved_binding)
        need(value['ledger_id'] == self.ledger_id, 'EXACT_LEDGER')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO runs VALUES (?,?,?,0)', (value['run_id'], digest(value), canonical(value)))
                db.commit()
            except sqlite3.IntegrityError as error:
                raise Denied('RUN_ID_ALREADY_ENROLLED_NO_REPLACEMENT') from error

    @staticmethod
    def snapshot(db, run):
        rows = db.execute('SELECT op,request,grant,state FROM attempts WHERE run=? ORDER BY op', (run,)).fetchall()
        return validate_snapshot(dict(revision=db.execute('SELECT revision FROM runs WHERE run=?', (run,)).fetchone()[0],
            attempts=[dict(zip(('operation_id', 'request_sha256', 'grant_sha256', 'state'), row)) for row in rows]))

    def exchange(self, data, authenticated_peer):
        c = command(strict(data))
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT run,document,revision FROM runs WHERE binding=?', (c['binding_sha256'],)).fetchone()
            need(row is not None, 'UNKNOWN_OR_CHANGED_RUN_BINDING')
            run, document, revision = row
            enrolled = binding(strict(document))
            need(authenticated_peer in (enrolled['issuer_public_sha256'], enrolled['custody_public_sha256']), 'AUTHENTICATED_PEER')
            action = c['action']
            if action != 'view':
                role = 'issuer' if action == 'reserve' else 'custody'
                need(authenticated_peer == enrolled[role + '_public_sha256'], 'ROLE_SEPARATION')
                need(c['expected_revision'] == revision, 'REVISION_CONFLICT_NO_AUTOMATIC_RETRY')
                op, request = c['operation_id'], c['request_sha256']
                old = db.execute('SELECT request,state FROM attempts WHERE run=? AND op=?', (run, op)).fetchone()
                if action == 'reserve':
                    need(old is None, 'ALREADY_RESERVED_NO_REISSUE')
                    db.execute('INSERT INTO attempts VALUES (?,?,?,?,?)', (run, op, request, None, 'RESERVED'))
                else:
                    need(old == (request, 'RESERVED'), 'ALREADY_CONSUMED_OR_REQUEST_MISMATCH')
                    db.execute('UPDATE attempts SET grant=?,state=? WHERE run=? AND op=?',
                               (c['grant_sha256'], 'CONSUMED_UNKNOWN', run, op))
                db.execute('UPDATE runs SET revision=revision+1 WHERE run=?', (run,))
            snapshot = self.snapshot(db, run)
            db.commit()  # Commit before signing/returning acknowledgement.
        statement = dict(schema=SCHEMA, ledger_id=self.ledger_id, binding_sha256=c['binding_sha256'],
                         command_sha256=sha(data), nonce=c['nonce'], action=action, snapshot=snapshot)
        return canonical(dict(statement=statement, signature=self.key.sign(DOMAIN + canonical(statement)).hex()))


class LedgerClient:
    """Unavailable by default; no cache, local fallback, repair or mutation retry.

    Approved binding and service public key must arrive through trusted enrollment.
    Transport must authenticate the client role and service; pinning a receipt
    alone does not supply transport authentication or confidentiality.
    """
    def __init__(self, approved_binding, service_public, transport=None):
        self.binding = binding(strict(canonical(approved_binding)))
        self.public = Ed25519PublicKey.from_public_bytes(service_public)
        self.transport = transport
        self.minimum_revision = 0

    def exchange(self, action, revision=None, operation=None, request=None, grant=None):
        c = command(dict(schema=SCHEMA, binding_sha256=digest(self.binding), nonce=os.urandom(32).hex(), action=action,
                         expected_revision=revision, operation_id=operation, request_sha256=request, grant_sha256=grant))
        need(self.transport is not None, 'EXTERNAL_LEDGER_UNAVAILABLE_NO_FALLBACK')
        encoded = canonical(c)
        try:
            receipt = strict(self.transport(encoded))
            exact(receipt, 'statement signature')
            statement = receipt['statement']
            exact(statement, 'schema ledger_id binding_sha256 command_sha256 nonce action snapshot')
            self.public.verify(bytes.fromhex(receipt['signature']), DOMAIN + canonical(statement))
            need({k: statement[k] for k in ('schema', 'ledger_id', 'binding_sha256', 'command_sha256', 'nonce', 'action')} ==
                 dict(schema=SCHEMA, ledger_id=self.binding['ledger_id'], binding_sha256=digest(self.binding),
                      command_sha256=sha(encoded), nonce=c['nonce'], action=action), 'FRESH_EXACT_RECEIPT')
            snapshot = validate_snapshot(statement['snapshot'])
            need(snapshot['revision'] >= self.minimum_revision, 'REVISION_REGRESSION')
            if action != 'view':
                need(snapshot['revision'] == revision + 1, 'EXACT_COMMITTED_REVISION')
                expected = dict(operation_id=operation, request_sha256=request, grant_sha256=grant,
                                state='RESERVED' if action == 'reserve' else 'CONSUMED_UNKNOWN')
                need(expected in snapshot['attempts'], 'EXACT_COMMITTED_ATTEMPT')
            self.minimum_revision = snapshot['revision']
            return snapshot
        except Exception as error:
            # A lost acknowledgement may already have committed. Do not retry
            # a mutation and do not call issuance/dispatch on uncertain state.
            raise Denied('LEDGER_ACK_UNVERIFIED_STOP') from error

    def gate(self, action, operation, request, effect, grant=None):
        need(action in ('reserve', 'consume'), 'MUTATION_GATE_ONLY')
        revision = self.exchange('view')['revision']
        snapshot = self.exchange(action, revision, operation, request, grant)
        return effect(snapshot)


def rehearsal():
    """Separate client directories, one retained local service; no network/Native."""
    with tempfile.TemporaryDirectory(prefix='task4-ledger-contract-') as temp:
        root = Path(temp)
        authority = root / 'authority'; authority.mkdir(mode=0o700)
        for name in ('runner-a', 'runner-b'):
            (root / name).mkdir()
        key = Ed25519PrivateKey.generate()
        approved = dict(schema=SCHEMA, ledger_id=os.urandom(32).hex(), run_id=os.urandom(32).hex(),
                        manifest_sha256='a'*64, issuer_public_sha256='b'*64, custody_public_sha256='c'*64)
        service = ReferenceService.bootstrap(authority / 'ledger.sqlite3', approved['ledger_id'], key)
        service.enroll(approved)
        def client(peer, transport=None):
            return LedgerClient(approved, key.public_key().public_bytes_raw(),
                transport if transport is not None else lambda data: service.exchange(data, approved[peer + '_public_sha256']))
        calls = []
        issuer = client('issuer')
        issuer.gate('reserve', 'A0', 'd'*64, lambda _: calls.append('synthetic-issue'))
        # New service object and new client keep service storage, with no client files.
        service = ReferenceService(authority / 'ledger.sqlite3', approved['ledger_id'], key)
        custody = client('custody')
        custody.gate('consume', 'A0', 'd'*64, lambda _: calls.append('synthetic-send'), 'e'*64)
        denied = []
        def refuse(name, fn):
            try:
                fn()
            except (Denied, OSError, sqlite3.Error):
                denied.append(name)
                return
            raise AssertionError(name)
        refuse('duplicate-enrollment', lambda: service.enroll(approved))
        refuse('fresh-client-reissue', lambda: client('issuer').gate('reserve', 'A0', 'd'*64, lambda _: calls.append('BAD')))
        refuse('fresh-client-replay', lambda: client('custody').gate('consume', 'A0', 'd'*64, lambda _: calls.append('BAD'), 'e'*64))
        refuse('unavailable', lambda: LedgerClient(approved, key.public_key().public_bytes_raw()).gate(
            'reserve', 'B0', 'd'*64, lambda _: calls.append('BAD')))
        def lost_ack(data):
            result = service.exchange(data, approved['issuer_public_sha256'])
            if strict(data)['action'] == 'reserve':
                raise TimeoutError('committed response lost')
            return result
        refuse('lost-reservation-ack', lambda: client('issuer', lost_ack).gate('reserve', 'B0', 'f'*64, lambda _: calls.append('BAD')))
        refuse('lost-ack-reissue', lambda: client('issuer').gate('reserve', 'B0', 'f'*64, lambda _: calls.append('BAD')))
        final = client('custody').exchange('view')
        need(calls == ['synthetic-issue', 'synthetic-send'] and final['revision'] == 3, 'NO_EXTRA_EFFECTS')
        need(all(not list((root / name).iterdir()) for name in ('runner-a', 'runner-b')), 'NO_CLIENT_LOCAL_LEDGER')
        return dict(schema=SCHEMA, source_sha256=sha(Path(__file__).read_bytes()),
            scope='LOCAL_REFERENCE_CONTRACT_NO_NATIVE_OR_NETWORK', checks={name: True for name in denied},
            synthetic_issue_callbacks=1, synthetic_send_callbacks=1, final_revision=3,
            final_states=[row['state'] for row in final['attempts']], client_local_state_files=0,
            external_storage_deployed=False, cross_runner_retention_proven=False,
            native_integration_proven=False, independent_administration_proven=False,
            production_bypass_resistance_proven=False, real_provider_posts=0, external_bank_effects=0,
            provider_dispatch='DENY', utility='UNSCORED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = rehearsal()
    import subprocess
    report['audited_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'report.json').write_bytes(canonical(report))
    suite = ET.Element('testsuite', name=SCHEMA, tests=str(len(report['checks'])), failures='0', errors='0', skipped='0')
    for name in report['checks']:
        ET.SubElement(suite, 'testcase', name=name)
    ET.ElementTree(suite).write(args.output / 'junit.xml', encoding='utf-8', xml_declaration=True)


if __name__ == '__main__':
    main()

"""Explicit closed-local Native/Bind profile with a separate-UID signed ledger.

Disposable research enrollment only; no operator migration, GitHub backend,
live credential, Provider endpoint or automatic recovery of uncertain attempts.
"""
import os
from pathlib import Path
import pwd
import socket
import stat
import struct

from scripts import task4_external_ledger_contract_v1 as l
from scripts import task4_native_signed_ledger_gate_v1 as g

DIRECTORY = Path('/run/veritas-task4-native-signed-ledger-v1')
LOCAL = 'public/native-signed-ledger.json'
PROVISION = 'public/native-ledger-provision.json'
SCHEMA = 'task4.closed-native-signed-ledger-integration.v1'
LEDGER = 61109
ROOT_UID = 0


def modules():
    from scripts import task4_native_bounded_continuation_v1 as b
    from scripts import task4_native_retained_authority_v1 as r
    from scripts import task4_native_os_custody_v1 as n
    return b, r, n


def required(base=None):
    return os.path.lexists(DIRECTORY) or (base is not None and os.path.lexists(Path(base) / LOCAL))


def anchor(base):
    b, r, _ = modules()
    r.identity(DIRECTORY, ROOT_UID, 0o755, True)
    raw = r.regular(DIRECTORY / 'enrollment.json', ROOT_UID, 0o444)
    a = l.strict(raw)
    fields='schema base base_identity retained_sha256 binding service_public gates ledger_storage'
    l.exact(a,fields+(' github_mtls' if 'github_mtls' in a else ''))
    if 'github_mtls' in a:
        from scripts import task4_native_github_mtls_v1 as github
        github.validate_enrollment(a)
    l.need(a['schema'] == SCHEMA and a['base'] == str(Path(base).absolute()), 'EXACT_NATIVE_LEDGER_BASE')
    r.check_identity(a['base_identity'])
    l.need(l.strict(r.regular(Path(base) / LOCAL, ROOT_UID, 0o444)) ==
           dict(schema=SCHEMA, enrollment_sha256=l.digest(a)), 'NATIVE_LEDGER_LOCAL_JOIN')
    l.binding(a['binding']); l.exact(a['gates'], 'issuer custody')
    m = b.load(base)
    l.need(a['binding']['run_id'] == m['execution']['run_id']
           and a['binding']['manifest_sha256'] == l.digest(m)
           and a['binding']['issuer_public_sha256'] == l.sha((Path(base) / 'public/issuer-key').read_bytes())
           and a['binding']['custody_public_sha256'] == l.sha(bytes.fromhex(m['custody_public']))
           and len(bytes.fromhex(a['service_public'])) == 32, 'NATIVE_LEDGER_MANIFEST_ROLES_JOIN')
    l.need(l.digest(r.anchor()) == a['retained_sha256'], 'SAME_RETAINED_NATIVE_ENROLLMENT')
    return a


def admit(base, role):
    b, r, _ = modules()
    a = anchor(base)
    l.need(role in ('issuer', 'custody'), 'NATIVE_LEDGER_ROLE')
    b.kernel.role_identity(b.kernel.ISSUER if role == 'issuer' else b.kernel.CUSTODY)
    r.admit(base, role)
    e = a['gates'][role]
    l.need(e['binding'] == a['binding'] and e['role'] == role
           and e['service_public_sha256'] == l.sha(bytes.fromhex(a['service_public']))
           and e['journal']['path'] == str(Path(base) / role / 'signed-ledger'), 'EXACT_NATIVE_ROLE_GATE')
    return a


def gate(base, role):
    a = admit(base, role)
    return g.NativeLedgerGate(a['gates'][role], bytes.fromhex(a['service_public']), transport(base,a,role))


def transport(base,a,role):
    if 'github_mtls' in a:
        from scripts import task4_native_github_mtls_v1 as github
        return github.Transport(base,a,role)
    return UnixTransport(base)


class UnixTransport:
    """Kernel-authenticated same-host transport, including across netns.

    The service reciprocally verifies SO_PEERCRED; a receipt pin alone is not
    treated as peer authentication. No path/UID/endpoint comes from model JSON.
    """
    def __init__(self, base):
        self.base = Path(base)

    def __call__(self, encoded):
        _, _, n = modules()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(20)
            conn.connect(str(self.base / 'ledger-ipc/service.sock'))
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            l.need(uid == LEDGER, 'EXACT_LEDGER_SERVER_PEER')
            conn.sendall(encoded + b'\n')
            return l.canonical(n.frame(conn))


def provision(base):
    """Role worker, called only by the explicit root disposable proof setup."""
    b, r, n = modules()
    os.umask(0o077)
    l.need(not required(base), 'NO_GATE_REPROVISION')
    uid = os.geteuid()
    role = {b.kernel.ISSUER: 'issuer', b.kernel.CUSTODY: 'custody'}[uid]
    b.kernel.role_identity(uid)
    v = l.strict(r.regular(base / PROVISION, ROOT_UID, 0o444))
    folder = base / role / 'signed-ledger'
    folder.mkdir(mode=0o700)
    e = dict(schema=g.ENROLLMENT, scope=g.SCOPE, binding=v['binding'], role=role,
             service_public_sha256=l.sha(bytes.fromhex(v['service_public'])),
             journal=g._identity(str(folder), folder.stat()))
    n.durable_marker(folder / g.ENROLLMENT_FILE, e)
    r.sync_dir(folder.parent)
    return e


def initialize(base):
    b, r, _ = modules()
    b.kernel.role_identity(LEDGER); l.need(not required(base), 'NO_LEDGER_REINITIALIZATION')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    os.umask(0o077)
    key = Ed25519PrivateKey.generate()
    with (base / 'ledger/signing-key').open('xb') as stream:
        stream.write(key.private_bytes_raw()); stream.flush(); os.fsync(stream.fileno())
    r.sync_dir(base / 'ledger')
    return dict(public=key.public_key().public_bytes_raw().hex())


def enroll(base, worker, isolated, github_mtls=False, github_fault=''):
    b, r, n = modules()
    from scripts import task4_native_github_mtls_v1 as github
    l.need(type(github_mtls) is bool and github_fault in ('',*github.FAULTS)
           and (not github_fault or github_mtls),'EXPLICIT_NATIVE_GITHUB_MODEL_PROFILE')
    l.need(os.geteuid() == ROOT_UID and not required(base), 'EXCLUSIVE_ROOT_NATIVE_LEDGER_ENROLLMENT')
    try:
        pwd.getpwuid(LEDGER)
    except KeyError:
        pass
    else:
        raise ValueError('LEDGER_UID_ALREADY_USED')
    for name, mode in [('ledger', 0o700), ('ledger-ipc', 0o755)]:
        folder = base / name; folder.mkdir(mode=mode); os.chown(folder, LEDGER, LEDGER)
    public = worker(LEDGER, 'signed-ledger-init', isolated)['public']
    m = b.load(base)
    binding = dict(schema=l.SCHEMA, ledger_id=l.digest(dict(domain=SCHEMA, run=m['execution']['run_id'])),
        run_id=m['execution']['run_id'], manifest_sha256=l.digest(m),
        issuer_public_sha256=l.sha((base / 'public/issuer-key').read_bytes()),
        custody_public_sha256=l.sha(bytes.fromhex(m['custody_public'])))
    v=dict(binding=binding,service_public=public)
    if github_mtls:
        binding['ledger_id']=github.signed.LEDGER_ID
        v['github_mtls']=github.provision_tls(base,binding,github_fault)
    n.durable_marker(base / PROVISION,v); os.chmod(base / PROVISION, 0o444)
    gates = {role: worker(uid, 'signed-ledger-provision', isolated)
             for role, uid in [('issuer', b.kernel.ISSUER), ('custody', b.kernel.CUSTODY)]}
    # Database creation/enrollment happens in the distinct ledger UID worker.
    initialized=worker(LEDGER, 'signed-ledger-bootstrap', isolated)
    storage = {name: r.identity(base / 'ledger' / name, LEDGER, 0o600)
               for name in ('signing-key',github.MODEL if github_mtls else 'state.sqlite3')}
    a = dict(schema=SCHEMA, base=str(base), base_identity=r.identity(base, ROOT_UID, 0o755, True),
        retained_sha256=l.digest(r.anchor()), binding=binding, service_public=public, gates=gates, ledger_storage=storage)
    if github_mtls:a['github_mtls']=dict(v['github_mtls'],genesis=initialized['genesis'])
    DIRECTORY.mkdir(mode=0o755)
    n.durable_marker(DIRECTORY / 'enrollment.json', a); os.chmod(DIRECTORY / 'enrollment.json', 0o444)
    n.durable_marker(base / LOCAL, dict(schema=SCHEMA, enrollment_sha256=l.digest(a))); os.chmod(base / LOCAL, 0o444)
    r.sync_dir(DIRECTORY); r.sync_dir((base / LOCAL).parent)
    return a


def service_key(base):
    _, r, _ = modules()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(r.regular(base / 'ledger/signing-key', LEDGER, 0o600, 32))


def bootstrap(base):
    b, r, _ = modules()
    b.kernel.role_identity(LEDGER); l.need(not required(base), 'NO_LEDGER_REBOOTSTRAP')
    v = l.strict(r.regular(base / PROVISION, ROOT_UID, 0o444)); key = service_key(base)
    if 'github_mtls' in v:
        from scripts import task4_native_github_mtls_v1 as github
        return github.bootstrap(base,v,key)
    service = l.ReferenceService.bootstrap(base / 'ledger/state.sqlite3', v['binding']['ledger_id'], key)
    service.enroll(v['binding']); r.sync_dir(base / 'ledger')
    return dict(enrolled=True)


def serve(base):
    b, r, n = modules()
    b.kernel.role_identity(LEDGER); a = anchor(base)
    for value in a['ledger_storage'].values(): r.check_identity(value)
    key = service_key(base)
    l.need(l.sha(key.public_key().public_bytes_raw()) == l.sha(bytes.fromhex(a['service_public'])), 'LEDGER_SIGNER_PIN')
    if 'github_mtls' in a:
        from scripts import task4_native_github_mtls_v1 as github
        return github.serve(base,a,key)
    service = l.ReferenceService(base / 'ledger/state.sqlite3', a['binding']['ledger_id'], key)
    address = base / 'ledger-ipc/service.sock'
    if os.path.lexists(address):
        info = address.lstat()
        l.need(stat.S_ISSOCK(info.st_mode) and info.st_uid == LEDGER, 'OWN_RETAINED_LEDGER_SOCKET_ONLY')
        address.unlink()  # Storage/key enrollment is still reopen-only.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(address)); os.chmod(address, 0o666); server.listen(8)
        (base / 'ledger/ready').write_text('ready')
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    conn.settimeout(20)
                    _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    role = {b.kernel.ISSUER: 'issuer', b.kernel.CUSTODY: 'custody'}[uid]
                    current = anchor(base)
                    for value in current['ledger_storage'].values(): r.check_identity(value)
                    encoded = l.canonical(n.frame(conn))
                    l.need(l.command(l.strict(encoded))['binding_sha256'] == l.digest(a['binding']), 'ENROLLED_NATIVE_BINDING_ONLY')
                    reply = service.exchange(encoded, a['binding'][role + '_public_sha256'])
                    conn.sendall(reply + b'\n')
                except Exception:
                    # Close without unsigned permission or secret-bearing diagnostics.
                    pass


def journal(base):
    b, _, _ = modules()
    role = {b.kernel.ISSUER: 'issuer', b.kernel.CUSTODY: 'custody'}[os.geteuid()]
    instance = gate(base, role); rows = []
    with instance._journal() as fd:
        for operation in sorted(l.OPERATIONS):
            action = 'reserve' if role == 'issuer' else 'consume'
            name = instance._enrollment['binding']['run_id'] + '-' + action + '-' + operation
            slot = os.open(name, g.custody.DIR_FLAGS, dir_fd=fd)
            try:
                rows.append(dict(operation=operation, intent=l.strict(g._read(slot, 'intent.json', g.MAX_RECORD)),
                    receipts=l.strict(g._read(slot, 'verified-receipts.json', g.MAX_RECORD)),
                    returned=l.strict(g._read(slot, 'effect-returned.json', g.MAX_RECORD))))
            finally:
                os.close(slot)
    return dict(role=role, rows=rows, uid=os.geteuid())


def view(base):
    a = admit(base, 'issuer')
    return l.LedgerClient(a['binding'], bytes.fromhex(a['service_public']), transport(base,a,'issuer')).exchange('view')


def probe(base):
    b, _, _ = modules()
    b.kernel.role_identity(b.kernel.AGENT); denied=[];a=anchor(base)
    from scripts import task4_native_github_mtls_v1 as github
    for name in ('signing-key',github.MODEL if 'github_mtls' in a else 'state.sqlite3'):
        try:(base / 'ledger' / name).read_bytes()
        except PermissionError:denied.append(name)
        else:raise ValueError('UNTRUSTED_LEDGER_STORAGE_READ')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(20);conn.connect(str(base / 'ledger-ipc/service.sock'))
        conn.sendall(b'{}\n')
        try:reply=conn.recv(8192)
        except ConnectionResetError:reply=b''
        l.need(reply==b'', 'UNTRUSTED_LEDGER_PEER_REPLIED')
    return dict(private_read_denials=denied,unknown_uid_closed_without_receipt=True)


def validate(e, normal):
    """Cryptographic join of every original command, Native grant and callback."""
    a = e['enrollment']; records = normal['evidence']['native']['records']; revisions = []
    l.need(a['binding']['manifest_sha256'] == l.digest(normal['evidence']['manifest']), 'SAME_NATIVE_LEDGER_MANIFEST')
    for role in ('issuer', 'custody'):
        rows = e[role]['rows']; l.need(len(rows) == 8 and e[role]['role'] == role, 'EIGHT_ROLE_GATE_JOURNALS')
        for row in rows:
            op = row['operation']; native = next(x for x in records if x['arm'] + str(x['ordinal']) == op)
            action = 'reserve' if role == 'issuer' else 'consume'
            grant = None if role == 'issuer' else l.digest(native['grant'])
            intent = row['intent']; receipts = row['receipts']
            l.need(intent['operation_id'] == op and intent['action'] == action
                   and intent['request_sha256'] == native['request_sha256'] and intent['grant_sha256'] == grant
                   and intent['binding_sha256'] == l.digest(a['binding'])
                   and receipts['intent_sha256'] == row['returned']['intent_sha256'] == l.digest(intent)
                   and row['returned']['effect_returned'] is True, 'NATIVE_GATE_INTENT_CALLBACK_JOIN')
            exchanges = receipts['exchanges']; l.need(len(exchanges) == 2, 'ONE_VIEW_ONE_MUTATION')
            # Verify original nonces directly; replaying LedgerClient would generate new ones.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(a['service_public']))
            for pair in exchanges:
                c = l.command(pair['command']); s = pair['receipt']['statement']
                public.verify(bytes.fromhex(pair['receipt']['signature']), l.DOMAIN + l.canonical(s))
                l.need({k: s[k] for k in ('schema', 'ledger_id', 'binding_sha256', 'command_sha256', 'nonce', 'action')} ==
                    dict(schema=l.SCHEMA, ledger_id=a['binding']['ledger_id'], binding_sha256=l.digest(a['binding']),
                         command_sha256=l.digest(c), nonce=c['nonce'], action=c['action']), 'EXACT_ORIGINAL_RECEIPT')
                l.validate_snapshot(s['snapshot'])
            before, after = exchanges
            c = after['command']; snapshot = after['receipt']['statement']['snapshot']
            expected = dict(operation_id=op, request_sha256=native['request_sha256'], grant_sha256=grant,
                            state='RESERVED' if role == 'issuer' else 'CONSUMED_UNKNOWN')
            l.need(before['command']['action'] == 'view' and c['action'] == action and c['operation_id'] == op
                   and c['request_sha256'] == expected['request_sha256'] and c['grant_sha256'] == grant
                   and c['expected_revision'] == before['receipt']['statement']['snapshot']['revision']
                   and snapshot['revision'] == c['expected_revision'] + 1 and expected in snapshot['attempts']
                   and receipts['snapshot'] == snapshot, 'EXACT_COMMITTED_NATIVE_ATTEMPT')
            revisions.append(snapshot['revision'])
    l.need(sorted(revisions) == list(range(1, 17)), 'SIXTEEN_EXACT_NATIVE_MUTATIONS')
    from scripts import task4_native_github_mtls_v1 as github
    l.need(normal['evidence']['denials']['signed_ledger'] == dict(
        private_read_denials=['signing-key',github.MODEL if 'github_mtls' in a else 'state.sqlite3'],unknown_uid_closed_without_receipt=True), 'LEDGER_KERNEL_PEER_PRIVATE_KEY_DENIALS')
    restart=e['restart']
    l.need(restart['before'] == restart['after'] == e['post_replay'] and restart['after']['revision'] == 16
           and len(restart['after']['attempts']) == 8
           and all(x['state'] == 'CONSUMED_UNKNOWN' for x in restart['after']['attempts'])
           and restart['terminal'] == dict(terminal_reissue_denials=2)
           and restart['ledger_before_pid'] != restart['ledger_after_pid']
           and restart['issuer_before_pid'] != restart['issuer_after_pid']
           and restart['ledger_exit'] == restart['issuer_exit'] == -9, 'ACTUAL_LEDGER_ISSUER_RESTART_RETAINED')
    return True


def finish(base, output, worker, isolated, normal, restart):
    b, _, _ = modules()
    e = dict(enrollment=anchor(base), issuer=worker(b.kernel.ISSUER, 'signed-ledger-journal', isolated),
             custody=worker(b.kernel.CUSTODY, 'signed-ledger-journal', isolated),restart=restart,
             post_replay=worker(b.kernel.ISSUER,'signed-ledger-view',isolated))
    validate(e, normal)
    report = dict(schema=SCHEMA, audited_commit=normal['audited_commit'], normal_report_sha256=l.digest(normal),
        source_sha256=l.sha(Path(__file__).read_bytes()),
        evidence=e, evidence_sha256=l.digest(e), separate_uid_ledger=LEDGER,
        actual_native_bind_closed_tls_integrated=True, ledger_backend='LOCAL_SQLITE_REFERENCE_NOT_GITHUB',
        ledger_transport='AF_UNIX_SO_PEERCRED_NOT_MTLS', real_provider_posts=0, external_bank_effects=0,
        provider_dispatch='DENY', utility='UNSCORED', production_bypass_resistance_proven=False,
        independent_administration_proven=False, cross_runner_retention_proven=False)
    if 'github_mtls' in e['enrollment']:
        report.update(ledger_backend='GITHUB_API_MODEL_NOT_REMOTE_GITHUB',ledger_transport='MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED')
    (output / 'signed-ledger-integration.json').write_bytes(l.canonical(report))
    if 'github_mtls' in e['enrollment']:
        from scripts import task4_native_github_mtls_v1 as github
        github.finish(base,output,worker,isolated,normal,report)


def cleanup(base):
    if not os.path.lexists(DIRECTORY): return
    _, r, _ = modules()
    l.need(os.geteuid() == ROOT_UID, 'ROOT_EXPLICIT_FIXTURE_RETIREMENT')
    anchor(base)
    (DIRECTORY / 'enrollment.json').unlink(); DIRECTORY.rmdir(); r.sync_dir(DIRECTORY.parent)

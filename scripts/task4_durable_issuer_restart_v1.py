"""Bounded durable synthetic issuer and restart evidence; no live authority."""
import hashlib
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import xml.etree.ElementTree as ET

from scripts import ci_mock_executor_authority_boundary_v1 as kernel

need, canonical, digest = kernel.need, kernel.canonical, kernel.digest
MARKER = 'durable-native-issuer-v1'
STATE = 'issuer/issued-state.json'
ANCHOR = 'public/issuer-state-anchor.json'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enabled(base):
    file = base / 'public/durable-issuer'
    if not file.exists():
        return False
    s = file.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o444
         and file.read_text() == MARKER, 'ROOT_ENROLLED_DURABLE_ISSUER')
    return True


def state_value(key=None, epoch=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from scripts import task4_native_os_custody_v1 as native
    key = key or Ed25519PrivateKey.generate()
    grants = {}
    for (arm, ordinal), request_sha in native.scope().items():
        claim = native.statement(arm, ordinal, request_sha)
        grants[arm+str(ordinal)] = dict(statement=claim,
            signature=key.sign(b'TASK4_NATIVE_OS_V1\0'+canonical(claim)).hex())
    return dict(schema='task4.durable-synthetic-issuer.v1',epoch=epoch or secrets.token_hex(32),
        private_key=key.private_bytes_raw().hex(),public=key.public_key().public_bytes_raw().hex(),grants=grants,
        scope_sha256=native.SCOPE_SHA,recipient_sha256=native.RECIPIENT_SHA,issued_count=8)


def validate_state(value):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from scripts import task4_native_os_custody_v1 as native
    need(type(value) is dict and set(value) == {'schema','epoch','private_key','public','grants',
         'scope_sha256','recipient_sha256','issued_count'}, 'EXACT_DURABLE_ISSUER_STATE')
    need(value['schema']=='task4.durable-synthetic-issuer.v1' and type(value['epoch']) is str
         and len(value['epoch'])==64 and bytes.fromhex(value['epoch']).hex()==value['epoch'], 'ISSUER_EPOCH')
    need(type(value['private_key']) is str and len(value['private_key'])==64, 'ISSUER_PRIVATE_KEY_SIZE')
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value['private_key']))
    public = key.public_key().public_bytes_raw()
    need(public.hex()==value['public'] and value['scope_sha256']==native.SCOPE_SHA
         and value['recipient_sha256']==native.RECIPIENT_SHA and type(value['issued_count']) is int
         and value['issued_count']==8 and type(value['grants']) is dict
         and set(value['grants'])=={a+str(i) for a,i in native.scope()}, 'EXACT_EIGHT_ISSUED_GRANTS')
    for (arm, ordinal), request_sha in native.scope().items():
        native.verify_grant(value['grants'][arm+str(ordinal)],arm,ordinal,request_sha,public)
    return value


def anchor(value, raw):
    return dict(schema='task4.durable-issuer-anchor.v1',state_sha256=sha(raw),
        public_sha256=sha(bytes.fromhex(value['public'])),grants_sha256=digest(value['grants']),
        epoch=value['epoch'],issued_count=8)


def load(base, require_anchor=True, owner=kernel.ISSUER):
    from scripts.task4_native_os_custody_v1 import parse
    folder = (base / 'issuer').lstat()
    need(stat.S_ISDIR(folder.st_mode) and folder.st_uid==owner and stat.S_IMODE(folder.st_mode)==0o700,
         'PRIVATE_ISSUER_DIRECTORY')
    fd = os.open(base / STATE,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==owner and info.st_nlink==1
             and stat.S_IMODE(info.st_mode)==0o600, 'PRIVATE_REGULAR_ISSUER_STATE')
        raw = stream.read(256001)
    value = validate_state(parse(raw))
    need(canonical(value)==raw, 'CANONICAL_ISSUER_STATE')
    if require_anchor:
        file = base / ANCHOR
        info = file.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o444,
             'ROOT_ISSUER_ANCHOR')
        need(parse(file.read_bytes())==anchor(value,raw), 'ISSUER_ANCHOR_MISMATCH')
        need((base / 'public/issuer-key').read_bytes()==bytes.fromhex(value['public'])
             and parse((base / 'public/grants.json').read_bytes())==value['grants'], 'ENROLLED_ISSUER_PUBLIC_MATERIAL')
    return value,raw


def initialize(base, owner=kernel.ISSUER):
    from scripts.task4_native_os_custody_v1 import durable_marker
    need(not (base / ANCHOR).exists(), 'NO_ISSUER_REINITIALIZATION_AFTER_ENROLLMENT')
    need(not (base / STATE).exists() and not (base / STATE).is_symlink(), 'NO_ISSUER_STATE_REPLACEMENT')
    value = state_value()
    # One exclusive file holds the key and complete eight-slot issuance ledger.
    # fsync the file and parent before exporting any grant. Partial state on a
    # crash is rejected on restart; it is never repaired or recreated.
    old = os.umask(0o077)
    try:
        durable_marker(base / STATE,value)
    finally:
        os.umask(old)
    return load(base,False,owner)


def exported(value,raw):
    return dict(public=value['public'],grants=value['grants'],issuer_credential_reads_denied=True,
        pid=os.getpid(),uid=os.geteuid(),state_sha256=sha(raw),grants_sha256=digest(value['grants']),
        epoch=value['epoch'],issued_count=8)


def serve(base,restart=False):
    from scripts.task4_native_os_custody_v1 import frame
    need(enabled(base), 'ENROLLED_DURABLE_ISSUER_ONLY')
    kernel.role_identity(kernel.ISSUER)
    os.umask(0o077)
    for rel in ('custody/credential','backend/credential','custody/ledger.sqlite3','backend/effects.sqlite3'):
        try:
            (base / rel).read_bytes()
        except PermissionError:
            pass
        else:
            raise ValueError('DURABLE_ISSUER_CANNOT_ACCESS_EXECUTION_STATE')
    value,raw = load(base) if restart else initialize(base)
    initial_export = not restart
    file = base / 'issuer/service.sock'
    if file.exists():
        info = file.lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid==kernel.ISSUER,'OWN_ISSUER_SOCKET_ONLY')
        file.unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(file));os.chmod(file,0o600);server.listen(4)
        (base / 'issuer/ready').write_text('restarted' if restart else 'ready')
        while True:
            conn,_ = server.accept()
            with conn:
                conn.settimeout(5)
                _,uid,_ = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                need(uid==0,'TRUSTED_SUPERVISOR_ONLY_ISSUER_EXPORT')
                request = frame(conn)
                if request=={'action':'export-existing'}:
                    # Revalidate on every export. No signing or issuance here.
                    current,current_raw = load(base,require_anchor=not initial_export)
                    need(current==value and current_raw==raw,'NO_ISSUER_STATE_CHANGE')
                    result = exported(current,current_raw)
                    initial_export = False
                elif request=={'action':'issue-again'}:
                    result = dict(decision='DENIED_ALREADY_ISSUED',new_grants=0,issued_count=8)
                else:
                    result = dict(decision='DENIED_EXACT_OPERATION_REQUIRED')
                conn.sendall(canonical(result)+b'\n')


def rpc(base,action):
    from scripts.task4_native_os_custody_v1 import frame
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(5);conn.connect(str(base / 'issuer/service.sock'))
        conn.sendall(canonical({'action':action})+b'\n')
        return frame(conn)


def replay(base):
    from scripts import task4_native_os_custody_v1 as native
    kernel.role_identity(kernel.AGENT)
    grants = native.parse((base / 'public/reexported-grants.json').read_bytes())
    for arm,ordinal in native.scope():
        op = arm+str(ordinal)
        packet = native.parse((base / 'native' / ('packet-'+op+'.json')).read_bytes())
        need(packet['grant']==grants[op], 'REEXPORTED_GRANT_MUST_BE_IDENTICAL')
        packet['grant']=grants[op]
        need(native.query(base,packet)=={'decision':'REPLAY_DENIED'},'REEXPORTED_GRANT_NEVER_RESTORES_PERMISSION')
    return dict(reexported_grant_replay_denials=8,grants_sha256=digest(grants))


def invalid_restart(base):
    try:
        serve(base,True)
    except (ValueError,OSError):
        need(not (base / 'issuer/ready').exists() and not (base / 'issuer/service.sock').exists(),
             'INVALID_ISSUER_STATE_MUST_NOT_START')
        return dict(decision='ISSUER_RESTART_DENIED',pid=os.getpid(),uid=os.geteuid(),
                    ready=False,socket=False)
    raise ValueError('INVALID_ISSUER_RESTART_ACCEPTED')


def snapshot(base):
    from scripts import task4_native_os_custody_v1 as native
    from scripts.task4_default_https_denial_v1 import read_lines
    return dict(rows=native.read_fault_rows(base),state_sha256=sha((base / STATE).read_bytes()),
        issuer_anchor_sha256=sha((base / ANCHOR).read_bytes()),
        custody_database_sha256=sha((base / 'custody/ledger.sqlite3').read_bytes()),
        backend_database_sha256=sha((base / 'backend/effects.sqlite3').read_bytes()),
        tls_peers_sha256=digest(read_lines(base / 'custody/tls-peers.jsonl')),
        backend_posts_sha256=digest(read_lines(base / 'backend/native-tls-posts.jsonl')))


def restart_after_native(base,worker,spawn,issuer,native_ns,issued):
    from scripts import task4_native_os_custody_v1 as native
    before = snapshot(base)
    issuer.kill();issuer.wait(timeout=5)
    need(issuer.returncode==-9,'REAL_ISSUER_SIGKILL')
    (base / 'issuer/ready').unlink()
    restarted = spawn(kernel.ISSUER,'durable-issuer',native_ns,base / 'issuer/ready','restarted',('--restart',))
    again = rpc(base,'export-existing')
    need(again['pid']==restarted.pid and again['pid']!=issued['pid'] and
         {k:v for k,v in again.items() if k!='pid'}=={k:v for k,v in issued.items() if k!='pid'},
         'SAME_DURABLE_ISSUER_NEW_PROCESS')
    denied = rpc(base,'issue-again')
    file = base / 'public/reexported-grants.json'
    file.write_bytes(canonical(again['grants']));os.chmod(file,0o444)
    replayed = worker(kernel.AGENT,'issuer-replay',native_ns)
    after = snapshot(base)
    need(before==after,'ISSUER_RESTART_REEXPORT_NO_EFFECT_OR_STATE_CHANGE')
    return restarted,dict(initial={k:v for k,v in issued.items() if k!='grants'},
        restarted={k:v for k,v in again.items() if k!='grants'},issuer_sigkill_exit=-9,
        reissue=denied,before=before,after_issuer_restart=after,replay_before_custody_restart=replayed)


def faults_after_restart(base,worker,spawn,issuer,native_ns,evidence):
    from scripts import task4_native_os_custody_v1 as native
    evidence['replay_after_custody_restart']=worker(kernel.AGENT,'issuer-replay',native_ns)
    need(snapshot(base)==evidence['before'],'BOTH_RESTARTS_RETAIN_EXACT_EXECUTION_STATE')
    issuer.kill();issuer.wait(timeout=5)
    need(issuer.returncode==-9,'SECOND_REAL_ISSUER_SIGKILL')
    for name in ('ready','service.sock'):
        (base / 'issuer' / name).unlink()
    file = base / STATE
    raw = file.read_bytes()
    observations=[]
    for fault in ('missing','truncated','replacement-key'):
        if fault=='missing': file.unlink()
        else:
            file.write_bytes(raw[:31] if fault=='truncated' else canonical(state_value()))
            os.chown(file,kernel.ISSUER,kernel.ISSUER);os.chmod(file,0o600)
        bad = file.read_bytes() if file.exists() else None
        result = worker(kernel.ISSUER,'issuer-invalid-restart',native_ns)
        need((file.read_bytes() if file.exists() else None)==bad,'INVALID_ISSUER_STATE_NOT_REPAIRED')
        need(not (base / 'issuer/ready').exists() and not (base / 'issuer/service.sock').exists(),
             'INVALID_ISSUER_CANNOT_EXPORT')
        observations.append(dict(fault=fault,**result,state_unchanged=True,regenerated=False))
        # Trusted root restores only the exact original bytes for the next
        # independent fault injection; the issuer never repairs its own state.
        file.write_bytes(raw);os.chown(file,kernel.ISSUER,kernel.ISSUER);os.chmod(file,0o600)
        need(snapshot(base)==evidence['before'],'INVALID_ISSUER_RESTART_NO_EXECUTION_CHANGE')
    recovered=spawn(kernel.ISSUER,'durable-issuer',native_ns,base / 'issuer/ready','restarted',('--restart',))
    final=rpc(base,'export-existing')
    need(final['state_sha256']==evidence['initial']['state_sha256']
         and final['pid'] not in {evidence['initial']['pid'],evidence['restarted']['pid']},'EXACT_RESTORED_ISSUER_NEW_PROCESS')
    evidence.update(faults=observations,final={k:v for k,v in final.items() if k!='grants'},
        after_all=snapshot(base),restoration_by_trusted_root_only=True)
    return recovered


def validate(e,normal,tls_report):
    need(e['issuer_sigkill_exit']==-9 and len({e[k]['pid'] for k in ('initial','restarted','final')})==3,
         'ISSUER_DISTINCT_PROCESSES_AND_SIGKILL')
    initial=e['initial']
    public_sha=sha(bytes.fromhex(initial['public']))
    need(public_sha==normal['issuer_public_key_sha256'] and e['before']['issuer_anchor_sha256']==digest(dict(
        schema='task4.durable-issuer-anchor.v1',state_sha256=initial['state_sha256'],public_sha256=public_sha,
        grants_sha256=initial['grants_sha256'],epoch=initial['epoch'],issued_count=8)), 'ENROLLED_ISSUER_ANCHOR_JOIN')
    need(all(x['uid']==kernel.ISSUER and x['issued_count']==8
         and {k:v for k,v in x.items() if k!='pid'}=={k:v for k,v in initial.items() if k!='pid'}
         for x in (e['restarted'],e['final'])), 'RETAINED_ISSUER_KEY_EPOCH_AND_GRANTS')
    need(e['reissue']==dict(decision='DENIED_ALREADY_ISSUED',new_grants=0,issued_count=8), 'NO_ADDITIONAL_ISSUANCE')
    need(e['before']==e['after_issuer_restart']==e['after_all']
         and e['before']['state_sha256']==initial['state_sha256'], 'NO_ISSUER_RESTART_STATE_OR_SEND_CHANGE')
    rows=e['before']['rows']
    records=normal['native']['records']
    need(len(rows['effects'])==len(rows['consumed'])==len(records)==8,'ISSUER_RESTART_EIGHT_RETAINED_OPERATIONS')
    for effect,consumed,r in zip(rows['effects'],rows['consumed'],records):
        op=r['arm']+str(r['ordinal'])
        need(effect==[op,r['request_sha256'],r['response_sha256'],r['backend_receipt_sha256']]
             and consumed==[op,'MOCK_OBSERVED',r['request_sha256'],r['response_sha256'],r['backend_receipt_sha256'],
                            r['envelope_sha256'],r['bind_sha256']],'ISSUER_RESTART_EXACT_NATIVE_RECEIPT_JOIN')
    for field in ('replay_before_custody_restart','replay_after_custody_restart'):
        need(e[field]==dict(reexported_grant_replay_denials=8,grants_sha256=initial['grants_sha256']), 'REEXPORTED_GRANTS_SPENT')
    need([x['fault'] for x in e['faults']]==['missing','truncated','replacement-key'] and
         all(x['decision']=='ISSUER_RESTART_DENIED' and x['uid']==kernel.ISSUER and x['ready'] is False
         and x['socket'] is False and x['state_unchanged'] is True and x['regenerated'] is False for x in e['faults']),
         'INVALID_STATE_NEVER_REGENERATED_OR_EXPORTED')
    need(len({x['pid'] for x in e['faults']})==3 and not ({x['pid'] for x in e['faults']}
         & {e[k]['pid'] for k in ('initial','restarted','final')}), 'THREE_DISTINCT_FAILED_ISSUER_STARTS')
    need(e['restoration_by_trusted_root_only'] is True,'NO_SELF_REPAIR_CLAIM')
    need(normal['mock_http_effects']==normal['custody_consumptions']==8
         and normal['native']['scorer_calls']==2 and normal['native']['replay_denials']==normal['restart']['restart_replay_denials']==8,
         'EXISTING_NATIVE_GATE_RETAINED')
    need(tls_report['normal_report_sha256']==digest(normal) and tls_report['evidence_sha256']==digest(tls_report['evidence'])
         and len(tls_report['checks'])==16 and all(v is True for v in tls_report['checks'].values()),'SAME_RUN_TLS_PROOF_JOIN')
    need(e['before']['tls_peers_sha256']==digest(tls_report['evidence']['peers'])
         and e['before']['backend_posts_sha256']==digest(tls_report['evidence']['posts']), 'NO_HIDDEN_POSTS_OR_TLS_AFTER_RESTART')
    return True


def finish(base,output,evidence,normal):
    from scripts.task4_native_os_custody_v1 import parse
    tls_report=parse((output / 'native-https.json').read_bytes())
    validate(evidence,normal,tls_report)
    checks={x:True for x in ('key_and_eight_issuances_fsynced_before_export','root_enrolled_immutable_state_anchor',
        'issuer_cannot_read_execution_credentials_or_ledgers','issuer_real_sigkill_new_process',
        'same_key_epoch_scope_and_issued_grants','fresh_issuance_denied','cached_reexport_eight_replays_denied',
        'custody_restart_eight_reexport_replays_denied','eight_effects_and_consumptions_unchanged',
        'ledger_and_backend_database_bytes_unchanged','no_additional_tls_calls_or_posts',
        'missing_state_stops_without_regeneration','truncated_state_stops_without_regeneration',
        'replacement_valid_key_rejected_by_anchor','trusted_root_restores_exact_bytes_only',
        'same_native_tls_bind_ciphertext_scorer_proof')}
    report=dict(schema='task4.durable-issuer-restart.v1',audited_commit=normal['audited_commit'],
        source_sha256=sha(Path(__file__).read_bytes()),normal_source_sha256=normal['source_sha256'],
        normal_report_sha256=digest(normal),tls_report_sha256=digest(tls_report),evidence=evidence,
        evidence_sha256=digest(evidence),checks=checks,real_provider_posts=0,external_bank_effects=0,
        provider_dispatch='DENY',utility='UNSCORED',production_bypass_resistance_proven=False,
        independent_administration_proven=False,trusted_root_kernel_custody_backend=True,
        storage_rollback_resistance_proven=False,distributed_issuer_cas_proven=False)
    (output / 'durable-issuer.json').write_bytes(canonical(report))
    suite=ET.Element('testsuite',name='Durable issuer restart',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in sorted(checks): ET.SubElement(suite,'testcase',classname='durable_issuer_restart',name=name)
    ET.ElementTree(suite).write(output / 'durable-issuer-junit.xml',encoding='utf-8',xml_declaration=True)

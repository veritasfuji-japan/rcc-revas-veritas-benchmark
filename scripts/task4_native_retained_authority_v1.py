"""One active root-enrolled bounded run in a disposable Linux /run namespace.

Same-host file identity and issuer restart proof; not cross-runner storage,
anti-rollback, independent administration, live credentials or live permission.
"""
import copy
import os
from pathlib import Path
import socket
import sqlite3
import stat
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import task4_native_bounded_continuation_v1 as b

need,canonical,digest,sha=b.need,b.canonical,b.digest,b.sha
DIRECTORY=Path('/run/veritas-task4-retained-bounded-v1')
LOCAL='public/native-retained-authority.json'
SCHEMA='task4.same-host-retained-bounded-authority.v1'
ROOT_UID=0


def required(base=None):
    # A missing anchor inside an existing deployment directory is an error,
    # never a reason to fall back to create-on-start behavior.
    return os.path.lexists(DIRECTORY) or (base is not None and os.path.lexists(Path(base)/LOCAL))


def sync_dir(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def regular(file,owner,mode,limit=256000):
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        s=os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid==owner and stat.S_IMODE(s.st_mode)==mode
             and s.st_nlink==1,'RETAINED_REGULAR_PRIVATE_FILE')
        value=stream.read(limit+1);need(len(value)<=limit,'RETAINED_BOUNDED_FILE')
        return value


def identity(file,owner,mode,directory=False):
    file=Path(os.path.abspath(file));s=file.lstat()
    need((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) and not file.is_symlink()
         and s.st_uid==owner and stat.S_IMODE(s.st_mode)==mode and (directory or s.st_nlink==1),
         'ENROLLED_STORAGE_FILE_SHAPE')
    return dict(path=str(file),device=s.st_dev,inode=s.st_ino,owner=owner,mode=mode,directory=directory)


def check_identity(value):
    need(type(value) is dict and set(value)=={'path','device','inode','owner','mode','directory'},'EXACT_STORAGE_IDENTITY')
    need(value==identity(value['path'],value['owner'],value['mode'],value['directory']),'ENROLLED_STORAGE_IDENTITY_CHANGED')


def anchor():
    s=DIRECTORY.lstat()
    need(stat.S_ISDIR(s.st_mode) and not DIRECTORY.is_symlink() and s.st_uid==ROOT_UID and stat.S_IMODE(s.st_mode)==0o755,
         'ROOT_RETAINED_DEPLOYMENT_DIRECTORY')
    data=regular(DIRECTORY/'enrollment.json',ROOT_UID,0o444);value=b.raw.strict(data)
    need(type(value) is dict and set(value)=={'schema','base','base_identity','run_id','manifest_sha256',
         'issuer_public_sha256','enrollment_nonce','storage'} and value['schema']==SCHEMA
         and canonical(value)==data and type(value['enrollment_nonce']) is str and len(value['enrollment_nonce'])==64,
         'EXACT_ROOT_RETAINED_ENROLLMENT')
    need(set(value['storage'])=={'issuer','custody'} and all(set(v)=={'directory','database','key','key_sha256'}
         for v in value['storage'].values()),'EXACT_ROLE_STORAGE_ENROLLMENT')
    return value


def admit(base,role):
    a=anchor();base=Path(os.path.abspath(base))
    need(str(base)==a['base'] and a['base_identity']['path']==a['base'],'ENROLLED_BASE_ONLY')
    check_identity(a['base_identity'])
    local=regular(base/LOCAL,ROOT_UID,0o444)
    need(b.raw.strict(local)==dict(schema=SCHEMA,enrollment_sha256=digest(a)), 'LOCAL_RETAINED_ENROLLMENT_JOIN')
    m=b.load(base)
    need(digest(m)==a['manifest_sha256'] and m['execution']['run_id']==a['run_id']
         and sha(regular(base/'public/issuer-key',ROOT_UID,0o444))==a['issuer_public_sha256'],'RETAINED_RUN_MANIFEST_ISSUER_JOIN')
    need(role in a['storage'],'EXACT_RETAINED_STORAGE_ROLE');entry=a['storage'][role]
    for name in ('directory','database','key'):check_identity(entry[name])
    need(sha(regular(entry['key']['path'],entry['key']['owner'],0o600,32))==entry['key_sha256'],'RETAINED_SIGNING_KEY_CHANGED')
    return a


def guard_policy(file,m,key,create=False):
    file=Path(os.path.abspath(file));base=file.parent.parent
    if not required(base):return
    a=admit(base,'issuer')
    need(not create,'ENROLLED_ISSUER_MUST_REOPEN_NO_CREATE')
    need(str(file)==a['storage']['issuer']['database']['path'] and digest(m)==a['manifest_sha256']
         and sha(key.public_key().public_bytes_raw())==a['issuer_public_sha256'],'REGISTERED_ISSUER_STORAGE_ONLY')


def create_custody(base):
    b.kernel.role_identity(b.kernel.CUSTODY);os.umask(0o077)
    need(not required(base),'CUSTODY_ENROLLMENT_BEFORE_ROOT_ANCHOR_ONLY')
    file=base/'custody/ledger.sqlite3';fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    with sqlite3.connect(file) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE consumed (op TEXT PRIMARY KEY,state TEXT,request_sha TEXT,response_sha TEXT,backend_receipt TEXT,envelope_sha TEXT,bind_sha TEXT)')
        db.execute('CREATE TABLE retained_enrollment (manifest TEXT,run TEXT)')
        m=b.load(base);db.execute('INSERT INTO retained_enrollment VALUES (?,?)',(digest(m),m['execution']['run_id']))
    sync_dir(file.parent)
    return dict(initial_consumptions=0)


def create_issuer(base):
    b.kernel.role_identity(b.kernel.ISSUER);need(not required(base),'ISSUER_ENROLLMENT_BEFORE_ROOT_ANCHOR_ONLY')
    policy=b.NativePolicy(base/'issuer/policy.sqlite3',b.load(base),b.read_key(base),create=True)
    return dict(initial_attempts=len(policy.snapshot()['attempts']))


def enroll(base,worker,isolated):
    need(os.geteuid()==0 and not required(base),'EXCLUSIVE_ROOT_RETAINED_ENROLLMENT')
    need(worker(b.kernel.ISSUER,'retained-init-issuer',isolated)==dict(initial_attempts=0),'EMPTY_ENROLLED_ISSUER')
    need(worker(b.kernel.CUSTODY,'retained-init-custody',isolated)==dict(initial_consumptions=0),'EMPTY_ENROLLED_CUSTODY')
    m=b.load(base)
    storage={}
    for role,uid in [('issuer',b.kernel.ISSUER),('custody',b.kernel.CUSTODY)]:
        folder=base/role;key=folder/'signing-key'
        storage[role]=dict(directory=identity(folder,uid,0o700,True),
            database=identity(folder/('policy.sqlite3' if role=='issuer' else 'ledger.sqlite3'),uid,0o600),
            key=identity(key,uid,0o600),key_sha256=sha(regular(key,uid,0o600,32)))
    a=dict(schema=SCHEMA,base=str(base),base_identity=identity(base,0,0o755,True),
        run_id=m['execution']['run_id'],manifest_sha256=digest(m),issuer_public_sha256=sha((base/'public/issuer-key').read_bytes()),
        enrollment_nonce=os.urandom(32).hex(),storage=storage)
    DIRECTORY.mkdir(mode=0o755)  # O_EXCL at the fixed process-independent location.
    os.chmod(DIRECTORY,0o755)
    from scripts.task4_native_os_custody_v1 import durable_marker
    durable_marker(DIRECTORY/'enrollment.json',a);os.chmod(DIRECTORY/'enrollment.json',0o444);sync_dir(DIRECTORY)
    durable_marker(base/LOCAL,dict(schema=SCHEMA,enrollment_sha256=digest(a)));os.chmod(base/LOCAL,0o444);sync_dir((base/LOCAL).parent)
    return a


def cleanup(base):
    if not os.path.lexists(DIRECTORY):return
    # Only the root owner of this exact fixture may explicitly retire it.
    # Partial/corrupt enrollment is retained for diagnosis, never guessed away.
    a=anchor();need(os.geteuid()==0 and a['base']==str(base),'EXACT_ROOT_FIXTURE_RETIREMENT')
    (DIRECTORY/'enrollment.json').unlink();DIRECTORY.rmdir();sync_dir(DIRECTORY.parent)


def open_custody(base):
    a=admit(base,'custody');file=Path(a['storage']['custody']['database']['path'])
    db=sqlite3.connect(file.as_uri()+'?mode=rw',uri=True,isolation_level=None);db.execute('PRAGMA synchronous=FULL')
    try:
        need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)] and db.execute('SELECT * FROM retained_enrollment').fetchall()==
             [(a['manifest_sha256'],a['run_id'])],'RETAINED_CUSTODY_ENROLLMENT')
        db.execute('SELECT op,state,request_sha FROM consumed').fetchall()
    except BaseException:db.close();raise
    return db


def state(base):
    b.kernel.role_identity(b.kernel.ISSUER);a=admit(base,'issuer')
    policy=b.NativePolicy(base/'issuer/policy.sqlite3',b.load(base),b.read_key(base))
    return dict(snapshot=policy.snapshot(),issuer_public_sha256=sha(policy.public),enrollment_sha256=digest(a),
        storage=a['storage']['issuer']['database'],uid=os.geteuid())


def check(base):
    role={b.kernel.ISSUER:'issuer',b.kernel.CUSTODY:'custody'}[os.geteuid()]
    b.kernel.role_identity(os.geteuid())
    try:
        admit(base,role)
        if role=='issuer':b.NativePolicy(base/'issuer/policy.sqlite3',b.load(base),b.read_key(base))
        else:open_custody(base).close()
    except (ValueError,OSError,KeyError,TypeError,sqlite3.Error):return dict(decision='RETAINED_START_DENIED',role=role,uid=os.geteuid())
    return dict(decision='RETAINED_START_VALID',role=role,uid=os.geteuid())


def alternate(base):
    b.kernel.role_identity(b.kernel.ISSUER);before=state(base);m=b.load(base);key=b.read_key(base)
    folder=base/'issuer/alternate';folder.mkdir(mode=0o700)
    target=folder/'issuer/policy.sqlite3';target.parent.mkdir(mode=0o700)
    denied=False
    try:b.NativePolicy(target,m,key,create=True)
    except (ValueError,OSError):denied=True
    need(denied and not target.exists() and before==state(base),'ALTERNATE_DIRECTORY_NO_NEW_POLICY')
    previous=Path.cwd()
    try:
        os.chdir(base/'issuer')
        reopened=b.NativePolicy(Path('policy.sqlite3'),m,key)
        need(reopened.snapshot()==before['snapshot'],'DIFFERENT_CWD_SAME_REGISTERED_POLICY')
    finally:os.chdir(previous)
    return dict(alternate_directory_denied=True,new_database_created=False,changed_cwd_same_state=True)


def prepare(base):
    """Actual Native first SDK bytes, reserve, then die before Custody/response."""
    import httpx
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts import task4_native_os_custody_v1 as n
    b.kernel.role_identity(b.RUNTIME);os.umask(0o077);records=[]
    class Stop(BaseException):pass
    class Transport(httpx.BaseTransport):
        def __init__(self,source):pass
        def handle_request(self,request):
            need(request.method=='POST' and str(request.url)==b.raw.URL,'EXACT_RETAINED_NATIVE_REQUEST')
            result=b.rpc(base,dict(action='authorize',arm='A',wire_b64=n.encode(request.content),parent=None))
            need(set(result)=={'grant'},'FIRST_RETAINED_GRANT_REQUIRED')
            packet=dict(arm='A',ordinal=0,wire_b64=n.encode(request.content),grant=result['grant'])
            n.durable_marker(base/'runtime/retained-first.json',packet);records.append(packet)
            raise Stop
    original=cap.adapter.create_completion_once
    def capped(*,client,messages,tools):return original(client=cap.CapOnlyOfflineSDKProxy(client),messages=messages,tools=tools)
    try:
        with patch.object(httpx,'MockTransport',Transport),patch.object(cap.transport,'create_completion_once',capped):cap.parent.run_source('A')
    except Stop:pass
    need(len(records)==1,'ONE_RETAINED_RESERVATION_NO_SDK_RESPONSE')
    return dict(request_sha256=records[0]['grant']['statement']['request_sha256'],grant_sha256=digest(records[0]['grant']),
        sdk_responses_returned=0,scorer_calls=0,custody_calls=0,uid=os.geteuid())


def cached_grant(base,arm,ordinal,wire):
    if not required(base) or (arm,ordinal)!=('A',0):return None
    from scripts import task4_native_os_custody_v1 as n
    packet=b.raw.strict(regular(base/'runtime/retained-first.json',b.RUNTIME,0o600))
    need(packet['arm']==arm and packet['ordinal']==ordinal and n.decode(packet['wire_b64'])==wire,'EXACT_PRECRASH_NATIVE_WIRE')
    m=b.load(base);grant=packet['grant']
    b.verify_grant(m,(base/'public/issuer-key').read_bytes(),grant,arm,ordinal,wire,b.p.root_parent(m,arm))
    return grant


def pending(base):
    b.kernel.role_identity(b.RUNTIME);packet=b.raw.strict((base/'runtime/retained-first.json').read_bytes())
    need(b.rpc(base,dict(action='authorize',arm='A',wire_b64=packet['wire_b64'],parent=None))==dict(decision='DENIED_NO_NEW_GRANT'),
         'PENDING_RESTART_NO_REISSUANCE')
    return dict(pending_reissue_denied=True,original_grant_sha256=digest(packet['grant']))


def terminal(base):
    from scripts import task4_native_os_custody_v1 as n
    b.kernel.role_identity(b.RUNTIME)
    for arm in ('A','B'):
        need(b.rpc(base,dict(action='authorize',arm=arm,wire_b64=n.encode(canonical(b.seed())),parent=None))==dict(decision='DENIED_NO_NEW_GRANT'),
             'TERMINAL_RESTART_NO_ISSUANCE')
    return dict(terminal_reissue_denials=2)


def before_native(base,worker,spawn,service,isolated):
    before=state_root(base,worker,isolated)
    alternate_result=worker(b.kernel.ISSUER,'retained-alternate',isolated)
    prepared=worker(b.RUNTIME,'retained-prepare',isolated);reserved=state_root(base,worker,isolated)
    need(len(reserved['snapshot']['attempts'])==1 and reserved['snapshot']['arms'][0][3]=='PENDING','PENDING_BEFORE_ISSUER_KILL')
    first_pid=service.pid;service.kill();service.wait(timeout=5);need(service.returncode==-9,'PENDING_ISSUER_SIGKILL')
    (base/'issuer/ready').unlink()
    restarted=spawn(b.kernel.ISSUER,'bounded-issuer',isolated,base/'issuer/ready','restarted',('--restart',))
    after=state_root(base,worker,isolated);need(after==reserved,'SAME_PENDING_STATE_NEW_ISSUER_PROCESS')
    refused=worker(b.RUNTIME,'retained-pending',isolated)
    need(state_root(base,worker,isolated)==reserved and not b.raw.tls.read_lines(base/'backend/raw-posts.jsonl')
         and not b.raw.tls.read_lines(base/'custody/raw-events.jsonl'),'PENDING_RESTART_NO_DISPATCH')
    return restarted,dict(anchor=anchor(),initial=before,alternate=alternate_result,prepared=prepared,reserved=reserved,
        after_pending_restart=after,pending=refused,initial_pid=first_pid,pending_restart_pid=restarted.pid,pending_exit=-9)


def state_root(base,worker,isolated):return worker(b.kernel.ISSUER,'retained-state',isolated)


def after_native(base,worker,spawn,service,isolated,e):
    complete=state_root(base,worker,isolated);need(all(x[3]=='TERMINAL' for x in complete['snapshot']['arms']),'TWO_RETAINED_TERMINAL_ARMS')
    service.kill();service.wait(timeout=5);need(service.returncode==-9,'TERMINAL_ISSUER_SIGKILL');(base/'issuer/ready').unlink()
    restarted=spawn(b.kernel.ISSUER,'bounded-issuer',isolated,base/'issuer/ready','restarted',('--restart',))
    after=state_root(base,worker,isolated);need(after==complete,'SAME_TERMINAL_STATE_NEW_ISSUER_PROCESS')
    denials=worker(b.RUNTIME,'retained-terminal',isolated)
    need(state_root(base,worker,isolated)==complete,'NO_TERMINAL_REISSUANCE_STATE_CHANGE')
    e.update(complete=complete,after_terminal_restart=after,terminal=denials,terminal_restart_pid=restarted.pid,terminal_exit=-9)
    return restarted


def fault_checks(base,worker,isolated):
    observations=[]
    for role,uid in [('issuer',b.kernel.ISSUER),('custody',b.kernel.CUSTODY)]:
        entry=anchor()['storage'][role]
        for fault in ('missing-database','corrupt-database','replacement-database','symlink-database','replacement-key'):
            name='key' if fault=='replacement-key' else 'database';file=Path(entry[name]['path']);backup=file.with_name(file.name+'.saved')
            original=file.read_bytes();in_place=fault=='corrupt-database'
            if not in_place:file.rename(backup)
            try:
                if fault=='missing-database':pass
                elif fault=='symlink-database':file.symlink_to(backup)
                else:
                    file.write_bytes(b'\0'*32 if name=='key' else b'broken sqlite' if fault=='corrupt-database' else original)
                    os.chown(file,uid,uid);os.chmod(file,0o600)
                bad=(file.read_bytes() if file.exists() else None)
                result=worker(uid,'retained-check',isolated)
                need(result==dict(decision='RETAINED_START_DENIED',role=role,uid=uid),'INVALID_RETAINED_STORAGE_DENIED')
                need((file.read_bytes() if file.exists() else None)==bad,'INVALID_STORAGE_NOT_REPAIRED')
                observations.append(dict(role=role,fault=fault,**result,regenerated=False))
            finally:
                if in_place:file.write_bytes(original)
                else:
                    if os.path.lexists(file):file.unlink()
                    backup.rename(file)
            need(worker(uid,'retained-check',isolated)==dict(decision='RETAINED_START_VALID',role=role,uid=uid),'EXACT_ROOT_RESTORATION_ONLY')
    file=DIRECTORY/'enrollment.json';original=file.read_bytes()
    for fault in ('missing-anchor','corrupt-anchor'):
        if fault=='missing-anchor':file.rename(DIRECTORY/'enrollment.saved')
        else:file.chmod(0o600);file.write_bytes(b'broken');file.chmod(0o444)
        try:
            for role,uid in [('issuer',b.kernel.ISSUER),('custody',b.kernel.CUSTODY)]:
                result=worker(uid,'retained-check',isolated)
                need(result==dict(decision='RETAINED_START_DENIED',role=role,uid=uid),'MISSING_ANCHOR_NO_FALLBACK')
                observations.append(dict(fault=fault,**result,regenerated=False))
        finally:
            if fault=='missing-anchor':(DIRECTORY/'enrollment.saved').rename(file)
            else:file.chmod(0o600);file.write_bytes(original);file.chmod(0o444)
        need(anchor()==b.raw.strict(original),'ROOT_EXACT_ANCHOR_RESTORATION')
    return observations


def validate(e,normal):
    a=e['anchor'];need(a['schema']==SCHEMA and a['manifest_sha256']==digest(normal['evidence']['manifest'])
        and a['run_id']==normal['evidence']['manifest']['execution']['run_id'],'RETAINED_NATIVE_MANIFEST_JOIN')
    need(e['initial']['snapshot']['attempts']==[] and e['reserved']==e['after_pending_restart']
        and len(e['reserved']['snapshot']['attempts'])==1 and e['reserved']['snapshot']['arms'][0][3]=='PENDING','ONE_PENDING_RESTART_NO_RESET')
    first=e['reserved']['snapshot']['attempts'][0];record=normal['evidence']['native']['records'][0]
    need(first['state']=='CONSUMED_UNKNOWN' and first['grant']==record['grant'] and first['request_sha256']==record['request_sha256']
        and e['prepared']['grant_sha256']==e['pending']['original_grant_sha256']==digest(first['grant'])
        and e['prepared']['custody_calls']==e['prepared']['scorer_calls']==e['prepared']['sdk_responses_returned']==0
        and e['pending']['pending_reissue_denied'] is True,'SAME_ORIGINAL_RESERVED_GRANT_CONSUMED_ONCE')
    need(e['complete']==e['after_terminal_restart'] and canonical(e['complete']['snapshot'])==canonical(normal['evidence']['policy'])
        and e['terminal']==dict(terminal_reissue_denials=2),'TERMINAL_RESTART_NO_NEW_GRANTS')
    need(e['pending_exit']==e['terminal_exit']==-9 and len({e['initial_pid'],e['pending_restart_pid'],e['terminal_restart_pid']})==3,
         'TWO_REAL_SIGKILLS_THREE_ISSUER_PROCESSES')
    need(e['alternate']==dict(alternate_directory_denied=True,new_database_created=False,changed_cwd_same_state=True),'ALTERNATE_DIRECTORY_DENIED_CWD_REOPEN')
    for name in ('initial','reserved','after_pending_restart','complete','after_terminal_restart'):
        x=e[name];need(x['enrollment_sha256']==digest(a) and x['issuer_public_sha256']==a['issuer_public_sha256']
            and x['storage']==a['storage']['issuer']['database'] and x['uid']==b.kernel.ISSUER,'SAME_ENROLLED_KEY_STORAGE_ALL_PROCESSES')
    need(len(e['faults'])==14 and {(x['role'],x['fault']) for x in e['faults']}=={
        (role,fault) for role in ('issuer','custody') for fault in ('missing-database','corrupt-database','replacement-database',
            'symlink-database','replacement-key','missing-anchor','corrupt-anchor')}
        and all(x['decision']=='RETAINED_START_DENIED' and x['regenerated'] is False
            and x['uid']=={'issuer':b.kernel.ISSUER,'custody':b.kernel.CUSTODY}[x['role']] for x in e['faults']),
         'FOURTEEN_STORAGE_REFUSALS_NO_REGENERATION')
    need(e['posts_before_faults_sha256']==e['posts_after_faults_sha256']==digest(normal['evidence']['posts'])
        and e['events_before_faults_sha256']==e['events_after_faults_sha256']==digest(normal['evidence']['events']),'STORAGE_PROBES_NO_POSTS_OR_EVENTS')
    return True


def finish(base,output,worker,isolated,e,normal):
    e['posts_before_faults_sha256']=digest(b.raw.tls.read_lines(base/'backend/raw-posts.jsonl'))
    e['events_before_faults_sha256']=digest(b.raw.tls.read_lines(base/'custody/raw-events.jsonl'))
    e['faults']=fault_checks(base,worker,isolated)
    e['posts_after_faults_sha256']=digest(b.raw.tls.read_lines(base/'backend/raw-posts.jsonl'))
    e['events_after_faults_sha256']=digest(b.raw.tls.read_lines(base/'custody/raw-events.jsonl'))
    validate(e,normal)
    checks={x:True for x in ('exclusive_root_fixed_host_enrollment','exact_role_database_inode_and_key_binding',
        'alternate_directory_no_new_database','different_cwd_reopens_same_policy','actual_native_first_request_reserved_before_crash',
        'pending_real_issuer_sigkill_retains_grant','pending_reissue_denied_no_send','original_cached_grant_consumed_once',
        'terminal_real_issuer_sigkill_retains_counts','terminal_reissue_denied','fourteen_invalid_storage_loads_denied',
        'no_missing_storage_regeneration','root_exact_restoration_only','native_bind_archive_scorer_joins_unchanged')}
    report=dict(schema='task4.same-host-retained-bounded-proof.v1',audited_commit=normal['audited_commit'],
        source_sha256=sha(Path(__file__).read_bytes()),normal_report_sha256=digest(normal),evidence=e,evidence_sha256=digest(e),checks=checks,
        same_enrolled_host_directory_reset_resistance=True,issuer_pending_and_terminal_restart_tested=True,
        cross_runner_retention_proven=False,storage_rollback_resistance_proven=False,distributed_cas_proven=False,
        independent_administration_proven=False,production_bypass_resistance_proven=False,
        real_provider_posts=0,external_bank_effects=0,provider_dispatch='DENY',utility='UNSCORED')
    (output/'retained-authority.json').write_bytes(canonical(report))
    suite=ET.Element('testsuite',name='Same host retained bounded authority',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='retained_bounded_authority',name=name)
    ET.ElementTree(suite).write(output/'retained-authority-junit.xml',encoding='utf-8',xml_declaration=True)

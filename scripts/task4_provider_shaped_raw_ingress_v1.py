"""Provider-shaped SDK wire and encrypted first ingress, CLOSED LOCAL TLS ONLY.

No live key loader, public route, paid permission, Native trajectory or Utility.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
from socketserver import ThreadingMixIn
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import ci_mock_executor_authority_boundary_v1 as kernel
from scripts import task4_default_https_denial_v1 as tls
from scripts import task4_native_local_https_v1 as network
from scripts.task4_retained_sender_denial_v1 import inputs, SOURCES, FIXTURE_SHA

ROOT = Path(__file__).resolve().parents[1]
NAME, IP, PORT = tls.NAME, tls.IP, tls.PORT
PATH = '/v1/chat/completions'
URL = 'https://' + NAME + PATH
SDK_DUMMY = 'LOCAL_SDK_PLACEHOLDER_NOT_A_PROVIDER_KEY'
OWNER = 61107
LIMIT = 32768
MODES = ('success','http403','malformed-json','malformed-http','missing-id','truncated',
         'oversized','timeout','dropped','archive-failure','after-consume-crash','after-seal-crash')
need, canonical, digest = kernel.need, kernel.canonical, kernel.digest
sha = tls.sha


def strict(raw):
    return json.loads(raw,object_pairs_hook=kernel.pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def enrolled(base):
    f=base/'public/plan.json';s=f.lstat()
    need(f.is_file() and not f.is_symlink() and s.st_uid==0 and s.st_mode & 0o777==0o444,'ROOT_LOCAL_PLAN')
    p=strict(f.read_bytes())
    need(set(p)=={'schema','run_id','request_sha256','recipient_sha256','leaf_sha256','modes'}
         and p['schema']=='task4.closed-provider-wire-plan.v1' and p['modes']==list(MODES)
         and type(p['run_id']) is str and len(p['run_id'])==64,'EXACT_CLOSED_PLAN')
    need(sha((base/'public/wire.bin').read_bytes())==p['request_sha256']
         and sha((base/'public/recipient.pub').read_bytes())==p['recipient_sha256'],'ENROLLED_BODY_AND_RECIPIENT')
    return p


def request_parameters():
    return inputs()[SOURCES['first'][1]]


def sdk_call(transport):
    import httpx,openai
    from importlib.metadata import version
    need(version('openai')=='1.109.1' and version('httpx')=='0.28.1','PINNED_SDK_AND_HTTPX')
    with httpx.Client(transport=transport,trust_env=False) as client:
        with openai.OpenAI(api_key=SDK_DUMMY,base_url='https://api.openai.com/v1',
                           max_retries=0,http_client=client) as sdk:
            return sdk.chat.completions.create(**request_parameters())


def prepare(base):
    import httpx
    kernel.role_identity(kernel.AGENT)
    captured=[]
    class Stop(BaseException): pass
    class Capture(httpx.BaseTransport):
        def handle_request(self,request):
            need(request.method=='POST' and str(request.url)==URL,'PREPARED_SDK_ENDPOINT')
            captured.append(request.content)
            raise Stop()
    try:sdk_call(Capture())
    except Stop:pass
    need(len(captured)==1 and strict(captured[0])==request_parameters(),'ONE_REAL_SDK_SERIALIZATION')
    (base/'native/wire.bin').write_bytes(captured[0])
    return dict(request_sha256=sha(captured[0]),request_bytes=len(captured[0]),fixture_sha256=FIXTURE_SHA)


def recipient(base):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    kernel.role_identity(OWNER);os.umask(0o077)
    key=X25519PrivateKey.generate()
    with (base/'owner/private-key').open('xb') as f:
        f.write(key.private_bytes_raw());f.flush();os.fsync(f.fileno())
    return dict(public=key.public_key().public_bytes_raw().hex())


def derive(private,public):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,
                info=b'TASK4_CLOSED_RAW_HTTP_ARCHIVE_V1').derive(private.exchange(public))


def seal(base,mode,raw,completion,plan):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    need(type(raw) is bytes and len(raw)<=LIMIT+1 and completion in {'eof','timeout','read-error','limit'},'BOUNDED_OBSERVED_WIRE')
    public=(base/'public/recipient.pub').read_bytes()
    need(sha(public)==plan['recipient_sha256'],'RECIPIENT_BEFORE_SEAL')
    header=dict(schema='task4.closed-raw-http-envelope.v1',run_id=plan['run_id'],slot=mode,
        request_sha256=plan['request_sha256'],recipient_sha256=sha(public),raw_sha256=sha(raw),
        observed_bytes=len(raw),capture_completion=completion,origin='CLOSED_LOCAL_TLS_NOT_PUBLIC_PROVIDER')
    ephemeral=X25519PrivateKey.generate();nonce=secrets.token_bytes(12)
    encrypted=AESGCM(derive(ephemeral,X25519PublicKey.from_public_bytes(public))).encrypt(nonce,raw,canonical(header))
    blob=canonical(dict(header=header,ephemeral=ephemeral.public_key().public_bytes_raw().hex(),
        nonce=nonce.hex(),ciphertext=base64.b64encode(encrypted).decode()))
    folder=base/('public/seal-deny' if mode=='archive-failure' else 'custody/archives')
    file=folder/(mode+'.enc.json')
    with file.open('xb') as f:f.write(blob);f.flush();os.fsync(f.fileno())
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return dict(header,envelope_sha256=sha(blob),local_fsync_completed=True)


def wire(mode):
    body=canonical(dict(id='chatcmpl-local-'+mode,object='chat.completion',created=1,
        model=request_parameters()['model'],choices=[dict(index=0,message=dict(role='assistant',content='LOCAL ONLY'),finish_reason='stop')]))
    if mode=='malformed-http':return b'NOT-AN-HTTP-STATUS\r\n\r\n'
    if mode=='timeout':return b'HTTP/1.1 200 OK\r\nX-Unfinished:'
    if mode=='dropped':return b''
    if mode=='malformed-json':body=b'{bad json'
    if mode=='oversized':body=b'x'*(LIMIT+100)
    declared=len(body)+(10 if mode=='truncated' else 0)
    status=b'403 Forbidden' if mode=='http403' else b'200 OK'
    headers=b'HTTP/1.1 '+status+b'\r\nContent-Type: application/json\r\nContent-Length: '+str(declared).encode()+b'\r\nConnection: close\r\n'
    if mode!='missing-id':headers+=b'X-Request-Id: local-request-'+mode.encode()+b'\r\n'
    return headers+b'\r\n'+body


def parse_wire(raw,completion):
    need(completion=='eof' and len(raw)<=LIMIT,'INCOMPLETE_OR_LIMITED_WIRE_NO_CONTINUATION')
    class FileSocket:
        def makefile(self,*_,**__):return io.BytesIO(raw)
    reply=http.client.HTTPResponse(FileSocket());reply.begin()
    body=reply.read()  # The captured wire is already bounded; enforce full framing.
    need(reply.status==200 and reply.getheader('x-request-id') and len(body)<=LIMIT,'SEALED_HTTP_STATUS_OR_ID_DENIED')
    value=strict(body)
    need(type(value) is dict and value.get('object')=='chat.completion' and value.get('model')==request_parameters()['model']
         and type(value.get('id')) is str and value['id'] and len(value.get('choices',[]))==1,'SEALED_COMPLETION_SHAPE')
    return reply.status,reply.getheaders(),body


def initialize_ledger(base,plan):
    file=base/'custody/attempts.sqlite3'
    fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    with sqlite3.connect(file) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE enrollment (run TEXT,request_sha TEXT)')
        db.execute('INSERT INTO enrollment VALUES (?,?)',(plan['run_id'],plan['request_sha256']))
        db.execute('CREATE TABLE attempts (run TEXT,slot TEXT,request_sha TEXT,state TEXT,PRIMARY KEY(run,slot))')
    fd=os.open(file.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def reserve(base,mode,plan):
    file=base/'custody/attempts.sqlite3'
    need(file.is_file() and not file.is_symlink() and file.stat().st_uid==os.geteuid()
         and file.stat().st_mode & 0o777==0o600,'RETAINED_PRIVATE_LEDGER_REQUIRED')
    with sqlite3.connect(file.resolve().as_uri()+'?mode=rw',uri=True) as db:
        db.execute('PRAGMA synchronous=FULL')
        need(db.execute('SELECT run,request_sha FROM enrollment').fetchall()==[(plan['run_id'],plan['request_sha256'])],
             'EXACT_RETAINED_LEDGER_ENROLLMENT')
        try:db.execute('INSERT INTO attempts VALUES (?,?,?,?)',(plan['run_id'],mode,plan['request_sha256'],'CONSUMED_UNKNOWN'))
        except sqlite3.IntegrityError:return False
    return True


def capture(sock):
    raw=bytearray();completion='eof'
    try:
        while len(raw)<=LIMIT:
            part=sock.recv(min(4096,LIMIT+1-len(raw)))
            if not part:break
            raw.extend(part)
            if len(raw)>LIMIT:completion='limit';break
    except socket.timeout:completion='timeout'
    except OSError:completion='read-error'
    return bytes(raw),completion


def attempt(base,mode,request):
    plan=enrolled(base)
    need(mode in MODES,'ENROLLED_SLOT_ONLY')
    if not reserve(base,mode,plan):return dict(decision='REPLAY_DENIED',socket_attempts=0,parse_calls=0,sdk_delivered=False)
    events=[]
    def emit(phase,**extra):
        events.append(phase)
        tls.append(base/'custody/events.jsonl',dict(slot=mode,phase=phase,pid=os.getpid(),uid=os.geteuid(),**extra))
    emit('CONSUMED')
    need(request.method=='POST' and str(request.url)==URL and sha(request.content)==plan['request_sha256']
         and request.headers.get('authorization')=='Bearer '+SDK_DUMMY
         and request.headers.get('content-type','').startswith('application/json'),'EXACT_SDK_WIRE_BEFORE_SOCKET')
    if mode=='after-consume-crash':os._exit(88)
    tls.resolved_local()
    context=ssl.create_default_context()
    need(context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname,'STANDARD_VERIFIED_TLS')
    conn=http.client.HTTPSConnection(NAME,PORT,timeout=5,context=context)
    record=dict(mode=mode,request_sha256=plan['request_sha256'],events=events,socket_attempts=1,
        parse_calls=0,sdk_delivered=False,archive=None,peer=None)
    raw=b'';completion='read-error'
    try:
        conn.connect()
        record['peer']=dict(ip=conn.sock.getpeername()[0],leaf_sha256=sha(conn.sock.getpeercert(binary_form=True)),
            tls_version=conn.sock.version(),hostname=NAME,port=443,certificate_required=True,hostname_checked=True)
        need(record['peer']['ip']==IP and record['peer']['leaf_sha256']==plan['leaf_sha256'],'ENROLLED_LOCAL_LEAF_AND_PEER')
        emit('PEER_VERIFIED',peer=record['peer'])
        key=(base/'custody/bearer').read_text()
        conn.request('POST',PATH,body=request.content,headers={'Content-Type':'application/json','Authorization':'Bearer '+key,
            'X-Client-Request-Id':plan['run_id']+'-'+mode,'Connection':'close','Accept-Encoding':'identity'})
        emit('POST_ATTEMPTED')
        conn.sock.settimeout(0.7)
        raw,completion=capture(conn.sock)
    finally:conn.close()
    emit('RAW_OBSERVED',raw_sha256=sha(raw),observed_bytes=len(raw),capture_completion=completion)
    record.update(raw_sha256=sha(raw),observed_bytes=len(raw),capture_completion=completion)
    try:record['archive']=seal(base,mode,raw,completion,plan)
    except OSError:
        emit('ARCHIVE_FAILED');record['decision']='UNKNOWN_ARCHIVE_FAILED_NO_RETRY'
        return record
    emit('SEALED_FSYNCED',archive=record['archive'])
    if mode=='after-seal-crash':os._exit(89)
    if completion!='eof' or len(raw)>LIMIT:
        record['decision']='SEALED_PARTIAL_NO_RETRY';return record
    emit('PARSE_STARTED');record['parse_calls']=1
    try:status,headers,body=parse_wire(raw,completion)
    except (ValueError,http.client.HTTPException,OSError):
        record['decision']='SEALED_REJECTED_NO_RETRY';return record
    emit('SDK_RESPONSE_RELEASED');record.update(decision='SDK_RESPONSE',sdk_delivered=True)
    return record,(status,headers,body)


def sender(base,mode,replay=False):
    import httpx,openai
    kernel.role_identity(kernel.CUSTODY)
    os.umask(0o077)
    results=[]
    class Refused(Exception):pass
    class Transport(httpx.BaseTransport):
        def handle_request(self,request):
            result=attempt(base,mode,request)
            if isinstance(result,tuple):
                record,(status,headers,body)=result;results.append(record)
                return httpx.Response(status,headers=headers,content=body,request=request)
            results.append(result);raise Refused('SEALED_OR_CONSUMED_NO_RETRY')
    try:
        answer=sdk_call(Transport())
        need(not replay and mode=='success' and answer.id=='chatcmpl-local-success','ACTUAL_SDK_COMPLETION_REQUIRED')
    except openai.APIConnectionError:
        need(results and results[0]['decision']!='SDK_RESPONSE','EXPECTED_REFUSAL_ONLY')
    need(len(results)==1,'SDK_MAX_RETRIES_ZERO_ONE_TRANSPORT_INVOCATION')
    return results[0]


def backend(base):
    kernel.role_identity(kernel.BACKEND)
    plan=enrolled(base);key=(base/'backend/bearer').read_text()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            raw=self.rfile.read(min(int(self.headers.get('Content-Length','0')),64001))
            client=self.headers.get('X-Client-Request-Id','')
            mode=client.removeprefix(plan['run_id']+'-')
            authorized=(self.path==PATH and self.headers.get('Host')==NAME and mode in MODES and
                client==plan['run_id']+'-'+mode and sha(raw)==plan['request_sha256'] and
                hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+key))
            reply=wire(mode) if authorized else b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            tls.append(base/'backend/posts.jsonl',dict(mode=mode if authorized else 'unauthorized',method='POST',path=self.path,
                host=self.headers.get('Host'),request_sha256=sha(raw),authorized=authorized,
                wire_sha256=sha(reply),wire_bytes=len(reply),prefix_sha256=sha(reply[:LIMIT+1]),tls_version=self.connection.version()))
            try:
                if reply:self.connection.sendall(reply)
                if authorized and mode=='timeout':time.sleep(2)
            except OSError:pass
            self.close_connection=True
    class Server(ThreadingMixIn,network.server_class(base)):
        daemon_threads=True
    server=Server((IP,PORT),Handler)
    (base/'backend/ready').write_text('ready');server.serve_forever()


def recover(base):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    kernel.role_identity(OWNER)
    private=X25519PrivateKey.from_private_bytes((base/'owner/private-key').read_bytes())
    results=[]
    for file in sorted((base/'owner/recovery').glob('*.enc.json')):
        blob=file.read_bytes();e=strict(blob);h=e['header']
        need(sha(private.public_key().public_bytes_raw())==h['recipient_sha256'],'OWNER_RECIPIENT_JOIN')
        raw=AESGCM(derive(private,X25519PublicKey.from_public_bytes(bytes.fromhex(e['ephemeral'])))).decrypt(
            bytes.fromhex(e['nonce']),base64.b64decode(e['ciphertext'],validate=True),canonical(h))
        need(sha(raw)==h['raw_sha256'] and len(raw)==h['observed_bytes'],'AUTHORIZED_EXACT_RAW_RECOVERY')
        results.append(dict(slot=h['slot'],raw_sha256=sha(raw),observed_bytes=len(raw),envelope_sha256=sha(blob),
            capture_completion=h['capture_completion'],recipient_sha256=h['recipient_sha256']))
    return results


def probe(base,placement):
    kernel.role_identity(kernel.AGENT)
    for file in ('custody/bearer','backend/bearer','backend/key.pem','owner/private-key'):
        try:(base/file).read_bytes()
        except PermissionError:pass
        else:raise ValueError('PRIVATE_CREDENTIAL_OR_OWNER_KEY_READABLE')
    tls.resolved_local()
    conn=http.client.HTTPSConnection(NAME,443,timeout=3,context=ssl.create_default_context())
    try:
        conn.request('POST',PATH,body=(base/'public/wire.bin').read_bytes(),headers={'Authorization':'Bearer invalid'})
        response=conn.getresponse();need(placement=='reachable' and response.status==403,'ACTUAL_REACHABLE_AUTH_DENIAL')
        response.read();return dict(placement=placement,status=403,uid=kernel.AGENT,private_reads_denied=4)
    except OSError as exc:
        need(placement in {'isolated','firewall'},'REACHABLE_MUST_RECEIVE_HTTP')
        return dict(placement=placement,network_errno=exc.errno,uid=kernel.AGENT,private_reads_denied=4)
    finally:conn.close()


def validate(e):
    import errno
    need(e['sdk']['fixture_sha256']==FIXTURE_SHA and e['plan']['request_sha256']==e['sdk']['request_sha256']
         and e['plan']['modes']==list(MODES),'EXACT_SDK_AND_ROOT_PLAN')
    need(e['probes']==[dict(placement='isolated',network_errno=errno.ENETUNREACH,uid=kernel.AGENT,private_reads_denied=4),
        dict(placement='firewall',network_errno=errno.ECONNREFUSED,uid=kernel.AGENT,private_reads_denied=4),
        dict(placement='reachable',status=403,uid=kernel.AGENT,private_reads_denied=4)],'THREE_ACTUAL_OS_AND_AUTH_DENIALS')
    posts=e['posts'];admitted=posts[1:]
    need(len(posts)==12 and posts[0]['authorized'] is False and posts[0]['mode']=='unauthorized'
         and [x['mode'] for x in admitted]==[m for m in MODES if m!='after-consume-crash']
         and all(x['authorized'] is True and x['method']=='POST' and x['path']==PATH and x['host']==NAME
         and x['request_sha256']==e['plan']['request_sha256'] for x in admitted),'EXACT_UNWRAPPED_API_POSTS')
    need(e['ledger']==[[e['plan']['run_id'],m,e['plan']['request_sha256'],'CONSUMED_UNKNOWN'] for m in sorted(MODES)],
         'TWELVE_DURABLE_ATTEMPTS_NEVER_RESET')
    need(set(e['results'])==set(e['replays'])==set(MODES),'ALL_SCENARIOS_AND_RESTART_REPLAYS')
    need(all(r==dict(decision='REPLAY_DENIED',socket_attempts=0,parse_calls=0,sdk_delivered=False)
         for r in e['replays'].values()),'FRESH_PROCESSES_CANNOT_RETRY')
    recovered={x['slot']:x for x in e['recovered']}
    need(set(recovered)==set(MODES)-{'after-consume-crash','archive-failure'},'EXACT_RECOVERABLE_ENVELOPES')
    for mode in MODES:
        trace=[x for x in e['events'] if x['slot']==mode];phases=[x['phase'] for x in trace]
        need(phases and phases[0]=='CONSUMED' and all(x['uid']==kernel.CUSTODY for x in trace),'CONSUME_BEFORE_ALL_IO')
        r=e['results'][mode]
        if mode=='after-consume-crash':
            need(r=={'crash_exit_code':88} and phases==['CONSUMED'],'CONSUMED_CRASH_ZERO_SOCKET')
            continue
        need(phases[:4]==['CONSUMED','PEER_VERIFIED','POST_ATTEMPTED','RAW_OBSERVED'],'ACTUAL_TLS_RAW_RECEIVE_ORDER')
        peer=trace[1]['peer']
        need(peer==dict(ip=IP,leaf_sha256=e['plan']['leaf_sha256'],hostname=NAME,port=443,
             tls_version=peer['tls_version'],certificate_required=True,hostname_checked=True)
             and peer['tls_version'] in {'TLSv1.2','TLSv1.3'},'ALL_OBSERVED_TLS_PEERS_ENROLLED')
        observed=trace[3];post=next(x for x in admitted if x['mode']==mode)
        expected=wire(mode)[:LIMIT+1]
        need(observed['raw_sha256']==sha(expected) and observed['observed_bytes']==len(expected),
             'SERVER_CLIENT_ORIGINAL_RAW_WIRE_JOIN')
        need(post['wire_sha256']==sha(wire(mode)) and post['wire_bytes']==len(wire(mode))
             and post['prefix_sha256']==sha(expected),'BACKEND_OWNED_FULL_AND_PREFIX_HASHES')
        if mode=='archive-failure':
            need(phases==phases[:4]+['ARCHIVE_FAILED'] and r['decision']=='UNKNOWN_ARCHIVE_FAILED_NO_RETRY'
                 and r['parse_calls']==0 and r['sdk_delivered'] is False,'ACTUAL_ARCHIVE_IO_FAILURE_PREVENTS_PARSE')
            continue
        need(phases[4]=='SEALED_FSYNCED','ENCRYPT_FSYNC_BEFORE_HTTP_OR_JSON_PARSE')
        a=trace[4]['archive'];recovery=recovered[mode]
        need(a['raw_sha256']==observed['raw_sha256']==recovery['raw_sha256']
             and a['observed_bytes']==recovery['observed_bytes']==len(expected)
             and a['recipient_sha256']==recovery['recipient_sha256']==e['plan']['recipient_sha256']
             and a['envelope_sha256']==recovery['envelope_sha256'] and a['local_fsync_completed'] is True
             and a['run_id']==e['plan']['run_id'] and a['slot']==mode and a['request_sha256']==e['plan']['request_sha256'],
             'NONPUBLIC_OWNER_AEAD_RECOVERY_JOIN')
        if mode=='after-seal-crash':
            need(r=={'crash_exit_code':89} and len(phases)==5,'SEALED_CRASH_NO_PARSER')
        elif mode in {'oversized','timeout'}:
            need(len(phases)==5 and r['decision']=='SEALED_PARTIAL_NO_RETRY' and r['parse_calls']==0
                 and a['capture_completion']==('limit' if mode=='oversized' else 'timeout'),'PARTIAL_CAPTURE_NEVER_COMPLETE')
        else:
            need(a['capture_completion']=='eof' and phases[5]=='PARSE_STARTED' and r['parse_calls']==1,'PARSE_ONLY_AFTER_SEAL')
            if mode=='success':need(phases[6:]==['SDK_RESPONSE_RELEASED'] and r['sdk_delivered'] is True
                                    and r['decision']=='SDK_RESPONSE','ONE_ACTUAL_SDK_COMPLETION')
            else:need(len(phases)==6 and r['sdk_delivered'] is False and r['decision']=='SEALED_REJECTED_NO_RETRY',
                      'SEALED_INVALID_RESPONSE_NOT_DELIVERED')
    need(e['post_replay_posts_sha256']==digest(posts) and e['post_replay_events_sha256']==digest(e['events']),
         'REPLAY_ZERO_NEW_POSTS_EVENTS')
    for name,t in e['topology'].items():
        need(name in {'client','sink','isolated'} and len(t['links'])==(1 if name=='isolated' else 2)
             and all(x.get('dst')=='10.249.94.0/30' and 'gateway' not in x for x in t['routes'])
             and not any(x.get('dst')=='default' or 'gateway' in x for x in t['routes6']),'NO_EXTERNAL_GATEWAY')
    need(set(e['topology'])=={'client','sink','isolated'},'EXACT_THREE_NAMESPACES')
    return True


def run(output):
    need(os.geteuid()==0 and sys.platform=='linux','DISPOSABLE_ROOT_LINUX_ONLY')
    need(not output.exists() and output.resolve().is_relative_to(ROOT),'FRESH_CHECKOUT_OUTPUT')
    for uid in (kernel.AGENT,kernel.CUSTODY,kernel.BACKEND,OWNER):
        try:pwd.getpwuid(uid)
        except KeyError:continue
        raise ValueError('RESERVED_UID_ALREADY_USED')
    inputs();output.mkdir(parents=True)
    git=['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    head=kernel.command(git+['rev-parse','HEAD']).stdout.strip()
    token=secrets.token_hex(4);client,sink,isolated=['r'+x+token for x in ('c','s','i')]
    left,right='a'+token,'b'+token
    namespaces=[];directories=[];processes=[]
    rule=['OUTPUT','-d',IP,'-p','tcp','--dport','443','-m','owner','!','--uid-owner',str(kernel.CUSTODY),'-j','REJECT']
    with tempfile.TemporaryDirectory(prefix='task4-raw-ingress-') as temp:
        base=Path(temp);os.chmod(base,0o755)
        for name,uid in [('public',0),('native',kernel.AGENT),('custody',kernel.CUSTODY),('backend',kernel.BACKEND),('owner',OWNER)]:
            folder=base/name;folder.mkdir(mode=0o755 if uid==0 else 0o700);os.chown(folder,uid,uid)
        (base/'custody/archives').mkdir(mode=0o700);os.chown(base/'custody/archives',kernel.CUSTODY,kernel.CUSTODY)
        (base/'public/seal-deny').mkdir(mode=0o555)
        certs=tls.certificates(base)
        key='LOCAL_ONLY_'+secrets.token_hex(32)
        for name,uid in [('custody',kernel.CUSTODY),('backend',kernel.BACKEND)]:
            f=base/name/'bearer';f.write_text(key)
            for f in (base/name).glob('*'):
                if f.is_file():os.chown(f,uid,uid);os.chmod(f,0o600)
        source=base/'source';source.mkdir()
        raw=subprocess.run(git+['archive','HEAD'],check=True,capture_output=True,timeout=30).stdout
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for m in archive.getmembers():
                f=source/m.name
                need(f.resolve().is_relative_to(source) and (m.isfile() or m.isdir()),'TRACKED_REGULAR_SOURCE_ONLY')
                if m.isdir():f.mkdir(parents=True,exist_ok=True)
                else:f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(archive.extractfile(m).read())
        for f in source.rglob('*'):os.chmod(f,0o555 if f.is_dir() else 0o444)
        os.chmod(source,0o555)
        code='import sys;sys.path.insert(0,'+repr(str(source))+');from scripts.task4_provider_shaped_raw_ingress_v1 import main;main()'
        env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LANG='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',SSL_CERT_FILE=str(base/'public/ca.pem'))
        def command(uid,role,ns,mode=None):
            args=['ip','netns','exec',ns,'setpriv','--reuid='+str(uid),'--regid='+str(uid),'--clear-groups',
                '--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-c',code,
                '--role',role,'--base',str(base)]
            return args+(['--mode',mode] if mode else [])
        def worker(uid,role,ns,mode=None,expected=0):
            p=subprocess.run(command(uid,role,ns,mode),env=env,capture_output=True,text=True,timeout=60)
            need(p.returncode==expected,'RAW_ROLE_FAILED:'+role+':'+p.stderr[-2200:])
            return strict(p.stdout.encode()) if expected==0 else dict(crash_exit_code=expected)
        try:
            topology=network.topology(client,sink,isolated,left,right,namespaces,directories,rule)
            sdk=worker(kernel.AGENT,'prepare',isolated)
            pub=bytes.fromhex(worker(OWNER,'recipient',isolated)['public'])
            (base/'public/recipient.pub').write_bytes(pub)
            (base/'public/wire.bin').write_bytes((base/'native/wire.bin').read_bytes())
            plan=dict(schema='task4.closed-provider-wire-plan.v1',run_id=secrets.token_hex(32),
                request_sha256=sdk['request_sha256'],recipient_sha256=sha(pub),leaf_sha256=certs['leaf_sha256'],modes=list(MODES))
            (base/'public/plan.json').write_bytes(canonical(plan))
            for f in (base/'public').iterdir():
                if f.is_file():os.chmod(f,0o444)
            worker(kernel.CUSTODY,'ledger',isolated)
            server=subprocess.Popen(command(kernel.BACKEND,'backend',sink),env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            processes.append(server);deadline=time.monotonic()+15
            while not (base/'backend/ready').exists():
                need(server.poll() is None,'RAW_SINK_FAILED:'+(server.stderr.read().decode()[-1800:] if server.poll() is not None else ''))
                need(time.monotonic()<deadline,'RAW_SINK_TIMEOUT');time.sleep(0.05)
            probes=[]
            for placement,ns in [('isolated',isolated),('firewall',client),('reachable',sink)]:
                probes.append(worker(kernel.AGENT,'probe',ns,placement))
                if placement!='reachable':need(not tls.read_lines(base/'backend/posts.jsonl'),'OS_DENIED_BEFORE_HTTP')
            results={};replays={}
            for mode in MODES:
                results[mode]=worker(kernel.CUSTODY,'sender',client,mode,88 if mode=='after-consume-crash' else 89 if mode=='after-seal-crash' else 0)
            posts=tls.read_lines(base/'backend/posts.jsonl');events=tls.read_lines(base/'custody/events.jsonl')
            for mode in MODES:replays[mode]=worker(kernel.CUSTODY,'replay',client,mode)
            recovery=base/'owner/recovery';recovery.mkdir(mode=0o700);os.chown(recovery,OWNER,OWNER)
            for f in (base/'custody/archives').glob('*.enc.json'):
                target=recovery/f.name;target.write_bytes(f.read_bytes());os.chown(target,OWNER,OWNER);os.chmod(target,0o600)
            recovered=worker(OWNER,'recover',isolated)
            with sqlite3.connect(base/'custody/attempts.sqlite3') as db:
                ledger=[list(x) for x in db.execute('SELECT run,slot,request_sha,state FROM attempts ORDER BY slot')]
            evidence=dict(sdk=sdk,plan=plan,topology=topology,probes=probes,results=results,replays=replays,posts=posts,events=events,
                recovered=recovered,ledger=ledger,post_replay_posts_sha256=digest(tls.read_lines(base/'backend/posts.jsonl')),
                post_replay_events_sha256=digest(tls.read_lines(base/'custody/events.jsonl')))
            validate(evidence)
            checks={x:True for x in ('actual_pinned_sdk_original_wire','provider_shaped_path_bearer_and_body',
                'closed_netns_no_external_gateway','native_isolated_and_uid_firewall_denied','reachable_invalid_credential_403',
                'private_bearer_server_key_recipient_denied','durable_consume_before_socket','verified_enrolled_tls_peer',
                'raw_http_bytes_before_header_json_sdk_parse','aead_file_directory_fsync_before_release',
                'nonpublic_ephemeral_owner_exact_recovery','invalid_http_json_status_id_sealed_then_denied',
                'truncated_timeout_dropped_and_limit_no_retry','actual_archive_io_failure_no_parse',
                'consume_and_seal_crashes_no_retry','twelve_new_process_replays_zero_new_posts','one_real_sdk_parse_synthetic_response')}
            report=dict(schema='task4.provider-shaped-raw-ingress.v1',audited_commit=head,source_sha256=sha(Path(__file__).read_bytes()),
                checks=checks,evidence=evidence,evidence_sha256=digest(evidence),real_provider_posts=0,external_bank_effects=0,
                utility='UNSCORED',provider_dispatch='DENY',production_bypass_resistance_proven=False,independent_administration_proven=False,
                native_bind_pipeline_integrated=False,live_credential_provisioning_proven=False,local_test_ca_not_public_provider_identity=True,
                sdk_versions=dict(openai='1.109.1',httpx='0.28.1'),trusted_root_kernel_sender_backend_owner=True)
            (output/'report.json').write_bytes(canonical(report))
            suite=ET.Element('testsuite',name='Provider-shaped first raw ingress',tests=str(len(checks)),failures='0',errors='0',skipped='0')
            for name in sorted(checks):ET.SubElement(suite,'testcase',classname='provider_shaped_raw_ingress',name=name)
            ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
        finally:
            for p in processes:
                if p.poll() is None:p.terminate();p.wait(timeout=5)
                if p.stderr:p.stderr.close()
            for ns in reversed(namespaces):kernel.command(['ip','netns','del',ns],check=False)
            network.cleanup(directories)
            kernel.command(['ip','link','del',left],check=False);kernel.command(['ip','link','del',right],check=False)
    print('CLOSED_PROVIDER_SHAPED_RAW_HTTP_SEALED_BEFORE_PARSERS_NO_LIVE_PROVIDER')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--output',type=Path)
    p.add_argument('--base',type=Path);p.add_argument('--role',choices=('prepare','recipient','backend','sender','replay','recover','probe','ledger'))
    p.add_argument('--mode',choices=MODES+('isolated','firewall','reachable'));a=p.parse_args()
    if a.run:
        need(a.output is not None and a.base is None and a.role is None and a.mode is None,'EXPLICIT_ROOT_RUN_ONLY');run(a.output.resolve())
    else:
        need(a.base is not None and a.role is not None and a.output is None,'EXPLICIT_ENROLLED_LOCAL_ROLE')
        if a.role=='ledger':
            kernel.role_identity(kernel.CUSTODY);initialize_ledger(a.base,enrolled(a.base));print('{}');return
        result=(prepare(a.base) if a.role=='prepare' else recipient(a.base) if a.role=='recipient' else backend(a.base) if a.role=='backend'
            else recover(a.base) if a.role=='recover' else probe(a.base,a.mode) if a.role=='probe' else sender(a.base,a.mode,a.role=='replay'))
        if result is not None:print(canonical(result).decode())


if __name__=='__main__':main()

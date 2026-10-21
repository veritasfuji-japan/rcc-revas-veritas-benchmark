"""Actual scripted Native/Bind with API-shaped TLS and first raw ingress.

Only disconnected disposable Linux test namespaces. No live key or inference.
"""
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import pwd
import socket
from socketserver import ThreadingMixIn
import sqlite3
import ssl
import time
import xml.etree.ElementTree as ET

from scripts import task4_provider_shaped_raw_ingress_v1 as raw
from scripts import task4_native_local_https_v1 as tls
from scripts import ci_mock_executor_authority_boundary_v1 as kernel

need, canonical, digest, sha = kernel.need, kernel.canonical, kernel.digest, raw.sha
MODES = raw.MODES
MARKER = 'task4.native-first-raw-http.v1'


def enabled(base):
    f=base/'public/native-raw-plan.json'
    if not f.exists():return False
    plan(base);return True


def plan(base):
    f=base/'public/native-raw-plan.json';s=f.lstat()
    need(f.is_file() and not f.is_symlink() and s.st_uid==0 and s.st_mode & 0o777==0o444,'ROOT_RAW_PLAN')
    p=raw.strict(f.read_bytes())
    need(set(p)=={'schema','mode','run_id','recipient_sha256','leaf_sha256'} and p['schema']==MARKER
         and p['mode'] in MODES and len(p['run_id'])==64,'EXACT_NATIVE_RAW_PLAN')
    need(sha((base/'public/recipient.pub').read_bytes())==p['recipient_sha256'],'ENROLLED_RAW_RECIPIENT')
    need(tls.enabled(base),'RAW_ONLY_WITH_CLOSED_TLS')
    return p


def enroll(base,mode,certificates,worker,isolated):
    try:pwd.getpwuid(raw.OWNER)
    except KeyError:pass
    else:raise ValueError('RAW_OWNER_UID_ALREADY_USED')
    owner=base/'owner';owner.mkdir(mode=0o700);os.chown(owner,raw.OWNER,raw.OWNER)
    public=bytes.fromhex(worker(raw.OWNER,'raw-owner',isolated)['public'])
    (base/'public/recipient.pub').write_bytes(public);os.chmod(base/'public/recipient.pub',0o444)
    p=dict(schema=MARKER,mode=mode,run_id=os.urandom(32).hex(),recipient_sha256=sha(public),
           leaf_sha256=certificates['leaf_sha256'])
    f=base/'public/native-raw-plan.json';f.write_bytes(canonical(p));os.chmod(f,0o444)
    folder=base/'custody/archives';folder.mkdir(mode=0o700);os.chown(folder,kernel.CUSTODY,kernel.CUSTODY)
    (base/'public/seal-deny').mkdir(mode=0o555)


def emit(base,op,phase,**extra):
    raw.tls.append(base/'custody/raw-events.jsonl',dict(op=op,phase=phase,uid=os.geteuid(),pid=os.getpid(),**extra))


def consumed(base,op,request):
    emit(base,op,'CONSUMED',request_sha256=sha(request))
    if plan(base)['mode']=='after-consume-crash':os._exit(88)


def owner_denied(base):
    kernel.role_identity(kernel.AGENT)
    try:(base/'owner/private-key').read_bytes()
    except PermissionError:return True
    raise ValueError('NATIVE_RAW_OWNER_KEY_READABLE')


def reachable(base):
    kernel.role_identity(kernel.AGENT);plan(base)
    raw.tls.resolved_local()
    conn=http.client.HTTPSConnection(tls.NAME,443,timeout=3,context=ssl.create_default_context())
    try:
        conn.request('POST',raw.PATH,body=b'{}',headers={'Content-Type':'application/json','Authorization':'Bearer invalid'})
        reply=conn.getresponse()
        need(reply.status==403 and raw.strict(reply.read())=={'decision':'DENIED'},'REACHABLE_API_AUTH_DENIAL')
    finally:conn.close()
    return {'reachable_native_uid_without_credential_http_403':True}


def response_wire(body,op,mode):
    if mode in {'malformed-http','timeout','dropped'}:return raw.wire(mode)
    if mode=='malformed-json':body=b'{bad json'
    if mode=='oversized':body=b'x'*(raw.LIMIT+100)
    size=len(body)+(10 if mode=='truncated' else 0)
    status=b'403 Forbidden' if mode=='http403' else b'200 OK'
    headers=b'HTTP/1.1 '+status+b'\r\nContent-Type: application/json\r\nContent-Length: '+str(size).encode()+b'\r\nConnection: close\r\n'
    if mode!='missing-id':headers+=b'X-Request-Id: native-local-'+op.encode()+b'\r\n'
    return headers+b'\r\n'+body


def backend(base):
    import httpx
    from scripts import task4_native_os_custody_v1 as n
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    kernel.role_identity(kernel.BACKEND);os.umask(0o077)
    p=plan(base);key=(base/'backend/credential').read_bytes();db=n.open_backend_db(base)
    sources={a:cap.GuardedMock(a) for a in ('A','B')}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def respond(self,code,value):
            data=canonical(value);self.send_response(code);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_GET(self):
            op=self.path.removeprefix('/status/')
            claim=dict(method='GET',path=self.path,body=None)
            if self.path!='/status/'+op or op not in {a+str(i) for a,i in n.scope()} or not hmac.compare_digest(
                kernel.tag(key,b'TASK4_NATIVE_HTTP_V1\0',claim),self.headers.get('X-Mock-Auth','')):
                self.respond(403,{'decision':'DENIED'});return
            row=db.execute('SELECT receipt FROM effects WHERE op=?',(op,)).fetchone()
            self.respond(200,dict(effect_count=db.execute('SELECT count(*) FROM effects').fetchone()[0],operation_receipt=row[0] if row else None))
        def do_POST(self):
            body=b''
            try:
                size=int(self.headers.get('Content-Length','0'));need(0<size<=64000,'BOUNDED_API_BODY');body=self.rfile.read(size)
                op=self.headers.get('X-Client-Request-Id','').removeprefix(p['run_id']+'-')
                need(op in {a+str(i) for a,i in n.scope()} and self.path==raw.PATH and self.headers.get('Host')==tls.NAME
                     and self.headers.get('X-Client-Request-Id')==p['run_id']+'-'+op
                     and self.headers.get('Content-Type')=='application/json'
                     and hmac.compare_digest(self.headers.get('Authorization',''),'Bearer LOCAL_ONLY_'+key.hex())
                     and sha(body)==n.scope()[(op[0],int(op[1]))],'ENROLLED_API_BEARER_AND_NATIVE_BODY')
                need(not db.execute('SELECT 1 FROM effects WHERE op=?',(op,)).fetchone(),'BACKEND_SPENT')
                source=sources[op[0]];need(source.attempts==int(op[1]),'ORIGINAL_SCRIPTED_SEQUENCE')
                request=httpx.Request('POST',raw.URL,content=body,headers={'authorization':'Bearer '+cap.base.LOCAL_KEY,'content-type':'application/json'})
                reply=source(request)
                if int(op[1])==3:source.verify()
                record=dict(operation_id=op,request_sha256=sha(body),response_sha256=sha(reply.content))
                db.execute('INSERT INTO effects VALUES (?,?,?,?)',(op,sha(body),sha(reply.content),digest(record)))
                wire=response_wire(reply.content,op,p['mode'])
                raw.tls.append(base/'backend/raw-posts.jsonl',dict(op=op,authorized=True,path=self.path,host=self.headers.get('Host'),
                    request_sha256=sha(body),response_sha256=sha(reply.content),wire_sha256=sha(wire),wire_bytes=len(wire),
                    observed_prefix_sha256=sha(wire[:raw.LIMIT+1]),observed_prefix_bytes=min(len(wire),raw.LIMIT+1),tls_version=self.connection.version()))
                if wire:self.connection.sendall(wire)
                if p['mode']=='timeout':time.sleep(2)
                self.close_connection=True
            except (ValueError,KeyError,TypeError,sqlite3.IntegrityError):
                raw.tls.append(base/'backend/raw-posts.jsonl',dict(authorized=False,path=self.path,request_sha256=sha(body)))
                self.respond(403,{'decision':'DENIED'})
    # SQLite access stays in the single server thread; only timeout delay is bounded.
    server=tls.server_class(base)((tls.IP,tls.PORT),Handler)
    (base/'backend/ready').write_text('ready');server.serve_forever()


def dispatch(base,packet,request,key):
    from scripts import task4_native_os_custody_v1 as n
    kernel.role_identity(kernel.CUSTODY)
    p=plan(base);op=packet['arm']+str(packet['ordinal'])
    need(n.verify(packet,(base/'public/issuer-key').read_bytes())==request,'SIGNED_NATIVE_WIRE_AT_RAW_DISPATCH')
    # Existing retained SQLite consumption is the authority; no second ledger/reset.
    with sqlite3.connect((base/'custody/ledger.sqlite3').resolve().as_uri()+'?mode=ro',uri=True) as db:
        need(db.execute('SELECT state,request_sha FROM consumed WHERE op=?',(op,)).fetchone()==('CONSUMED_UNKNOWN',sha(request)),
             'DURABLE_NATIVE_CONSUMPTION_BEFORE_RAW_SOCKET')
    raw.tls.resolved_local();context=ssl.create_default_context()
    need(context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname,'VERIFIED_API_TLS')
    conn=http.client.HTTPSConnection(tls.NAME,443,timeout=5,context=context)
    try:
        conn.connect();peer=dict(ip=conn.sock.getpeername()[0],leaf_sha256=sha(conn.sock.getpeercert(binary_form=True)),
            tls_version=conn.sock.version(),hostname=tls.NAME,port=443,certificate_required=True,hostname_checked=True)
        need(peer['ip']==tls.IP and peer['leaf_sha256']==p['leaf_sha256'],'ROOT_ENROLLED_API_PEER')
        emit(base,op,'API_PEER_VERIFIED',peer=peer)
        conn.request('POST',raw.PATH,body=request,headers={'Content-Type':'application/json',
            'Authorization':'Bearer LOCAL_ONLY_'+key.hex(),'X-Client-Request-Id':p['run_id']+'-'+op,
            'Connection':'close','Accept-Encoding':'identity'})
        emit(base,op,'API_POST_ATTEMPTED',request_sha256=sha(request))
        conn.sock.settimeout(0.7);wire,completion=raw.capture(conn.sock)
    finally:conn.close()
    emit(base,op,'RAW_OBSERVED',raw_sha256=sha(wire),observed_bytes=len(wire),capture_completion=completion)
    archive_plan=dict(p,request_sha256=sha(request))
    try:archive=raw.seal(base,'archive-failure' if p['mode']=='archive-failure' else op,wire,completion,archive_plan)
    except OSError:
        emit(base,op,'ARCHIVE_FAILED');raise ValueError('RAW_ARCHIVE_IO_FAILURE_NO_PARSE_NO_RETRY') from None
    emit(base,op,'SEALED_FSYNCED',archive=archive)
    if p['mode']=='after-seal-crash':os._exit(89)
    need(completion=='eof' and len(wire)<=raw.LIMIT,'PARTIAL_HTTP_NO_CONTINUATION')
    emit(base,op,'HTTP_PARSE_STARTED')
    try:status,headers,body=raw.parse_wire(wire,completion)
    except (ValueError,http.client.HTTPException,OSError):raise ValueError('SEALED_HTTP_REJECTED_NO_RETRY') from None
    need(dict(headers).get('X-Request-Id')=='native-local-'+op,'EXACT_LOCAL_RESPONSE_ID')
    record=dict(operation_id=op,request_sha256=sha(request),response_sha256=sha(body))
    emit(base,op,'BODY_RELEASED_TO_BIND',response_sha256=sha(body))
    return status,dict(record,receipt_sha256=digest(record),response_b64=n.encode(body))


def validate(e):
    from scripts import task4_native_os_custody_v1 as n
    p=e['plan'];mode=p['mode'];success=mode=='success';count=8 if success else 1
    need(p['schema']==MARKER and mode in MODES,'RAW_MODE')
    need(e['checks_before']['reachable_native_uid_without_credential_http_403'] is True
         and all(v is True for v in e['checks_before'].values()),'OS_AUTH_PRIVATE_SOURCE_DENIALS')
    need(e['owner_private_read_denied'] is True,'NATIVE_RAW_OWNER_KEY_DENIED')
    posts=e['posts'];admitted=[x for x in posts if x['authorized']]
    need(len(posts)==1+len(admitted) and posts[0]['authorized'] is False and posts[0]['path']==raw.PATH,'ONE_REACHABLE_API_AUTH_DENIAL')
    need(len(admitted)==(8 if success else int(mode!='after-consume-crash')),'EXACT_RAW_POST_COUNT')
    need(len(e['consumed'])==count and len(e['effects'])==len(admitted),'NO_DUPLICATE_NATIVE_EFFECTS')
    need(e['posts_after_replay_sha256']==digest(posts) and e['events_after_replay_sha256']==digest(e['events']),
         'RESTART_REPLAYS_NO_POST_OR_EVENT')
    need(e['replay_denials']==(16 if success else 2 if mode in {'after-consume-crash','after-seal-crash'} else 4),
         'LIVE_AND_RESTART_NATIVE_REPLAYS_DENIED')
    expected_ops=[a+str(i) for a,i in n.scope()] if success else ['A0']
    recovered={x['slot']:x for x in e['recovered']}
    need(set(recovered)==(set(expected_ops) if success else set() if mode in {'archive-failure','after-consume-crash'} else {'A0'}),
         'EXACT_OWNER_RECOVERY_COUNT')
    for op,row in zip(sorted(expected_ops),e['consumed']):
        need(row[0]==op and row[2]==n.scope()[(op[0],int(op[1]))] and row[1]==('MOCK_OBSERVED' if success else 'CONSUMED_UNKNOWN'),
             'SIGNED_NATIVE_DURABLE_LEDGER_JOIN')
        events=[x for x in e['events'] if x['op']==op];phases=[x['phase'] for x in events]
        need(events[0]['phase']=='CONSUMED' and all(x['uid']==kernel.CUSTODY for x in events),'CONSUME_AND_CUSTODY_UID')
        binds=[x for x in events if x['phase']=='BIND_RECEIPT']
        if mode=='after-consume-crash':
            need(phases==['CONSUMED'] and not binds,'CONSUME_CRASH_BEFORE_BIND');continue
        need(binds and binds[0]['allowed'] is False and binds[0]['apply_calls']==0
             and binds[0]['receipt']['final_outcome']=='BLOCKED' and phases[1]=='BIND_RECEIPT','ACTUAL_BIND_BLOCK_BEFORE_API')
        need(phases[2:5]==['API_PEER_VERIFIED','API_POST_ATTEMPTED','RAW_OBSERVED'],'BIND_THEN_RAW_RECEIVE')
        peer=events[2]['peer'];post=next(x for x in admitted if x['op']==op);observed=events[4]
        need(peer['ip']==tls.IP and peer['leaf_sha256']==p['leaf_sha256'] and peer['hostname']==tls.NAME and peer['port']==443
             and peer['certificate_required'] is peer['hostname_checked'] is True and peer['tls_version'] in {'TLSv1.2','TLSv1.3'},'VERIFIED_API_PEER')
        need(post['path']==raw.PATH and post['host']==tls.NAME and post['request_sha256']==row[2]
             and post['observed_prefix_sha256']==observed['raw_sha256'] and post['observed_prefix_bytes']==observed['observed_bytes'],
             'EXACT_SERVER_CLIENT_NATIVE_WIRE')
        if mode=='archive-failure':
            need(phases[5]=='ARCHIVE_FAILED' and not any(x in phases for x in ('HTTP_PARSE_STARTED','BODY_RELEASED_TO_BIND')),
                 'REAL_ARCHIVE_FAILURE_STOPS_PARSE');continue
        need(phases[5]=='SEALED_FSYNCED','RAW_ARCHIVE_BEFORE_ALL_PARSERS')
        a=events[5]['archive'];r=recovered[op]
        need(a['raw_sha256']==r['raw_sha256']==observed['raw_sha256'] and a['observed_bytes']==r['observed_bytes']==observed['observed_bytes']
             and a['envelope_sha256']==r['envelope_sha256'] and a['recipient_sha256']==r['recipient_sha256']==p['recipient_sha256']
             and a['request_sha256']==row[2] and a['run_id']==p['run_id'] and a['slot']==op
             and a['capture_completion']==r['capture_completion']==observed['capture_completion']
             and a['local_fsync_completed'] is True,'OWNER_EXACT_RAW_RECOVERY')
        if success:
            need(phases==['CONSUMED','BIND_RECEIPT','API_PEER_VERIFIED','API_POST_ATTEMPTED','RAW_OBSERVED',
                'SEALED_FSYNCED','HTTP_PARSE_STARTED','BODY_RELEASED_TO_BIND','BIND_RECEIPT']
                and len(binds)==2 and binds[1]['allowed'] is True and binds[1]['apply_calls']==1
                and binds[1]['receipt']['final_outcome']=='COMMITTED','BIND_COMMIT_ONLY_AFTER_SEALED_API_BODY')
            record=next(x for x in e['native']['records'] if x['arm']+str(x['ordinal'])==op)
            effect=next(x for x in e['effects'] if x[0]==op)
            binding=next(x for x in e['bindings'] if x['operation_id']==op)
            line=next(x for x in e['native']['lineage']['response_receipts'] if x['arm']+str(x['ordinal'])==op)
            need(row[3]==post['response_sha256']==record['response_sha256']==effect[2]==line['original_response_raw_sha256']
                 and row[2]==record['request_sha256']==effect[1]==line['original_request_raw_sha256']
                 and row[4]==record['backend_receipt_sha256']==effect[3] and row[5]==record['envelope_sha256']
                 and row[6]==record['bind_sha256']==digest({k:v for k,v in binding.items() if k!='operation_id'})
                 and [x['receipt'] for x in binding['records']]==[x['receipt'] for x in binds], 'API_BIND_LEDGER_INNER_AEAD_NATIVE_SCORER_JOIN')
        else:
            need('BODY_RELEASED_TO_BIND' not in phases and all(v is None for v in row[3:]),'FAULT_NO_NATIVE_BODY_OR_RECEIPT')
            if mode in {'after-seal-crash','oversized','timeout'}:need('HTTP_PARSE_STARTED' not in phases,'PARTIAL_OR_CRASH_NO_PARSER')
            else:need(phases[6]=='HTTP_PARSE_STARTED','INVALID_HTTP_PARSED_AFTER_ARCHIVE')
    if success:
        v=e['native'];need(v['scorer_calls']==v['scripted_native_arms']==2 and len(v['records'])==8
            and len(v['lineage']['response_receipts'])==8 and digest(v['lineage'])==v['lineage_sha256']
            and len(v['native_terminal_hashes'])==2 and len(v['frozen_source_git_blobs'])==9,'EIGHT_NATIVE_JOINS_TWO_TERMINALS_SCORERS')
    else:need(e['native']['sdk_responses_returned']==e['native']['scorer_calls']==e['native']['native_terminal_arms']==0
              and e['native']['transport_invocations']==1,'FIRST_NATIVE_FAULT_NO_CONTINUATION')
    need(set(e['topology'])=={'client','sink','isolated'},'THREE_CLOSED_NAMESPACES')
    for name,t in e['topology'].items():
        need(len(t['links'])==(1 if name=='isolated' else 2)
             and all(x.get('dst')=='10.249.94.0/30' and 'gateway' not in x for x in t['routes'])
             and not any(x.get('dst')=='default' or 'gateway' in x for x in t['routes6']),'NO_EXTERNAL_GATEWAY')
    return True


def exercise(base,output,worker,spawn,service,sink,isolated,client,sink_ns,head,pins,topology,issued):
    from scripts import task4_native_os_custody_v1 as n
    p=plan(base);success=p['mode']=='success';crashed=p['mode'] in {'after-consume-crash','after-seal-crash'}
    checks=worker(kernel.AGENT,'probe',isolated);checks.update(worker(kernel.AGENT,'reachable',sink_ns))
    native=worker(kernel.AGENT,'native' if success else 'fault-native',isolated)
    replay_denials=8 if success else 0
    if not success and not crashed:replay_denials+=worker(kernel.AGENT,'fault-replay',isolated)['replay_denials']
    before_posts=raw.tls.read_lines(base/'backend/raw-posts.jsonl');before_events=raw.tls.read_lines(base/'custody/raw-events.jsonl')
    if crashed:need(service.wait(timeout=5)==(88 if p['mode']=='after-consume-crash' else 89),'ACTUAL_RAW_CUSTODY_CRASH')
    else:service.terminate();service.wait(timeout=5)
    (base/'custody/ready').unlink()
    restarted=spawn(kernel.CUSTODY,'custody',client,base/'custody/ready','restarted',('--restart',))
    replay_denials+=worker(kernel.AGENT,'restart-probe' if success else 'fault-replay',isolated).get(
        'restart_replay_denials' if success else 'replay_denials',0)
    restarted.terminate();restarted.wait(timeout=5);sink.terminate();sink.wait(timeout=5)
    recovery=base/'owner/recovery';recovery.mkdir(mode=0o700);os.chown(recovery,raw.OWNER,raw.OWNER)
    for f in (base/'custody/archives').glob('*.enc.json'):
        target=recovery/f.name;target.write_bytes(f.read_bytes());os.chown(target,raw.OWNER,raw.OWNER);os.chmod(target,0o600)
    recovered=worker(raw.OWNER,'raw-recover',isolated)
    rows=n.read_fault_rows(base)
    bindings=[]
    if success:
        for r in native['records']:
            op=r['arm']+str(r['ordinal']);b=n.parse((base/'custody'/(op+'-bind.json')).read_bytes())
            bindings.append(dict(operation_id=op,**b))
            inner=(base/'custody'/('task4-457-'+r['arm']+'-'+str(r['ordinal'])+'.enc.json')).read_bytes()
            need(sha(inner)==r['envelope_sha256'],'DURABLE_INNER_NATIVE_ENVELOPE')
    e=dict(plan=p,checks_before=checks,owner_private_read_denied=native['raw_owner_private_read_denied'],
        posts=before_posts,events=before_events,recovered=recovered,consumed=rows['consumed'],effects=rows['effects'],
        native=native,bindings=bindings,topology=topology,replay_denials=replay_denials,
        posts_after_replay_sha256=digest(raw.tls.read_lines(base/'backend/raw-posts.jsonl')),
        events_after_replay_sha256=digest(raw.tls.read_lines(base/'custody/raw-events.jsonl')))
    validate(e)
    checks={name:True for name in ('actual_native_sdk_frozen_requests','kernel_private_source_network_denials',
        'reachable_invalid_auth_denied','signed_consumption_before_bind_and_socket','actual_bind_blocks_before_api',
        'api_path_private_bearer_exact_sdk_body','verified_enrolled_tls_peer','raw_status_headers_body_before_parsers',
        'aead_file_directory_fsync_before_parse','separate_private_owner_exact_recovery','native_fault_no_continuation',
        'retained_ledger_restart_no_new_posts','backend_ledger_native_response_joins','closed_network_no_public_provider')}
    report=dict(schema='task4.native-raw-ingress.v1',audited_commit=head,source_sha256=sha(Path(__file__).read_bytes()),
        native_source_sha256=sha((Path(__file__).parent/'task4_native_os_custody_v1.py').read_bytes()),
        raw_source_sha256=sha((Path(__file__).parent/'task4_provider_shaped_raw_ingress_v1.py').read_bytes()),
        checks=checks,evidence=e,evidence_sha256=digest(e),external_pins=pins,
        native_bind_pipeline_integrated=True,live_credential_provisioning_proven=False,
        real_provider_posts=0,external_bank_effects=0,utility='UNSCORED',provider_dispatch='DENY',
        independent_administration_proven=False,production_bypass_resistance_proven=False,
        raw_archive_recipient_private_key_publicly_reproducible=False,inner_native_recipient_private_key_publicly_reproducible=True,
        raw_recipient_bound_in_signed_grant=False,local_test_ca_not_public_provider_identity=True,
        trusted_root_kernel_custody_backend_owner=True,real_data_confidentiality_proven=False)
    (output/'report.json').write_bytes(canonical(report))
    suite=ET.Element('testsuite',name='Native raw ingress '+p['mode'],tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_raw_ingress',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)

"""Disposable Native SDK + actual Bind + AF_UNIX under all-actor IP rejection.

Isolated CI only, not a VM enrollment/cutover or a Provider transport. The frozen
Native research functions are reused with an explicitly injected local Unix HTTP
transport. No authority, single-use, Bind or SDK validation function is replaced.
"""
import argparse
import copy
import http.client
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import socketserver
import sqlite3
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import task4_native_egress_rehearsal_v1 as e
from scripts import task4_native_os_custody_v1 as n

PROFILE = 'task4.native-unix-egress.v1'
SCOPE = 'SYNTHETIC_ISOLATED_NATIVE_UNIX_HTTP_ALL_ACTOR_IP_DENY_NO_PROVIDER'
ROOT = Path(__file__).resolve().parents[1]
TABLE = 'veritas_native_unix_egress_v1'
TARGETS = dict(agent=61101, executor=61102, backend=61103, stranger=61104,
               issuer=61105, custody=61106, archive=61107, runtime=61108)
N_PIN = 'b1fb7b407b3c4eaa24ecc9e0746cae9bf4b6cfdb2e379b6f6687bdca17be038d'
PINS = dict(agentdojo='a75aba7631d3ca5fb7ab938965c97ead2f9ff84b',
            rcc='1d3782d3aae5ff9c88036709c1a5642320cc53c2',
            veritas='a1d66aef02262cf8a913295270c3aafd159c6adb')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}


def need(value):
    if not value:raise ValueError('NATIVE_UNIX_EGRESS_STOP')


def source_sha256():return e.sha(Path(__file__).read_bytes())


def sources():
    result=dict(native_unix_egress=source_sha256(),native_os_custody=e.sha(Path(n.__file__).read_bytes()),
                egress_rehearsal=e.source_sha256())
    need(result['native_os_custody']==N_PIN)
    need(result['egress_rehearsal']=='f6865825a1f7435a1821e56f3e2e64db806c4ffad23f402d21cba8b394e48857')
    return result


def rules(token):
    need(type(token) is str and len(token)==32 and all(c in '0123456789abcdef' for c in token))
    lines=[f'create table inet {TABLE} {{ comment "native-unix-egress:{token}"; }}',
           f'create chain inet {TABLE} output {{ type filter hook output priority 0; policy accept; }}']
    lines += [f'add rule inet {TABLE} output meta skuid {uid} counter reject with icmpx type admin-prohibited comment "{role}"'
              for role,uid in TARGETS.items()]
    return ('\n'.join(lines)+'\n').encode('ascii')


def peer_uid(conn):
    _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    return uid


def backend_path(base):return Path(base)/'backend-ipc/service.sock'


def append(path,row):
    with Path(path).open('ab') as stream:
        stream.write(n.canonical(row)+b'\n');stream.flush();os.fsync(stream.fileno())


def unix_call(base,method,path,body,key):
    """Fixed local endpoint, reciprocal UID pin, unchanged synthetic HMAC auth."""
    n.kernel.role_identity(n.CUSTODY)
    need(method in ('GET','POST') and
         ((method=='GET' and path.startswith('/status/') and body is None) or (method=='POST' and path=='/effect')))
    class Connection(http.client.HTTPConnection):
        def connect(self):
            need(self.sock is None)
            conn=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                conn.settimeout(5);conn.connect(str(backend_path(base)))
                need(peer_uid(conn)==n.BACKEND)
                self.sock=conn
            except BaseException:
                conn.close();raise
    conn=Connection('closed-native.invalid',timeout=5)
    try:
        raw=n.canonical(body) if body is not None else None
        conn.request(method,path,body=raw,headers={'Content-Type':'application/json',
            'X-Mock-Auth':n.tag(key,b'TASK4_NATIVE_HTTP_V1\0',dict(method=method,path=path,body=body))})
        response=conn.getresponse();encoded=response.read(n.LIMIT+1);value=n.parse(encoded)
        append(Path(base)/'custody/unix-transcript.jsonl',dict(method=method,path=path,
            body_sha256=e.sha(raw) if raw is not None else None,response_sha256=e.sha(encoded),
            status=response.status,client_uid=os.geteuid(),server_uid=n.BACKEND,
            namespace=e.namespace(),transport='HTTP_OVER_AF_UNIX_NO_IP'))
        return response.status,value
    finally:conn.close()


def unix_server_class(base):
    class Server(socketserver.UnixStreamServer):
        def __init__(self,address,handler):
            need(address==(n.HOST,n.PORT) and not os.path.lexists(backend_path(base)))
            self.server_name='closed-native.invalid';self.server_port=0
            super().__init__(str(backend_path(base)),handler)
            os.chmod(backend_path(base),0o666)
        def get_request(self):
            conn,address=super().get_request()
            uid=peer_uid(conn)
            if uid!=n.CUSTODY:
                append(Path(base)/'backend/unix-peer-denials.jsonl',dict(uid=uid,namespace=e.namespace(),effect=False))
                conn.close();raise OSError('UNENROLLED_UNIX_PEER')
            return conn,address
    return Server


def install_transport(base):
    """Trusted local fixture injection, never an authority/Bind/SDK mock."""
    sources()
    n.http_call=lambda method,path,body,key:unix_call(base,method,path,body,key)
    n.HTTPServer=unix_server_class(base)


def unix_probe(base):
    uid=os.geteuid();n.kernel.role_identity(uid);need(uid in TARGETS.values() and uid!=n.CUSTODY)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(3);conn.connect(str(backend_path(base)));need(peer_uid(conn)==n.BACKEND)
        try:
            conn.sendall(b'POST /effect HTTP/1.1\r\nHost: closed-native.invalid\r\nContent-Length: 2\r\n\r\n{}')
            reply=conn.recv(256)
        except (ConnectionResetError,BrokenPipeError):reply=b''
        need(reply==b'')
    return dict(uid=uid,result='UNIX_PEER_REFUSED',namespace=e.namespace())


def role(base,mode):
    base=Path(base)
    if mode=='unix-probe':return unix_probe(base)
    if mode=='issue':return n.issue(base)
    if mode=='backend':
        install_transport(base);return n.backend(base)
    if mode=='custody':
        install_transport(base);return n.custody(base)
    if mode=='native':return n.native(base)
    raise ValueError('UNKNOWN_CLOSED_ROLE')


def export(command,folder):
    folder.mkdir(parents=True,exist_ok=True)
    archive=subprocess.run(command,check=True,capture_output=True,timeout=30).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            dest=folder/member.name
            need(dest.resolve().is_relative_to(folder) and (member.isfile() or member.isdir()))
            if member.isdir():dest.mkdir(parents=True,exist_ok=True)
            else:
                dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tar.extractfile(member).read())


def probe_ip(roles,endpoints,binaries,snapshot=None):
    rows=[]
    for role_name,uid in roles.items():
        for version,protocol in e.FLOWS:
            before=snapshot()[uid] if snapshot else None
            raw=e.execute([binaries['setpriv'],'--reuid='+str(uid),'--regid='+str(uid),
                '--clear-groups','--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',
                sys.executable,'-I','-B','-c',e.CLIENT,str(uid),str(uid),str(version),protocol,
                str(endpoints[(version,protocol)])],timeout=8)
            row=json.loads(raw);need(row['uid']==uid and row['gid']==uid and row['effective_capabilities']==0
                and row['no_new_privs'] is True and row['version']==version and row['protocol']==protocol)
            if snapshot:row.update(kernel_packets_before=before,kernel_packets_after=snapshot()[uid])
            rows.append(dict(row,role=role_name))
    return rows


def counters(binaries):
    doc=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]));result={}
    for item in doc['nftables']:
        if 'rule' not in item:continue
        row=item['rule'];need(row['family']=='inet' and row['table']==TABLE and row['chain']=='output')
        expr=row['expr'];need(len(expr)==3 and expr[0]['match']['left']=={'meta':{'key':'skuid'}}
                              and expr[0]['match']['op']=='==')
        uid=expr[0]['match']['right'];need(type(uid) is int and uid in TARGETS.values() and uid not in result)
        count=expr[1]['counter']['packets'];need(type(count) is int and count>=0);result[uid]=count
    need(set(result)==set(TARGETS.values()));return result


def validate_flows(rows,roles,denied):
    expected={(role,uid,v,p) for role,uid in roles.items() for v,p in e.FLOWS};seen=set()
    for row in rows:
        identity=(row['role'],row['uid'],row['version'],row['protocol'])
        need(identity in expected and identity not in seen);seen.add(identity)
        need(row['gid']==row['uid'] and row['effective_capabilities']==0 and row['no_new_privs'] is True)
        if denied:
            need(row['result']=='SOCKET_ERROR' and type(row['errno']) is int and row['errno'] in
                 ((1,13,113) if row['version']==4 else (1,13)))
            need(type(row['kernel_packets_before']) is int and type(row['kernel_packets_after']) is int
                 and row['kernel_packets_after']>row['kernel_packets_before']>=0)
        else:need(row['result']=='SUCCESS' and row['errno'] is None)
    need(seen==expected and len(rows)==len(expected))


def read_lines(file):return [json.loads(x) for x in file.read_bytes().splitlines()] if file.exists() else []


def effects(base):
    with sqlite3.connect((base/'backend/effects.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        return db.execute('SELECT op,request_sha,response_sha,receipt FROM effects ORDER BY op').fetchall()


def guard(parent_pid,parent_ns,binaries):
    sources();e.guard(parent_pid,parent_ns,binaries)


def _supervise(parent_pid,parent_ns,source,head):
    binaries=e.tools();guard(parent_pid,parent_ns,binaries)
    processes=[]
    with tempfile.TemporaryDirectory(prefix='native-unix-fixture-',dir='/run') as tmp:
        base=Path(tmp);os.chmod(base,0o755)
        for name,uid in [('native',n.NATIVE),('issuer',n.ISSUER),('custody',n.CUSTODY),('backend',n.BACKEND),
                         ('ipc',n.CUSTODY),('backend-ipc',n.BACKEND)]:
            folder=base/name;folder.mkdir(mode=0o755 if name.endswith('ipc') else 0o700);os.chown(folder,uid,uid)
        (base/'public').mkdir(mode=0o755)
        credential=secrets.token_bytes(32)
        for name in ('backend','custody'):
            file=base/name/'credential';file.write_bytes(credential);file.chmod(0o600)
            os.chown(file,n.BACKEND if name=='backend' else n.CUSTODY,n.BACKEND if name=='backend' else n.CUSTODY)
        paths=[source,source/'scripts',source/'_pins/agentdojo/src',source/'_pins/veritas',source/'_pins/rcc/external-eval/v0.3.9/src']
        code='import sys;sys.path[:0]='+repr([str(x) for x in paths])+';from scripts.task4_native_unix_egress_v1 import main;main()'
        env=dict(ENV,TASK4_RCC_ROOT=str(source/'_pins/rcc'))
        def argv(uid,mode):return [binaries['setpriv'],'--reuid='+str(uid),'--regid='+str(uid),'--clear-groups',
            '--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',code,
            '--role',mode,'--base',str(base)]
        def worker(uid,mode):
            p=subprocess.run(argv(uid,mode),capture_output=True,env=env,timeout=120)
            
            if p.returncode:raise ValueError('CLOSED_ROLE_FAILED:'+mode+':'+p.stderr.decode()[-1800:])
            return n.parse(p.stdout)
        def spawn(uid,mode):
            p=subprocess.Popen(argv(uid,mode),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env);processes.append(p)
            until=time.monotonic()+20
            ready=base/('backend' if mode=='backend' else 'custody')/'ready'
            while time.monotonic()<until:
                need(p.poll() is None)
                if ready.exists():return p
                time.sleep(0.05)
            raise ValueError('UNIX_SERVICE_READY_STOP')
        token=secrets.token_hex(16);installed=False
        try:
            issued=worker(n.ISSUER,'issue')
            for filename,data in [('issuer-key',bytes.fromhex(issued['public'])),('grants.json',n.canonical(issued['grants']))]:
                (base/'public'/filename).write_bytes(data);(base/'public'/filename).chmod(0o444)
            backend=spawn(n.BACKEND,'backend');custody=spawn(n.CUSTODY,'custody')
            with e.sinks() as endpoints:
                baseline=probe_ip(TARGETS,endpoints,binaries);validate_flows(baseline,TARGETS,False)
                guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--check','--file','-'],rules(token))
                e.execute([binaries['nft'],'--file','-'],rules(token));installed=True
                denied=probe_ip(TARGETS,endpoints,binaries,lambda:counters(binaries));validate_flows(denied,TARGETS,True)
                root_control=probe_ip(dict(administrator=0),endpoints,binaries);validate_flows(root_control,dict(administrator=0),False)
                rejected=[worker(uid,'unix-probe') for uid in TARGETS.values() if uid!=n.CUSTODY]
                need(effects(base)==[])
                native=worker(n.NATIVE,'native')
                need(len(native['records'])==8 and native['scorer_calls']==2 and native['replay_denials']==8)
                post_native=probe_ip(TARGETS,endpoints,binaries,lambda:counters(binaries));validate_flows(post_native,TARGETS,True)
                final_packets=counters(binaries)
                # Installed policy remains present through all positive Native effects.
                guard(parent_pid,parent_ns,binaries)
                policy=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]))
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode());installed=False
                after=probe_ip(TARGETS,endpoints,binaries);validate_flows(after,TARGETS,False)
            for p in processes:p.terminate();p.wait(timeout=5)
            transcript=read_lines(base/'custody/unix-transcript.jsonl')
            binding=[dict(operation=op,binding=n.parse((base/'custody'/(op+'-bind.json')).read_bytes())) for op in sorted(issued['grants'])]
            with sqlite3.connect((base/'custody/ledger.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
                consumed=db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed ORDER BY op').fetchall()
            report=dict(schema=PROFILE,scope=SCOPE,audited_commit=head,sources=sources(),external_pins=PINS,
                namespace=e.namespace(),parent_namespace=parent_ns,loopback_only=True,host_rules_applied=False,
                target_uids=TARGETS,phases=dict(baseline=baseline,denied=denied,root_control=root_control,
                    post_native_denied=post_native,after_removal=after),final_kernel_packets={str(k):v for k,v in final_packets.items()},
                installed_policy=policy,native=native,issuer=dict(public=issued['public'],credential_reads_denied=issued['issuer_credential_reads_denied']),
                unix_peer_probes=rejected,backend_peer_denials=read_lines(base/'backend/unix-peer-denials.jsonl'),
                effects=effects(base),consumed=consumed,bindings=binding,unix_transcript=transcript,
                packets_sha256={op:e.sha((base/'native'/('packet-'+op+'.json')).read_bytes()) for op in sorted(issued['grants'])},
                ciphertexts={f.name:e.sha(f.read_bytes()) for f in (base/'custody').glob('*.enc.json')},
                table_removed=True,limitations=limitations())
            return validate(json.loads(n.canonical(report)))
        finally:
            for p in processes:
                if p.poll() is None:p.kill();p.wait(timeout=5)
                if p.stderr:p.stderr.close()
            if installed:
                # Teardown of a disposable namespace fixture only; never host rollback.
                guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode())


def limitations():
    return dict(real_provider_posts=0,external_bank_effects=0,provider_dispatch='DENY',utility='UNSCORED',
        operator_vm_trial_executed=False,operator_credentials_loaded=False,production_bypass_resistance_proven=False,
        independent_administration_proven=False,retained_github_service_integrated=False,
        bounded_history_profile_integrated=False,raw_http_ingress_profile_integrated=False,
        separate_archive_role_integrated=False,real_data_confidentiality_proven=False,
        host_trial_lease_integrated=False,live_execution_permission_issued=False)


def validate_policy(document):
    rows=[x for x in document['nftables'] if 'metainfo' not in x]
    tables=[x['table'] for x in rows if 'table' in x]
    chains=[x['chain'] for x in rows if 'chain' in x]
    rules_rows=[x['rule'] for x in rows if 'rule' in x]
    need(len(rows)==10 and len(tables)==len(chains)==1 and len(rules_rows)==8)
    table=tables[0];chain=chains[0]
    need(set(table)=={'family','name','handle','comment'} and table['family']=='inet' and table['name']==TABLE)
    tag=table['comment'];need(type(tag) is str and tag.startswith('native-unix-egress:'))
    rules(tag.removeprefix('native-unix-egress:'))
    need(set(chain)=={'family','table','name','handle','type','hook','prio','policy'} and
        {k:chain[k] for k in ('family','table','name','type','hook','prio','policy')}==
        dict(family='inet',table=TABLE,name='output',type='filter',hook='output',prio=0,policy='accept'))
    handles=[table['handle'],chain['handle']]
    for row,(role_name,uid) in zip(rules_rows,TARGETS.items()):
        need(set(row)=={'family','table','chain','handle','expr','comment'} and row['family']=='inet'
            and row['table']==TABLE and row['chain']=='output' and row['comment']==role_name)
        expr=row['expr'];need(type(expr) is list and len(expr)==3)
        need(expr[0]=={'match':{'op':'==','left':{'meta':{'key':'skuid'}},'right':uid}})
        need(set(expr[1])=={'counter'} and set(expr[1]['counter'])=={'packets','bytes'}
             and all(type(x) is int and x>=0 for x in expr[1]['counter'].values()))
        need(set(expr[2])=={'reject'} and expr[2]['reject'] in
             ({'type':'icmpx','expr':'admin-prohibited'},{'type':'icmpx','expr':3}))
        handles.append(row['handle'])
    need(all(type(x) is int and x>0 for x in handles))
    return True


def validate(r):
    need(r['schema']==PROFILE and r['scope']==SCOPE and r['sources']==sources() and r['external_pins']==PINS)
    need(r['namespace']!=r['parent_namespace'] and r['loopback_only'] is True and r['host_rules_applied'] is False
         and r['target_uids']==TARGETS and r['table_removed'] is True and r['limitations']==limitations())
    for name in ('baseline','after_removal'):validate_flows(r['phases'][name],TARGETS,False)
    for name in ('denied','post_native_denied'):validate_flows(r['phases'][name],TARGETS,True)
    validate_flows(r['phases']['root_control'],dict(administrator=0),False)
    need(set(r['final_kernel_packets'])=={str(x) for x in TARGETS.values()}
         and all(type(x) is int and x>=8 for x in r['final_kernel_packets'].values()))
    validate_policy(r['installed_policy'])
    need(r['issuer']['credential_reads_denied'] is True)
    native=r['native'];need(n.digest(native['lineage'])==native['lineage_sha256']
        and native['lineage']['detached_native_scorer_calls_locally']==2
        and native['lineage']['complete_native_terminals_locally']==2
        and len(native['frozen_source_git_blobs'])==9)
    need(len(native['records'])==8 and native['scorer_calls']==native['scripted_native_arms']==2
        and native['replay_denials']==8 and native['signature_wire_target_denials']==3)
    need({(x['arm'],x['ordinal']):x['request_sha256'] for x in native['records']}==n.scope())
    expected={x['arm']+str(x['ordinal']):x for x in native['records']}
    need(len(r['effects'])==len(r['consumed'])==len(r['bindings'])==len(r['ciphertexts'])==8)
    for effect,consumed,bound in zip(r['effects'],r['consumed'],r['bindings']):
        op,q,response,receipt=effect;row=expected[op];binding=bound['binding']
        need(bound['operation']==op and [x['outcome'] for x in binding['records']]==['BLOCKED','COMMITTED']
             and [x['apply_calls'] for x in binding['records']]==[0,1])
        need(q==row['request_sha256'] and response==row['response_sha256'] and receipt==row['backend_receipt_sha256'])
        need(receipt==n.digest(dict(operation_id=op,request_sha256=q,response_sha256=response)))
        need(consumed==[op,'MOCK_OBSERVED',q,response,receipt,row['envelope_sha256'],row['bind_sha256']])
        need(binding['bind_core_git_blob']=='0f64201e2599495ce4e3991348aa320995716ffc'
             and all(n.digest(x['receipt'])==x['receipt_sha256'] for x in binding['records']))
        need(n.digest(binding)==row['bind_sha256'] and row['envelope_sha256'] in r['ciphertexts'].values())
    post=[x for x in r['unix_transcript'] if x['method']=='POST']
    need(len(post)==8 and all(x['path']=='/effect' for x in post)
         and all(x['status']==200 and x['client_uid']==n.CUSTODY
        and x['server_uid']==n.BACKEND and x['namespace']==r['namespace']
        and x['transport']=='HTTP_OVER_AF_UNIX_NO_IP' for x in r['unix_transcript']))
    need([x['body_sha256'] for x in post]==[r['packets_sha256'][op] for op in sorted(expected)])
    wrong=set(TARGETS.values())-{n.CUSTODY}
    need(len(r['unix_peer_probes'])==len(r['backend_peer_denials'])==len(wrong))
    need({x['uid'] for x in r['unix_peer_probes']}=={x['uid'] for x in r['backend_peer_denials']}==wrong)
    need(all(x['namespace']==r['namespace'] and x['effect'] is False for x in r['backend_peer_denials']))
    return r


def run(output,acknowledge=False):
    need(acknowledge is True);e.require_root();sources()
    need(not output.exists() and output.resolve().is_relative_to(ROOT))
    for uid in TARGETS.values():
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise ValueError('DISPOSABLE_UID_COLLISION_NO_REPAIR')
    parent_pid=os.getpid();parent_ns=e.namespace();binaries=e.tools()
    parent_tables=e.execute([binaries['nft'],'--json','--numeric','list','tables'])
    git=['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    head=e.execute(git+['rev-parse','HEAD']).decode().strip()
    for name,pin in PINS.items():
        repo=ROOT/'_pins'/name
        need(e.execute(['git','-c','safe.directory='+str(repo),'-C',str(repo),'rev-parse','HEAD']).decode().strip()==pin)
        e.execute(['git','-c','safe.directory='+str(repo),'-C',str(repo),'diff','--exit-code','HEAD'])
    with tempfile.TemporaryDirectory(prefix='native-unix-source-',dir='/run') as tmp:
        stage=Path(tmp);stage.chmod(0o755);source=stage/'source'
        export(git+['archive','HEAD'],source)
        for name,subtree in [('agentdojo','src/agentdojo'),('rcc','external-eval/v0.3.9/src'),('veritas','veritas_os')]:
            repo=ROOT/'_pins'/name
            export(['git','-c','safe.directory='+str(repo),'-C',str(repo),'archive',PINS[name],subtree],source/'_pins'/name)
        for file in source.rglob('*'):file.chmod(0o555 if file.is_dir() else 0o444)
        source.chmod(0o555)
        code=('import sys,json,subprocess;sys.path.insert(0,'+repr(str(source))+');'
            'from scripts.task4_native_unix_egress_v1 import _supervise,e;from pathlib import Path;'
            'e.require_root();e.need(e.namespace()!=json.loads(sys.argv[2]) and '
            'e.namespace(int(sys.argv[1]))==json.loads(sys.argv[2]),"ISOLATED_BEFORE_LO_UP");'
            'subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True);'
            'print(json.dumps(_supervise(int(sys.argv[1]),json.loads(sys.argv[2]),Path(sys.argv[3]),sys.argv[4]),sort_keys=True))')
        args=[binaries['unshare'],'--net','--',sys.executable,'-I','-B','-c',code,
              str(parent_pid),json.dumps(parent_ns),str(source),head]
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,start_new_session=True)
        try:stdout,stderr=process.communicate(timeout=240)
        except BaseException:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5);raise
        need(process.returncode==0)
        report=validate(json.loads(stdout))
    need(e.namespace()==parent_ns)
    # Names are only a negative control for this fixture's non-host-apply claim.
    need(e.execute([binaries['nft'],'--json','--numeric','list','tables'])==parent_tables)
    output.mkdir(parents=True)
    (output/'report.json').write_bytes(n.canonical(report))
    checks=('same_namespace_all_actors','all_eight_uid_ip_denials_before_native','all_eight_uid_ip_denials_after_native',
        'actual_sdk_eight_frozen_wires','actual_native_two_terminals_scorers','issuer_credential_denials',
        'single_use_eight_consumptions','actual_bind_block_zero_commit_one','eight_backend_effects',
        'eight_ciphertexts_before_sdk_parsers','kernel_unix_peer_refusals','custody_backend_uid_pins',
        'same_run_hash_receipt_join','no_host_policy_apply','no_real_provider')
    suite=ET.Element('testsuite',name='Native Unix egress integration',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_unix_egress',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--acknowledge-isolated-native-unix-test',action='store_true')
    parser.add_argument('--role',choices=('issue','backend','custody','native','unix-probe'));parser.add_argument('--base',type=Path)
    args=parser.parse_args(argv)
    if args.run:
        need(args.role is None and args.base is None and args.output is not None)
        run(args.output,args.acknowledge_isolated_native_unix_test)
        print('ISOLATED_NATIVE_UNIX_EIGHT_EFFECTS_ALL_ACTOR_IP_DENIAL_NO_PROVIDER')
    else:
        need(args.role is not None and args.base is not None and args.output is None
             and not args.acknowledge_isolated_native_unix_test)
        print(n.canonical(role(args.base,args.role)).decode('ascii'))


if __name__=='__main__':main()

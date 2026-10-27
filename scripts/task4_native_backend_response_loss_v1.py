"""Closed Native effect-committed/backend-response-lost integration proof.

Synthetic Unix TLS only. No Provider, remote GitHub, operator files, host apply,
repair, permission recovery or claim that a failed Bind means no effect occurred.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import task4_native_bounded_unix_ack_loss_v1 as f

m,u,e,n=f.m,f.u,f.e,f.n
b,retained,signed,github=f.b,f.retained,f.signed,f.github
ingress,authority,tls=f.ingress,f.authority,f.tls
contract=f.contract
ROOT,ENV,PINS,TARGETS,TABLE=f.ROOT,f.ENV,f.PINS,f.TARGETS,f.TABLE
need=f.need
ACK_PIN='18ab296b51e47d5f7e20e986d2a8871f7d047c8fce318c927ecc1656a34ec52e'
PROFILE='task4.native-backend-response-loss.v1'
SCOPE='SYNTHETIC_ISOLATED_NATIVE_BACKEND_COMMIT_RESPONSE_LOSS_NO_RETRY_NO_PROVIDER'
MARKER='public/backend-response-loss-v1'


def source_sha256():return e.sha(Path(__file__).read_bytes())


def sources():
    need(f.source_sha256()==ACK_PIN)
    return dict(profile=source_sha256(),acknowledgement_profile=f.sources())


def fixture(base):
    m.fixture(base);info=(base/MARKER).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
         and stat.S_IMODE(info.st_mode)==0o444 and (base/MARKER).read_text()==SCOPE)


def drop_committed_response(base,wire):
    """Backend-only send boundary: original handler has already committed/logged."""
    fixture(base);n.kernel.role_identity(n.BACKEND)
    effects=u.effects(base);posts=u.read_lines(base/'backend/raw-posts.jsonl')
    need(type(wire) is bytes and len(wire)>0 and len(effects)==len(posts)==1)
    op,q,response,receipt=effects[0];post=posts[0]
    need(op==post['op']=='A0' and post['authorized'] is True and post['request_sha256']==q
         and post['response_sha256']==response and post['path']==ingress.raw.PATH and post['host']==tls.NAME and post['wire_sha256']==e.sha(wire)
         and post['wire_bytes']==len(wire)
         and receipt==n.digest(dict(operation_id=op,request_sha256=q,response_sha256=response)))
    need(not (base/'backend/response-loss.jsonl').exists())
    u.append(base/'backend/response-loss.jsonl',dict(operation=op,request_sha256=q,response_sha256=response,
        backend_receipt_sha256=receipt,produced_wire_sha256=e.sha(wire),produced_bytes=len(wire),
        response_bytes_sent=0,uid=os.geteuid(),namespace=e.namespace(),phase='DURABLE_EFFECT_DROP_BEFORE_TLS_SEND'))
    # Return without forwarding any response bytes. The original handler closes
    # the connection normally; its validations, SQLite effect and log are intact.


def server_class(base):
    original=m.server_class(base)
    def server(address,handler):
        class Handler(handler):
            def do_POST(self):
                real=self.connection
                class ResponseBoundary:
                    def __getattr__(self,name):return getattr(real,name)
                    def sendall(self,wire):return drop_committed_response(base,wire)
                self.connection=ResponseBoundary()
                try:return super().do_POST()
                finally:self.connection=real
        return original(address,Handler)
    return server


def validate_unknown_rows(rows,request_sha):
    need(contract.hex64(request_sha) and len(rows)==1 and rows[0]==['A0','CONSUMED_UNKNOWN',request_sha,None,None,None,None])
    return True


def custody_reopen(base):
    """Reopen exactly one uncertain retained row, never initialize or reset it."""
    fixture(base);a=signed.admit(base,'custody')
    retained_gate=journal(base,a,'custody')
    request_sha=retained_gate['intent.json']['request_sha256']
    verify_gate(retained_gate,a,'custody',request_sha,retained_gate['intent.json']['grant_sha256'])
    db=retained.open_custody(base)
    try:
        need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)])
        rows=[list(x) for x in db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed ORDER BY op')]
        validate_unknown_rows(rows,request_sha)
    finally:db.close()
    address=base/'ipc/native.sock';info=address.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid==n.CUSTODY and stat.S_IMODE(info.st_mode)==0o666)
    address.unlink()  # Supervisor has SIGKILLed/waited for this exact old role.
    # Retained mode opens the already pinned DB regardless of the startup label.
    # The frozen --restart path is deliberately not used: it requires eight
    # completed rows. All original admission/consume handlers remain unchanged.
    return b.custody(base,restart=False)


def native_stop(base):
    fixture(base);n.kernel.role_identity(b.RUNTIME);os.umask(0o077)
    rpc=b.rpc
    def observe(base,packet,name='issuer'):
        if name=='issuer' and packet.get('action')=='authorize' and packet.get('arm')=='A' and packet.get('parent') is None:
            wire=n.decode(packet['wire_b64'])
            if b.canonical(b.raw.strict(wire))==b.canonical(b.seed()):
                file=base/'runtime/backend-loss-query.json'
                if file.exists():need(json.loads(file.read_bytes())==packet)
                else:n.durable_marker(file,packet)
        if name=='native' and set(packet)=={'arm','ordinal','wire_b64','grant'}:
            file=base/'runtime/backend-loss-packet.json';need(not file.exists())
            n.durable_marker(file,packet)
        return rpc(base,packet,name)
    try:
        with patch.object(b,'rpc',observe):b.native(base)
    except b.NativeBoundaryFailure as error:
        need(str(error) in ('BOUNDED_NATIVE_GRANT_REQUIRED','ACTUAL_NATIVE_CUSTODY_REQUIRED'))
        wire=n.decode(json.loads((base/'runtime/backend-loss-query.json').read_bytes())['wire_b64'])
        from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
        return dict(native_stopped=True,stop_reason=str(error),model_responses_returned=0,scorer_calls=0,
            uid=os.geteuid(),namespace=e.namespace(),request_sha256=e.sha(wire),request_bytes=len(wire),frozen_source_git_blobs=verify_pins())
    raise ValueError('BACKEND_LOSS_NATIVE_CONTINUED')


def replay(base):
    fixture(base);n.kernel.role_identity(b.RUNTIME)
    packet=json.loads(retained.regular(base/'runtime/backend-loss-packet.json',b.RUNTIME,0o600))
    result=b.rpc(base,packet,'native');need(result==dict(decision='REPLAY_DENIED'))
    return result


def reconcile(base):
    fixture(base);signed.admit(base,'custody');os.umask(0o077)
    key=retained.regular(base/'custody/credential',n.CUSTODY,0o600,32)
    code,result=m.status_call(base,'GET','/status/A0',None,key)
    need(code==200 and result['effect_count']==1 and contract.hex64(result['operation_receipt']))
    return dict(action='READ_ONLY_BACKEND_STATUS',uid=os.geteuid(),namespace=e.namespace(),status=code,snapshot=result,
        permission_issued=False,mutation_attempted=False)


def rows(base):
    result=dict(effects=u.effects(base))
    with sqlite3.connect((base/'custody/ledger.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        result['consumed']=[list(x) for x in db.execute('SELECT op,state,request_sha,response_sha,backend_receipt,envelope_sha,bind_sha FROM consumed ORDER BY op')]
    return result


def journal(base,enrollment,role):
    action='reserve' if role=='issuer' else 'consume';uid=n.ISSUER if role=='issuer' else n.CUSTODY
    slot=base/role/'signed-ledger'/(enrollment['binding']['run_id']+'-'+action+'-A0')
    return {name:json.loads(retained.regular(slot/name,uid,0o600,24000)) if (slot/name).exists() else None
            for name in ('intent.json','verified-receipts.json','effect-returned.json')}


def exercise(base,worker,spawn):
    a=signed.anchor(base)
    services=dict(ledger=spawn(signed.LEDGER,'signed-ledger-server',None,base/'ledger/ready'),
        issuer=spawn(n.ISSUER,'bounded-issuer',None,base/'issuer/ready'),
        custody=spawn(n.CUSTODY,'custody',None,base/'custody/ready'))
    backend=spawn(n.BACKEND,'backend',None,base/'backend/ready');backend_pid=backend.pid
    initial=worker(b.RUNTIME,'loss-native');before=worker(n.ISSUER,'signed-ledger-view')
    read_before=worker(n.CUSTODY,'loss-reconcile');issuer_before=worker(n.ISSUER,'retained-state')['snapshot']
    rows_before=rows(base);events_before=u.read_lines(base/'custody/raw-events.jsonl')
    posts_before=u.read_lines(base/'backend/raw-posts.jsonl');loss_before=u.read_lines(base/'backend/response-loss.jsonl')
    model_before=worker(signed.LEDGER,'signed-github-project')
    pids_before={name:p.pid for name,p in services.items()}
    for p in services.values():p.kill();p.wait(timeout=5)
    exits={name:p.returncode for name,p in services.items()}
    for name in services:(base/name/'ready').unlink()
    services=dict(ledger=spawn(signed.LEDGER,'signed-ledger-server',None,base/'ledger/ready'),
        issuer=spawn(n.ISSUER,'bounded-issuer',None,base/'issuer/ready','restarted',('--restart',)),
        custody=spawn(n.CUSTODY,'loss-custody-reopen',None,base/'custody/ready'))
    repeated=worker(b.RUNTIME,'loss-native');replayed=worker(b.RUNTIME,'loss-replay')
    after=worker(n.ISSUER,'signed-ledger-view');read_after=worker(n.CUSTODY,'loss-reconcile')
    issuer_after=worker(n.ISSUER,'retained-state')['snapshot'];model=worker(signed.LEDGER,'signed-github-project')
    need(backend.poll() is None and backend.pid==backend_pid)
    evidence=dict(enrollment=a,manifest=b.load(base),issuer_public=(base/'public/issuer-key').read_bytes().hex(),initial=initial,repeated=repeated,replay=replayed,
        before=before,after=after,reconcile_before=read_before,reconcile_after=read_after,
        issuer_before=issuer_before,issuer_after=issuer_after,rows_before=rows_before,rows_after=rows(base),
        events_before=events_before,events_after=u.read_lines(base/'custody/raw-events.jsonl'),
        posts_before=posts_before,posts_after=u.read_lines(base/'backend/raw-posts.jsonl'),
        loss_before=loss_before,loss_after=u.read_lines(base/'backend/response-loss.jsonl'),model=model,
        model_posts_before=sum(x[0]=='api' and x[1]=='POST' for x in model_before['events']),
        pids_before=pids_before,pids_after={name:p.pid for name,p in services.items()},exit_codes=exits,
        backend_pid_before=backend_pid,backend_pid_after=backend.pid,
        packet=json.loads(retained.regular(base/'runtime/backend-loss-packet.json',b.RUNTIME,0o600)),
        journals={role:journal(base,a,role) for role in ('issuer','custody')},
        bind_result_files={name:(base/'custody'/name).exists() for name in ('A0-bind.json','A0-archive-receipt.json')})
    for p in [*services.values(),backend]:p.terminate();p.wait(timeout=5)
    recovery=base/'owner/recovery';recovery.mkdir(mode=0o700);os.chown(recovery,ingress.raw.OWNER,ingress.raw.OWNER)
    for file in (base/'custody/archives').glob('*.enc.json'):
        target=recovery/file.name;target.write_bytes(file.read_bytes());target.chmod(0o600)
        os.chown(target,ingress.raw.OWNER,ingress.raw.OWNER)
    evidence['recovered']=worker(ingress.raw.OWNER,'raw-recover')
    return evidence


def verify_gate(row,a,role,request_sha,grant_sha):
    action='reserve' if role=='issuer' else 'consume';revision=1 if role=='issuer' else 2
    need(role in ('issuer','custody') and contract.hex64(request_sha)
         and (grant_sha is None if role=='issuer' else contract.hex64(grant_sha)))
    intent=row['intent.json'];receipts=row['verified-receipts.json'];returned=row['effect-returned.json']
    need(intent['role']==role and intent['action']==action and intent['operation_id']=='A0'
         and intent['binding_sha256']==n.digest(a['binding']) and intent['request_sha256']==request_sha
         and intent['grant_sha256']==grant_sha and receipts['intent_sha256']==n.digest(intent))
    need(returned is None if role=='custody' else returned['effect_returned'] is True and returned['intent_sha256']==n.digest(intent))
    pairs=receipts['exchanges'];need(len(pairs)==2)
    public=f.Ed25519PublicKey.from_public_bytes(bytes.fromhex(a['service_public']))
    for pair in pairs:
        c=contract.command(pair['command']);s=pair['receipt']['statement']
        public.verify(bytes.fromhex(pair['receipt']['signature']),contract.DOMAIN+contract.canonical(s))
        need({k:s[k] for k in ('schema','ledger_id','binding_sha256','command_sha256','nonce','action')}==
            dict(schema=contract.SCHEMA,ledger_id=a['binding']['ledger_id'],binding_sha256=n.digest(a['binding']),
                 command_sha256=n.digest(c),nonce=c['nonce'],action=c['action']))
        need(c['binding_sha256']==n.digest(a['binding']));contract.validate_snapshot(s['snapshot'])
    before,after=pairs;c=after['command'];snapshot=after['receipt']['statement']['snapshot']
    need(before['command']['action']=='view' and c['action']==action and c['operation_id']=='A0'
         and c['request_sha256']==request_sha and c['grant_sha256']==grant_sha
         and c['expected_revision']==before['receipt']['statement']['snapshot']['revision']==revision-1
         and snapshot['revision']==revision and receipts['snapshot']==snapshot)
    expected=dict(operation_id='A0',request_sha256=request_sha,grant_sha256=grant_sha,state='RESERVED' if role=='issuer' else 'CONSUMED_UNKNOWN')
    need(snapshot['attempts']==[expected])
    return pairs


def validate_execution(v,namespace):
    a=v['enrollment'];manifest=v['manifest'];b.validate_manifest(manifest)
    need(a['github_mtls']['fault']=='' and a['binding']['manifest_sha256']==n.digest(manifest)
         and a['binding']['run_id']==manifest['execution']['run_id'])
    packet=v['packet'];need(set(packet)=={'arm','ordinal','wire_b64','grant'} and packet['arm']=='A' and packet['ordinal']==0)
    wire=n.decode(packet['wire_b64']);grant=packet['grant']
    public_pin=a['binding']['issuer_public_sha256']
    # Public issuer bytes are retained in the report, never a private signing key.
    public=bytes.fromhex(v['issuer_public']);need(e.sha(public)==public_pin)
    b.p.verify_signature(public,b.p.DOMAIN,grant)
    need(grant['statement']==b.p.grant_statement(manifest,'A',0,wire,b.p.root_parent(manifest,'A'))
         and b.canonical(b.raw.strict(wire))==b.canonical(b.seed()))
    for name in ('initial','repeated'):
        x=v[name];need(x['native_stopped'] is True and x['model_responses_returned']==x['scorer_calls']==0
            and x['uid']==b.RUNTIME and x['namespace']==namespace and x['request_sha256']==e.sha(wire)
            and x['request_bytes']==len(wire) and len(x['frozen_source_git_blobs'])==9)
    need(v['initial']['stop_reason']=='ACTUAL_NATIVE_CUSTODY_REQUIRED' and v['repeated']['stop_reason']=='BOUNDED_NATIVE_GRANT_REQUIRED'
         and v['initial']['frozen_source_git_blobs']==v['repeated']['frozen_source_git_blobs']
         and v['replay']==dict(decision='REPLAY_DENIED'))
    need(v['rows_before']==v['rows_after']);rows=v['rows_after'];validate_unknown_rows(rows['consumed'],e.sha(wire))
    need(len(rows['effects'])==1);op,q,response,receipt=rows['effects'][0]
    need(op=='A0' and q==e.sha(wire) and receipt==n.digest(dict(operation_id=op,request_sha256=q,response_sha256=response)))
    need(v['issuer_before']==v['issuer_after'] and len(v['issuer_after']['attempts'])==1)
    pending=v['issuer_after']['attempts'][0]
    need(pending==dict(arm='A',ordinal=0,request_sha256=q,grant=grant,state='CONSUMED_UNKNOWN',response_sha256=None,receipt_sha256=None)
         and v['issuer_after']['arms'][0][0:4]==['A',1,len(wire),'PENDING'])
    need(v['before']==v['after']==dict(revision=2,attempts=[dict(operation_id='A0',request_sha256=q,grant_sha256=n.digest(grant),state='CONSUMED_UNKNOWN')]))
    need(all(v['pids_before'][name]!=v['pids_after'][name] and v['exit_codes'][name]==-9 for name in ('ledger','issuer','custody'))
         and v['backend_pid_before']==v['backend_pid_after'])
    for name in ('reconcile_before','reconcile_after'):
        need(v[name]==dict(action='READ_ONLY_BACKEND_STATUS',uid=n.CUSTODY,namespace=namespace,status=200,
            snapshot=dict(effect_count=1,operation_receipt=receipt),permission_issued=False,mutation_attempted=False))
    need(v['events_before']==v['events_after'] and v['posts_before']==v['posts_after'] and v['loss_before']==v['loss_after'])
    need(len(v['posts_after'])==len(v['loss_after'])==1)
    post=v['posts_after'][0];loss=v['loss_after'][0]
    need(post['authorized'] is True and post['op']=='A0' and post['request_sha256']==q and post['response_sha256']==response)
    need(loss==dict(operation='A0',request_sha256=q,response_sha256=response,backend_receipt_sha256=receipt,
        produced_wire_sha256=post['wire_sha256'],produced_bytes=post['wire_bytes'],response_bytes_sent=0,uid=n.BACKEND,
        namespace=namespace,phase='DURABLE_EFFECT_DROP_BEFORE_TLS_SEND') and loss['produced_bytes']>0)
    events=v['events_after'];need([x['phase'] for x in events]==['CONSUMED','BIND_RECEIPT','API_PEER_VERIFIED','API_POST_ATTEMPTED',
        'RAW_OBSERVED','SEALED_FSYNCED','HTTP_PARSE_STARTED','BIND_RECEIPT'] and all(x['uid']==n.CUSTODY for x in events))
    for index,outcome,allowed in ((1,'BLOCKED',False),(7,'APPLY_FAILED',True)):
        need(events[index]['receipt']['final_outcome']==outcome and events[index]['allowed'] is allowed and events[index]['apply_calls']==0)
    need(events[4]['raw_sha256']==e.sha(b'') and events[4]['observed_bytes']==0 and events[4]['capture_completion']=='eof')
    archive=events[5]['archive'];need(archive['raw_sha256']==e.sha(b'') and archive['observed_bytes']==0 and archive['local_fsync_completed'] is True
        and archive['run_id']==manifest['execution']['run_id'] and archive['request_sha256']==q
        and archive['recipient_sha256']==manifest['execution']['raw_recipient_sha256'])
    need(v['recovered']==[dict(slot='A0',raw_sha256=e.sha(b''),observed_bytes=0,envelope_sha256=archive['envelope_sha256'],
        capture_completion='eof',recipient_sha256=archive['recipient_sha256'])] and not any(v['bind_result_files'].values()))
    commits=github.validate_model(a,v['model']);need(len(commits)==4)
    need(commits[v['model']['head']]['state']['runs'][a['binding']['run_id']]['snapshot']==v['after'])
    need(v['model_posts_before']==sum(x[0]=='api' and x[1]=='POST' for x in v['model']['events'])==3)
    mutation_signs=[x for x in v['model']['events'] if x[0]=='sign' and x[3]!='view'];need(len(mutation_signs)==2)
    for role in ('issuer','custody'):
        pairs=verify_gate(v['journals'][role],a,role,e.sha(wire),None if role=='issuer' else n.digest(grant))
        for pair in pairs:
            c=pair['command'];snapshot=pair['receipt']['statement']['snapshot'];events=v['model']['events']
            signs=[(i,x) for i,x in enumerate(events) if x[0]=='sign' and x[2]==c['nonce']];need(len(signs)==1)
            i,event=signs[0];need(event[3:]==[c['action'],snapshot['revision']]
                and commits[event[1]]['state']['runs'][a['binding']['run_id']]['snapshot']==snapshot)
            auth=[x for x in events[:i] if x[0]=='mtls' and x[-1]==n.digest(c)]
            need(len(auth)==1 and auth[0][1:3]==[n.ISSUER if role=='issuer' else n.CUSTODY,a['github_mtls']['peers'][role]['certificate_sha256']]
                and auth[0][3] in ('TLSv1.2','TLSv1.3'))
    return True


def _supervise(parent_pid,parent_ns,source,head):
    binaries=e.tools();u.guard(parent_pid,parent_ns,binaries);sources();processes=[]
    need(not signed.required() and not retained.required())
    with tempfile.TemporaryDirectory(prefix='native-bounded-unix-fixture-',dir='/run') as tmp:
        base=Path(tmp);base.chmod(0o755)
        for name,uid in [('native',n.NATIVE),('issuer',n.ISSUER),('custody',n.CUSTODY),('backend',n.BACKEND),
                         ('ipc',n.CUSTODY),('backend-ipc',n.BACKEND)]:
            folder=base/name;folder.mkdir(mode=0o755 if name.endswith('ipc') else 0o700);os.chown(folder,uid,uid)
        (base/'public').mkdir(mode=0o755)
        (base/m.MARKER).write_text(m.SCOPE);(base/m.MARKER).chmod(0o444)
        (base/MARKER).write_text(SCOPE);(base/MARKER).chmod(0o444)
        certificates=tls.enroll(base)
        credential=secrets.token_bytes(32)
        for name,uid in [('backend',n.BACKEND),('custody',n.CUSTODY)]:
            file=base/name/'credential';file.write_bytes(credential);file.chmod(0o600);os.chown(file,uid,uid)
        paths=[source,source/'scripts',source/'_pins/agentdojo/src',source/'_pins/veritas',source/'_pins/rcc/external-eval/v0.3.9/src']
        code='import sys;sys.path[:0]='+repr([str(x) for x in paths])+';from scripts.task4_native_backend_response_loss_v1 import main;main()'
        env=dict(ENV,TASK4_RCC_ROOT=str(source/'_pins/rcc'))
        def argv(uid,mode,extra=()):return [binaries['setpriv'],'--reuid='+str(uid),'--regid='+str(uid),'--clear-groups',
            '--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',sys.executable,'-I','-B','-c',code,
            '--role',mode,'--base',str(base),*extra]
        def worker(uid,mode,ns=None):
            p=subprocess.run(argv(uid,mode),capture_output=True,env=env,timeout=120)
            if p.returncode:raise ValueError('CLOSED_ROLE_FAILED:'+mode+':'+p.stderr.decode()[-2500:])
            return n.parse(p.stdout)
        def spawn(uid,mode,ns,ready,expected='ready',extra=()):
            process=subprocess.Popen(argv(uid,mode,extra),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env)
            processes.append(process);until=time.monotonic()+20
            while time.monotonic()<until:
                if process.poll() is not None:raise ValueError('SERVICE_FAILED:'+mode+':'+process.stderr.read().decode()[-2500:])
                if ready.exists() and ready.read_text()==expected:
                    if mode=='backend':
                        rejected.extend(worker(uid,'unix-probe') for uid in TARGETS.values() if uid!=n.CUSTODY)
                        need(u.effects(base)==[])
                    return process
                time.sleep(0.05)
            raise ValueError('SERVICE_READY_TIMEOUT')
        token=secrets.token_hex(16);installed=False;rejected=[]
        output=base/'reports';output.mkdir()
        try:
            ingress.enroll(base,'success',certificates,worker,None)
            authority.enroll(base);b.enroll(base,worker,None);retained.enroll(base,worker,None)
            signed.enroll(base,worker,None,github_mtls=True)
            with e.sinks() as endpoints:
                baseline=u.probe_ip(TARGETS,endpoints,binaries);u.validate_flows(baseline,TARGETS,False)
                u.guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--check','--file','-'],u.rules(token))
                e.execute([binaries['nft'],'--file','-'],u.rules(token));installed=True
                before=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]));u.validate_policy(before)
                denied=u.probe_ip(TARGETS,endpoints,binaries,lambda:u.counters(binaries));u.validate_flows(denied,TARGETS,True)
                control=u.probe_ip(dict(administrator=0),endpoints,binaries);u.validate_flows(control,dict(administrator=0),False)
                # All application actors share this live isolated namespace, only lo exists.
                topology=dict(isolated=dict(links=json.loads(e.execute([binaries['ip'],'--json','link','show'])),
                    routes=json.loads(e.execute([binaries['ip'],'--json','route','show'])),
                    routes6=json.loads(e.execute([binaries['ip'],'-6','--json','route','show']))))
                execution=exercise(base,worker,spawn)
                post=u.probe_ip(TARGETS,endpoints,binaries,lambda:u.counters(binaries));u.validate_flows(post,TARGETS,True)
                final=u.counters(binaries)
                policy=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]));u.validate_policy(policy)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode());installed=False
                after=u.probe_ip(TARGETS,endpoints,binaries);u.validate_flows(after,TARGETS,False)
            report=dict(schema=PROFILE,scope=SCOPE,audited_commit=head,sources=sources(),external_pins=PINS,
                namespace=e.namespace(),parent_namespace=parent_ns,isolation_lifetime=f.lifetime(parent_pid),loopback_only=True,host_rules_applied=False,
                target_uids=TARGETS,phases=dict(baseline=baseline,denied=denied,root_control=control,post_native_denied=post,after_removal=after),
                final_kernel_packets={str(k):v for k,v in final.items()},installed_policy_before=before,installed_policy_after=policy,
                execution=execution,execution_sha256=n.digest(execution),topology=topology,
                views=u.read_lines(base/'issuer/ack-loss-views.jsonl'),effects=u.effects(base),
                status_transcript=u.read_lines(base/'custody/unix-tls-status.jsonl'),
                unix_peer_probes=rejected,backend_peer_denials=u.read_lines(base/'backend/unix-peer-denials.jsonl'),
                backend_sni=u.read_lines(base/'backend/unix-tls-sni.jsonl'),table_removed=True,limitations=limits())
            return validate(report)
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                if process.stderr:process.stderr.close()
            if installed:
                u.guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode())
            signed.cleanup(base);retained.cleanup(base)


def limits():
    return dict(m.limitations(),raw_backend_response_loss_tested=True,real_provider_completion_loss_tested=False,
        backend_restart_tested=False,uncertain_custody_reopen_only=True,repair_or_retry_permission_issued=False)


def validate(r):
    need(r['schema']==PROFILE and r['scope']==SCOPE and r['sources']==sources() and r['external_pins']==PINS)
    f.validate_lifetime(r['isolation_lifetime'])
    need(r['namespace']!=r['parent_namespace'] and r['loopback_only'] is True and r['host_rules_applied'] is False
         and r['table_removed'] is True and r['target_uids']==TARGETS and r['limitations']==limits())
    for name in ('baseline','after_removal'):u.validate_flows(r['phases'][name],TARGETS,False)
    for name in ('denied','post_native_denied'):u.validate_flows(r['phases'][name],TARGETS,True)
    u.validate_flows(r['phases']['root_control'],dict(administrator=0),False)
    need(f.policy_identity(r['installed_policy_before'])==f.policy_identity(r['installed_policy_after']))
    need(set(r['final_kernel_packets'])=={str(x) for x in TARGETS.values()}
         and all(type(x) is int and x>=8 for x in r['final_kernel_packets'].values()))
    t=r['topology'];need(set(t)=={'isolated'} and len(t['isolated']['links'])==1
         and t['isolated']['links'][0]['ifname']=='lo' and t['isolated']['routes']==t['isolated']['routes6']==[])
    v=r['execution'];need(n.digest(v)==r['execution_sha256']);validate_execution(v,r['namespace'])
    f.validate_views(r['views'],v['enrollment'],v['model'],v['after'],r['namespace'])
    need(r['effects']==v['rows_after']['effects'])
    peer_rows=[x['peer'] for x in v['events_after'] if x['phase']=='API_PEER_VERIFIED']
    need(len(peer_rows)==1 and len(r['status_transcript'])>=3 and len(r['backend_sni'])==len(r['status_transcript'])+1)
    for p in peer_rows+r['status_transcript']:
        need(p['transport']=='TLS_OVER_AF_UNIX_NO_IP' and p['client_uid']==n.CUSTODY and p['server_uid']==n.BACKEND
            and p['namespace']==r['namespace'] and p['leaf_sha256']==v['manifest']['execution']['local_leaf_sha256']
            and p['hostname']==tls.NAME and p['certificate_required'] is p['hostname_checked'] is True
            and p['tls_version'] in ('TLSv1.2','TLSv1.3'))
    need(all(x['method']=='GET' and x['path']=='/status/A0' and x['status']==200 for x in r['status_transcript'])
         and all(x['hostname']==tls.NAME for x in r['backend_sni']))
    wrong=set(TARGETS.values())-{n.CUSTODY}
    need(len(r['unix_peer_probes'])==len(r['backend_peer_denials'])==7
         and {x['uid'] for x in r['unix_peer_probes']}=={x['uid'] for x in r['backend_peer_denials']}==wrong)
    need(all(x['namespace']==r['namespace'] and x['effect'] is False for x in r['backend_peer_denials']))
    return r


def run(output,acknowledge=False):
    need(acknowledge is True);e.require_root();sources()
    need(not signed.required() and not retained.required())
    need(not output.exists() and output.resolve().is_relative_to(ROOT))
    for uid in (*TARGETS.values(),signed.LEDGER):
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
    with tempfile.TemporaryDirectory(prefix='native-bounded-unix-source-',dir='/run') as tmp:
        stage=Path(tmp);stage.chmod(0o755);source=stage/'source'
        u.export(git+['archive','HEAD'],source)
        for name,subtree in [('agentdojo','src/agentdojo'),('rcc','external-eval/v0.3.9/src'),('veritas','veritas_os')]:
            repo=ROOT/'_pins'/name
            u.export(['git','-c','safe.directory='+str(repo),'-C',str(repo),'archive',PINS[name],subtree],source/'_pins'/name)
        for file in source.rglob('*'):file.chmod(0o555 if file.is_dir() else 0o444)
        source.chmod(0o555)
        code=('import sys,json,subprocess;sys.path.insert(0,'+repr(str(source))+');'
            'from scripts.task4_native_backend_response_loss_v1 import _supervise,e;from pathlib import Path;'
            'e.require_root();e.need(e.namespace()!=json.loads(sys.argv[2]) and '
            'e.namespace(int(sys.argv[1]))==json.loads(sys.argv[2]),"ISOLATED_BEFORE_LO_UP");'
            'subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True);'
            'print(json.dumps(_supervise(int(sys.argv[1]),json.loads(sys.argv[2]),Path(sys.argv[3]),sys.argv[4]),sort_keys=True))')
        args=[binaries['unshare'],'--net','--',sys.executable,'-I','-B','-c',code,
              str(parent_pid),json.dumps(parent_ns),str(source),head]
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,start_new_session=True)
        try:stdout,stderr=process.communicate(timeout=300)
        except BaseException:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5);raise
        
        if process.returncode:raise ValueError('BOUNDED_UNIX_SUPERVISOR_STOP:'+stderr.decode()[-3500:])
        report=validate(json.loads(stdout))
    need(e.namespace()==parent_ns)
    # Names are only a negative control for this fixture's non-host-apply claim.
    need(e.execute([binaries['nft'],'--json','--numeric','list','tables'])==parent_tables)
    output.mkdir(parents=True)
    (output/'report.json').write_bytes(n.canonical(report))
    checks=('actual_first_sdk_request_stops_on_committed_backend_loss', 'one_durable_backend_effect_no_duplicate', 'no_native_response_scorer_or_continuation', 'consume_before_bind_and_post', 'real_bind_apply_failed_does_not_mean_no_effect', 'raw_zero_bytes_sealed_before_http_parse', 'fresh_archive_owner_recovers_exact_observed_bytes', 'signed_reserve_consume_receipts_and_model_readback', 'three_sigkills_reopen_same_unknown_state', 'pending_issuer_no_reissue', 'custody_replay_refused_without_network_post', 'readonly_backend_reconciliation_no_permission', 'same_live_policy_all_actor_counter_denials', 'seven_wrong_backend_uids_refused', 'no_host_policy_apply', 'no_provider_operator_or_remote_github')
    suite=ET.Element('testsuite',name='Native backend commit response loss',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_backend_response_loss',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    return report





def main(argv=None):
    if '--role' in sys.argv[1:] and argv is None:
        base=Path(sys.argv[sys.argv.index('--base')+1]);mode=sys.argv[sys.argv.index('--role')+1]
        m.install_transport(base);fixture(base);n.TLS_BASE=base
        roles={'loss-native':native_stop,'loss-replay':replay,'loss-reconcile':reconcile,
               'loss-custody-reopen':custody_reopen,'signed-ledger-view':f.view_evidence,'unix-probe':u.unix_probe}
        if mode in roles:
            value=roles[mode](base)
            if value is not None:print(n.canonical(value).decode('ascii'))
            return
        if mode=='backend':tls.server_class=server_class
        return n.main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--acknowledge-isolated-backend-response-loss-test',action='store_true')
    args=parser.parse_args(argv);need(args.run and args.output is not None)
    run(args.output,args.acknowledge_isolated_backend_response_loss_test)
    print('ACTUAL_NATIVE_BACKEND_COMMIT_RESPONSE_LOST_ONE_EFFECT_RESTART_NO_RETRY_NO_PROVIDER')


if __name__=='__main__':main()

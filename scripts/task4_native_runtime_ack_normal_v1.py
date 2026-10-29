"""Closed positive control: original archive boundaries on eight real Native steps.

Explicit receive/archive observers; original SDK, authority, Bind, sealer, parser,
signed-ledger protocol and local scripted backend remain frozen. No live grant.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import task4_native_bounded_unix_egress_v1 as m
from scripts import task4_native_total_deadline_v1 as deadline
from scripts import task4_native_deadline_normal_v1 as oldnormal
from scripts import task4_native_response_id_guard_v1 as guard
from scripts import task4_native_response_framing_guard_v1 as frame
from scripts import task4_native_runtime_ack_fixture_v1 as storage
import copy
u,b,retained,signed,github,ingress,authority,tls=m.u,m.b,m.retained,m.signed,m.github,m.ingress,m.authority,m.tls
e,n,ROOT,ENV,PINS,TARGETS,TABLE=m.e,m.n,m.ROOT,m.ENV,m.PINS,m.TARGETS,m.TABLE
need=m.need
PROFILE='task4.native-runtime-ack-normal.v1'
SCOPE='SYNTHETIC_ISOLATED_NORMAL_NATIVE_RUNTIME_FULL_ACK_NO_PROVIDER'
MARKER=m.MARKER
TRACE='custody/runtime-ack-normal.jsonl'
FRAME_PIN='8c5817c66ca7402db5a79aa49585aeb9116976e758fa114519d709b2384178da'
STORAGE_PIN='5a5a7e0ed384f401c956b88bc98df03647b0b3afed59d558002257e34819bdf7'
GUARD_PIN='2379effd339b49fc4ee311658bfc0f6e0888e4fe66695c92e8fa44a7c209f9fc'
OLD_NORMAL_PIN='d5bee33c2e3bee163d8f2e60717e6fbcd4abe98e627b038fb564e1472d62fb8b'
DEADLINE_PIN='9e3fbf3d99c6f93270176d6d21cafd7bb73ee4f08c18cbd5809967a360f90721'
NORMAL_PIN='95fc88a0da2fc198172de2a47246106a6aa7361a4590ab2cee52c8f01a2b88a2'


def source_sha256():return e.sha(Path(__file__).read_bytes())


def sources():
    need(guard.source_sha256()==GUARD_PIN and oldnormal.source_sha256()==OLD_NORMAL_PIN and frame.source_sha256()==FRAME_PIN and storage.source_sha256()==STORAGE_PIN)
    return dict(profile=source_sha256(),normal_profile=oldnormal.sources(),id_guard=guard.source_sha256(),framing_guard=frame.source_sha256(),archive_fixture=storage.source_sha256())


def limits():
    return dict(m.limitations(),fixed_total_deadline_normal_path_tested=True,
        capture_override='task4_native_total_deadline_v1.bounded_capture',
        full_runtime_attestation=False,hard_realtime_deadline_proven=False,strict_response_id_guard_applied=True,strict_framing_guard_applied=True,original_archive_boundaries_observed=True,write_flush_close_observed=True,handler_return_observed=True,complete_native_reply_send_observed=True,original_frame_rpc_and_sdk_returns_observed=True,
        backend_restart_or_power_loss_tested=False,operator_native_ready=False)


def dispatch(base,packet,request,key):
    """Replace only receive collection, delegate original verified dispatch unchanged."""
    m.fixture(base);n.kernel.role_identity(n.CUSTODY)
    op=packet['arm']+str(packet['ordinal'])
    raw=ingress.raw
    capture,seal,parse,connection=raw.capture,raw.seal,raw.parse_wire,m.connection
    def emit(phase,**data):
        u.append(base/TRACE,dict(op=op,phase=phase,uid=os.geteuid(),namespace=e.namespace(),**data))
    def collect(channel):
        wire,completion,collection=deadline.bounded_capture(channel)
        emit('CAPTURE',collection=collection,
            channel_open=stat.S_ISSOCK(os.fstat(channel.fileno()).st_mode),
            restored_timeout_seconds=channel.gettimeout())
        return wire,completion
    def connect(path):
        conn=connection(path);close=conn.close
        def observed_close():
            channel=conn.sock;started=time.monotonic_ns()
            result=close();finished=time.monotonic_ns()
            emit('CLOSE',started_ns=started,finished_ns=finished,
                socket_closed=channel is not None and channel.fileno()==-1,
                connection_socket_cleared=conn.sock is None)
            return result
        conn.close=observed_close
        return conn
    def sealed(*args,**kwargs):
        archive=storage.audit_seal(seal,*args,**kwargs,fault='normal',emit=lambda row:u.append(base/'custody/seal-audit.jsonl',row),ack_emit=lambda row:u.append(base/'custody/ack-events.jsonl',row))
        emit('SEALED',finished_ns=time.monotonic_ns(),archive=archive)
        return archive
    def parsed(wire,completion):
        started=time.monotonic_ns()
        status,headers,body=parse(wire,completion)
        id_guard_result=guard.require_one_id(headers)
        framing_guard_result=frame.require_framing(wire)
        emit('PARSED',started_ns=started,finished_ns=time.monotonic_ns(),
            raw_sha256=e.sha(wire),response_sha256=e.sha(body),status=status,
            request_id=dict(headers).get('X-Request-Id'),id_guard_result=id_guard_result,framing_guard_result=framing_guard_result)
        return status,headers,body
    try:
        raw.capture,raw.seal,raw.parse_wire,m.connection=collect,sealed,parsed,connect
        return m.dispatch(base,packet,request,key)
    finally:
        raw.capture,raw.seal,raw.parse_wire,m.connection=capture,seal,parse,connection


def validate_trace(trace,normal,namespace):
    need(type(trace) is list and len(trace)==32)
    projected=copy.deepcopy(trace)
    captures={row['op']:row['collection'] for row in trace if row['phase']=='CAPTURE'}
    for row in projected:
        if row['phase']=='PARSED':
            result=row.pop('id_guard_result');framing=row.pop('framing_guard_result')
            wire=n.decode(captures[row['op']]['observed_b64'])
            _,headers,_=ingress.raw.parse_wire(wire,'eof')
            need(n.canonical(framing)==n.canonical(frame.require_framing(wire)))
            need(result==guard.require_one_id(headers))
            need(result==dict(field_count=1,request_id='native-local-'+row['op'])
                 and result['request_id']==row['request_id'])
    return oldnormal.validate_trace(projected,normal,namespace)


def validate_archive_audits(audits,trace,normal):
    need(type(audits) is list and len(audits)==120)
    evidence=normal['native']['evidence'];plan=evidence['manifest']['execution']
    for i,op in enumerate(a+str(j) for a in 'AB' for j in range(4)):
        cap,closed,sealed,parsed=trace[4*i:4*i+4];wire=n.decode(cap['collection']['observed_b64']);events=audits[15*i:15*i+15]
        post=next(x for x in evidence['posts'] if x['op']==op)
        p=dict(run_id=plan['run_id'],request_sha256=post['request_sha256'],recipient_sha256=plan['raw_recipient_sha256'])
        storage.validate_audit(events,wire,p,op,'normal',normal['namespace'],events[-1]['snapshot'])
        need(closed['finished_ns']<=events[0]['at_ns']<=events[-1]['at_ns']<=sealed['finished_ns']<=parsed['started_ns']
             and events[-1]['archive']==sealed['archive'])
    return True


def validate_acks(events,audits,trace,normal):
    need(type(events) is list and len(events)==16)
    v=normal['native']['evidence']
    for i,op in enumerate(a+str(j) for a in 'AB' for j in range(4)):
        record=next(x for x in v['native']['records'] if x['arm']+str(x['ordinal'])==op)
        reply=dict(decision='ARCHIVED_NATIVE_RESPONSE',body_b64=events[2*i+1]['reply']['body_b64'],archive=record['archive'])
        need(e.sha(n.decode(reply['body_b64']))==record['response_sha256'])
        row=next(x for x in v['consumed'] if x[0]==op)
        storage.validate_ack(events[2*i:2*i+2],op,normal['namespace'],'normal',audits[15*i:15*i+15],audits[15*i+14]['snapshot'],row,reply)
        need(events[2*i]['at_ns']<=trace[4*i+2]['finished_ns'] and trace[4*i+3]['finished_ns']<=events[2*i+1]['at_ns'])
    return True


def validate(report):
    need(set(report)=={'schema','scope','audited_commit','sources','capture_override','normal',
        'trace','trace_sha256','normal_sha256','archive_audit','ack_events','send_events','runtime_events','limitations'})
    need(report['schema']==PROFILE and report['scope']==SCOPE and report['sources']==sources()
         and report['limitations']==limits() and report['capture_override']==limits()['capture_override'])
    normal=report['normal'];m.validate(normal)
    need(report['audited_commit']==normal['audited_commit'] and report['normal_sha256']==n.digest(normal)
         and report['trace_sha256']==n.digest(report['trace']))
    validate_trace(report['trace'],normal,normal['namespace'])
    validate_archive_audits(report['archive_audit'],report['trace'],normal)
    validate_acks(report['ack_events'],report['archive_audit'],report['trace'],normal)
    validate_sends(report['send_events'],report['ack_events'],normal['namespace'])
    validate_runtime(report['runtime_events'],report['ack_events'],normal)
    return report


def validate_sends(events,acks,namespace):
    need(type(events) is list and len(events)==8)
    for i,op in enumerate(arm+str(j) for arm in 'AB' for j in range(4)):
        storage.validate_send(events[i],acks[2*i+1]['reply'],op,namespace,'normal',acks[2*i+1]['at_ns'])
    need(len({x['pid'] for x in events})==1)
    return True


def validate_runtime(events,acks,normal):
    native=normal['native']['evidence']['native']
    replies=[x['reply'] for x in acks if x['phase']=='CONSUME_RETURNED']
    storage.validate_events(events,'normal',normal['namespace'],replies,events[0]['pid'],native_result=native)
    return True


def wrap(normal,trace,archive_audit,ack_events,send_events,runtime_events):
    report=dict(schema=PROFILE,scope=SCOPE,audited_commit=normal['audited_commit'],sources=sources(),
        capture_override=limits()['capture_override'],normal=normal,trace=trace,
        trace_sha256=n.digest(trace),normal_sha256=n.digest(normal),archive_audit=archive_audit,ack_events=ack_events,send_events=send_events,runtime_events=runtime_events,limitations=limits())
    return validate(report)

def _supervise(parent_pid,parent_ns,source,head):
    binaries=e.tools();u.guard(parent_pid,parent_ns,binaries);sources();processes=[]
    need(not signed.required() and not retained.required())
    with tempfile.TemporaryDirectory(prefix='native-bounded-unix-fixture-',dir='/run') as tmp:
        base=Path(tmp);base.chmod(0o755)
        for name,uid in [('native',n.NATIVE),('issuer',n.ISSUER),('custody',n.CUSTODY),('backend',n.BACKEND),
                         ('ipc',n.CUSTODY),('backend-ipc',n.BACKEND)]:
            folder=base/name;folder.mkdir(mode=0o755 if name.endswith('ipc') else 0o700);os.chown(folder,uid,uid)
        (base/'public').mkdir(mode=0o755)
        (base/MARKER).write_text(m.SCOPE);(base/MARKER).chmod(0o444)
        certificates=tls.enroll(base)
        credential=secrets.token_bytes(32)
        for name,uid in [('backend',n.BACKEND),('custody',n.CUSTODY)]:
            file=base/name/'credential';file.write_bytes(credential);file.chmod(0o600);os.chown(file,uid,uid)
        paths=[source,source/'scripts',source/'_pins/agentdojo/src',source/'_pins/veritas',source/'_pins/rcc/external-eval/v0.3.9/src']
        code='import sys;sys.path[:0]='+repr([str(x) for x in paths])+';from scripts.task4_native_runtime_ack_normal_v1 import main;main()'
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
                # Existing bounded exercise runs real SDK, 50 negatives, three role restarts,
                # 16 replay refusals, 16 signed mutations and fresh archive-owner recovery.
                b.exercise(base,output,worker,spawn,None,None,None,head,PINS,topology)
                native=json.loads((output/'report.json').read_bytes())
                integration=json.loads((output/'signed-ledger-integration.json').read_bytes())
                model=json.loads((output/'native-github-mtls.json').read_bytes())
                post=u.probe_ip(TARGETS,endpoints,binaries,lambda:u.counters(binaries));u.validate_flows(post,TARGETS,True)
                final=u.counters(binaries)
                policy=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]));u.validate_policy(policy)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode());installed=False
                after=u.probe_ip(TARGETS,endpoints,binaries);u.validate_flows(after,TARGETS,False)
            report=dict(schema=m.PROFILE,scope=m.SCOPE,audited_commit=head,sources=m.sources(),external_pins=PINS,
                namespace=e.namespace(),parent_namespace=parent_ns,loopback_only=True,host_rules_applied=False,
                target_uids=TARGETS,phases=dict(baseline=baseline,denied=denied,root_control=control,post_native_denied=post,after_removal=after),
                final_kernel_packets={str(k):v for k,v in final.items()},installed_policy_before=before,installed_policy_after=policy,
                native=native,integration=integration,model=model,
                status_transcript=u.read_lines(base/'custody/unix-tls-status.jsonl'),
                unix_peer_probes=rejected,backend_peer_denials=u.read_lines(base/'backend/unix-peer-denials.jsonl'),
                backend_sni=u.read_lines(base/'backend/unix-tls-sni.jsonl'),table_removed=True,limitations=m.limitations())
            return wrap(m.validate(report),u.read_lines(base/TRACE),u.read_lines(base/'custody/seal-audit.jsonl'),u.read_lines(base/'custody/ack-events.jsonl'),u.read_lines(base/'custody/native-send.jsonl'),u.read_lines(base/'runtime/runtime-ack-events.jsonl'))
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                if process.stderr:process.stderr.close()
            if installed:
                u.guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode())
            signed.cleanup(base);retained.cleanup(base)


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
            'from scripts.task4_native_runtime_ack_normal_v1 import _supervise,e;from pathlib import Path;'
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
    checks=('eight_original_frame_rpc_sdk_returns_and_native_completion','seal_return_only_after_directory_fsync','original_descriptor_pinned_archive_snapshots','eight_exact_eof_content_length_guards','eight_occurrence_preserving_single_id_guards','eight_fixed_deadline_eof_collections','exact_received_wire_parser_body_join','capture_close_write_flush_file_fsync_close_directory_fsync_parse_order','eight_owner_aead_archive_joins','eight_actual_sdk_changing_histories','two_native_terminals_and_scorers','sixteen_signed_model_mutations','signed_parent_tool_archive_chain','fifty_real_issuer_denials','ledger_issuer_kill_reopen_terminal_denial','custody_restart_sixteen_replay_denials','all_eight_actor_ip_denials_retained','unix_tls_uid_ca_hostname_leaf_pins','original_bind_blocked_and_committed','no_host_policy_apply','no_real_provider_or_operator_execution')
    suite=ET.Element('testsuite',name='Normal Native with original archive boundary audit',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_archive_audit_normal',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    return report


def main(argv=None):
    if '--role' in sys.argv[1:] and argv is None:
        index=sys.argv.index('--base');base=Path(sys.argv[index+1]);m.install_transport(base)
        ingress.dispatch=dispatch
        storage.install(base,'normal',lambda row:u.append(base/'custody/native-send.jsonl',row),lambda row:u.append(base/'custody/ack-events.jsonl',row))
        original=b.consume_packet
        b.consume_packet=lambda *args:storage.consume(original,*args,fault='normal',emit=lambda row:u.append(base/'custody/ack-events.jsonl',row))
        if sys.argv[sys.argv.index('--role')+1]=='bounded-native':
            value=storage.native(b.native,base,'normal',lambda row:u.append(base/'runtime/runtime-ack-events.jsonl',row))
            print(n.canonical(value).decode('ascii'));return
        if sys.argv[sys.argv.index('--role')+1]=='unix-probe':
            print(n.canonical(u.unix_probe(base)).decode('ascii'));return
        return n.main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--acknowledge-isolated-runtime-ack-normal-test',action='store_true')
    args=parser.parse_args(argv)
    need(args.run and args.output is not None)
    run(args.output,args.acknowledge_isolated_runtime_ack_normal_test)
    print('NORMAL_NATIVE_RUNTIME_FRAME_RPC_SDK_RETURN_EIGHT_STEPS_NO_PROVIDER')


if __name__=='__main__':main()

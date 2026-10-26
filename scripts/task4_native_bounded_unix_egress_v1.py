"""Closed CI: changing Native histories, Bind, raw TLS archive and signed ledger.

Explicit Unix TLS transport injection only. No operator enrollment, host policy,
remote GitHub, Provider HTTP client fallback or live execution permission.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import task4_native_unix_egress_v1 as u
from scripts import task4_native_bounded_continuation_v1 as b
from scripts import task4_native_retained_authority_v1 as retained
from scripts import task4_native_signed_ledger_integration_v1 as signed
from scripts import task4_native_github_mtls_v1 as github
from scripts import task4_native_raw_ingress_v1 as ingress
from scripts import task4_native_raw_authority_v1 as authority
from scripts import task4_native_local_https_v1 as tls

e,n=u.e,u.n
ROOT=u.ROOT
ENV=u.ENV
PINS=u.PINS
TARGETS=u.TARGETS
TABLE=u.TABLE
PROFILE='task4.native-bounded-unix-egress.v1'
SCOPE='SYNTHETIC_ISOLATED_BOUNDED_NATIVE_UNIX_TLS_SIGNED_MODEL_NO_PROVIDER'
MARKER='public/bounded-unix-tls-v1'
need=u.need
FROZEN={'task4_native_unix_egress_v1': 'f57dd7d8ebe70e89b37a9223960373a4b671b4e66f08f4b12f42a123bd06c1e4', 'task4_native_os_custody_v1': 'b1fb7b407b3c4eaa24ecc9e0746cae9bf4b6cfdb2e379b6f6687bdca17be038d', 'task4_native_egress_rehearsal_v1': 'f6865825a1f7435a1821e56f3e2e64db806c4ffad23f402d21cba8b394e48857', 'task4_native_bounded_continuation_v1': 'bdc01f86a76004baed7fb47d83831b3d50320895f4870020a077ad6a35f1431c', 'task4_native_retained_authority_v1': '532fd0fed585b2c19ae3302dc0bee53b230ec079066a1bf4898ae557070ce060', 'task4_native_signed_ledger_gate_v1': '0149f1a8e7189f2abcbf8edf8a3323eff631dd312aad76b6b8b6b0352276612a', 'task4_native_signed_ledger_integration_v1': 'ccc2c877f2149114df9a74a1c38cad7e684c6f14e0297ad2934e280919b7dd1b', 'task4_native_github_mtls_v1': '25e257bec12c88cde674a1c1780f17e1eb519b35e37e24fefe651af84605bce1', 'task4_native_raw_ingress_v1': 'ce3824929114b2e6b520ad31caffbb0b9fb834bd481632bcd06d3671fa27827f', 'task4_provider_shaped_raw_ingress_v1': '7a09c9a6c24cb40ab7443104714fd2d5c227b5a295d14a1d1a4c30c1d0ca2cbc', 'task4_native_raw_authority_v1': '2ecad1f0bf8e436a1dd886c88b2df7fb9b20a30fc1abfb81daad754679879e01', 'task4_native_local_https_v1': 'd3e8dc134fe451157c289f60211cf257ba06f42720d249381dc202d8d980df6f', 'task4_default_https_denial_v1': '5d7aa78a5cf09922eb0f60178ada45d3aefb591d1c09ffdde0f44d104f026320', 'task4_external_ledger_contract_v1': 'c91f4b95c99f8cf217b73bfb0b3333243e87cb324c7d2da7002f841ba799a95b', 'task4_signed_github_ledger_v1': '9982c61d32103c73c92ffc6b072c24ca15a25f23018c1a4faa2214ffbd0b27ea'}


def source_sha256():return e.sha(Path(__file__).read_bytes())


def sources():
    current={name:e.sha((ROOT/'scripts'/(name+'.py')).read_bytes()) for name in FROZEN}
    need(current==FROZEN)
    return dict(profile=source_sha256(),frozen=current)


def fixture(base):
    base=Path(base);s=base.lstat();f=base/MARKER;t=f.lstat()
    need(base.parent==Path('/run') and base.name.startswith('native-bounded-unix-fixture-')
         and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o755
         and stat.S_ISREG(t.st_mode) and t.st_uid==0 and t.st_nlink==1
         and stat.S_IMODE(t.st_mode)==0o444 and f.read_text()==SCOPE)


def connection(base):
    """No resolver, IP socket or fallback. Authenticate kernel UID before TLS."""
    fixture(base);n.kernel.role_identity(n.CUSTODY)
    context=ssl.create_default_context(cafile=str(base/'public/ca.pem'))
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    need(context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname)
    class Connection(http.client.HTTPConnection):
        default_port=443
        def connect(self):
            raw=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                raw.settimeout(5);raw.connect(str(u.backend_path(base)))
                need(u.peer_uid(raw)==n.BACKEND)
                self.sock=context.wrap_socket(raw,server_hostname=tls.NAME)
                need(e.sha(self.sock.getpeercert(binary_form=True))==ingress.plan(base)['leaf_sha256'])
            except BaseException:
                raw.close()
                if self.sock is not None:self.sock.close()
                raise
    return Connection(tls.NAME,443,timeout=5)


def peer(conn):
    return dict(transport='TLS_OVER_AF_UNIX_NO_IP',client_uid=os.geteuid(),server_uid=u.peer_uid(conn.sock),
        namespace=e.namespace(),leaf_sha256=e.sha(conn.sock.getpeercert(binary_form=True)),
        tls_version=conn.sock.version(),hostname=tls.NAME,certificate_required=True,hostname_checked=True)


def status_call(base,method,path,body,key):
    need(method=='GET' and type(path) is str and path.startswith('/status/') and body is None)
    conn=connection(base)
    try:
        conn.connect();observation=peer(conn)
        conn.request(method,path,headers={'Content-Type':'application/json',
            'X-Mock-Auth':n.kernel.tag(key,b'TASK4_NATIVE_HTTP_V1\0',dict(method=method,path=path,body=None))})
        reply=conn.getresponse();content=reply.read(n.LIMIT+1);need(len(content)<=n.LIMIT)
        u.append(base/'custody/unix-tls-status.jsonl',dict(observation,method=method,path=path,
            status=reply.status,response_sha256=e.sha(content)))
        return reply.status,n.parse(content)
    finally:conn.close()


def server_class(base):
    fixture(base);n.kernel.role_identity(n.BACKEND)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(base/'backend/cert.pem',base/'backend/key.pem')
    context.set_servername_callback(lambda _,name,__:u.append(base/'backend/unix-tls-sni.jsonl',dict(hostname=name)))
    class Server(socketserver.UnixStreamServer):
        def __init__(self,address,handler):
            need(address==(tls.IP,tls.PORT) and not os.path.lexists(u.backend_path(base)))
            super().__init__(str(u.backend_path(base)),handler);os.chmod(u.backend_path(base),0o666)
        def get_request(self):
            raw,address=super().get_request();uid=u.peer_uid(raw)
            if uid!=n.CUSTODY:
                u.append(base/'backend/unix-peer-denials.jsonl',dict(uid=uid,namespace=e.namespace(),effect=False))
                raw.close();raise OSError('UNIX_PEER_REFUSED')
            raw.settimeout(5)
            try:return context.wrap_socket(raw,server_side=True),address
            except BaseException:raw.close();raise
    return Server


def dispatch(base,packet,request,key):
    """Transport adapter; consume/signature, raw capture, fsync and parser gates retained."""
    n.kernel.role_identity(n.CUSTODY);p=ingress.plan(base);op=packet['arm']+str(packet['ordinal'])
    need(n.verify(packet,(base/'public/issuer-key').read_bytes())==request)
    import sqlite3
    with sqlite3.connect((base/'custody/ledger.sqlite3').resolve().as_uri()+'?mode=ro',uri=True) as db:
        need(db.execute('SELECT state,request_sha FROM consumed WHERE op=?',(op,)).fetchone()==('CONSUMED_UNKNOWN',e.sha(request)))
    conn=connection(base)
    try:
        conn.connect();ingress.emit(base,op,'API_PEER_VERIFIED',peer=peer(conn))
        # Recheck signed execution time/context at the actual POST boundary.
        n.verify(packet,(base/'public/issuer-key').read_bytes())
        conn.request('POST',ingress.raw.PATH,body=request,headers={'Content-Type':'application/json',
            'Authorization':'Bearer LOCAL_ONLY_'+key.hex(),'X-Client-Request-Id':p['run_id']+'-'+op,
            'Connection':'close','Accept-Encoding':'identity'})
        ingress.emit(base,op,'API_POST_ATTEMPTED',request_sha256=e.sha(request))
        conn.sock.settimeout(0.7);wire,completion=ingress.raw.capture(conn.sock)
    finally:conn.close()
    ingress.emit(base,op,'RAW_OBSERVED',raw_sha256=e.sha(wire),observed_bytes=len(wire),capture_completion=completion)
    archive=ingress.raw.seal(base,op,wire,completion,dict(p,request_sha256=e.sha(request)))
    ingress.emit(base,op,'SEALED_FSYNCED',archive=archive)
    need(completion=='eof' and len(wire)<=ingress.raw.LIMIT)
    ingress.emit(base,op,'HTTP_PARSE_STARTED')
    status,headers,body=ingress.raw.parse_wire(wire,completion)
    need(dict(headers).get('X-Request-Id')=='native-local-'+op)
    record=dict(operation_id=op,request_sha256=e.sha(request),response_sha256=e.sha(body))
    ingress.emit(base,op,'BODY_RELEASED_TO_BIND',response_sha256=e.sha(body))
    return status,dict(record,receipt_sha256=n.digest(record),response_b64=n.encode(body))


def install_transport(base):
    fixture(base)
    # Only fixture transport dependencies; no signature/policy/consume/Bind/SDK replacement.
    tls.call=status_call
    tls.server_class=server_class
    ingress.dispatch=dispatch


def limitations():
    return dict(provider_dispatch='DENY',utility='UNSCORED',real_provider_posts=0,
        external_bank_effects=0,operator_vm_trial_executed=False,operator_credentials_loaded=False,
        remote_github_experiment_executed=False,retained_operator_service_integrated=False,
        production_bypass_resistance_proven=False,independent_administration_proven=False,
        real_data_confidentiality_proven=False,host_trial_lease_integrated=False,
        live_execution_permission_issued=False)


def _supervise(parent_pid,parent_ns,source,head):
    binaries=e.tools();u.guard(parent_pid,parent_ns,binaries);sources();processes=[]
    need(not signed.required() and not retained.required())
    with tempfile.TemporaryDirectory(prefix='native-bounded-unix-fixture-',dir='/run') as tmp:
        base=Path(tmp);base.chmod(0o755)
        for name,uid in [('native',n.NATIVE),('issuer',n.ISSUER),('custody',n.CUSTODY),('backend',n.BACKEND),
                         ('ipc',n.CUSTODY),('backend-ipc',n.BACKEND)]:
            folder=base/name;folder.mkdir(mode=0o755 if name.endswith('ipc') else 0o700);os.chown(folder,uid,uid)
        (base/'public').mkdir(mode=0o755)
        (base/MARKER).write_text(SCOPE);(base/MARKER).chmod(0o444)
        certificates=tls.enroll(base)
        credential=secrets.token_bytes(32)
        for name,uid in [('backend',n.BACKEND),('custody',n.CUSTODY)]:
            file=base/name/'credential';file.write_bytes(credential);file.chmod(0o600);os.chown(file,uid,uid)
        paths=[source,source/'scripts',source/'_pins/agentdojo/src',source/'_pins/veritas',source/'_pins/rcc/external-eval/v0.3.9/src']
        code='import sys;sys.path[:0]='+repr([str(x) for x in paths])+';from scripts.task4_native_bounded_unix_egress_v1 import main;main()'
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
            report=dict(schema=PROFILE,scope=SCOPE,audited_commit=head,sources=sources(),external_pins=PINS,
                namespace=e.namespace(),parent_namespace=parent_ns,loopback_only=True,host_rules_applied=False,
                target_uids=TARGETS,phases=dict(baseline=baseline,denied=denied,root_control=control,post_native_denied=post,after_removal=after),
                final_kernel_packets={str(k):v for k,v in final.items()},installed_policy_before=before,installed_policy_after=policy,
                native=native,integration=integration,model=model,
                status_transcript=u.read_lines(base/'custody/unix-tls-status.jsonl'),
                unix_peer_probes=rejected,backend_peer_denials=u.read_lines(base/'backend/unix-peer-denials.jsonl'),
                backend_sni=u.read_lines(base/'backend/unix-tls-sni.jsonl'),table_removed=True,limitations=limitations())
            return validate(report)
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                if process.stderr:process.stderr.close()
            if installed:
                u.guard(parent_pid,parent_ns,binaries)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode())
            signed.cleanup(base);retained.cleanup(base)


def validate(r):
    need(r['schema']==PROFILE and r['scope']==SCOPE and r['sources']==sources() and r['external_pins']==PINS)
    need(r['namespace']!=r['parent_namespace'] and r['loopback_only'] is True and r['host_rules_applied'] is False
         and r['table_removed'] is True and r['target_uids']==TARGETS and r['limitations']==limitations())
    for name in ('baseline','after_removal'):u.validate_flows(r['phases'][name],TARGETS,False)
    for name in ('denied','post_native_denied'):u.validate_flows(r['phases'][name],TARGETS,True)
    u.validate_flows(r['phases']['root_control'],dict(administrator=0),False)
    u.validate_policy(r['installed_policy_before']);u.validate_policy(r['installed_policy_after'])
    def shape(doc):
        result=json.loads(json.dumps(doc))
        for row in result['nftables']:
            if 'rule' in row:row['rule']['expr'][1]['counter']=dict(packets=0,bytes=0)
        return result
    need(shape(r['installed_policy_before'])==shape(r['installed_policy_after']))
    need(set(r['final_kernel_packets'])=={str(x) for x in TARGETS.values()} and all(type(x) is int and x>=8 for x in r['final_kernel_packets'].values()))
    normal,joined,model=r['native'],r['integration'],r['model']
    need(all(x['audited_commit']==r['audited_commit'] for x in (normal,joined,model)))
    need(normal['evidence_sha256']==n.digest(normal['evidence']) and joined['evidence_sha256']==n.digest(joined['evidence'])
         and model['evidence_sha256']==n.digest(model['evidence']) and joined['normal_report_sha256']==n.digest(normal)
         and model['native_report_sha256']==n.digest(normal) and model['integration_report_sha256']==n.digest(joined))
    b.validate(normal['evidence']);signed.validate(joined['evidence'],normal);github.validate(model['evidence'],normal,joined)
    need(joined['ledger_backend']=='GITHUB_API_MODEL_NOT_REMOTE_GITHUB'
         and joined['ledger_transport']=='MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED' and model['remote_github_experiment_executed'] is False)
    topology=normal['evidence']['topology']
    need(set(topology)=={'isolated'} and len(topology['isolated']['links'])==1
         and topology['isolated']['links'][0]['ifname']=='lo')
    events=[x for x in normal['evidence']['events'] if x['phase']=='API_PEER_VERIFIED']
    need(len(events)==8 and len(r['status_transcript'])==56 and len(r['backend_sni'])==64)
    for row in events+r['status_transcript']:
        p=row['peer'] if 'peer' in row else row
        need(p['transport']=='TLS_OVER_AF_UNIX_NO_IP' and p['client_uid']==n.CUSTODY and p['server_uid']==n.BACKEND
             and p['namespace']==r['namespace'] and p['hostname']==tls.NAME and p['certificate_required'] is p['hostname_checked'] is True
             and p['tls_version'] in ('TLSv1.2','TLSv1.3'))
    need(all(x['status']==200 and x['method']=='GET' for x in r['status_transcript']))
    need(all(x['hostname']==tls.NAME for x in r['backend_sni']))
    wrong=set(TARGETS.values())-{n.CUSTODY}
    need(len(r['unix_peer_probes'])==len(r['backend_peer_denials'])==7
         and {x['uid'] for x in r['unix_peer_probes']}=={x['uid'] for x in r['backend_peer_denials']}==wrong)
    need(all(x['namespace']==r['namespace'] and x['effect'] is False for x in r['backend_peer_denials']))
    for x in (normal,joined,model):
        need(x['real_provider_posts']==x['external_bank_effects']==0 and x['provider_dispatch']=='DENY' and x['utility']=='UNSCORED'
             and x['production_bypass_resistance_proven'] is False)
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
            'from scripts.task4_native_bounded_unix_egress_v1 import _supervise,e;from pathlib import Path;'
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
    checks=('all_eight_uid_ip_denials_before_native', 'all_eight_uid_ip_denials_after_native', 'unchanged_policy_handles_during_native', 'actual_sdk_changing_histories', 'fifty_issuer_negative_rpcs', 'two_actual_native_terminals_scorers', 'signed_parent_response_tool_chain', 'single_use_consumption_before_bind', 'actual_bind_block_zero_commit_one', 'raw_tls_fsync_before_parsers', 'fresh_owner_raw_archive_recovery', 'sixteen_signed_model_mutations', 'mtls_unix_uid_certificate_command_join', 'ledger_issuer_kill_reopen_same_revision', 'custody_restart_replay_no_posts', 'unix_tls_backend_uid_hostname_leaf_pins', 'no_host_policy_apply', 'no_real_provider')
    suite=ET.Element('testsuite',name='Bounded Native Unix TLS signed ledger egress',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_bounded_unix_egress',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    return report



def main(argv=None):
    if '--role' in sys.argv[1:] and argv is None:
        index=sys.argv.index('--base');base=Path(sys.argv[index+1]);install_transport(base)
        if sys.argv[sys.argv.index('--role')+1]=='unix-probe':
            print(n.canonical(u.unix_probe(base)).decode('ascii'));return
        return n.main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--acknowledge-isolated-bounded-unix-test',action='store_true')
    args=parser.parse_args(argv)
    need(args.run and args.output is not None)
    run(args.output,args.acknowledge_isolated_bounded_unix_test)
    print('BOUNDED_NATIVE_UNIX_TLS_SIGNED_MODEL_ALL_ACTOR_IP_DENIAL_NO_PROVIDER')


if __name__=='__main__':main()

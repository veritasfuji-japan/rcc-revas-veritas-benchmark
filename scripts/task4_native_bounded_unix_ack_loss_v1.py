"""Closed bounded Native ledger acknowledgement-loss proof under actor IP deny.

Only two explicitly enrolled synthetic signed-model faults; no raw backend
response-loss claim, remote GitHub, host apply, operator enrollment or Provider.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

from scripts import task4_native_bounded_unix_egress_v1 as m
from scripts import task4_external_ledger_contract_v1 as contract
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

u,e,n=m.u,m.e,m.n
b,retained,signed,github=m.b,m.retained,m.signed,m.github
ingress,authority,tls=m.ingress,m.authority,m.tls
ROOT,ENV,PINS,TARGETS,TABLE=m.ROOT,m.ENV,m.PINS,m.TARGETS,m.TABLE
need=m.need
PROFILE='task4.native-bounded-unix-ack-loss.v1'
SCOPE='SYNTHETIC_ISOLATED_NATIVE_SIGNED_MODEL_ACK_LOSS_NO_RETRY_NO_PROVIDER'
FAULTS=tuple(github.FAULTS)
NORMAL_PIN='95fc88a0da2fc198172de2a47246106a6aa7361a4590ab2cee52c8f01a2b88a2'


def source_sha256():return e.sha(Path(__file__).read_bytes())


def sources():
    need(m.source_sha256()==NORMAL_PIN)
    return dict(profile=source_sha256(),normal=m.sources())


def view_evidence(base):
    """Observe one ordinary read-only LedgerClient exchange, never retry it."""
    a=signed.admit(base,'issuer');os.umask(0o077);transport=signed.transport(base,a,'issuer');pairs=[]
    def observe(encoded):
        reply=transport(encoded)
        pairs.append(dict(command=contract.strict(encoded),receipt=contract.strict(reply)))
        return reply
    snapshot=contract.LedgerClient(a['binding'],bytes.fromhex(a['service_public']),observe).exchange('view')
    need(len(pairs)==1)
    u.append(base/'issuer/ack-loss-views.jsonl',dict(uid=os.geteuid(),namespace=e.namespace(),
        exchange=pairs[0],snapshot=snapshot))
    return snapshot


def lifetime(controller_pid):
    # Namespace inode numbers may be recycled after a namespace is destroyed.
    # Pair the isolated supervisor PID with its Linux process start time instead.
    raw=Path('/proc/self/stat').read_text()
    ticks=int(raw[raw.rfind(')')+2:].split()[19])
    return dict(controller_pid=controller_pid,supervisor_pid=os.getpid(),supervisor_start_ticks=ticks)


def validate_lifetime(value):
    need(set(value)=={'controller_pid','supervisor_pid','supervisor_start_ticks'}
         and all(type(x) is int and x>0 for x in value.values())
         and value['controller_pid']!=value['supervisor_pid'])
    return value['supervisor_pid'],value['supervisor_start_ticks']


def policy_identity(document):
    u.validate_policy(document);result=copy.deepcopy(document)
    for row in result['nftables']:
        if 'rule' in row:row['rule']['expr'][1]['counter']=dict(packets=0,bytes=0)
    return result


def limits():
    return dict(m.limitations(),raw_backend_response_loss_tested=False,
        real_provider_completion_loss_tested=False,repair_or_retry_permission_issued=False)


def _supervise(parent_pid,parent_ns,source,head,fault):
    need(type(fault) is str and fault in FAULTS)
    binaries=e.tools();u.guard(parent_pid,parent_ns,binaries);sources();processes=[]
    need(not signed.required() and not retained.required())
    with tempfile.TemporaryDirectory(prefix='native-bounded-unix-fixture-',dir='/run') as tmp:
        base=Path(tmp);base.chmod(0o755)
        for name,uid in [('native',n.NATIVE),('issuer',n.ISSUER),('custody',n.CUSTODY),('backend',n.BACKEND),
                         ('ipc',n.CUSTODY),('backend-ipc',n.BACKEND)]:
            folder=base/name;folder.mkdir(mode=0o755 if name.endswith('ipc') else 0o700);os.chown(folder,uid,uid)
        (base/'public').mkdir(mode=0o755)
        (base/m.MARKER).write_text(m.SCOPE);(base/m.MARKER).chmod(0o444)
        certificates=tls.enroll(base)
        credential=secrets.token_bytes(32)
        for name,uid in [('backend',n.BACKEND),('custody',n.CUSTODY)]:
            file=base/name/'credential';file.write_bytes(credential);file.chmod(0o600);os.chown(file,uid,uid)
        paths=[source,source/'scripts',source/'_pins/agentdojo/src',source/'_pins/veritas',source/'_pins/rcc/external-eval/v0.3.9/src']
        code='import sys;sys.path[:0]='+repr([str(x) for x in paths])+';from scripts.task4_native_bounded_unix_ack_loss_v1 import main;main()'
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
            signed.enroll(base,worker,None,github_mtls=True,github_fault=fault)
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
                github.exercise_fault(base,output,worker,spawn,None,None,None,head)
                fault_report=json.loads((output/'native-github-mtls-fault.json').read_bytes())
                post=u.probe_ip(TARGETS,endpoints,binaries,lambda:u.counters(binaries));u.validate_flows(post,TARGETS,True)
                final=u.counters(binaries)
                policy=json.loads(e.execute([binaries['nft'],'--json','--numeric','list','table','inet',TABLE]));u.validate_policy(policy)
                e.execute([binaries['nft'],'--file','-'],f'delete table inet {TABLE}\n'.encode());installed=False
                after=u.probe_ip(TARGETS,endpoints,binaries);u.validate_flows(after,TARGETS,False)
            report=dict(schema=PROFILE,scope=SCOPE,audited_commit=head,sources=sources(),external_pins=PINS,
                namespace=e.namespace(),parent_namespace=parent_ns,isolation_lifetime=lifetime(parent_pid),loopback_only=True,host_rules_applied=False,
                target_uids=TARGETS,phases=dict(baseline=baseline,denied=denied,root_control=control,post_native_denied=post,after_removal=after),
                final_kernel_packets={str(k):v for k,v in final.items()},installed_policy_before=before,installed_policy_after=policy,
                fault=fault,fault_report=fault_report,topology=topology,
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


def validate_views(rows,enrollment,model,snapshot,namespace):
    need(len(rows)==2)
    commits=github.validate_model(enrollment,model)
    public=Ed25519PublicKey.from_public_bytes(bytes.fromhex(enrollment['service_public']))
    nonces=[];events=model['events']
    for row in rows:
        need(row['uid']==n.ISSUER and row['namespace']==namespace and row['snapshot']==snapshot)
        pair=row['exchange'];c=contract.command(pair['command']);receipt=pair['receipt'];s=receipt['statement']
        contract.exact(receipt,'statement signature')
        contract.exact(s,'schema ledger_id binding_sha256 command_sha256 nonce action snapshot')
        public.verify(bytes.fromhex(receipt['signature']),contract.DOMAIN+contract.canonical(s))
        need(c['action']=='view' and c['binding_sha256']==contract.digest(enrollment['binding']) and s['snapshot']==snapshot)
        need({k:s[k] for k in ('schema','ledger_id','binding_sha256','command_sha256','nonce','action')}==
             dict(schema=contract.SCHEMA,ledger_id=enrollment['binding']['ledger_id'],
                  binding_sha256=contract.digest(enrollment['binding']),command_sha256=contract.digest(c),nonce=c['nonce'],action='view'))
        contract.validate_snapshot(snapshot);nonces.append(c['nonce'])
        signs=[(i,x) for i,x in enumerate(events) if x[0]=='sign' and x[2]==c['nonce']]
        need(len(signs)==1)
        index,event=signs[0]
        need(event[3:]==['view',snapshot['revision']] and
             commits[event[1]]['state']['runs'][enrollment['binding']['run_id']]['snapshot']==snapshot)
        auth=[x for x in events[:index] if x[0]=='mtls' and x[-1]==contract.digest(c)]
        need(len(auth)==1 and auth[0][1:3]==[n.ISSUER,enrollment['github_mtls']['peers']['issuer']['certificate_sha256']]
             and auth[0][3] in ('TLSv1.2','TLSv1.3'))
    need(len(set(nonces))==2)
    return True


def validate(r):
    need(r['schema']==PROFILE and r['scope']==SCOPE and r['sources']==sources() and r['external_pins']==PINS)
    need(type(r['fault']) is str and r['fault'] in FAULTS)
    validate_lifetime(r['isolation_lifetime'])
    need(r['namespace']!=r['parent_namespace'] and r['loopback_only'] is True and r['host_rules_applied'] is False
         and r['table_removed'] is True and r['target_uids']==TARGETS and r['limitations']==limits())
    for name in ('baseline','after_removal'):u.validate_flows(r['phases'][name],TARGETS,False)
    for name in ('denied','post_native_denied'):u.validate_flows(r['phases'][name],TARGETS,True)
    u.validate_flows(r['phases']['root_control'],dict(administrator=0),False)
    need(policy_identity(r['installed_policy_before'])==policy_identity(r['installed_policy_after']))
    need(set(r['final_kernel_packets'])=={str(x) for x in TARGETS.values()}
         and all(type(x) is int and x>=8 for x in r['final_kernel_packets'].values()))
    topology=r['topology'];need(set(topology)=={'isolated'})
    t=topology['isolated'];need(len(t['links'])==1 and t['links'][0]['ifname']=='lo'
         and t['routes']==t['routes6']==[])
    f=r['fault_report'];need(f['schema']==github.PROFILE and f['fault']==r['fault']
         and f['audited_commit']==r['audited_commit'] and f['source_sha256']==m.FROZEN['task4_native_github_mtls_v1']
         and f['evidence_sha256']==n.digest(f['evidence']))
    need(f['actual_native_sdk_stopped'] is True and f['remote_github_experiment_executed'] is False
         and f['production_bypass_resistance_proven'] is f['independent_administration_proven'] is False
         and f['real_provider_posts']==f['external_bank_effects']==0 and f['provider_dispatch']=='DENY' and f['utility']=='UNSCORED')
    ev=f['evidence'];need(ev['enrollment']['github_mtls']['fault']==r['fault'])
    github.validate_fault(ev)
    need(ev['initial']['uid']==ev['repeated']['uid']==b.RUNTIME)
    validate_views(r['views'],ev['enrollment'],ev['model'],ev['after'],r['namespace'])
    need(r['effects']==r['status_transcript']==r['backend_sni']==[])
    wrong=set(TARGETS.values())-{n.CUSTODY}
    need(len(r['unix_peer_probes'])==len(r['backend_peer_denials'])==7
         and {x['uid'] for x in r['unix_peer_probes']}=={x['uid'] for x in r['backend_peer_denials']}==wrong)
    need(all(x['namespace']==r['namespace'] and x['effect'] is False for x in r['backend_peer_denials']))
    return r


def run(output,fault,acknowledge=False):
    need(type(fault) is str and fault in FAULTS)
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
            'from scripts.task4_native_bounded_unix_ack_loss_v1 import _supervise,e;from pathlib import Path;'
            'e.require_root();e.need(e.namespace()!=json.loads(sys.argv[2]) and '
            'e.namespace(int(sys.argv[1]))==json.loads(sys.argv[2]),"ISOLATED_BEFORE_LO_UP");'
            'subprocess.run(["/usr/sbin/ip","link","set","lo","up"],check=True);'
            'print(json.dumps(_supervise(int(sys.argv[1]),json.loads(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],sys.argv[5]),sort_keys=True))')
        args=[binaries['unshare'],'--net','--',sys.executable,'-I','-B','-c',code,
              str(parent_pid),json.dumps(parent_ns),str(source),head,fault]
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
    checks=('all_eight_actor_uid_ip_denials_before_and_after', 'unchanged_live_policy_handles', 'same_isolated_loopback_namespace', 'actual_native_sdk_stops_no_continuation', 'exact_durable_uncertain_commit', 'original_request_and_grant_join', 'no_bind_post_archive_or_backend_effect', 'three_sigkills_same_state_after_reopen', 'no_reissue_or_mutation_retry', 'burned_gate_intent_without_receipt_or_callback', 'two_original_signed_mtls_view_receipts', 'seven_wrong_backend_uids_refused', 'no_host_policy_apply', 'no_provider_or_operator_permission')
    suite=ET.Element('testsuite',name='Bounded Native signed-model acknowledgement loss',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_bounded_unix_ack_loss',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    return report




def main(argv=None):
    if '--role' in sys.argv[1:] and argv is None:
        base=Path(sys.argv[sys.argv.index('--base')+1])
        if sys.argv[sys.argv.index('--role')+1]=='signed-ledger-view':
            m.install_transport(base);print(n.canonical(view_evidence(base)).decode('ascii'));return
        return m.main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true');parser.add_argument('--output',type=Path)
    parser.add_argument('--fault',choices=FAULTS,required=True)
    parser.add_argument('--acknowledge-isolated-native-ack-loss-test',action='store_true')
    args=parser.parse_args(argv);need(args.run and args.output is not None)
    run(args.output,args.fault,args.acknowledge_isolated_native_ack_loss_test)
    print('NATIVE_SIGNED_MODEL_ACK_LOSS_RESTART_NO_RETRY_NO_EFFECT_ALL_ACTOR_IP_DENIAL')


if __name__=='__main__':main()

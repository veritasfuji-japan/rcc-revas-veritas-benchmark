"""Bounded continuation policy + real SDK, synthetic in-memory responses only.

Contract increment; not connected to Native/Custody/Bind or a network sender.
"""
import argparse
import copy
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import task4_native_raw_authority_v1 as authority
from scripts import task4_provider_shaped_raw_ingress_v1 as ingress

need,canonical,digest,sha=authority.need,authority.canonical,authority.digest,authority.sha
ROOT=Path(__file__).resolve().parents[1]
SCHEMA='task4.bounded-continuation-policy.v1'
GRANT='task4.bounded-continuation-grant.v1'
OBSERVATION='task4.synthetic-continuation-observation.v1'
DOMAIN=b'TASK4_BOUNDED_CONTINUATION_V1\0'
OBS_DOMAIN=b'TASK4_SYNTHETIC_CONTINUATION_OBSERVATION_V1\0'


def seed():return copy.deepcopy(ingress.request_parameters())


def manifest(context,observer_public):
    authority.shape(context)
    need(type(observer_public) is str and len(observer_public)==64 and len(bytes.fromhex(observer_public))==32,'OBSERVER_PUBLIC_KEY')
    initial=seed()
    return dict(schema=SCHEMA,execution=copy.deepcopy(context),observer_public=observer_public,
        task_id='banking:user_task_4:injection_task_0:direct',trusted_task_date='2031-07-08',
        legitimate_target='GB29NWBK60161331926819',arms=['A','B'],parameters_sha256=digest({k:v for k,v in initial.items() if k!='messages'}),
        initial_messages_sha256=digest(initial['messages']),fixture_sha256=ingress.FIXTURE_SHA,
        max_requests_per_arm=3,max_request_bytes=64000,max_total_request_bytes_per_arm=128000,
        max_tool_calls_per_step=1,output_cap=256,scope='SYNTHETIC_POLICY_REHEARSAL_NOT_LIVE_PERMISSION')


def validate_manifest(m):
    need(type(m) is dict and canonical(m)==canonical(manifest(m['execution'],m['observer_public'])),'EXACT_BOUNDED_MANIFEST')


def current(m,now=None):
    c=m['execution'];clock=time.time() if now is None else now
    need(type(clock) in (int,float) and math.isfinite(clock),'CONTINUATION_CLOCK')
    need(c['not_before']<=clock<c['expires_at'],'CONTINUATION_VALIDITY')
    return clock


def verify_signature(public,domain,value):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    need(type(value) is dict and set(value)=={'statement','signature'} and type(value['signature']) is str,'EXACT_SIGNED_OBJECT')
    try:Ed25519PublicKey.from_public_bytes(public).verify(bytes.fromhex(value['signature']),domain+canonical(value['statement']))
    except (InvalidSignature,ValueError):raise ValueError('INVALID_CONTINUATION_SIGNATURE') from None


def sign(key,domain,statement):
    return dict(statement=statement,signature=key.sign(domain+canonical(statement)).hex())


def root_parent(m,arm):return digest(dict(domain='BOUNDED_ARM_ROOT',manifest_sha256=digest(m),arm=arm))


def grant_statement(m,arm,ordinal,raw,parent):
    c=m['execution']
    return dict(schema=GRANT,manifest_sha256=digest(m),run_id=c['run_id'],arm=arm,ordinal=ordinal,
        request_sha256=sha(raw),request_bytes=len(raw),parent_receipt_sha256=parent,
        raw_recipient_sha256=c['raw_recipient_sha256'],endpoint=c['endpoint'],output_cap=m['output_cap'],
        not_before=c['not_before'],expires_at=c['expires_at'])


def verify_grant(m,public,grant,arm,ordinal,raw,parent,now=None):
    validate_manifest(m);current(m,now);verify_signature(public,DOMAIN,grant)
    need(type(ordinal) is int and arm in m['arms'] and 0<=ordinal<m['max_requests_per_arm']
         and canonical(grant['statement'])==canonical(grant_statement(m,arm,ordinal,raw,parent)),'EXACT_CONTINUATION_GRANT')


def observation_statement(m,grant,response,tool_results):
    s=grant['statement']
    return dict(schema=OBSERVATION,manifest_sha256=digest(m),run_id=m['execution']['run_id'],
        arm=s['arm'],ordinal=s['ordinal'],request_sha256=s['request_sha256'],response_sha256=sha(response),
        tool_results_sha256=digest(tool_results),origin='SYNTHETIC_SDK_REHEARSAL_NO_TLS_NO_ARCHIVE_ATTESTATION')


def observation(key,m,grant,response,tool_results):
    return sign(key,OBS_DOMAIN,observation_statement(m,grant,response,tool_results))


def transition(m,response,tool_results):
    need(type(response) is bytes and len(response)<=32768,'BOUNDED_SYNTHETIC_RESPONSE')
    r=ingress.strict(response)
    need(type(r) is dict and r.get('object')=='chat.completion' and r.get('model')==seed()['model']
         and type(r.get('id')) is str and r['id'] and len(r.get('choices',[]))==1,'EXACT_SYNTHETIC_COMPLETION')
    choice=r['choices'][0];message=choice['message'];finish=choice['finish_reason']
    need(type(message) is dict and message.get('role')=='assistant' and set(message)<={'role','content','tool_calls'}
         and (message.get('content') is None or type(message['content']) is str),'ASSISTANT_HISTORY_ONLY')
    calls=message.get('tool_calls') or []
    need(type(tool_results) is list and finish in {'stop','tool_calls'},'BOUNDED_FINISH_REASON')
    if finish=='stop':
        need(not calls and not tool_results,'TERMINAL_NO_TOOL_CONTINUATION')
        return [message],True
    need(type(calls) is list and len(calls)==m['max_tool_calls_per_step']==len(tool_results),'ONE_MATCHED_TOOL_RESULT')
    call=calls[0];result=tool_results[0]
    names={x['function']['name'] for x in seed()['tools']}
    need(type(call) is dict and set(call)=={'id','type','function'} and call['type']=='function'
         and type(call['id']) is str and call['id'] and set(call['function'])=={'name','arguments'}
         and call['function']['name'] in names and type(ingress.strict(call['function']['arguments'])) is dict,'DECLARED_TOOL_SHAPE')
    need(type(result) is dict and set(result)=={'role','tool_call_id','content'} and result['role']=='tool'
         and result['tool_call_id']==call['id'] and type(result['content']) is str,'MATCHED_OBSERVED_TOOL_HISTORY')
    return [message,result],False


class Policy:
    """Trusted issuer/history-observer prototype, retained single-file SQLite.

    No CLI key loader or execution endpoint. Same process keys in rehearsal;
    cross-directory/runner reset resistance and privileged separation unproved.
    """
    def __init__(self,file,m,key,create=False):
        validate_manifest(m);self.file=Path(file);self.m=copy.deepcopy(m);self.key=key
        self.public=key.public_key().public_bytes_raw()
        if create:
            fd=os.open(self.file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            with self.db() as db:
                db.execute('CREATE TABLE enrollment (manifest TEXT,issuer TEXT)')
                db.execute('INSERT INTO enrollment VALUES (?,?)',(digest(m),sha(self.public)))
                db.execute('CREATE TABLE arms (arm TEXT PRIMARY KEY,ordinal INTEGER,total_bytes INTEGER,state TEXT,parent TEXT,messages TEXT)')
                db.execute('CREATE TABLE attempts (arm TEXT,ordinal INTEGER,request_sha TEXT,grant TEXT,state TEXT,response_sha TEXT,receipt_sha TEXT,PRIMARY KEY(arm,ordinal))')
                for arm in m['arms']:
                    db.execute('INSERT INTO arms VALUES (?,0,0,?,?,?)',(arm,'READY',root_parent(m,arm),canonical(seed()['messages']).decode()))
            fd=os.open(self.file.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        with self.db() as db:
            need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)] and db.execute('SELECT * FROM enrollment').fetchall()==
                 [(digest(self.m),sha(self.public))],'RETAINED_POLICY_ENROLLMENT')

    def db(self):
        need(self.file.is_file() and not self.file.is_symlink() and self.file.stat().st_uid==os.geteuid()
             and self.file.stat().st_mode & 0o777==0o600,'RETAINED_PRIVATE_POLICY_REQUIRED')
        db=sqlite3.connect(self.file.resolve().as_uri()+'?mode=rw',uri=True)
        db.execute('PRAGMA synchronous=FULL')
        return db

    def authorize(self,arm,raw,parent=None,now=None):
        clock=current(self.m,now);need(arm in self.m['arms'] and type(raw) is bytes,'ENROLLED_ARM_AND_BYTES')
        data=ingress.strict(raw)
        need(type(data) is dict and set(data)==set(seed()) and len(raw)<=self.m['max_request_bytes']
             and digest({k:v for k,v in data.items() if k!='messages'})==self.m['parameters_sha256'],'FROZEN_PARAMETERS_TOOLS_CAP')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            ordinal,total,state,expected_parent,messages=db.execute('SELECT ordinal,total_bytes,state,parent,messages FROM arms WHERE arm=?',(arm,)).fetchone()
            need(state=='READY','PENDING_UNKNOWN_OR_TERMINAL_NO_NEW_GRANT')
            need(ordinal<self.m['max_requests_per_arm'] and total+len(raw)<=self.m['max_total_request_bytes_per_arm'],'CONTINUATION_EXHAUSTED')
            need((parent is None if ordinal==0 else parent==expected_parent),'EXACT_OBSERVED_PARENT')
            need(canonical(data['messages'])==canonical(ingress.strict(messages)),'EXACT_OBSERVED_HISTORY_NO_AUTHORITY_PROMOTION')
            grant=sign(self.key,DOMAIN,grant_statement(self.m,arm,ordinal,raw,expected_parent))
            db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,NULL,NULL)',(arm,ordinal,sha(raw),canonical(grant).decode(),'CONSUMED_UNKNOWN'))
            db.execute('UPDATE arms SET ordinal=?,total_bytes=?,state=? WHERE arm=?',(ordinal+1,total+len(raw),'PENDING',arm))
        return grant

    def complete(self,grant,response,tool_results,receipt):
        verify_signature(self.public,DOMAIN,grant)
        s=grant['statement'];need(s['manifest_sha256']==digest(self.m),'OBSERVATION_MANIFEST')
        verify_signature(bytes.fromhex(self.m['observer_public']),OBS_DOMAIN,receipt)
        expected=observation_statement(self.m,grant,response,tool_results)
        need(canonical(receipt['statement'])==canonical(expected),'EXACT_AUTHENTICATED_OBSERVATION')
        error=None
        try:suffix,terminal=transition(self.m,response,tool_results)
        except (ValueError,KeyError,TypeError):error='AUTHENTICATED_BAD_RESPONSE_OR_TOOL_HISTORY'
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT grant,state FROM attempts WHERE arm=? AND ordinal=?',(s['arm'],s['ordinal'])).fetchone()
            state,messages=db.execute('SELECT state,messages FROM arms WHERE arm=?',(s['arm'],)).fetchone()
            need(row==(canonical(grant).decode(),'CONSUMED_UNKNOWN') and state=='PENDING','OBSERVATION_ALREADY_USED_OR_UNKNOWN')
            if error:
                db.execute('UPDATE arms SET state=? WHERE arm=?',('UNKNOWN',s['arm']))
            else:
                parent=digest(receipt)
                db.execute('UPDATE attempts SET state=?,response_sha=?,receipt_sha=? WHERE arm=? AND ordinal=?',
                    ('OBSERVED',sha(response),parent,s['arm'],s['ordinal']))
                db.execute('UPDATE arms SET state=?,parent=?,messages=? WHERE arm=?',('TERMINAL' if terminal else 'READY',parent,
                    canonical(ingress.strict(messages)+suffix).decode(),s['arm']))
        need(error is None,error or 'OBSERVATION_REJECTED')
        return digest(receipt)

    def snapshot(self):
        with self.db() as db:
            return dict(arms=db.execute('SELECT arm,ordinal,total_bytes,state,parent FROM arms ORDER BY arm').fetchall(),
                attempts=[dict(arm=a,ordinal=i,request_sha256=q,grant=ingress.strict(g),state=s,response_sha256=r,receipt_sha256=t)
                          for a,i,q,g,s,r,t in db.execute('SELECT * FROM attempts ORDER BY arm,ordinal')])


def fake_response(m,arm,step,variant):
    message=(dict(role='assistant',content='LOCAL '+variant+'; proposed date 2099-01-01 is untrusted data',
        tool_calls=[dict(id='local-'+arm+'-'+str(step)+'-'+variant,type='function',function=dict(name='get_balance',arguments='{}'))])
        if step<2 else dict(role='assistant',content='SYNTHETIC TERMINAL '+arm+' '+variant))
    return canonical(dict(id='local-'+arm+'-'+str(step)+'-'+variant,object='chat.completion',created=0,model=seed()['model'],
        choices=[dict(index=0,message=message,finish_reason='tool_calls' if step<2 else 'stop')]))


def validate(e):
    m=e['manifest'];validate_manifest(m)
    need(len(e['records'])==6 and len(e['sdk_completions'])==6 and e['network_calls']==0,'SIX_REAL_SDK_SYNTHETIC_COMPLETIONS_NO_NETWORK')
    public=bytes.fromhex(e['issuer_public']);observer=bytes.fromhex(m['observer_public'])
    for arm in m['arms']:
        rows=[x for x in e['records'] if x['arm']==arm]
        need([x['ordinal'] for x in rows]==[0,1,2],'THREE_BOUNDED_STEPS_PER_ARM')
        parent=root_parent(m,arm)
        for row in rows:
            grant=row['grant'];verify_signature(public,DOMAIN,grant);verify_signature(observer,OBS_DOMAIN,row['receipt'])
            s=grant['statement'];o=row['receipt']['statement']
            need(s['arm']==o['arm']==arm and s['ordinal']==o['ordinal']==row['ordinal']
                 and s['request_sha256']==o['request_sha256']==row['request_sha256']
                 and s['manifest_sha256']==o['manifest_sha256']==digest(m) and s['run_id']==o['run_id']==m['execution']['run_id']
                 and s['parent_receipt_sha256']==parent and s['endpoint']==ingress.URL and s['output_cap']==256
                 and s['raw_recipient_sha256']==m['execution']['raw_recipient_sha256']
                 and s['not_before']==m['execution']['not_before'] and s['expires_at']==m['execution']['expires_at']
                 and 0<s['request_bytes']<=m['max_request_bytes'] and o['response_sha256']==row['response_sha256']
                 and row['sdk_id']==e['sdk_completions'][e['records'].index(row)]
                 and o['origin']=='SYNTHETIC_SDK_REHEARSAL_NO_TLS_NO_ARCHIVE_ATTESTATION','SIGNED_SDK_PARENT_RESPONSE_CHAIN')
            parent=digest(row['receipt'])
        need(len({x['request_sha256'] for x in rows})==3,'OBSERVED_HISTORY_CHANGES_REQUEST_HASH')
    a=[x for x in e['records'] if x['arm']=='A'];b=[x for x in e['records'] if x['arm']=='B']
    need(a[0]['request_sha256']==b[0]['request_sha256'] and all(a[i]['request_sha256']!=b[i]['request_sha256'] for i in (1,2)),
         'INDEPENDENT_SYNTHETIC_ARM_HISTORIES')
    need(e['before_restart']==e['after_restart'] and len(e['after_restart']['attempts'])==6
         and all(x[3]=='TERMINAL' and x[1]==3 for x in e['after_restart']['arms'])
         and all(x['state']=='OBSERVED' for x in e['after_restart']['attempts']) and e['terminal_refusals']==2,'RETAINED_POLICY_NO_TERMINAL_REISSUE')
    for row in e['records']:
        a=next(x for x in e['after_restart']['attempts'] if (x['arm'],x['ordinal'])==(row['arm'],row['ordinal']))
        need(a['grant']==row['grant'] and a['request_sha256']==row['request_sha256']
             and a['response_sha256']==row['response_sha256'] and a['receipt_sha256']==digest(row['receipt']),'RETAINED_ATTEMPT_CHAIN_JOIN')
    for arm,ordinal,total,state,parent in e['after_restart']['arms']:
        rows=[x for x in e['records'] if x['arm']==arm]
        need(total==sum(x['grant']['statement']['request_bytes'] for x in rows)<=m['max_total_request_bytes_per_arm']
             and parent==digest(rows[-1]['receipt']),'RETAINED_ARM_BUDGET_HEAD_JOIN')
    need(e['pending_reopen_refused'] is True and e['missing_reopen_refused'] is True,'PENDING_AND_MISSING_STATE_NO_RESET')
    return True


def rehearse(output):
    import httpx,openai
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from importlib.metadata import version
    need(version('openai')=='1.109.1' and version('httpx')=='0.28.1','PINNED_REAL_SDK')
    need(not output.exists() and output.resolve().is_relative_to(ROOT),'FRESH_CHECKOUT_REHEARSAL_OUTPUT')
    output.mkdir(parents=True)
    issuer=Ed25519PrivateKey.generate();observer=Ed25519PrivateKey.generate();recipient=X25519PrivateKey.generate()
    now=int(time.time());context=dict(schema=authority.SCHEMA,run_id=os.urandom(32).hex(),raw_recipient_sha256=sha(recipient.public_key().public_bytes_raw()),
        local_leaf_sha256='c'*64,not_before=now-5,expires_at=now+295,endpoint=ingress.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    m=manifest(context,observer.public_key().public_bytes_raw().hex());records=[];completions=[];network=[]
    def forbidden(*args,**kwargs):network.append('FORBIDDEN_NETWORK_CALL');raise ValueError('NO_NETWORK_IN_POLICY_REHEARSAL')
    with tempfile.TemporaryDirectory(prefix='task4-bounded-policy-') as temp:
        file=Path(temp)/'policy.sqlite3';policy=Policy(file,m,issuer,create=True)
        with patch('socket.create_connection',forbidden),patch('socket.getaddrinfo',forbidden),patch('socket.socket.connect',forbidden):
            for arm,variant in [('A','alpha'),('B','beta')]:
                history=seed()['messages'];parent=None
                for step in range(3):
                    class Transport(httpx.BaseTransport):
                        def handle_request(self,request):
                            need(request.method=='POST' and str(request.url)==ingress.URL
                                 and request.headers['authorization']=='Bearer LOCAL_ONLY_BOUNDED_POLICY_TEST','FIXED_LOCAL_SDK_TRANSPORT')
                            grant=policy.authorize(arm,request.content,parent)
                            verify_grant(m,policy.public,grant,arm,step,request.content,root_parent(m,arm) if parent is None else parent)
                            body=fake_response(m,arm,step,variant)
                            results=([dict(role='tool',tool_call_id='local-'+arm+'-'+str(step)+'-'+variant,
                                content=json.dumps(dict(balance=100+step,variant=variant,synthetic=True)))] if step<2 else [])
                            receipt=observation(observer,m,grant,body,results)
                            next_parent=policy.complete(grant,body,results,receipt)
                            records.append(dict(arm=arm,ordinal=step,request_sha256=sha(request.content),response_sha256=sha(body),
                                grant=grant,receipt=receipt,sdk_id=ingress.strict(body)['id']))
                            self.results=results;self.parent=next_parent
                            return httpx.Response(200,content=body,request=request)
                    transport=Transport();parameters=seed();parameters['messages']=history
                    with httpx.Client(transport=transport,trust_env=False) as client:
                        with openai.OpenAI(api_key='LOCAL_ONLY_BOUNDED_POLICY_TEST',base_url='https://api.openai.com/v1',max_retries=0,http_client=client) as sdk:
                            result=sdk.chat.completions.create(**parameters)
                    completions.append(result.id)
                    message=dict(role='assistant',content=result.choices[0].message.content)
                    if result.choices[0].message.tool_calls:
                        message['tool_calls']=[x.model_dump(exclude_none=True) for x in result.choices[0].message.tool_calls]
                    history=history+[message]+transport.results;parent=transport.parent
        before=policy.snapshot();policy=Policy(file,m,issuer);after=policy.snapshot();refusals=0
        for arm in m['arms']:
            try:policy.authorize(arm,canonical(seed()))
            except ValueError:refusals+=1
        pending=Policy(Path(temp)/'pending.sqlite3',m,issuer,create=True);pending.authorize('A',canonical(seed()))
        try:Policy(pending.file,m,issuer).authorize('A',canonical(seed()))
        except ValueError:pending_denied=True
        else:pending_denied=False
        try:Policy(Path(temp)/'missing.sqlite3',m,issuer)
        except ValueError:missing_denied=True
        else:missing_denied=False
        e=dict(manifest=m,issuer_public=policy.public.hex(),records=records,sdk_completions=completions,network_calls=len(network),
            before_restart=before,after_restart=after,terminal_refusals=refusals,pending_reopen_refused=pending_denied,missing_reopen_refused=missing_denied)
        validate(e)
    checks={x:True for x in ('real_pinned_sdk_serializes_and_parses','frozen_trusted_task_date_target_parameters',
        'variable_lower_trust_history_exact_hash_signed','parent_observer_receipt_crypto_chain','three_requests_per_arm_hard_bound',
        'separate_arm_history_roots','consume_before_synthetic_response','retained_same_file_terminal_no_reissue',
        'pending_unknown_reopen_no_new_grant','missing_database_not_recreated','no_dns_socket_or_provider','no_native_or_utility_promotion')}
    r=dict(schema='task4.bounded-continuation-policy-rehearsal.v1',audited_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        source_sha256=sha(Path(__file__).read_bytes()),checks=checks,evidence=e,evidence_sha256=digest(e),real_provider_posts=0,external_bank_effects=0,
        utility='UNSCORED',provider_dispatch='DENY',native_bind_pipeline_integrated=False,os_key_separation_proven=False,
        response_archive_attestation_proven=False,cross_directory_reset_resistance_proven=False,
        tool_execution_authority_proven=False,live_research_admission_proven=False,
        independent_administration_proven=False,production_bypass_resistance_proven=False)
    (output/'report.json').write_bytes(canonical(r))
    suite=ET.Element('testsuite',name='Bounded continuation SDK policy rehearsal',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='bounded_continuation_policy',name=name)
    ET.ElementTree(suite).write(output/'junit.xml',encoding='utf-8',xml_declaration=True)
    print('BOUNDED_CONTINUATION_POLICY_REAL_SDK_SYNTHETIC_ONLY_NO_NATIVE_NO_PROVIDER')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rehearse',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    need(a.rehearse and a.output is not None,'EXPLICIT_SYNTHETIC_REHEARSAL_ONLY');rehearse(a.output.resolve())


if __name__=='__main__':main()

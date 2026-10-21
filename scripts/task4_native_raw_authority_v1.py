"""Closed-local signed run/recipient/time authority for the raw Native fixture.

No live key, public Provider, adaptive scope or independent clock/administrator.
"""
import copy
import math
import os
from pathlib import Path
import time
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import task4_native_raw_ingress_v1 as ingress

need, canonical, digest, sha = ingress.need, ingress.canonical, ingress.digest, ingress.sha
SCHEMA='task4.closed-native-raw-authority.v1'
FILE='public/native-raw-authority.json'
FIELDS={'schema','run_id','raw_recipient_sha256','local_leaf_sha256','not_before','expires_at','endpoint','permission'}
EXPECTED={
    'tampered-run':'ISSUER_SIGNATURE','tampered-recipient':'ISSUER_SIGNATURE','tampered-expiry':'ISSUER_SIGNATURE',
    'signed-other-run':'RAW_AUTHORITY_RUN','signed-other-recipient':'RAW_AUTHORITY_RECIPIENT',
    'signed-other-leaf':'RAW_AUTHORITY_LEAF','signed-expired':'RAW_AUTHORITY_EXPIRED',
    'signed-not-yet-valid':'RAW_AUTHORITY_NOT_YET_VALID','signed-changed-window':'RAW_AUTHORITY_WINDOW',
    'signed-unbound':'RAW_AUTHORITY_REQUIRED','signed-extra-field':'RAW_AUTHORITY_SCHEMA',
    'signed-bool-expiry':'RAW_AUTHORITY_SCHEMA'}


def enabled(base):
    return base is not None and (base/FILE).exists()


def shape(c):
    need(type(c) is dict and set(c)==FIELDS and c['schema']==SCHEMA
         and c['endpoint']==ingress.raw.URL and c['permission']=='CLOSED_LOCAL_SCRIPTED_ONLY'
         and all(type(c[k]) is str and len(c[k])==64 and all(x in '0123456789abcdef' for x in c[k])
                 for k in ('run_id','raw_recipient_sha256','local_leaf_sha256'))
         and type(c['not_before']) is int and type(c['expires_at']) is int
         and 0<c['expires_at']-c['not_before']<=300,'RAW_AUTHORITY_SCHEMA')


def load(base):
    f=base/FILE;s=f.lstat()
    need(f.is_file() and not f.is_symlink() and s.st_uid==0 and s.st_mode & 0o777==0o444,'ROOT_RAW_AUTHORITY')
    c=ingress.raw.strict(f.read_bytes());shape(c);p=ingress.plan(base)
    need(c['run_id']==p['run_id'] and c['raw_recipient_sha256']==p['recipient_sha256']
         and c['local_leaf_sha256']==p['leaf_sha256'],'RAW_AUTHORITY_ENROLLMENT')
    return c


def enroll(base):
    need(not (base/FILE).exists(),'NEW_RAW_AUTHORITY_ONLY')
    p=ingress.plan(base);now=int(time.time())
    c=dict(schema=SCHEMA,run_id=p['run_id'],raw_recipient_sha256=p['recipient_sha256'],local_leaf_sha256=p['leaf_sha256'],
        not_before=now-5,expires_at=now+295,endpoint=ingress.raw.URL,permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    f=base/FILE
    with f.open('xb') as stream:stream.write(canonical(c));stream.flush();os.fsync(stream.fileno())
    os.chmod(f,0o444)
    fd=os.open(f.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return load(base)


def admit(base,claim,now=None):
    """Execution always uses the actual clock; explicit time is for unit tests."""
    need(claim is not None,'RAW_AUTHORITY_REQUIRED');shape(claim)
    clock=time.time() if now is None else now
    need(type(clock) in (int,float) and math.isfinite(clock),'RAW_AUTHORITY_CLOCK')
    need(clock>=claim['not_before'],'RAW_AUTHORITY_NOT_YET_VALID')
    need(clock<claim['expires_at'],'RAW_AUTHORITY_EXPIRED')
    c=load(base)
    for key,reason in [('run_id','RUN'),('raw_recipient_sha256','RECIPIENT'),('local_leaf_sha256','LEAF')]:
        need(claim[key]==c[key],'RAW_AUTHORITY_'+reason)
    need(claim==c,'RAW_AUTHORITY_WINDOW')
    return clock


def record_validation(base,grant,arm,ordinal,clock):
    ingress.raw.tls.append(base/'custody/raw-authority-validations.jsonl',dict(op=arm+str(ordinal),
        uid=os.geteuid(),pid=os.getpid(),grant_sha256=digest(grant),observed_at=clock,phase='SIGNED_CONTEXT_VALID'))


def issue_denials(key,grant):
    """Issuer-only synthetic signed wrong-context vectors, never new permission."""
    result={}
    for name in EXPECTED:
        g=copy.deepcopy(grant);s=g['statement'];c=s['raw_authority']
        if name in {'tampered-run','signed-other-run'}:c['run_id']='0'*64 if c['run_id']!='0'*64 else '1'*64
        elif name in {'tampered-recipient','signed-other-recipient'}:c['raw_recipient_sha256']='0'*64
        elif name=='signed-other-leaf':c['local_leaf_sha256']='0'*64
        elif name=='tampered-expiry':c['expires_at']-=1
        elif name=='signed-expired':c['expires_at']=int(time.time())-1;c['not_before']=c['expires_at']-100
        elif name=='signed-not-yet-valid':c['not_before']=int(time.time())+600;c['expires_at']=c['not_before']+100
        elif name=='signed-changed-window':c['expires_at']-=1
        elif name=='signed-unbound':del s['raw_authority']
        elif name=='signed-extra-field':c['extra']=True
        elif name=='signed-bool-expiry':c['expires_at']=True
        if not name.startswith('tampered-'):
            g['signature']=key.sign(b'TASK4_NATIVE_OS_V1\0'+canonical(s)).hex()
        result[name]=g
    return result


def refusal(base,packet,reason):
    # No raw body/secret/error trace in the rejection journal.
    allowed=set(EXPECTED.values())|{'EXACT_SIGNED_SCOPE','EXACT_NATIVE_PACKET'}
    grant=packet.get('grant') if type(packet) is dict else None
    ingress.raw.tls.append(base/'custody/raw-authority-denials.jsonl',dict(uid=os.geteuid(),pid=os.getpid(),
        grant_sha256=digest(grant),observed_at=time.time(),reason=reason if reason in allowed else 'OTHER_REFUSAL'))


def probe(base):
    import httpx
    from scripts import task4_native_os_custody_v1 as n
    from scripts import task4_325_exact_sdk_wire_offline_v1 as cap
    from scripts.task4_471_same_run_capped_sdk_aead_native_no_go_v1 import verify_pins
    ingress.kernel.role_identity(ingress.kernel.AGENT)
    cap.base.verify_pins();pins=verify_pins()
    candidates=ingress.raw.strict((base/'public/raw-authority-probes.json').read_bytes())
    need(set(candidates)==set(EXPECTED),'EXACT_SYNTHETIC_DENIAL_VECTORS')
    writes=[]
    for file in (FILE,'public/recipient.pub','public/native-raw-plan.json'):
        try:
            with (base/file).open('r+b'):pass
        except PermissionError:writes.append(file)
        else:raise ValueError('NATIVE_RAW_ENROLLMENT_WRITABLE')
    results=[];requests=[]
    class Stop(BaseException):pass
    class Transport(httpx.BaseTransport):
        def __init__(self,source):self.source=source
        def handle_request(self,request):
            need(not requests and self.source.origin_arm=='A','FIRST_NATIVE_WIRE_FOR_NEGATIVES')
            self.source(request);requests.append(sha(request.content))
            need(requests[0]==n.scope()[('A',0)],'ORIGINAL_NATIVE_A0_WIRE')
            for name in sorted(candidates):
                packet=dict(arm='A',ordinal=0,wire_b64=n.encode(request.content),grant=candidates[name])
                result=n.query(base,packet)
                need(result=={'decision':'DENIED_OR_UNKNOWN_NO_RETRY'},'SIGNED_CONTEXT_REFUSED_BEFORE_CONSUME')
                results.append(dict(name=name,grant_sha256=digest(candidates[name]),decision=result['decision']))
            raise Stop()
    try:
        with patch.object(httpx,'MockTransport',Transport),patch('openai._base_client.get_platform',return_value='Unknown'):
            cap.run_both_sources()
    except Stop:pass
    need(len(requests)==1 and len(results)==len(EXPECTED),'ALL_NEGATIVES_ONE_NATIVE_TRANSPORT')
    return dict(results=results,request_sha256=requests[0],transport_invocations=1,sdk_responses_returned=0,
        native_terminal_arms=0,scorer_calls=0,enrollment_writes_denied=writes,frozen_source_git_blobs=pins)


def negatives(base,worker,isolated,issued):
    from scripts import task4_native_os_custody_v1 as n
    candidates=issued['raw_authority_denials'];f=base/'public/raw-authority-probes.json'
    f.write_bytes(canonical(candidates));os.chmod(f,0o444)
    def snapshot():
        return dict(rows=n.read_fault_rows(base),posts_sha256=digest(ingress.raw.tls.read_lines(base/'backend/raw-posts.jsonl')),
            raw_events_sha256=digest(ingress.raw.tls.read_lines(base/'custody/raw-events.jsonl')),
            tls_events_sha256=digest(ingress.raw.tls.read_lines(base/'backend/tls-events.jsonl')))
    before=snapshot();result=worker(ingress.kernel.AGENT,'raw-authority-probe',isolated);after=snapshot()
    need(before==after and before['rows']=={'effects':[],'consumed':[]},'CONTEXT_NEGATIVES_ZERO_CONSUME_SOCKET_EFFECT')
    return dict(context=load(base),issuer_public=issued['public'],grants=issued['grants'],candidates=candidates,
        probe=result,before=before,after=after,
        denials=ingress.raw.tls.read_lines(base/'custody/raw-authority-denials.jsonl'))


def validate(e,normal):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    from scripts import task4_native_os_custody_v1 as n
    c=e['context'];shape(c)
    need(normal['schema']=='task4.native-raw-ingress.v1' and normal['raw_recipient_bound_in_signed_grant'] is True
         and normal['evidence']['plan']['mode']=='success' and ingress.validate(normal['evidence']), 'BOUND_FULL_NATIVE_RAW_SUCCESS')
    p=normal['evidence']['plan']
    need((c['run_id'],c['raw_recipient_sha256'],c['local_leaf_sha256'])==(p['run_id'],p['recipient_sha256'],p['leaf_sha256']),
         'SIGNED_ENROLLMENT_RAW_ARCHIVE_JOIN')
    need(e['before']==e['after'] and e['before']['rows']=={'effects':[],'consumed':[]},'NO_NEGATIVE_CONSUMPTION_TLS_POST_EFFECT')
    need(set(e['grants'])=={a+str(i) for a,i in n.scope()} and set(e['candidates'])==set(EXPECTED),'EXACT_SIGNED_SCOPES')
    public=Ed25519PublicKey.from_public_bytes(bytes.fromhex(e['issuer_public']))
    def signature(g):public.verify(bytes.fromhex(g['signature']),b'TASK4_NATIVE_OS_V1\0'+canonical(g['statement']))
    for op,g in e['grants'].items():
        signature(g);s=g['statement'];need(s['raw_authority']==c and s['request_sha256']==n.scope()[(op[0],int(op[1]))]
            and s['recipient_sha256']==n.RECIPIENT_SHA and s['target']==n.TARGET and s['output_cap']==256,'EIGHT_SIGNED_RUN_KEY_TIME_GRANTS')
    probe=e['probe'];names=sorted(EXPECTED)
    need([x['name'] for x in probe['results']]==names and len(e['denials'])==len(names)
         and probe['transport_invocations']==1 and probe['request_sha256']==n.scope()[('A',0)]
         and probe['sdk_responses_returned']==probe['native_terminal_arms']==probe['scorer_calls']==0
         and probe['enrollment_writes_denied']==[FILE,'public/recipient.pub','public/native-raw-plan.json']
         and len(probe['frozen_source_git_blobs'])==9,'REAL_NATIVE_CONTEXT_PROBES_NO_SDK_CONTINUATION')
    for name,result,denial in zip(names,probe['results'],e['denials']):
        g=e['candidates'][name]
        need(result['grant_sha256']==denial['grant_sha256']==digest(g)
             and result['decision']=='DENIED_OR_UNKNOWN_NO_RETRY' and denial['uid']==ingress.kernel.CUSTODY
             and denial['reason']==EXPECTED[name] and type(denial['observed_at']) in (int,float)
             and math.isfinite(denial['observed_at']),'CUSTODY_SIGNED_CONTEXT_DENIAL_JOIN')
        if name=='signed-expired':need(denial['observed_at']>=g['statement']['raw_authority']['expires_at'],'EXPIRED_ACTUAL_CLOCK')
        if name=='signed-not-yet-valid':need(denial['observed_at']<g['statement']['raw_authority']['not_before'],'FUTURE_ACTUAL_CLOCK')
        if name.startswith('tampered-'):
            try:signature(g)
            except InvalidSignature:pass
            else:raise ValueError('MUTATED_CONTEXT_SIGNATURE_MUST_FAIL')
        else:signature(g)
    need(normal['evidence']['replay_denials']==16 and e['final_denials_count']==len(EXPECTED)+3,
         'SIGNED_SCOPE_RESTART_REPLAYS_NO_NEW_SEND')
    validations=e['validations'];need(len(validations)==40,'EIGHT_TRIPLE_CHECKS_AND_SIXTEEN_REPLAY_VALIDATIONS')
    for op,g in e['grants'].items():
        group=[x for x in validations if x['op']==op]
        need(len(group)==5 and all(x['uid']==ingress.kernel.CUSTODY and x['grant_sha256']==digest(g)
            and x['phase']=='SIGNED_CONTEXT_VALID' and type(x['observed_at']) in (int,float)
            and c['not_before']<=x['observed_at']<c['expires_at'] for x in group),'SIGNED_LIVE_CLOCK_CHECKS_JOINED')
    return True


def finish(base,output,e,normal):
    e['final_denials_count']=len(ingress.raw.tls.read_lines(base/'custody/raw-authority-denials.jsonl'))
    e['validations']=ingress.raw.tls.read_lines(base/'custody/raw-authority-validations.jsonl')
    need(e['final_denials_count']==len(EXPECTED)+3,'TWELVE_CONTEXT_AND_THREE_OLD_NATIVE_DENIALS')
    validate(e,normal)
    checks={name:True for name in ('eight_crypto_signed_run_recipient_time_scopes','three_context_mutations_invalid_signature',
        'valid_signed_other_run_recipient_leaf_denied','actual_clock_expired_and_future_denied','changed_window_and_unbound_denied',
        'strict_schema_extra_and_bool_denied','kernel_enrollment_write_denied','one_actual_native_sdk_wire_twelve_ipc_refusals',
        'zero_negative_consumptions_tls_posts_effects','eight_bind_raw_archive_owner_native_scorer_joins',
        'sixteen_retained_custody_replays_denied','no_live_provider_or_production_claim')}
    r=dict(schema='task4.native-raw-authority-proof.v1',audited_commit=normal['audited_commit'],
        source_sha256=sha(Path(__file__).read_bytes()),normal_report_sha256=digest(normal),evidence=e,evidence_sha256=digest(e),checks=checks,
        raw_recipient_bound_in_signed_grant=True,run_id_and_validity_bound_in_signed_grant=True,
        checks_before_consumption_and_api_post=True,independent_clock_proven=False,independent_administration_proven=False,
        production_bypass_resistance_proven=False,live_recipient_provisioning_proven=False,real_data_confidentiality_proven=False,
        real_provider_posts=0,external_bank_effects=0,utility='UNSCORED',provider_dispatch='DENY',trusted_root_kernel_issuer_custody_backend_owner=True)
    (output/'raw-authority.json').write_bytes(canonical(r))
    suite=ET.Element('testsuite',name='Signed Native raw archive authority',tests=str(len(checks)),failures='0',errors='0',skipped='0')
    for name in checks:ET.SubElement(suite,'testcase',classname='native_raw_authority',name=name)
    ET.ElementTree(suite).write(output/'raw-authority-junit.xml',encoding='utf-8',xml_declaration=True)

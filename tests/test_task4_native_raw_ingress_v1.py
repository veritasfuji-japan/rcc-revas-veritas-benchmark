import copy
import json
from pathlib import Path
import pytest

from scripts import task4_native_raw_ingress_v1 as p
from scripts import task4_native_os_custody_v1 as n


def evidence(mode):
    success=mode=='success';ops=[a+str(i) for a,i in n.scope()] if success else ['A0']
    plan=dict(schema=p.MARKER,mode=mode,run_id='a'*64,recipient_sha256='b'*64,leaf_sha256='c'*64)
    posts=[dict(authorized=False,path=p.raw.PATH)];events=[];recovered=[];consumed=[];effects=[];bindings=[];records=[];lines=[]
    blocked=dict(final_outcome='BLOCKED');committed=dict(final_outcome='COMMITTED')
    for op in ops:
        req=n.scope()[(op[0],int(op[1]))];res='d'*64
        row=[op,'MOCK_OBSERVED' if success else 'CONSUMED_UNKNOWN',req,None,None,None,None];consumed.append(row)
        events.append(dict(op=op,phase='CONSUMED',uid=p.kernel.CUSTODY))
        if mode=='after-consume-crash':continue
        events.append(dict(op=op,phase='BIND_RECEIPT',uid=p.kernel.CUSTODY,allowed=False,apply_calls=0,receipt=blocked))
        posts.append(dict(op=op,authorized=True,path=p.raw.PATH,host=p.tls.NAME,request_sha256=req,response_sha256=res,
            observed_prefix_sha256='e'*64,observed_prefix_bytes=100))
        effects.append([op,req,res,'f'*64])
        peer=dict(ip=p.tls.IP,leaf_sha256='c'*64,hostname=p.tls.NAME,port=443,
            certificate_required=True,hostname_checked=True,tls_version='TLSv1.3')
        completion='timeout' if mode=='timeout' else 'limit' if mode=='oversized' else 'eof'
        for phase,extra in [('API_PEER_VERIFIED',{'peer':peer}),('API_POST_ATTEMPTED',{}),
            ('RAW_OBSERVED',dict(raw_sha256='e'*64,observed_bytes=100,capture_completion=completion))]:
            events.append(dict(op=op,phase=phase,uid=p.kernel.CUSTODY,**extra))
        if mode=='archive-failure':events.append(dict(op=op,phase='ARCHIVE_FAILED',uid=p.kernel.CUSTODY));continue
        archive=dict(raw_sha256='e'*64,observed_bytes=100,envelope_sha256='1'*64,recipient_sha256='b'*64,
            request_sha256=req,run_id='a'*64,slot=op,capture_completion=completion,local_fsync_completed=True)
        recovered.append({k:archive[k] for k in ('slot','raw_sha256','observed_bytes','envelope_sha256','recipient_sha256','capture_completion')})
        events.append(dict(op=op,phase='SEALED_FSYNCED',uid=p.kernel.CUSTODY,archive=archive))
        if mode in {'after-seal-crash','oversized','timeout'}:continue
        events.append(dict(op=op,phase='HTTP_PARSE_STARTED',uid=p.kernel.CUSTODY))
        if not success:continue
        events.append(dict(op=op,phase='BODY_RELEASED_TO_BIND',uid=p.kernel.CUSTODY))
        events.append(dict(op=op,phase='BIND_RECEIPT',uid=p.kernel.CUSTODY,allowed=True,apply_calls=1,receipt=committed))
        binding=dict(records=[dict(receipt=blocked),dict(receipt=committed)])
        bindings.append(dict(operation_id=op,**binding));row[3:]=[res,'f'*64,'2'*64,p.digest(binding)]
        records.append(dict(arm=op[0],ordinal=int(op[1]),request_sha256=req,response_sha256=res,
            backend_receipt_sha256='f'*64,envelope_sha256='2'*64,bind_sha256=p.digest(binding)))
        lines.append(dict(arm=op[0],ordinal=int(op[1]),original_request_raw_sha256=req,original_response_raw_sha256=res))
    native=(dict(records=records,lineage=dict(response_receipts=lines),lineage_sha256=p.digest(dict(response_receipts=lines)),
        scorer_calls=2,scripted_native_arms=2,native_terminal_hashes=['3'*64,'4'*64],frozen_source_git_blobs=list(range(9))) if success else
        dict(sdk_responses_returned=0,scorer_calls=0,native_terminal_arms=0,transport_invocations=1))
    return dict(plan=plan,checks_before=dict(reachable_native_uid_without_credential_http_403=True),owner_private_read_denied=True,
        posts=posts,events=events,recovered=recovered,consumed=sorted(consumed),effects=effects,native=native,bindings=bindings,
        replay_denials=16 if success else 2 if mode in {'after-consume-crash','after-seal-crash'} else 4,
        posts_after_replay_sha256=p.digest(posts),events_after_replay_sha256=p.digest(events),
        topology={k:dict(links=['lo'] if k=='isolated' else ['lo','veth'],routes=[],routes6=[]) for k in ('client','sink','isolated')})


@pytest.mark.parametrize('mode',p.MODES)
def test_all_required_modes_validate(mode):assert p.validate(evidence(mode))


@pytest.mark.parametrize('fault',['auth','owner','duplicate','consume','bind','peer','body','archive-order','archive-hash',
    'recipient','release','replay','lineage','scorer','route'])
def test_false_green_native_join_refused(fault):
    e=evidence('success')
    if fault=='auth':e['checks_before']['reachable_native_uid_without_credential_http_403']=False
    elif fault=='owner':e['owner_private_read_denied']=False
    elif fault=='duplicate':e['posts'].append(e['posts'][-1])
    elif fault=='consume':e['consumed'][0][1]='REUSABLE'
    elif fault=='bind':e['events'][1]['receipt']['final_outcome']='COMMITTED'
    elif fault=='peer':e['events'][2]['peer']['certificate_required']=False
    elif fault=='body':e['posts'][1]['request_sha256']='0'*64
    elif fault=='archive-order':e['events'][5]['phase']='HTTP_PARSE_STARTED'
    elif fault=='archive-hash':e['recovered'][0]['raw_sha256']='0'*64
    elif fault=='recipient':e['plan']['recipient_sha256']='0'*64
    elif fault=='release':e['events'][7]['phase']='HTTP_PARSE_STARTED'
    elif fault=='replay':e['replay_denials']=0
    elif fault=='lineage':e['native']['lineage']['response_receipts'][0]['original_response_raw_sha256']='0'*64
    elif fault=='scorer':e['native']['scorer_calls']=0
    else:e['topology']['client']['routes']=[dict(dst='default',gateway='1.1.1.1')]
    with pytest.raises((ValueError,IndexError)):p.validate(e)


@pytest.mark.parametrize('mode',['http403','malformed-json','malformed-http','missing-id','truncated','oversized','timeout','dropped'])
def test_original_body_fault_framing_is_not_a_success(mode):
    wire=p.response_wire(p.raw.canonical(dict(object='chat.completion',model=p.raw.request_parameters()['model'],id='local',choices=[{}])), 'A0',mode)
    with pytest.raises((ValueError,p.http.client.HTTPException)):
        p.raw.parse_wire(wire[:p.raw.LIMIT+1],'timeout' if mode=='timeout' else 'limit' if mode=='oversized' else 'eof')


def test_absent_marker_preserves_original_route(tmp_path):assert p.enabled(tmp_path) is False


def test_untrusted_marker_cannot_enable_transport(tmp_path):
    (tmp_path/'public').mkdir();(tmp_path/'public/native-raw-plan.json').write_text('{}')
    with pytest.raises(ValueError):p.enabled(tmp_path)


def test_unknown_raw_mode_refused_before_privileged_operations(tmp_path):
    with pytest.raises(ValueError,match='RAW_INGRESS_SEPARATE'):
        n.run(tmp_path/'output',local_https=True,raw_ingress='live')


def test_raw_mode_requires_separate_tls_fixture(tmp_path):
    with pytest.raises(ValueError,match='RAW_INGRESS_SEPARATE'):
        n.run(tmp_path/'output',raw_ingress='success')

"""Portable joins and adapter failure boundaries; root Native proof is mandatory CI."""
import copy
from pathlib import Path
import pytest
from scripts import task4_native_deadline_normal_v1 as z


def test_new_adapter_pins_existing_collector_and_full_authority_sources():
    value=z.sources()
    assert z.deadline.source_sha256()==z.DEADLINE_PIN
    assert z.m.source_sha256()==z.NORMAL_PIN
    assert len(value['normal']['frozen'])==15
    assert value['deadline']['profile']==z.DEADLINE_PIN


def test_ack_required_before_root(monkeypatch):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):z.run(Path('/tmp/not-created'))


@pytest.mark.parametrize('component',['signed','retained'])
def test_existing_deployment_denies_before_output_or_tools(monkeypatch,component):
    monkeypatch.setattr(z.e,'require_root',lambda:None)
    monkeypatch.setattr(getattr(z,component),'required',lambda:True)
    monkeypatch.setattr(z.e,'tools',lambda:pytest.fail('tools before collision refusal'))
    with pytest.raises(ValueError):z.run(Path('/tmp/not-created'),True)


def test_scope_does_not_convert_local_success_to_live_permission():
    value=z.limits()
    assert value['fixed_total_deadline_normal_path_tested'] is True
    assert value['capture_override']=='task4_native_total_deadline_v1.bounded_capture'
    assert value['live_execution_permission_issued'] is value['operator_native_ready'] is False
    assert value['host_trial_lease_integrated'] is value['retained_operator_service_integrated'] is False
    assert value['backend_restart_or_power_loss_tested'] is value['hard_realtime_deadline_proven'] is False
    assert value['real_provider_posts']==0 and value['utility']=='UNSCORED'


@pytest.fixture
def trace_vector():
    """Synthetic validator vector, never represented as actual UID/Native evidence."""
    namespace=dict(device=4,inode=123)
    evidence=dict(posts=[],recovered=[],native=dict(records=[]),events=[])
    normal=dict(native=dict(evidence=evidence))
    trace=[]
    for index,op in enumerate(arm+str(i) for arm in 'AB' for i in range(4)):
        body=z.n.canonical(dict(id='test-'+op,object='chat.completion',
            model=z.ingress.raw.request_parameters()['model'],choices=[dict(index=0)]))
        wire=z.ingress.response_wire(body,op,'success')
        start=10_000_000_000*(index+1)
        collection=dict(started_ns=start,finished_ns=start+50,deadline_ns=start+z.deadline.TOTAL_NS,
            total_budget_ns=z.deadline.TOTAL_NS,inactivity_seconds=.7,stop_reason='eof',
            observed_b64=z.n.encode(wire),observed_bytes=len(wire),raw_sha256=z.e.sha(wire),capture_completion='eof',
            reads=[dict(before_ns=start+1,after_ns=start+10,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(wire)),
                   dict(before_ns=start+20,after_ns=start+30,wait_seconds=.7,outcome='eof',part_b64='')])
        archive=dict(raw_sha256=z.e.sha(wire),envelope_sha256=z.e.sha(op.encode()))
        common=dict(op=op,uid=z.n.CUSTODY,namespace=namespace)
        trace.extend([dict(common,phase='CAPTURE',collection=collection,channel_open=True,restored_timeout_seconds=.7),
            dict(common,phase='CLOSE',started_ns=start+60,finished_ns=start+70,socket_closed=True,connection_socket_cleared=True),
            dict(common,phase='SEALED',finished_ns=start+80,archive=archive),
            dict(common,phase='PARSED',started_ns=start+90,finished_ns=start+100,raw_sha256=z.e.sha(wire),
                response_sha256=z.e.sha(body),status=200,request_id='native-local-'+op)])
        evidence['posts'].append(dict(op=op,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),response_sha256=z.e.sha(body)))
        evidence['recovered'].append(dict(slot=op,raw_sha256=z.e.sha(wire),observed_bytes=len(wire),capture_completion='eof',
            envelope_sha256=archive['envelope_sha256']))
        evidence['native']['records'].append(dict(arm=op[0],ordinal=int(op[1]),response_sha256=z.e.sha(body),
            archive=dict(statement=dict(archive=archive))))
        evidence['events'].extend([dict(op=op) for _ in range(5)]+[dict(op=op,archive=archive)])
    return trace,normal,namespace


def test_eight_distinct_eof_traces_join_actual_parser_bytes_and_archive_metadata(trace_vector):
    assert z.validate_trace(*trace_vector)
    assert len({x['collection']['started_ns'] for x in trace_vector[0] if x['phase']=='CAPTURE'})==8


@pytest.mark.parametrize('fault',['missing','duplicate','order','uid','namespace','deadline_reset','budget','timeout',
    'receive_bytes','receive_hash','wait_reset','last_outcome','restored_timeout','not_closed','conn_retained',
    'parse_before_seal','seal_before_close','previous_response_overlap','archive','owner_hash','owner_length',
    'owner_completion','body','request_id','status','post_hash','post_length','parsed_hash','extra_field'])
def test_changed_capture_parser_archive_or_temporal_join_is_rejected(trace_vector,fault):
    trace,normal,ns=trace_vector
    cap,close,sealed,parsed=trace[:4];c=cap['collection'];ev=normal['native']['evidence']
    if fault=='missing':trace.pop()
    elif fault=='duplicate':trace[4:8]=copy.deepcopy(trace[:4])
    elif fault=='order':trace[0],trace[1]=trace[1],trace[0]
    elif fault=='uid':cap['uid']=61104
    elif fault=='namespace':cap['namespace']={}
    elif fault=='deadline_reset':c['deadline_ns']+=1
    elif fault=='budget':c['total_budget_ns']+=1
    elif fault=='timeout':c['capture_completion']='timeout';c['stop_reason']='total-deadline'
    elif fault=='receive_bytes':c['observed_b64']=z.n.encode(b'changed')
    elif fault=='receive_hash':c['raw_sha256']='0'*64
    elif fault=='wait_reset':c['reads'][1]['wait_seconds']=1
    elif fault=='last_outcome':c['reads'][-1]['outcome']='timeout'
    elif fault=='restored_timeout':cap['restored_timeout_seconds']=2
    elif fault=='not_closed':close['socket_closed']=False
    elif fault=='conn_retained':close['connection_socket_cleared']=False
    elif fault=='parse_before_seal':parsed['started_ns']=sealed['finished_ns']-1
    elif fault=='seal_before_close':sealed['finished_ns']=close['finished_ns']-1
    elif fault=='previous_response_overlap':trace[4]['collection']['started_ns']=1
    elif fault=='archive':sealed['archive']=dict(raw_sha256='0'*64,envelope_sha256='1'*64)
    elif fault=='owner_hash':ev['recovered'][0]['raw_sha256']='0'*64
    elif fault=='owner_length':ev['recovered'][0]['observed_bytes']+=1
    elif fault=='owner_completion':ev['recovered'][0]['capture_completion']='timeout'
    elif fault=='body':parsed['response_sha256']='0'*64
    elif fault=='request_id':parsed['request_id']='native-local-B0'
    elif fault=='status':parsed['status']=201
    elif fault=='post_hash':ev['posts'][0]['wire_sha256']='0'*64
    elif fault=='post_length':ev['posts'][0]['wire_bytes']+=1
    elif fault=='parsed_hash':parsed['raw_sha256']='0'*64
    else:cap['unreviewed']=True
    with pytest.raises((ValueError,KeyError,IndexError)):z.validate_trace(trace,normal,ns)


@pytest.mark.parametrize('failure',[None,'capture','seal','parse','dispatch'])
def test_transport_override_restores_dependencies_and_propagates_failures(monkeypatch,tmp_path,failure):
    monkeypatch.setattr(z.m,'fixture',lambda _:None)
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    raw=z.ingress.raw
    originals=(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    authorities=(z.n.verify,z.b.verify_packet,z.b.consume_packet,z.n.bind_post,z.b.native,z.signed.gate)
    class Stop(RuntimeError):pass
    def fail(*_,**__):raise Stop(failure)
    monkeypatch.setattr(z.deadline,'bounded_capture',fail)
    monkeypatch.setattr(z.u,'append',lambda *args:None)
    monkeypatch.setattr(raw,'seal',fail)
    monkeypatch.setattr(raw,'parse_wire',fail)
    saved=(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    def original_dispatch(base,packet,request,key):
        assert authorities==(z.n.verify,z.b.verify_packet,z.b.consume_packet,z.n.bind_post,z.b.native,z.signed.gate)
        assert raw.capture is not saved[0] and raw.seal is not saved[1] and raw.parse_wire is not saved[2]
        if failure=='capture':raw.capture(None)
        if failure=='seal':raw.seal(None)
        if failure=='parse':raw.parse_wire(b'', 'eof')
        if failure=='dispatch':fail()
        return 200,dict(original_dispatch_return=True)
    monkeypatch.setattr(z.m,'dispatch',original_dispatch)
    if failure:
        with pytest.raises(Stop):z.dispatch(tmp_path,dict(arm='A',ordinal=0),b'raw',b'key')
    else:assert z.dispatch(tmp_path,dict(arm='A',ordinal=0),b'raw',b'key')==(200,dict(original_dispatch_return=True))
    assert saved==(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    assert originals[0] is raw.capture

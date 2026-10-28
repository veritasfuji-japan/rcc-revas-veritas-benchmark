"""Portable framing comparisons and evidence rejection; real UID joins run in CI."""
import copy
from pathlib import Path
import pytest
from scripts import task4_native_response_framing_guard_v1 as frame
from scripts import task4_native_response_id_guard_v1 as guard
from scripts import task4_native_ambiguous_framing_v1 as z
from scripts import task4_native_framing_guard_normal_v1 as normal


def test_sources_and_unchanged_guards_are_pinned():
    assert z.sources()['framing_guard']==normal.sources()['framing_guard']==frame.source_sha256()
    assert z.sources()['id_guard']==normal.sources()['id_guard']==guard.source_sha256()


@pytest.mark.parametrize('profile',[z,normal])
def test_explicit_ack_before_root_or_output(profile,monkeypatch):
    monkeypatch.setattr(profile.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):profile.run(Path('/tmp/unused'))


@pytest.mark.parametrize('size',[0,1,9,100,2000,32000])
@pytest.mark.parametrize('name',[b'Content-Length',b'content-length',b'CONTENT-LENGTH'])
def test_one_canonical_length_exact_body_and_no_transfer_coding(size,name):
    wire=b'HTTP/1.1 200 OK\r\n'+name+b': '+str(size).encode()+b'\r\n\r\n'+b'x'*size
    assert frame.require_framing(wire)==dict(length_field_count=1,content_length=size,body_bytes=size,transfer_encoding_present=False)


@pytest.mark.parametrize('value',[b'-1',b'+1',b'01',b'1, 1',b'1,2',b'1 ',b' 1',b'1\t',b'',b'1;foo',b'0x1',b'999999',b'\xff',b'1\nX: y'])
def test_noncanonical_or_list_lengths_are_never_coerced(value):
    with pytest.raises(frame.AmbiguousFraming):frame.require_framing(b'HTTP/1.1 200 OK\r\nContent-Length: '+value+b'\r\n\r\nx')


@pytest.mark.parametrize('wire',[None,bytearray(b'x'),b'',b'x'*32769,b'HTTP/1.1 200 OK\nContent-Length: 1\n\nx',
    b'HTTP/1.1 200 OK\r\n\r\nx',b'HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\n Content-Length: 1\r\n\r\nx',b'HTTP/1.1 200 OK\r\nContent-Length : 1\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx',b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: identity\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\ntransfer-encoding: chunked\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx'])
def test_missing_ambiguous_truncated_extra_or_nonprofile_wire_is_refused(wire):
    with pytest.raises(frame.AmbiguousFraming):frame.require_framing(wire)


@pytest.fixture
def full_wire():
    body=z.n.canonical(dict(id='synthetic-public',object='chat.completion',model=z.ingress.raw.request_parameters()['model'],
        choices=[dict(index=0,message=dict(role='assistant',content='public fixture'))]))
    return z.ingress.response_wire(body,'A0','success')


@pytest.mark.parametrize('fault',z.MODES)
def test_ambiguous_fixture_changes_only_headers_and_original_parser_still_succeeds(full_wire,fault):
    wire=z.substituted_wire(full_wire,fault)
    code,headers,body=z.ingress.raw.parse_wire(wire,'eof')
    assert code==200 and body==full_wire.partition(b'\r\n\r\n')[2]
    with pytest.raises(frame.AmbiguousFraming):frame.require_framing(wire)
    assert guard.require_one_id(headers)==dict(field_count=1,request_id='native-local-A0')


@pytest.mark.parametrize('fault',[None,'wrong-single',*z.MODES])
def test_original_dispatch_comparison_and_hardened_guard_differential(full_wire,fault,tmp_path,monkeypatch):
    """Original dispatcher with stubbed transport/authority, not an actual Native proof."""
    import sqlite3
    request=b'public synthetic request';packet=dict(arm='A',ordinal=0)
    wire=(full_wire if fault is None else z.binding_profile.substituted_wire(full_wire,'other-step-id') if fault=='wrong-single' else z.substituted_wire(full_wire,fault))
    (tmp_path/'custody').mkdir();(tmp_path/'public').mkdir();(tmp_path/'public/issuer-key').write_bytes(b'public')
    with sqlite3.connect(tmp_path/'custody/ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op TEXT,state TEXT,request_sha TEXT)')
        db.execute('INSERT INTO consumed VALUES (?,?,?)',('A0','CONSUMED_UNKNOWN',z.e.sha(request)))
    events=[]
    class Channel:
        def settimeout(self,value):assert value==.7
    class Connection:
        sock=Channel()
        closed=0
        def connect(self):pass
        def request(self,method,path,body,headers):assert method=='POST' and body==request
        def close(self):self.closed+=1
    conn=Connection();original=z.ingress.raw.parse_wire
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(z.n,'verify',lambda *args:request)
    monkeypatch.setattr(z.ingress,'plan',lambda _:dict(run_id='1'*64))
    monkeypatch.setattr(z.m,'connection',lambda _:conn)
    monkeypatch.setattr(z.m,'peer',lambda _:dict(test_only=True))
    monkeypatch.setattr(z.ingress,'emit',lambda base,op,phase,**data:events.append(phase))
    monkeypatch.setattr(z.ingress.raw,'capture',lambda _: (wire,'eof'))
    monkeypatch.setattr(z.ingress.raw,'seal',lambda *args:dict(test_only_archive=True))
    if fault=='wrong-single':
        with pytest.raises(ValueError):z.m.dispatch(tmp_path,packet,request,b'key')
        assert events[-1]=='HTTP_PARSE_STARTED'
    else:
        assert z.m.dispatch(tmp_path,packet,request,b'key')[0]==200
        assert events[-1]=='BODY_RELEASED_TO_BIND'  # Explicit legacy regression witness.
    events.clear()
    def hardened(wire,completion):
        result=original(wire,completion);guard.require_one_id(result[1]);frame.require_framing(wire);return result
    monkeypatch.setattr(z.ingress.raw,'parse_wire',hardened)
    if fault is None:
        assert z.m.dispatch(tmp_path,packet,request,b'key')[0]==200
        assert events[-1]=='BODY_RELEASED_TO_BIND'
    elif fault=='wrong-single':
        with pytest.raises(ValueError) as error:z.m.dispatch(tmp_path,packet,request,b'key')
        assert not isinstance(error.value,frame.AmbiguousFraming)
        assert events[-1]=='HTTP_PARSE_STARTED' and 'BODY_RELEASED_TO_BIND' not in events
    else:
        with pytest.raises(frame.AmbiguousFraming):z.m.dispatch(tmp_path,packet,request,b'key')
        assert events[-1]=='HTTP_PARSE_STARTED' and 'BODY_RELEASED_TO_BIND' not in events
    assert conn.closed==2 and events.index('SEALED_FSYNCED')<events.index('HTTP_PARSE_STARTED')


@pytest.fixture(params=z.MODES)
def trace_vector(request,full_wire):
    fault=request.param;wire=z.substituted_wire(full_wire,fault);ns=dict(device=4,inode=123)
    c=dict(started_ns=100,finished_ns=150,deadline_ns=100+z.deadline.TOTAL_NS,total_budget_ns=z.deadline.TOTAL_NS,
        inactivity_seconds=.7,stop_reason='eof',reads=[dict(before_ns=101,after_ns=110,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(wire)),
        dict(before_ns=120,after_ns=130,wait_seconds=.7,outcome='eof',part_b64='')],observed_b64=z.n.encode(wire),
        observed_bytes=len(wire),raw_sha256=z.e.sha(wire),capture_completion='eof')
    archive=dict(raw_sha256=z.e.sha(wire),observed_bytes=len(wire),local_fsync_completed=True)
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    code,headers,body=z.ingress.raw.parse_wire(wire,'eof');values=guard.id_values(headers)
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=160,finished_ns=170,socket_closed=True,connection_socket_cleared=True),
        dict(common,phase='SEALED',finished_ns=180,archive=archive),dict(common,phase='PARSER_RETURNED',started_ns=190,finished_ns=200,
        raw_sha256=z.e.sha(wire),status=code,request_id_values=values,response_sha256=z.e.sha(body)),
        dict(common,phase='FRAMING_GUARD_REFUSED',finished_ns=210,error_class='AmbiguousFraming',request_id_values=values)]
    return trace,wire,archive,ns,fault


def test_exact_received_wire_parse_and_guard_refusal_join(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['deadline','budget','timeout','wait','fragment','digest','uid','namespace','guard_error',
    'parser_refused','not_closed','not_cleared','restore','parse_before_seal','seal_before_close','archive','missing_event','extra_event',
    'collapsed_ids','changed_body','refusal_before_parse'])
def test_changed_deadline_archive_parser_or_occurrence_evidence_is_rejected(trace_vector,change):
    trace,wire,archive,ns,fault=trace_vector;cap,closed,sealed,parser,refused=trace;c=cap['collection']
    if change=='deadline':c['deadline_ns']+=1
    elif change=='budget':c['total_budget_ns']+=1
    elif change=='timeout':c['capture_completion']='timeout'
    elif change=='wait':c['reads'][-1]['wait_seconds']=2
    elif change=='fragment':c['reads'][0]['part_b64']=''
    elif change=='digest':c['raw_sha256']='0'*64
    elif change=='uid':cap['uid']=61104
    elif change=='namespace':cap['namespace']={}
    elif change=='guard_error':refused['error_class']='ValueError'
    elif change=='parser_refused':parser['phase']='PARSER_REFUSED'
    elif change=='not_closed':closed['socket_closed']=False
    elif change=='not_cleared':closed['connection_socket_cleared']=False
    elif change=='restore':cap['restored_timeout_seconds']=2
    elif change=='parse_before_seal':parser['started_ns']=sealed['finished_ns']-1
    elif change=='seal_before_close':sealed['finished_ns']=closed['finished_ns']-1
    elif change=='archive':sealed['archive']=dict(raw_sha256='0'*64)
    elif change=='missing_event':trace.pop()
    elif change=='extra_event':trace.append(copy.deepcopy(parser))
    elif change=='collapsed_ids':parser['request_id_values']=refused['request_id_values']=['native-local-B3']
    elif change=='changed_body':parser['response_sha256']='0'*64
    else:refused['finished_ns']=parser['finished_ns']-1
    with pytest.raises((ValueError,KeyError)):z.validate_trace(trace,wire,archive,ns,fault)


@pytest.mark.parametrize('fault',z.MODES)
def test_new_observer_preserves_guard_exception_and_restores_functions(full_wire,fault,monkeypatch,tmp_path):
    raw=z.ingress.raw;wire=z.substituted_wire(full_wire,fault);original=(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    events=[];monkeypatch.setattr(z,'fixture',lambda _:fault);monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(z.u,'append',lambda path,row:events.append(row))
    monkeypatch.setattr(z.m,'dispatch',lambda *_:raw.parse_wire(wire,'eof'))
    with pytest.raises(frame.AmbiguousFraming):z.observed_dispatch(tmp_path,dict(arm='A',ordinal=0),b'',b'')
    assert original==(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    assert [x['phase'] for x in events]==['ORIGINAL_PARSER_RETURNED','PARSER_RETURNED','STRICT_FRAMING_GUARD_REFUSED','FRAMING_GUARD_REFUSED']


def test_normal_adapter_applies_same_guard_and_preserves_parser_result(full_wire,monkeypatch,tmp_path):
    raw=normal.ingress.raw;original=(raw.capture,raw.seal,raw.parse_wire,normal.m.connection)
    events=[];monkeypatch.setattr(normal.m,'fixture',lambda _:None);monkeypatch.setattr(normal.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(normal.u,'append',lambda path,row:events.append(row))
    monkeypatch.setattr(normal.m,'dispatch',lambda *_:raw.parse_wire(full_wire,'eof'))
    result=normal.dispatch(tmp_path,dict(arm='A',ordinal=0),b'',b'')
    assert result[0]==200 and events[-1]['phase']=='PARSED'
    assert events[-1]['id_guard_result']==dict(field_count=1,request_id='native-local-A0')
    assert original==(raw.capture,raw.seal,raw.parse_wire,normal.m.connection)


@pytest.fixture
def normal_trace_vector():
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
    for row in trace:
        if row['phase']=='PARSED':
            row['id_guard_result']=dict(field_count=1,request_id=row['request_id'])
            row['framing_guard_result']=frame.require_framing(z.n.decode(trace[trace.index(row)-3]['collection']['observed_b64']))
    return trace,normal,namespace


def test_eight_normal_collections_independently_replay_the_same_guard(normal_trace_vector):
    assert normal.validate_trace(*normal_trace_vector)


@pytest.mark.parametrize('change',['missing_proof','wrong_count','wrong_id','duplicate_actual_wire'])
def test_normal_guard_proof_and_actual_wire_cannot_be_substituted(normal_trace_vector,change):
    trace,report,ns=normal_trace_vector;parsed=trace[3]
    if change=='missing_proof':parsed.pop('id_guard_result')
    elif change=='wrong_count':parsed['id_guard_result']['field_count']=2
    elif change=='wrong_id':parsed['id_guard_result']['request_id']='native-local-A1'
    else:
        wire=z.n.decode(trace[0]['collection']['observed_b64'])
        line=b'X-Request-Id: native-local-A0\r\n'
        trace[0]['collection']['observed_b64']=z.n.encode(wire.replace(line,line+line,1))
        with pytest.raises(guard.AmbiguousResponseId):normal.validate_trace(trace,report,ns)
        return
    with pytest.raises((ValueError,KeyError)):normal.validate_trace(trace,report,ns)


@pytest.mark.parametrize('change',['missing','count','size','bool_count','transfer','extra'])
def test_normal_framing_evidence_is_replayed_not_trusted(normal_trace_vector,change):
    trace,report,ns=normal_trace_vector;row=trace[3];result=row['framing_guard_result']
    if change=='missing':row.pop('framing_guard_result')
    elif change=='count':result['length_field_count']=2
    elif change=='size':result['body_bytes']+=1
    elif change=='bool_count':result['length_field_count']=True
    elif change=='transfer':result['transfer_encoding_present']=True
    else:result['extra']=False
    with pytest.raises((ValueError,KeyError)):normal.validate_trace(trace,report,ns)

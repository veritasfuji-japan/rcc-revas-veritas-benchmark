"""Portable size-boundary checks; actual Native UID/restarts run in mandatory CI."""
import copy
from pathlib import Path
import socket
import pytest
from scripts import task4_native_response_size_fixture_v1 as size
from scripts import task4_native_size_overflow_v1 as z
from scripts import task4_native_size_boundary_normal_v1 as normal


@pytest.fixture
def original():
    return z.n.canonical(dict(id='synthetic-public',object='chat.completion',model=z.ingress.raw.request_parameters()['model'],
        choices=[dict(index=0,message=dict(role='assistant',content='public fixture'))]))


def padding_record(body,op,target,ns):
    padded=size.padded_body(body,op,target)
    return dict(op=op,uid=z.n.BACKEND,namespace=ns,original_body_b64=z.n.encode(body),original_body_sha256=z.e.sha(body),
        padded_body_sha256=z.e.sha(padded),target_wire_bytes=target,padded_body_bytes=len(padded),phase=size.PHASE)


@pytest.mark.parametrize('target',size.TARGETS)
@pytest.mark.parametrize('op',[a+str(i) for a in 'AB' for i in range(4)])
def test_whitespace_padding_changes_exact_wire_size_without_changing_json(original,target,op):
    padded=size.padded_body(original,op,target);wire=z.ingress.response_wire(padded,op,'success')
    assert len(wire)==target and padded.startswith(original)
    assert padded[len(original):].strip(b' ')==b''
    assert z.ingress.raw.strict(padded)==z.ingress.raw.strict(original)
    record=padding_record(original,op,target,{'device':4,'inode':123})
    assert size.validate_padding(record,wire,op,target,{'device':4,'inode':123})==padded
    if target<=size.LIMIT:
        assert z.ingress.raw.parse_wire(wire,'eof')[2]==padded
        assert z.frame.require_framing(wire)['body_bytes']==len(padded)
    else:
        with pytest.raises(ValueError):z.ingress.raw.parse_wire(wire,'eof')


@pytest.mark.parametrize('target',[True,False,None,32768.0,0,-1,32766,32770,10**9])
def test_arbitrary_padding_sizes_are_not_admitted(original,target):
    with pytest.raises(ValueError):size.padded_body(original,'A0',target)


@pytest.mark.parametrize('field',['op','uid','namespace','original_body_sha256','padded_body_sha256',
    'target_wire_bytes','padded_body_bytes','phase','original_body_b64','extra'])
def test_padding_record_cannot_be_substituted(original,field):
    target=size.LIMIT;ns={'device':4,'inode':123};row=padding_record(original,'A0',target,ns)
    wire=z.ingress.response_wire(size.padded_body(original,'A0',target),'A0','success')
    if field=='original_body_b64':row[field]=z.n.encode(b'{}')
    else:row[field]='changed'
    with pytest.raises((ValueError,KeyError)):size.validate_padding(row,wire,'A0',target,ns)


class Channel:
    def __init__(self,wire,chunk=4096):self.wire=wire;self.chunk=chunk;self.offset=0;self.timeout=.7;self.requests=[]
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value
    def recv(self,count):
        self.requests.append(count);part=self.wire[self.offset:self.offset+min(count,self.chunk)];self.offset+=len(part);return part


def clock():
    value=iter(range(1_000_000_000,2_000_000_000,1000))
    return lambda:next(value)


@pytest.mark.parametrize('target',size.TARGETS)
@pytest.mark.parametrize('chunk',[4096,1024,257])
def test_real_fixed_collector_reads_exact_cap_or_one_sentinel_and_restores_timeout(original,target,chunk):
    wire=z.ingress.response_wire(size.padded_body(original,'A0',target),'A0','success');channel=Channel(wire,chunk)
    observed,completion,c=z.deadline.bounded_capture(channel,clock())
    assert channel.timeout==.7 and observed==wire[:size.LIMIT+1]
    if target<=size.LIMIT:
        assert completion=='eof' and channel.offset==target and c['reads'][-1]['outcome']=='eof'
        z.deadline.validate_collection(c,observed,'eof','eof')
    else:
        assert completion=='limit' and channel.offset==size.LIMIT+1 and c['reads'][-1]['outcome']=='bytes'
        z.validate_byte_limit(c,observed)
    seen=0
    for count,item in zip(channel.requests,c['reads']):
        assert count==min(4096,size.LIMIT+1-seen)
        seen+=len(z.n.decode(item['part_b64']))


@pytest.fixture(params=z.MODES)
def trace_vector(request,original):
    fault=request.param;ns={'device':4,'inode':123};target=z.TARGET_BYTES[fault]
    generated=z.ingress.response_wire(size.padded_body(original,'A0',target),'A0','success')
    observed,_,c=z.deadline.bounded_capture(Channel(generated),clock());start=c['finished_ns'];archive=dict(raw_sha256=z.e.sha(observed))
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=start+1,finished_ns=start+2,socket_closed=True,connection_socket_cleared=True),
        dict(common,phase='SEALED',finished_ns=start+3,archive=archive)]
    return trace,observed,archive,ns,fault


def test_exact_overflow_trace_validates_without_http_parse(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['deadline','budget','completion','reason','fragment','length','digest','wait','eof',
    'uid','namespace','open','restored','not_closed','retained_socket','seal_before_close','missing','parser_called'])
def test_size_or_lifecycle_trace_substitution_is_refused(trace_vector,change):
    trace,wire,archive,ns,fault=trace_vector;cap,closed,sealed=trace;c=cap['collection']
    if change=='deadline':c['deadline_ns']+=1
    elif change=='budget':c['total_budget_ns']+=1
    elif change=='completion':c['capture_completion']='eof'
    elif change=='reason':c['stop_reason']='read-count-limit'
    elif change=='fragment':c['reads'][-1]['part_b64']=''
    elif change=='length':c['observed_bytes']-=1
    elif change=='digest':c['raw_sha256']='0'*64
    elif change=='wait':c['reads'][-1]['wait_seconds']=2
    elif change=='eof':c['reads'][-1]['outcome']='eof'
    elif change=='uid':cap['uid']=61104
    elif change=='namespace':cap['namespace']={}
    elif change=='open':cap['channel_open']=False
    elif change=='restored':cap['restored_timeout_seconds']=2
    elif change=='not_closed':closed['socket_closed']=False
    elif change=='retained_socket':closed['connection_socket_cleared']=False
    elif change=='seal_before_close':sealed['finished_ns']=closed['finished_ns']-1
    elif change=='missing':trace.pop()
    else:trace.append(dict(cap,phase='PARSER_RETURNED'))
    with pytest.raises((ValueError,KeyError)):z.validate_trace(trace,wire,archive,ns,fault)


@pytest.mark.parametrize('fault',z.MODES)
def test_original_dispatch_limit_gate_prevents_parser_after_seal(original,fault,tmp_path,monkeypatch):
    """Real dispatcher/collector, stubbed transport and authority; not a Native proof."""
    import sqlite3
    wire=z.ingress.response_wire(size.padded_body(original,'A0',z.TARGET_BYTES[fault]),'A0','success')
    request=b'public synthetic request';packet=dict(arm='A',ordinal=0)
    (tmp_path/'custody').mkdir();(tmp_path/'public').mkdir();(tmp_path/'public/issuer-key').write_bytes(b'public')
    with sqlite3.connect(tmp_path/'custody/ledger.sqlite3') as db:
        db.execute('CREATE TABLE consumed (op TEXT,state TEXT,request_sha TEXT)')
        db.execute('INSERT INTO consumed VALUES (?,?,?)',('A0','CONSUMED_UNKNOWN',z.e.sha(request)))
    left,right=socket.socketpair();channel=Channel(wire);channel.fileno=left.fileno
    class Connection:
        sock=channel
        def connect(self):pass
        def request(self,*args,**kwargs):pass
        def close(self):left.close();self.sock=None
    conn=Connection();events=[];observed=[];originals=(z.ingress.raw.capture,z.ingress.raw.seal,z.ingress.raw.parse_wire,z.m.connection)
    monkeypatch.setattr(z,'fixture',lambda _:fault);monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(z.n,'verify',lambda *args:request);monkeypatch.setattr(z.ingress,'plan',lambda _:dict(run_id='1'*64))
    monkeypatch.setattr(z.m,'connection',lambda _:conn);monkeypatch.setattr(z.m,'peer',lambda _:dict(test_only=True))
    monkeypatch.setattr(z.ingress,'emit',lambda base,op,phase,**kw:events.append(phase))
    monkeypatch.setattr(z.u,'append',lambda path,row:observed.append(row))
    def seal(*args):
        assert len(args[2])==size.LIMIT+1 and args[3]=='limit';return dict(test_only=True)
    monkeypatch.setattr(z.ingress.raw,'seal',seal)
    monkeypatch.setattr(z.ingress.raw,'parse_wire',lambda *_:pytest.fail('parser after overflow'))
    saved=(z.ingress.raw.capture,z.ingress.raw.seal,z.ingress.raw.parse_wire,z.m.connection)
    try:
        with pytest.raises(ValueError):z.observed_dispatch(tmp_path,packet,request,b'key')
        assert saved==(z.ingress.raw.capture,z.ingress.raw.seal,z.ingress.raw.parse_wire,z.m.connection)
        assert [x['phase'] for x in observed]==['CAPTURE','CLOSE','SEALED']
        assert events[-1]=='SEALED_FSYNCED' and 'HTTP_PARSE_STARTED' not in events
        assert channel.offset==size.LIMIT+1 and left.fileno()==-1
    finally:left.close();right.close()


def test_selected_sources_are_pinned():
    assert z.sources()['size_fixture']==normal.sources()['size_fixture']==size.source_sha256()


@pytest.mark.parametrize('profile',[z,normal])
def test_ack_required_before_root_or_output(profile,monkeypatch):
    monkeypatch.setattr(profile.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):profile.run(Path('/tmp/unused'))


@pytest.fixture
def normal_trace_vector():
    """Synthetic validator vector, never represented as actual UID/Native evidence."""
    namespace=dict(device=4,inode=123)
    evidence=dict(posts=[],recovered=[],native=dict(records=[]),events=[])
    normal=dict(native=dict(evidence=evidence))
    trace=[];padding=[]
    for index,op in enumerate(arm+str(i) for arm in 'AB' for i in range(4)):
        body=z.n.canonical(dict(id='test-'+op,object='chat.completion',
            model=z.ingress.raw.request_parameters()['model'],choices=[dict(index=0)]))
        original=body;target=size.LIMIT-(1 if index%2==0 else 0)
        body=size.padded_body(original,op,target)
        padding.append(padding_record(original,op,target,namespace))
        wire=z.ingress.response_wire(body,op,'success')
        start=10_000_000_000*(index+1)
        ticks=iter(range(start,start+1_000_000_000,1))
        _,_,collection=z.deadline.bounded_capture(Channel(wire),lambda:next(ticks))
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
            row['framing_guard_result']=z.frame.require_framing(z.n.decode(trace[trace.index(row)-3]['collection']['observed_b64']))
    return trace,normal,namespace,padding



def test_eight_normal_near_boundary_wires_join_original_body_archive_and_padding(normal_trace_vector):
    trace,report,ns,padding=normal_trace_vector
    assert normal.validate_trace(trace,report,ns)
    assert normal.validate_padding_events(padding,trace,ns)
    assert [row['collection']['observed_bytes'] for row in trace if row['phase']=='CAPTURE']==[size.LIMIT-1,size.LIMIT]*4


@pytest.mark.parametrize('change',['missing','extra','wrong_target','wrong_body_hash','wrong_op','wrong_uid','changed_original','swapped','wire_suffix','framing_metadata'])
def test_boundary_normal_evidence_cannot_be_relabelled_or_repaired(normal_trace_vector,change):
    trace,report,ns,padding=normal_trace_vector
    if change=='missing':padding.pop()
    elif change=='extra':padding.append(copy.deepcopy(padding[0]))
    elif change=='wrong_target':padding[0]['target_wire_bytes']=size.LIMIT
    elif change=='wrong_body_hash':padding[0]['padded_body_sha256']='0'*64
    elif change=='wrong_op':padding[0]['op']='B0'
    elif change=='wrong_uid':padding[0]['uid']=0
    elif change=='changed_original':padding[0]['original_body_b64']=z.n.encode(b'{}')
    elif change=='swapped':padding[0],padding[1]=padding[1],padding[0]
    elif change=='wire_suffix':trace[0]['collection']['observed_b64']=z.n.encode(z.n.decode(trace[0]['collection']['observed_b64'])+b' ')
    else:trace[3]['framing_guard_result']['body_bytes']-=1
    with pytest.raises((ValueError,KeyError)):
        normal.validate_trace(trace,report,ns)
        normal.validate_padding_events(padding,trace,ns)


@pytest.mark.parametrize('profile',[z,normal])
def test_explicit_cli_forwards_real_ack_and_output_to_selected_runner(profile,monkeypatch,tmp_path):
    calls=[]
    monkeypatch.setattr(profile,'run',lambda *args:calls.append(args))
    argv=['--run','--output',str(tmp_path/'proof')]
    if profile is z:
        argv+=['--fault','one-byte-over','--acknowledge-isolated-size-overflow-test']
        expected=(tmp_path/'proof','one-byte-over',True)
    else:
        argv+=['--acknowledge-isolated-size-boundary-normal-test']
        expected=(tmp_path/'proof',True)
    profile.main(argv)
    assert calls==[expected]

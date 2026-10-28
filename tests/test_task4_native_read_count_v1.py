"""Portable read-count joins and real TLS mechanics; actual UID proof is CI-only."""
import copy
import datetime
import http.client
import os
from pathlib import Path
import socket
import ssl
import threading
import pytest
from scripts import task4_native_read_fragment_fixture_v1 as fragment
from scripts import task4_native_read_count_limit_v1 as z
from scripts import task4_native_read_count_normal_v1 as normal


def full_wire(op='A0'):
    body=z.n.canonical(dict(id='public-'+op,object='chat.completion',model=z.ingress.raw.request_parameters()['model'],
        choices=[dict(index=0,message=dict(role='assistant',content='PUBLIC '*80))]))
    return z.ingress.response_wire(body,op,'success')


class Channel:
    def __init__(self,parts):self.parts=list(parts);self.timeout=.7;self.calls=0
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value
    def recv(self,count):
        self.calls+=1
        part=self.parts.pop(0) if self.parts else b''
        assert len(part)<=count
        return part


def collection(wire,mode,start=10000):
    ticks=iter(range(start,start+1_000_000_000))
    channel=Channel(fragment.fragments(wire,mode))
    raw,completion,c=z.deadline.bounded_capture(channel,lambda:next(ticks))
    assert channel.calls==fragment.COUNT and channel.timeout==.7
    return raw,completion,c


def record(wire,mode,namespace,op='A0',start=10000,terminal_finished=None):
    parts=fragment.fragments(wire,mode);total=0;writes=[]
    for i,part in enumerate(parts):
        total+=len(part);writes.append(dict(part_b64=z.n.encode(part),finished_ns=start+i+1,cumulative_bytes=total))
    sent=b''.join(parts)
    return dict(op=op,mode=mode,uid=z.n.BACKEND,namespace=namespace,wire_b64=z.n.encode(wire),wire_sha256=z.e.sha(wire),wire_bytes=len(wire),
        transmitted_b64=z.n.encode(sent),transmitted_sha256=z.e.sha(sent),transmitted_bytes=len(sent),writes=writes,
        started_ns=start,terminal_started_ns=start+fragment.COUNT+1,terminal_finished_ns=terminal_finished or start+2000,
        termination='TLS_CLOSE_NOTIFY' if mode=='normal' else 'HOLD_OPEN_UNTIL_CLIENT_CLOSE',
        terminal_result='SSLEOFError' if mode=='normal' else 'EOF',phase='COMMITTED_EFFECT_FRAGMENTED_TLS_RESPONSE')


@pytest.mark.parametrize('op',[a+str(i) for a in 'AB' for i in range(4)])
@pytest.mark.parametrize('mode',fragment.MODES)
def test_unchanged_wire_split_schedule_and_exact_read_cap(op,mode):
    wire=full_wire(op);parts=fragment.fragments(wire,mode)
    assert len(parts)==(255 if mode=='normal' else 256) and all(parts)
    expected=wire[:256] if mode=='prefix-at-cap' else wire
    assert b''.join(parts)==expected
    observed,completion,c=collection(wire,mode)
    assert observed==expected and completion==('eof' if mode=='normal' else 'limit')
    assert fragment.validate_collection(c,wire,mode)==expected
    assert fragment.validate_record(record(wire,mode,{},op),wire,mode,op,{})==expected
    if mode!='normal':assert z.validate_read_count(c,observed,mode)


@pytest.mark.parametrize('wire,mode',[(None,'normal'),(b'','normal'),(b'x'*256,'normal'),(b'x'*32769,'normal'),
    (b'NOT HTTP'*60,'normal'),(full_wire(),'other'),(full_wire().replace(b'Content-Length:',b'Transfer-Encoding:'),'normal')])
def test_no_unbounded_or_unreviewed_fragment_schedule(wire,mode):
    with pytest.raises((ValueError,TypeError,http.client.HTTPException)):fragment.fragments(wire,mode)


@pytest.mark.parametrize('mode',fragment.MODES)
@pytest.mark.parametrize('change',['missing_write','extra_write','part','offset','bool_offset','wire','transmitted','uid','mode','namespace',
    'phase','termination','terminal_result','time_order','extra_field'])
def test_sender_record_substitution_is_refused(mode,change):
    wire=full_wire();ns={'device':4,'inode':123};r=record(wire,mode,ns)
    if change=='missing_write':r['writes'].pop()
    elif change=='extra_write':r['writes'].append(copy.deepcopy(r['writes'][-1]))
    elif change=='part':r['writes'][0]['part_b64']=z.n.encode(b'other')
    elif change=='offset':r['writes'][-1]['cumulative_bytes']+=1
    elif change=='bool_offset':r['writes'][0]['cumulative_bytes']=True
    elif change=='wire':r['wire_b64']=z.n.encode(b'other')
    elif change=='transmitted':r['transmitted_b64']=z.n.encode(b'other')
    elif change=='uid':r['uid']=0
    elif change=='mode':r['mode']='normal' if mode!='normal' else 'complete-at-cap'
    elif change=='namespace':r['namespace']={}
    elif change=='phase':r['phase']='BEFORE_COMMIT'
    elif change=='termination':r['termination']='CLOSED_BEFORE_CAP'
    elif change=='terminal_result':r['terminal_result']='fabricated'
    elif change=='time_order':r['terminal_started_ns']=r['started_ns']-1
    else:r['extra']=True
    with pytest.raises((ValueError,KeyError)):fragment.validate_record(r,wire,mode,'A0',ns)


@pytest.mark.parametrize('mode',fragment.MODES)
@pytest.mark.parametrize('change',['missing_read','extra_read','fragment','deadline','budget','wait','digest','length','completion','reason','last_outcome','late_finish'])
def test_collector_schedule_substitution_is_refused(mode,change):
    wire=full_wire();_,_,c=collection(wire,mode)
    if change=='missing_read':c['reads'].pop()
    elif change=='extra_read':c['reads'].append(copy.deepcopy(c['reads'][-1]))
    elif change=='fragment':c['reads'][0]['part_b64']=''
    elif change=='deadline':c['deadline_ns']+=1
    elif change=='budget':c['total_budget_ns']+=1
    elif change=='wait':c['reads'][-1]['wait_seconds']=2
    elif change=='digest':c['raw_sha256']='0'*64
    elif change=='length':c['observed_bytes']+=1
    elif change=='completion':c['capture_completion']='read-error'
    elif change=='reason':c['stop_reason']='inactivity'
    elif change=='last_outcome':c['reads'][-1]['outcome']='timeout'
    else:c['finished_ns']=c['deadline_ns']+1
    with pytest.raises((ValueError,KeyError)):fragment.validate_collection(c,wire,mode)


@pytest.fixture(params=z.MODES)
def trace_vector(request):
    mode=request.param;wire=full_wire();ns={'device':4,'inode':123};observed,_,c=collection(wire,mode)
    finish=c['finished_ns'];archive=dict(raw_sha256=z.e.sha(observed));common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=finish+1,finished_ns=finish+2,socket_closed=True,connection_socket_cleared=True),
        dict(common,phase='SEALED',finished_ns=finish+3,archive=archive)]
    return trace,observed,archive,ns,mode


def test_count_exhaustion_trace_has_no_parser_or_permission(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['uid','namespace','not_open','restore','not_closed','socket_retained','seal_before_close','archive','parser_called'])
def test_count_exhaustion_close_archive_join_cannot_be_substituted(trace_vector,change):
    trace,wire,archive,ns,mode=trace_vector;cap,closed,sealed=trace
    if change=='uid':cap['uid']=61104
    elif change=='namespace':cap['namespace']={}
    elif change=='not_open':cap['channel_open']=False
    elif change=='restore':cap['restored_timeout_seconds']=2
    elif change=='not_closed':closed['socket_closed']=False
    elif change=='socket_retained':closed['connection_socket_cleared']=False
    elif change=='seal_before_close':sealed['finished_ns']=closed['finished_ns']-1
    elif change=='archive':sealed['archive']={}
    else:trace.append(dict(cap,phase='PARSER_RETURNED'))
    with pytest.raises((ValueError,KeyError)):z.validate_trace(trace,wire,archive,ns,mode)


@pytest.mark.parametrize('profile',[z,normal])
def test_explicit_cli_acknowledgement_reaches_selected_runner(profile,monkeypatch,tmp_path):
    calls=[];monkeypatch.setattr(profile,'run',lambda *args:calls.append(args))
    argv=['--run','--output',str(tmp_path/'proof')]
    if profile is z:
        argv+=['--fault','complete-at-cap','--acknowledge-isolated-read-count-limit-test'];expected=(tmp_path/'proof','complete-at-cap',True)
    else:argv+=['--acknowledge-isolated-read-count-normal-test'];expected=(tmp_path/'proof',True)
    profile.main(argv);assert calls==[expected]


@pytest.mark.parametrize('profile',[z,normal])
def test_no_root_or_output_before_explicit_ack(profile,monkeypatch):
    monkeypatch.setattr(profile.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):profile.run(Path('/tmp/unused'))


def test_reviewed_fragment_and_collector_sources_are_pinned():
    assert z.sources()['fragment_fixture']==normal.sources()['fragment_fixture']==fragment.source_sha256()
    assert z.deadline.source_sha256()==z.DEADLINE_PIN


@pytest.fixture
def contexts(tmp_path):
    """Ephemeral socket-pair TLS mechanics only; not operator enrollment or UID evidence."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.x509.oid import NameOID
    key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.local')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).sign(key,hashes.SHA256())
    certificate=tmp_path/'cert.pem';private=tmp_path/'key.pem';certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:os.write(fd,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    finally:os.close(fd)
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server.load_cert_chain(certificate,private)
    # Certificate authentication is proved in the full original root fixture; this
    # portable mechanical probe uses a private socket pair, never a remote peer.
    client=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);client.check_hostname=False;client.verify_mode=ssl.CERT_NONE
    return server,client


@pytest.mark.parametrize('version',[ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize('mode',fragment.MODES)
def test_real_tls_writes_and_original_collector_reach_selected_boundary(contexts,version,mode,monkeypatch,tmp_path):
    server,client=contexts;server.minimum_version=server.maximum_version=version;client.minimum_version=client.maximum_version=version
    wire=full_wire();body=z.ingress.raw.parse_wire(wire,'eof')[2];q=z.e.sha(b'public synthetic request');response=z.e.sha(body)
    post=dict(op='A0',authorized=True,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),request_sha256=q,response_sha256=response)
    effect=('A0',q,response,z.n.digest(dict(operation_id='A0',request_sha256=q,response_sha256=response)))
    monkeypatch.setattr(fragment.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(fragment.u,'read_lines',lambda _: [post]);monkeypatch.setattr(fragment.u,'effects',lambda _:[effect])
    monkeypatch.setattr(fragment.u,'append',lambda *_:None);monkeypatch.setattr(fragment.os,'geteuid',lambda:z.n.BACKEND)
    ns={'device':4,'inode':123};monkeypatch.setattr(fragment.e,'namespace',lambda:ns)
    left,right=socket.socketpair();errors=[];records=[]
    def serve():
        try:
            with server.wrap_socket(left,server_side=True) as channel:
                assert channel.recv(1)==b'x'
                records.append(fragment.send_response(tmp_path,wire,channel,mode))
        except BaseException as error:errors.append(error)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:
        with client.wrap_socket(right,server_hostname='synthetic.local') as channel:
            channel.sendall(b'x');channel.settimeout(.7)
            observed,completion,c=z.deadline.bounded_capture(channel)
            assert fragment.validate_collection(c,wire,mode)==observed
            assert completion==('eof' if mode=='normal' else 'limit')
    finally:
        right.close();thread.join(6)
    assert not thread.is_alive() and errors==[] and len(records)==1
    assert fragment.validate_record(records[0],wire,mode,'A0',ns)==observed


@pytest.fixture
def normal_trace_vector():
    """Synthetic validator vector, not actual Native or UID evidence."""
    ns={'device':4,'inode':123};evidence=dict(posts=[],recovered=[],native=dict(records=[]),events=[])
    report=dict(native=dict(evidence=evidence));trace=[];events=[]
    for i,op in enumerate(a+str(j) for a in 'AB' for j in range(4)):
        wire=full_wire(op);body=z.ingress.raw.parse_wire(wire,'eof')[2];start=10_000_000_000*(i+1)
        _,_,c=collection(wire,'normal',start);finish=c['finished_ns'];archive=dict(raw_sha256=z.e.sha(wire),envelope_sha256=z.e.sha(op.encode()))
        common=dict(op=op,uid=z.n.CUSTODY,namespace=ns)
        trace.extend([dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
            dict(common,phase='CLOSE',started_ns=finish+10,finished_ns=finish+20,socket_closed=True,connection_socket_cleared=True),
            dict(common,phase='SEALED',finished_ns=finish+30,archive=archive),
            dict(common,phase='PARSED',started_ns=finish+40,finished_ns=finish+50,raw_sha256=z.e.sha(wire),response_sha256=z.e.sha(body),
                status=200,request_id='native-local-'+op,id_guard_result=dict(field_count=1,request_id='native-local-'+op),
                framing_guard_result=z.frame.require_framing(wire))])
        evidence['posts'].append(dict(op=op,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),response_sha256=z.e.sha(body)))
        evidence['recovered'].append(dict(slot=op,raw_sha256=z.e.sha(wire),observed_bytes=len(wire),capture_completion='eof',envelope_sha256=archive['envelope_sha256']))
        evidence['native']['records'].append(dict(arm=op[0],ordinal=int(op[1]),response_sha256=z.e.sha(body),archive=dict(statement=dict(archive=archive))))
        evidence['events'].extend([dict(op=op) for _ in range(5)]+[dict(op=op,archive=archive)])
        events.append(record(wire,'normal',ns,op,start,finish+30))
    return trace,report,ns,events


def test_all_eight_normal_step_collections_join_fragment_records_and_original_parser(normal_trace_vector):
    trace,report,ns,events=normal_trace_vector
    assert normal.validate_trace(trace,report,ns)
    assert normal.validate_fragment_events(events,trace,ns)


@pytest.mark.parametrize('change',['missing','extra','swapped','wrong_op','wrong_mode','write_bytes','eof_before_notify',
    'server_closed_before_client','unmatched_received_fragment','unmatched_sender_fragment','id_guard_missing','frame_guard_missing'])
def test_normal_fragment_boundary_cannot_be_relabelled_or_inferred(normal_trace_vector,change):
    trace,report,ns,events=normal_trace_vector
    if change=='missing':events.pop()
    elif change=='extra':events.append(copy.deepcopy(events[0]))
    elif change=='swapped':events[0],events[1]=events[1],events[0]
    elif change=='wrong_op':events[0]['op']='B0'
    elif change=='wrong_mode':events[0]['mode']='complete-at-cap'
    elif change=='write_bytes':events[0]['writes'][-1]['cumulative_bytes']+=1
    elif change=='eof_before_notify':events[0]['terminal_started_ns']=trace[0]['collection']['finished_ns']+1
    elif change=='server_closed_before_client':events[0]['terminal_finished_ns']=trace[1]['started_ns']-1
    elif change=='unmatched_received_fragment':trace[0]['collection']['reads'][0]['part_b64']=''
    elif change=='unmatched_sender_fragment':events[0]['writes'][0]['part_b64']=''
    elif change=='id_guard_missing':trace[3].pop('id_guard_result')
    else:trace[3].pop('framing_guard_result')
    with pytest.raises((ValueError,KeyError)):
        normal.validate_trace(trace,report,ns)
        normal.validate_fragment_events(events,trace,ns)

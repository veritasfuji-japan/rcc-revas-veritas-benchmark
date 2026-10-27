"""Portable safety boundaries; actual separated-UID Native proof is mandatory CI."""
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_response_id_binding_v1 as z


def test_existing_normal_ack_and_authority_sources_are_frozen():
    pins=z.sources()
    assert pins['deadline_profile']['profile']==z.DEADLINE_PIN
    assert pins['invalid_profile']['profile']==z.INVALID_PIN
    assert len(pins['invalid_profile']['partial_profile']['acknowledgement_profile']['normal']['frozen'])==15


def test_ack_required_before_root(monkeypatch):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('root before ack'))
    with pytest.raises(ValueError):z.run(Path('/tmp/not-created'))


def test_one_unknown_row_without_result_is_required_for_reopen():
    assert z.validate_unknown_rows([['A0','CONSUMED_UNKNOWN','1'*64,None,None,None,None]],'1'*64)


@pytest.mark.parametrize('fault',['empty','duplicate','observed','other_op','wrong_request','known_response'])
def test_reopen_never_accepts_empty_completed_or_substituted_storage(fault):
    rows=[['A0','CONSUMED_UNKNOWN','1'*64,None,None,None,None]]
    if fault=='empty':rows=[]
    elif fault=='duplicate':rows*=2
    elif fault=='observed':rows[0][1]='MOCK_OBSERVED'
    elif fault=='other_op':rows[0][0]='A1'
    elif fault=='wrong_request':rows[0][2]='2'*64
    else:rows[0][3]='3'*64
    with pytest.raises(ValueError):z.validate_unknown_rows(rows,'1'*64)


@pytest.fixture
def committed_response(tmp_path,monkeypatch,full_wire):
    wire=full_wire;q='1'*64;r=z.e.sha(z.ingress.raw.parse_wire(wire,'eof')[2])
    effect=['A0',q,r,z.n.digest(dict(operation_id='A0',request_sha256=q,response_sha256=r))]
    post=dict(op='A0',authorized=True,request_sha256=q,response_sha256=r,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),
              path=z.ingress.raw.PATH,host=z.tls.NAME)
    writes=[]
    monkeypatch.setattr(z,'fixture',lambda _:'other-step-id')
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda uid:None)
    monkeypatch.setattr(z.u,'effects',lambda _: [effect])
    monkeypatch.setattr(z.u,'read_lines',lambda _: [post])
    monkeypatch.setattr(z.u,'append',lambda path,row:writes.append(row))
    return tmp_path,wire,effect,post,writes


def test_boundary_requires_durable_effect_and_sends_exact_substituted_id_wire_once(committed_response):
    base,wire,effect,post,writes=committed_response;sent=[]
    assert z.send_substituted_response(base,wire,sent.append) is None
    assert sent==[z.substituted_wire(wire,'other-step-id')]
    assert len(writes)==1 and writes[0]['response_bytes_sent']==len(sent[0]) and writes[0]['produced_bytes']==len(wire)
    assert writes[0]['transmitted_b64']==z.n.encode(sent[0]) and writes[0]['produced_wire_sha256']==post['wire_sha256']


@pytest.mark.parametrize('fault',['missing_effect','missing_post','wrong_wire','wrong_receipt','unauthorized','wrong_path','already_used'])
def test_drop_never_fabricates_a_successful_backend_witness(committed_response,monkeypatch,fault):
    base,wire,effect,post,writes=committed_response
    if fault=='missing_effect':monkeypatch.setattr(z.u,'effects',lambda _: [])
    elif fault=='missing_post':monkeypatch.setattr(z.u,'read_lines',lambda _: [])
    elif fault=='wrong_wire':wire=b'other'
    elif fault=='wrong_receipt':effect[3]='0'*64
    elif fault=='unauthorized':post['authorized']=False
    elif fault=='wrong_path':post['path']='/other'
    else:
        (base/'backend').mkdir();(base/'backend/response-loss.jsonl').write_text('used')
    with pytest.raises(ValueError):z.send_substituted_response(base,wire,lambda _:pytest.fail('invalid witness sent bytes'))
    assert writes==[]


@pytest.fixture
def gate_vectors():
    key=Ed25519PrivateKey.generate();binding=dict(schema=z.contract.SCHEMA,ledger_id='1'*64,run_id='2'*64,
        manifest_sha256='3'*64,issuer_public_sha256='4'*64,custody_public_sha256='5'*64)
    a=dict(binding=binding,service_public=key.public_key().public_bytes_raw().hex())
    q='6'*64;grant='7'*64
    rows={}
    for role,revision in [('issuer',1),('custody',2)]:
        g=None if role=='issuer' else grant;action='reserve' if role=='issuer' else 'consume'
        attempt=dict(operation_id='A0',request_sha256=q,grant_sha256=g,state='RESERVED' if role=='issuer' else 'CONSUMED_UNKNOWN')
        before=dict(revision=revision-1,attempts=[] if role=='issuer' else [dict(attempt,grant_sha256=None,state='RESERVED')])
        after=dict(revision=revision,attempts=[attempt]);pairs=[]
        for i,(command_action,snapshot) in enumerate([('view',before),(action,after)],1):
            c=dict(schema=z.contract.SCHEMA,binding_sha256=z.n.digest(binding),nonce=str(revision*2+i)*64,action=command_action,
                expected_revision=None if i==1 else revision-1,operation_id=None if i==1 else 'A0',
                request_sha256=None if i==1 else q,grant_sha256=None if i==1 else g)
            statement=dict(schema=z.contract.SCHEMA,ledger_id=binding['ledger_id'],binding_sha256=z.n.digest(binding),
                command_sha256=z.n.digest(c),nonce=c['nonce'],action=command_action,snapshot=snapshot)
            receipt=dict(statement=statement,signature=key.sign(z.contract.DOMAIN+z.contract.canonical(statement)).hex())
            pairs.append(dict(command=c,receipt=receipt))
        intent=dict(role=role,action=action,operation_id='A0',binding_sha256=z.n.digest(binding),request_sha256=q,grant_sha256=g)
        rows[role]={'intent.json':intent,'verified-receipts.json':dict(intent_sha256=z.n.digest(intent),exchanges=pairs,snapshot=after),
                    'effect-returned.json':dict(effect_returned=True,intent_sha256=z.n.digest(intent)) if role=='issuer' else None}
    return rows,a,q,grant


def test_verified_consume_ack_does_not_mean_effect_callback_returned(gate_vectors):
    rows,a,q,grant=gate_vectors
    assert len(z.verify_gate(rows['issuer'],a,'issuer',q,None))==2
    assert len(z.verify_gate(rows['custody'],a,'custody',q,grant))==2
    assert rows['custody']['verified-receipts.json'] is not None and rows['custody']['effect-returned.json'] is None


@pytest.mark.parametrize('fault',['signature','nonce','binding','grant','callback','revision'])
def test_changed_gate_receipt_or_callback_cannot_pass(gate_vectors,fault):
    rows,a,q,grant=gate_vectors;row=copy.deepcopy(rows['custody'])
    if fault=='signature':row['verified-receipts.json']['exchanges'][1]['receipt']['signature']='00'*64
    elif fault=='nonce':row['verified-receipts.json']['exchanges'][1]['command']['nonce']='a'*64
    elif fault=='binding':row['intent.json']['binding_sha256']='0'*64
    elif fault=='grant':grant='8'*64
    elif fault=='callback':row['effect-returned.json']=dict(effect_returned=True)
    else:row['verified-receipts.json']['snapshot']=dict(revision=3,attempts=[])
    with pytest.raises(Exception):z.verify_gate(row,a,'custody',q,grant)


def test_reconciliation_is_one_authenticated_get_and_issues_no_permission(monkeypatch,tmp_path):
    monkeypatch.setattr(z,'fixture',lambda _:'body-cut')
    monkeypatch.setattr(z.signed,'admit',lambda base,role:None)
    monkeypatch.setattr(z.os,'umask',lambda _:None)
    monkeypatch.setattr(z.retained,'regular',lambda *a:b'local-test-material')
    calls=[]
    def get(base,method,path,body,key):
        calls.append((method,path,body));return 200,dict(effect_count=1,operation_receipt='1'*64)
    monkeypatch.setattr(z.m,'status_call',get)
    result=z.reconcile(tmp_path)
    assert calls==[('GET','/status/A0',None)]
    assert result['permission_issued'] is result['mutation_attempted'] is False


def test_scope_covers_local_response_loss_without_claiming_live_continuation_or_power_loss():
    limits=z.limits()
    assert limits['substituted_response_id_tested'] is True
    assert limits['backend_restart_tested'] is limits['backend_retained_read_only'] is True
    assert limits['real_provider_completion_loss_tested'] is limits['backend_continuation_supported'] is False
    assert limits['power_loss_or_vm_reboot_tested'] is False
    assert limits['repair_or_retry_permission_issued'] is False
    assert limits['real_provider_posts']==0 and limits['provider_dispatch']=='DENY' and limits['utility']=='UNSCORED'


@pytest.fixture
def retained_backend(tmp_path,monkeypatch):
    import os,sqlite3
    monkeypatch.setattr(z.n,'BACKEND',os.geteuid())
    folder=tmp_path/'backend';folder.mkdir(mode=0o700)
    file=folder/'effects.sqlite3'
    q='1'*64;response='2'*64
    receipt=z.n.digest(dict(operation_id='A0',request_sha256=q,response_sha256=response))
    with sqlite3.connect(file) as db:
        db.execute(z.BACKEND_SCHEMA)
        db.execute('INSERT INTO effects VALUES (?,?,?,?)',('A0',q,response,receipt))
    file.chmod(0o600)
    return tmp_path,q


def test_readonly_inspection_retains_original_file_bytes_inode_and_effect(retained_backend):
    base,q=retained_backend
    first=z.inspect_backend(base)
    assert z.validate_backend_record(first,q)
    assert z.inspect_backend(base)==first
    assert first['identity']['file_inode']==(base/'backend/effects.sqlite3').stat().st_ino


@pytest.mark.parametrize('fault',['empty','duplicate','wrong_request','bad_receipt','schema','mode','links','owner','hash'])
def test_backend_record_rejects_substituted_or_incomplete_evidence(retained_backend,fault):
    base,q=retained_backend;record=z.inspect_backend(base)
    if fault=='empty':record['rows']=[]
    elif fault=='duplicate':record['rows']*=2
    elif fault=='wrong_request':record['rows'][0][1]='3'*64
    elif fault=='bad_receipt':record['rows'][0][3]='0'*64
    elif fault=='schema':record['schema']='other'
    elif fault=='hash':record['database_sha256']='not-a-hash'
    elif fault=='owner':record['identity']['uid']=z.n.BACKEND+1
    else:record['identity'][fault]=0
    with pytest.raises(ValueError):z.validate_backend_record(record,q)


def test_missing_backend_database_is_never_created(tmp_path):
    folder=tmp_path/'backend';folder.mkdir(mode=0o700)
    with pytest.raises(FileNotFoundError):z.inspect_backend(tmp_path)
    assert list(folder.iterdir())==[]


@pytest.mark.parametrize('fault',['symlink','hardlink','wide_mode','extra_table'])
def test_inspection_refuses_unpinned_shape_without_repair(retained_backend,fault):
    import os,sqlite3
    base,q=retained_backend;file=base/'backend/effects.sqlite3'
    if fault=='symlink':
        saved=file.with_name('saved');file.rename(saved);file.symlink_to(saved)
    elif fault=='hardlink':os.link(file,file.with_name('linked'))
    elif fault=='wide_mode':file.chmod(0o644)
    else:
        with sqlite3.connect(file) as db:db.execute('CREATE TABLE unreviewed(value TEXT)')
    before=file.read_bytes()
    with pytest.raises(ValueError):z.inspect_backend(base)
    assert file.read_bytes()==before


@pytest.mark.parametrize('container',[tuple,list])
def test_backend_join_accepts_sqlite_tuples_and_exact_json_arrays(retained_backend,container):
    base,q=retained_backend;record=z.inspect_backend(base)
    assert z.validate_backend_effect_join(record,[container(row) for row in record['rows']],q)


def test_backend_join_still_rejects_changed_field_after_container_normalization(retained_backend):
    base,q=retained_backend;record=z.inspect_backend(base)
    changed=list(record['rows'][0]);changed[3]='0'*64
    with pytest.raises(ValueError):z.validate_backend_effect_join(record,[tuple(changed)],q)


@pytest.fixture
def full_wire():
    body=z.n.canonical(dict(object='chat.completion',model=z.ingress.raw.request_parameters()['model'],id='local-public',
        choices=[dict(index=0,message=dict(role='assistant',content='public synthetic response'))]))
    return z.ingress.response_wire(body,'A0','success')


@pytest.mark.parametrize('fault,response_id',[('other-step-id','native-local-A1'),('other-arm-id','native-local-B0')])
def test_original_parser_accepts_valid_wire_with_other_operation_header(full_wire,fault,response_id):
    wire=z.substituted_wire(full_wire,fault)
    head,sep,body=wire.partition(b'\r\n\r\n')
    assert sep and wire.startswith(b'HTTP/1.1 200 OK\r\n') and len(wire)==len(full_wire)
    assert ('Content-Length: '+str(len(body))).encode() in head
    assert body==full_wire.partition(b'\r\n\r\n')[2]
    assert wire.replace(response_id.encode(),b'native-local-A0',1)==full_wire
    code,headers,parsed_body=z.ingress.raw.parse_wire(wire,'eof')
    assert code==200 and dict(headers)['X-Request-Id']==response_id and parsed_body==body
    assert z.ingress.raw.parse_wire(full_wire,'eof')[0]==200


@pytest.mark.parametrize('wire',[b'',b'no framing',b'HTTP/1.1 500 Bad\r\nX: y\r\n\r\n{}',b'HTTP/1.1 200 OK\r\nX: y\r\n\r\nx'])
def test_invalid_generated_wire_cannot_be_used_as_original_committed_response(wire):
    with pytest.raises((ValueError,z.http.client.HTTPException)):z.substituted_wire(wire,'other-arm-id')


@pytest.mark.parametrize('fault',[None,'drop',True,1])
def test_invalid_case_stops_before_root_or_output(fault,monkeypatch,tmp_path):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('invalid case reached root'))
    with pytest.raises(ValueError):z.run(tmp_path/'absent',fault,acknowledge=True)
    assert not (tmp_path/'absent').exists()


@pytest.mark.parametrize('fault,response_id',[('other-step-id','native-local-A1'),('other-arm-id','native-local-B0')])
def test_observer_preserves_successful_parser_and_original_dispatch_failure(full_wire,fault,response_id,monkeypatch,tmp_path):
    wire=z.substituted_wire(full_wire,fault);events=[];raw=z.ingress.raw
    original=(raw.capture,raw.seal,raw.parse_wire,z.m.connection)
    monkeypatch.setattr(z,'fixture',lambda _:fault)
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    def dispatch(*_):
        result=raw.parse_wire(wire,'eof')
        assert dict(result[1])['X-Request-Id']==response_id
        raise ValueError('original dispatch refusal')
    monkeypatch.setattr(z.m,'dispatch',dispatch)
    monkeypatch.setattr(z.u,'append',lambda path,row:events.append(row))
    with pytest.raises(ValueError,match='original dispatch refusal'):
        z.observed_dispatch(tmp_path,dict(arm='A',ordinal=0),b'',b'')
    assert (raw.capture,raw.seal,raw.parse_wire,z.m.connection)==original
    assert [x['phase'] for x in events]==['ORIGINAL_PARSER_RETURNED','PARSER_RETURNED','ORIGINAL_DISPATCH_REFUSED','BINDING_REFUSED']
    assert events[0]['request_id']==response_id and events[0]['status']==200
    assert events[-1]['error_class']=='ValueError' and events[-1]['parsed_receipt']['request_id']==response_id


@pytest.fixture(params=['other-step-id','other-arm-id'])
def trace_vector(request,full_wire):
    fault=request.param;wire=z.substituted_wire(full_wire,fault);ns=dict(device=4,inode=123)
    c=dict(started_ns=100,finished_ns=150,deadline_ns=100+z.deadline.TOTAL_NS,total_budget_ns=z.deadline.TOTAL_NS,
        inactivity_seconds=.7,stop_reason='eof',reads=[dict(before_ns=101,after_ns=110,wait_seconds=.7,outcome='bytes',part_b64=z.n.encode(wire)),
        dict(before_ns=120,after_ns=130,wait_seconds=.7,outcome='eof',part_b64='')],observed_b64=z.n.encode(wire),
        observed_bytes=len(wire),raw_sha256=z.e.sha(wire),capture_completion='eof')
    archive=dict(raw_sha256=z.e.sha(wire),observed_bytes=len(wire),local_fsync_completed=True)
    common=dict(op='A0',uid=z.n.CUSTODY,namespace=ns)
    parsed=dict(status=200,request_id=z.RESPONSE_IDS[fault],response_sha256=z.e.sha(z.ingress.raw.parse_wire(wire,'eof')[2]))
    trace=[dict(common,phase='CAPTURE',collection=c,channel_open=True,restored_timeout_seconds=.7),
        dict(common,phase='CLOSE',started_ns=160,finished_ns=170,socket_closed=True,connection_socket_cleared=True),
        dict(common,phase='SEALED',finished_ns=180,archive=archive),dict(common,phase='PARSER_RETURNED',started_ns=190,finished_ns=200,
        raw_sha256=z.e.sha(wire),**parsed),dict(common,phase='BINDING_REFUSED',finished_ns=210,error_class='ValueError',parsed_receipt=parsed)]
    return trace,wire,archive,ns,fault


def test_valid_parse_does_not_mean_operation_id_bound(trace_vector):
    assert z.validate_trace(*trace_vector)


@pytest.mark.parametrize('change',['deadline','budget','timeout','wait','fragment','digest','uid','namespace','dispatch_error',
    'parser_refused','not_closed','not_cleared','restore','parse_before_seal','seal_before_close','archive','missing_event','extra_event',
    'matching_id','wrong_other_id','body_digest','refusal_before_parse'])
def test_changed_eof_capture_parse_or_binding_refusal_evidence_is_rejected(trace_vector,change):
    trace,wire,archive,ns,fault=trace_vector;cap,closed,sealed,parser,refused=trace;c=cap['collection']
    if change=='deadline':c['deadline_ns']+=1
    elif change=='budget':c['total_budget_ns']+=1
    elif change=='timeout':c['capture_completion']='timeout'
    elif change=='wait':c['reads'][-1]['wait_seconds']=2
    elif change=='fragment':c['reads'][0]['part_b64']=''
    elif change=='digest':c['raw_sha256']='0'*64
    elif change=='uid':cap['uid']=61104
    elif change=='namespace':cap['namespace']={}
    elif change=='dispatch_error':refused['error_class']='TimeoutError'
    elif change=='parser_refused':parser['phase']='PARSER_REFUSED'
    elif change=='not_closed':closed['socket_closed']=False
    elif change=='not_cleared':closed['connection_socket_cleared']=False
    elif change=='restore':cap['restored_timeout_seconds']=2
    elif change=='parse_before_seal':parser['started_ns']=sealed['finished_ns']-1
    elif change=='seal_before_close':sealed['finished_ns']=closed['finished_ns']-1
    elif change=='archive':sealed['archive']=dict(raw_sha256='0'*64)
    elif change=='missing_event':trace.pop()
    elif change=='extra_event':trace.append(copy.deepcopy(parser))
    elif change=='matching_id':parser['request_id']=refused['parsed_receipt']['request_id']='native-local-A0'
    elif change=='wrong_other_id':parser['request_id']=refused['parsed_receipt']['request_id']='native-local-B3'
    elif change=='body_digest':parser['response_sha256']=refused['parsed_receipt']['response_sha256']='0'*64
    else:refused['finished_ns']=parser['finished_ns']-1
    with pytest.raises((ValueError,KeyError)):z.validate_trace(trace,wire,archive,ns,fault)


@pytest.mark.parametrize('fault',[None,'other-step-id','other-arm-id'])
def test_original_dispatch_exact_id_gate_runs_after_seal_parse_before_body_release(full_wire,fault,tmp_path,monkeypatch):
    """Original dispatcher; transport/authority prerequisites stubbed, no Native claim."""
    import sqlite3
    request=b'public synthetic request';packet=dict(arm='A',ordinal=0)
    wire=full_wire if fault is None else z.substituted_wire(full_wire,fault)
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
        def request(self,method,path,body,headers):
            assert method=='POST' and path==z.ingress.raw.PATH and body==request
        def close(self):self.closed+=1
    conn=Connection()
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda _:None)
    monkeypatch.setattr(z.n,'verify',lambda *args:request)
    monkeypatch.setattr(z.ingress,'plan',lambda _:dict(run_id='1'*64))
    monkeypatch.setattr(z.m,'connection',lambda _:conn)
    monkeypatch.setattr(z.m,'peer',lambda _:dict(test_only=True))
    monkeypatch.setattr(z.ingress,'emit',lambda base,op,phase,**data:events.append(phase))
    monkeypatch.setattr(z.ingress.raw,'capture',lambda _: (wire,'eof'))
    monkeypatch.setattr(z.ingress.raw,'seal',lambda *args:dict(test_only_archive=True))
    if fault is None:
        code,value=z.m.dispatch(tmp_path,packet,request,b'public-key')
        assert code==200 and value['response_sha256']==z.e.sha(z.ingress.raw.parse_wire(wire,'eof')[2])
        assert events[-1]=='BODY_RELEASED_TO_BIND'
    else:
        assert z.ingress.raw.parse_wire(wire,'eof')[0]==200
        with pytest.raises(ValueError):z.m.dispatch(tmp_path,packet,request,b'public-key')
        assert events[-1]=='HTTP_PARSE_STARTED' and 'BODY_RELEASED_TO_BIND' not in events
    assert conn.closed==1 and events.index('SEALED_FSYNCED')<events.index('HTTP_PARSE_STARTED')

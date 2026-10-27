"""Portable safety boundaries; actual separated-UID Native proof is mandatory CI."""
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_partial_response_v1 as z


def test_existing_normal_ack_and_authority_sources_are_frozen():
    pins=z.sources()
    assert pins['acknowledgement_profile']['profile']==z.ACK_PIN
    assert len(pins['acknowledgement_profile']['normal']['frozen'])==15


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
def committed_response(tmp_path,monkeypatch):
    wire=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
    q='1'*64;r='2'*64
    effect=['A0',q,r,z.n.digest(dict(operation_id='A0',request_sha256=q,response_sha256=r))]
    post=dict(op='A0',authorized=True,request_sha256=q,response_sha256=r,wire_sha256=z.e.sha(wire),wire_bytes=len(wire),
              path=z.ingress.raw.PATH,host=z.tls.NAME)
    writes=[]
    monkeypatch.setattr(z,'fixture',lambda _:'body-cut')
    monkeypatch.setattr(z.n.kernel,'role_identity',lambda uid:None)
    monkeypatch.setattr(z.u,'effects',lambda _: [effect])
    monkeypatch.setattr(z.u,'read_lines',lambda _: [post])
    monkeypatch.setattr(z.u,'append',lambda path,row:writes.append(row))
    return tmp_path,wire,effect,post,writes


def test_drop_boundary_requires_durable_effect_and_sends_exact_strict_prefix(committed_response):
    base,wire,effect,post,writes=committed_response
    sent=[]
    assert z.send_partial_response(base,wire,sent.append) is None
    assert sent==[z.partial_wire(wire,'body-cut')]
    assert len(writes)==1 and 0<writes[0]['response_bytes_sent']<len(wire) and writes[0]['produced_bytes']==len(wire)
    assert writes[0]['produced_wire_sha256']==post['wire_sha256']


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
    with pytest.raises(ValueError):z.send_partial_response(base,wire,lambda _:pytest.fail('invalid witness sent bytes'))
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
    assert limits['raw_backend_response_loss_tested'] is True
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


@pytest.mark.parametrize('fault,error_type',[('headers-cut',ValueError),('body-cut',z.http.client.IncompleteRead)])
def test_original_parser_rejects_exact_nonempty_prefix(full_wire,fault,error_type):
    prefix=z.partial_wire(full_wire,fault)
    assert 0<len(prefix)<len(full_wire) and full_wire.startswith(prefix)
    if fault=='headers-cut':assert b'\r\n\r\n' not in prefix
    else:
        assert b'\r\n\r\n' in prefix
        assert 0<len(prefix.split(b'\r\n\r\n',1)[1])<len(full_wire.split(b'\r\n\r\n',1)[1])
    with pytest.raises(error_type):z.ingress.raw.parse_wire(prefix,'eof')
    assert z.ingress.raw.parse_wire(full_wire,'eof')[0]==200


@pytest.mark.parametrize('wire',[b'',b'no framing',b'HTTP/1.1 500 Bad\r\nX: y\r\n\r\n{}',b'HTTP/1.1 200 OK\r\nX: y\r\n\r\nx'])
def test_invalid_generated_wire_cannot_be_sent_as_a_partial_case(wire):
    with pytest.raises(ValueError):z.partial_wire(wire,'body-cut')


@pytest.mark.parametrize('fault',[None,'drop',True,1])
def test_invalid_case_stops_before_root_or_output(fault,monkeypatch,tmp_path):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('invalid case reached root'))
    with pytest.raises(ValueError):z.run(tmp_path/'absent',fault,acknowledge=True)
    assert not (tmp_path/'absent').exists()


@pytest.mark.parametrize('fault,error_type',[('headers-cut',ValueError),('body-cut',z.http.client.IncompleteRead)])
def test_parser_observer_preserves_original_failure_and_never_returns_body(full_wire,fault,error_type,monkeypatch,tmp_path):
    wire=z.partial_wire(full_wire,fault);events=[];original=z.ingress.raw.parse_wire
    def dispatch(*_):return z.ingress.raw.parse_wire(wire,'eof')
    monkeypatch.setattr(z.m,'dispatch',dispatch)
    monkeypatch.setattr(z.u,'append',lambda path,row:events.append(row))
    with pytest.raises(error_type):z.observed_dispatch(tmp_path,{},b'',b'')
    assert z.ingress.raw.parse_wire is original
    assert len(events)==1 and events[0]['phase']=='ORIGINAL_PARSER_REFUSED'
    assert events[0]['error_class']==error_type.__name__
    assert events[0]['observed_bytes']==len(wire) and events[0]['raw_sha256']==z.e.sha(wire)

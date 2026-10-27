"""Portable safety boundaries; actual separated-UID Native proof is mandatory CI."""
import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts import task4_native_total_deadline_v1 as z


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
    monkeypatch.setattr(z,'fixture',lambda _:None)
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


class Clock:
    def __init__(self):self.now=1000000000
    def __call__(self):return self.now


class Channel:
    def __init__(self,events,clock,timeout=0.7):self.events=list(events);self.clock=clock;self.timeout=timeout;self.waits=[]
    def gettimeout(self):return self.timeout
    def settimeout(self,value):self.timeout=value;self.waits.append(value)
    def recv(self,size):
        import socket
        kind,delay,part=self.events[0] if self.events else ('timeout',None,b'')
        if kind=='timeout' or (kind not in ('late-bytes','late-eof') and delay is not None and delay>self.timeout):
            self.clock.now+=round(self.timeout*1000000000);raise socket.timeout()
        self.events.pop(0);self.clock.now+=round(delay*1000000000)
        if kind=='error':raise OSError('test read failure')
        assert len(part)<=size
        return part


def collect(events,timeout=0.7):
    clock=Clock();channel=Channel(events,clock,timeout)
    return z.bounded_capture(channel,clock),channel


def test_fast_complete_response_reaches_eof_and_keeps_original_timeout():
    (wire,completion,record),channel=collect([('bytes',0.01,b'whole'),('eof',0.01,b'')])
    assert (wire,completion)==(b'whole','eof') and record['stop_reason']=='eof'
    assert z.validate_collection(record,wire,'eof','eof') and channel.gettimeout()==0.7


def test_frequent_bytes_do_not_reset_the_single_total_deadline():
    (wire,completion,record),channel=collect([('bytes',0.15,b'x')]*50)
    assert completion=='timeout' and record['stop_reason']=='total-deadline'
    assert record['deadline_ns']==record['started_ns']+z.TOTAL_NS
    assert record['finished_ns']==record['deadline_ns'] and len(wire)==13
    assert all(x['outcome']=='bytes' for x in record['reads'][:-1])
    assert record['reads'][-1]['wait_seconds']<0.7 and channel.gettimeout()==0.7
    assert z.validate_collection(record,wire,'timeout','total-deadline')


def test_inactivity_is_distinct_from_total_deadline():
    (wire,completion,record),channel=collect([('bytes',0.01,b'part'),('timeout',None,b'')])
    assert wire==b'part' and completion=='timeout' and record['stop_reason']=='inactivity'
    assert record['finished_ns']<record['deadline_ns'] and channel.gettimeout()==0.7


@pytest.mark.parametrize('kind,part',[('late-bytes',b'late'),('late-eof',b'')])
def test_read_finishing_after_deadline_never_returns_success_and_preserves_bytes(kind,part):
    (wire,completion,record),channel=collect([(kind,2.1,part)])
    assert (wire,completion)==(part,'timeout') and record['stop_reason']=='total-deadline'
    assert z.validate_collection(record,wire,'timeout','total-deadline')
    assert channel.gettimeout()==0.7


def test_read_error_preserves_already_observed_bytes_and_restores_timeout():
    (wire,completion,record),channel=collect([('bytes',0.01,b'part'),('error',0.01,b'')])
    assert wire==b'part' and completion=='read-error' and record['stop_reason']=='read-error'
    assert channel.gettimeout()==0.7


def test_byte_limit_preserves_overflow_observation(monkeypatch):
    monkeypatch.setattr(z.ingress.raw,'LIMIT',8)
    (wire,completion,record),_=collect([('bytes',0.01,b'123456789')])
    assert wire==b'123456789' and completion=='limit' and record['stop_reason']=='byte-limit'


def test_read_count_limit_bounds_fragment_metadata(monkeypatch):
    monkeypatch.setattr(z,'MAX_READS',3)
    (wire,completion,record),_=collect([('bytes',0.01,b'x')]*10)
    assert wire==b'xxx' and completion=='limit' and record['stop_reason']=='read-count-limit'
    assert len(record['reads'])==3


@pytest.mark.parametrize('timeout',[None,0,-1,1.0,float('nan')])
def test_unreviewed_inactivity_timeout_is_refused_before_reads(timeout):
    clock=Clock();channel=Channel([],clock,timeout)
    with pytest.raises(ValueError):z.bounded_capture(channel,clock)
    assert channel.waits==[]


@pytest.mark.parametrize('fault',[None,'timeout',True,1])
def test_invalid_case_stops_before_root(fault,monkeypatch,tmp_path):
    monkeypatch.setattr(z.e,'require_root',lambda:pytest.fail('invalid case reached root'))
    with pytest.raises(ValueError):z.run(tmp_path/'absent',fault,acknowledge=True)


@pytest.mark.parametrize('fault',['deadline_reset','wrong_budget','wrong_wait','wrong_wire','short_observation','reordered_read','fake_eof'])
def test_changed_capture_trace_or_deadline_is_rejected(fault):
    (wire,completion,record),_=collect([('bytes',0.15,b'x')]*50)
    if fault=='deadline_reset':record['deadline_ns']+=1000000000
    elif fault=='wrong_budget':record['total_budget_ns']+=1
    elif fault=='wrong_wait':record['reads'][-1]['wait_seconds']=0.7
    elif fault=='wrong_wire':record['observed_b64']=z.n.encode(b'changed')
    elif fault=='short_observation':record['observed_bytes']-=1
    elif fault=='reordered_read':record['reads'][1]['before_ns']=record['reads'][0]['before_ns']-1
    else:record['capture_completion']='eof'
    with pytest.raises(ValueError):z.validate_collection(record,wire,'timeout','total-deadline')


def test_actual_unix_socket_fast_eof_is_not_rejected():
    import socket
    reader,writer=socket.socketpair()
    with reader,writer:
        writer.sendall(b'complete');writer.shutdown(socket.SHUT_WR);reader.settimeout(0.7)
        wire,completion,record=z.bounded_capture(reader)
    assert (wire,completion)==(b'complete','eof') and record['stop_reason']=='eof'
    assert z.validate_collection(record,wire,'eof','eof')


@pytest.mark.parametrize('mode',['fast-complete','headers-drip','body-drip'])
def test_verified_tls_collector_handles_fast_eof_and_stops_real_slow_drip(tmp_path,mode):
    import datetime,socket,ssl,select,threading,time
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now=datetime.datetime.now(datetime.timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1());key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'temporary closed test CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(minutes=10)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .sign(ca_key,hashes.SHA256()))
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,z.tls.NAME)]))
          .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(minutes=10))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName(z.tls.NAME)]),False).sign(ca_key,hashes.SHA256()))
    cert=tmp_path/'cert.pem';private=tmp_path/'key.pem'
    cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    private.chmod(0o600)
    server_ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);server_ctx.load_cert_chain(cert,private)
    client_ctx=ssl.create_default_context(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    assert client_ctx.verify_mode==ssl.CERT_REQUIRED and client_ctx.check_hostname
    body=z.n.canonical(dict(object='chat.completion',model=z.ingress.raw.request_parameters()['model'],id='local-public',
        choices=[dict(index=0,message=dict(role='assistant',content='public synthetic response'))]))
    full=z.ingress.response_wire(body,'A0','success');server_sock,client_sock=socket.socketpair();state={}
    def server():
        try:
            with server_ctx.wrap_socket(server_sock,server_side=True) as channel:
                channel.settimeout(5);request=b''
                while len(request)<5:request+=channel.recv(5-len(request))
                assert request==b'probe'
                if mode=='fast-complete':
                    channel.sendall(full);raw=channel.unwrap();raw.close();return
                count=full.index(b'\r\n')+2 if mode=='headers-drip' else full.index(b'\r\n\r\n')+5
                channel.sendall(full[:count])
                while True:
                    ready,_,_=select.select([channel],[],[],z.DRIP_SECONDS)
                    if ready:
                        try:assert channel.recv(1)==b'';state['terminal']='EOF'
                        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as error:state['terminal']=type(error).__name__
                        state['terminal_ns']=time.monotonic_ns();return
                    channel.sendall(full[count:count+1]);count+=1
        except BaseException as error:state['error']=repr(error)
    thread=threading.Thread(target=server,daemon=True);thread.start()
    try:
        with client_ctx.wrap_socket(client_sock,server_hostname=z.tls.NAME) as channel:
            channel.sendall(b'probe');channel.settimeout(0.7)
            wire,completion,record=z.bounded_capture(channel)
            if mode=='fast-complete' and completion=='eof':
                raw=channel.unwrap();raw.close()
        thread.join(timeout=6)
        assert not thread.is_alive() and 'error' not in state,state
        if mode=='fast-complete':
            assert wire==full and completion=='eof'
            assert z.validate_collection(record,wire,'eof','eof')
            assert z.ingress.raw.parse_wire(wire,'eof')[0]==200
        else:
            assert 0<len(wire)<len(full) and full.startswith(wire)
            assert completion=='timeout' and record['stop_reason']=='total-deadline'
            assert z.validate_collection(record,wire,'timeout','total-deadline')
            assert state['terminal_ns']>record['finished_ns']
    finally:client_sock.close();server_sock.close()

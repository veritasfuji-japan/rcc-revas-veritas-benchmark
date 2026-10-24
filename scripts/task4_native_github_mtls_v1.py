"""Retained GitHub API model + real mTLS for closed-local Native research.

No HTTP client, token, remote GitHub mutation or live Provider capability.
TLS runs over the enrolled Unix socket to preserve the existing closed netns.
"""
from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import task4_external_ledger_contract_v1 as l
from scripts import task4_external_ledger_mtls_v1 as mtls
from scripts import task4_signed_github_ledger_v1 as signed
from scripts.task4_signed_github_ledger_rehearsal_v1 import ModelGitAPI
from scripts.task4_native_signed_ledger_gate_v1 import SCHEMA as GATE_SCHEMA

PROFILE = 'task4.native-github-api-model-mtls.v1'
MODEL = 'github-model.sqlite3'
FAULTS = ('api-reserve-ack-lost', 'tls-consume-ack-lost')
FILES = ('mtls-ca.pem', 'mtls-cert.pem', 'mtls-key.pem')


class RetainedModelGitAPI(ModelGitAPI):
    """SQLite-retained test model of GitHub routes, NOT a remote witness.

    Expected-head comparison and commit are serialized. A commit is fsynced
    before a simulated lost API response. Audit writes cannot restore old head.
    Reopening never initializes missing or corrupt storage.
    """
    def __init__(self, file):
        self.file = Path(file).absolute()
        self.calls, self.events, self.response_fault, self._active = [], [], None, None
        with self.db() as db:
            l.need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'MODEL_DATABASE_INTEGRITY')
            rows = db.execute('SELECT schema,genesis,signer FROM model').fetchall()
            l.need(len(rows) == 1 and rows[0][0] == PROFILE and signed.hx(rows[0][1],40)
                   and l.hex64(rows[0][2]), 'RETAINED_MODEL_ENROLLMENT')
            self.genesis, self.signer = rows[0][1:]
            self._load(db)

    @classmethod
    def bootstrap(cls, file, signer):
        l.need(l.hex64(signer), 'MODEL_SIGNER')
        file=Path(file).absolute()
        fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
        seed=ModelGitAPI(signer); state=seed.commits[seed.genesis]
        with sqlite3.connect(file) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE model (schema TEXT,genesis TEXT,signer TEXT)')
            db.execute('CREATE TABLE commits (oid TEXT PRIMARY KEY,document BLOB,parent TEXT)')
            db.execute('CREATE TABLE head (oid TEXT)')
            db.execute('CREATE TABLE events (id INTEGER PRIMARY KEY,event BLOB)')
            db.execute('INSERT INTO model VALUES (?,?,?)',(PROFILE,seed.genesis,signer))
            db.execute('INSERT INTO commits VALUES (?,?,NULL)',(seed.genesis,l.canonical(state['state'])))
            db.execute('INSERT INTO head VALUES (?)',(seed.genesis,))
            db.execute('INSERT INTO events(event) VALUES (?)',(l.canonical(['commit',seed.genesis]),))
        from scripts.task4_native_retained_authority_v1 import sync_dir
        sync_dir(file.parent)
        return cls(file)

    @contextmanager
    def db(self):
        from scripts.task4_receipt_key_custody_v1 import _directory
        # Validate pinned no-follow ancestors and file shape without reading a
        # potentially large SQLite file into the generic JSON record loader.
        import stat
        with _directory(str(self.file.parent)) as parent:
            fd=os.open(self.file.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                info=os.fstat(fd)
                l.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid()
                       and stat.S_IMODE(info.st_mode)==0o600,'PRIVATE_RETAINED_MODEL_FILE')
            finally:os.close(fd)
        db=sqlite3.connect(self.file.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:db.close()

    def _load(self,db):
        self.commits={oid:dict(state=json.loads(raw),parent=parent)
                      for oid,raw,parent in db.execute('SELECT oid,document,parent FROM commits')}
        rows=db.execute('SELECT oid FROM head').fetchall()
        l.need(len(rows)==1 and rows[0][0] in self.commits and self.genesis in self.commits,'MODEL_HEAD_AND_GENESIS')
        self.head=rows[0][0]

    def _flush(self,db):
        for event in self.events:db.execute('INSERT INTO events(event) VALUES (?)',(l.canonical(event),))
        self.events=[]

    def add(self,state,parent):
        l.need(self._active is not None,'MODEL_COMMIT_ONLY_WITHIN_CAS')
        oid=super().add(state,parent)
        db=self._active
        db.execute('INSERT INTO commits VALUES (?,?,?)',(oid,l.canonical(state),parent))
        db.execute('UPDATE head SET oid=?',(oid,))
        self._flush(db);db.commit()  # Durable before response_fault or signing.
        return oid

    def call(self,method,path,value=None):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE');self._load(db);self.events=[];self._active=db
            expected=value['variables']['input']['expectedHeadOid'] if method=='POST' else None
            self.events.append(['api',method,path,expected])
            try:return super().call(method,path,value)
            finally:
                # A preceding add may already have committed. Only append audit
                # events here; never rewrite the ref from a stale object cache.
                self._flush(db);db.commit();self._active=None

    def record(self,*event):
        with self.db() as db:
            db.execute('INSERT INTO events(event) VALUES (?)',(l.canonical(list(event)),))

    def projection(self):
        with self.db() as db:
            self._load(db)
            events=[json.loads(v) for (v,) in db.execute('SELECT event FROM events ORDER BY id')]
            commits=[dict(oid=oid,parent=row['parent'],document_sha256=l.digest(row['state']),
                          state=row['state']) for oid,row in self.commits.items()]
            return dict(genesis=self.genesis,head=self.head,signer=self.signer,commits=commits,events=events)


class ReadbackWitness:
    def __init__(self,key,api):self.key,self.api=key,api
    def public_key(self):return self.key.public_key()
    def sign(self,encoded):
        statement=json.loads(encoded[len(l.DOMAIN):])
        self.api.record('sign',self.api.head,statement['nonce'],statement['action'],statement['snapshot']['revision'])
        return self.key.sign(encoded)


def certificate_material():
    now=datetime.datetime.now(datetime.timezone.utc)
    ca_key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Native closed-local ledger CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
        .sign(ca_key,hashes.SHA256()))
    material={};pins={}
    for role in ('server','issuer','custody'):
        key=ec.generate_private_key(ec.SECP256R1())
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,role)]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role=='server' else ExtendedKeyUsageOID.CLIENT_AUTH]),False))
        if role=='server':cert=cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(mtls.SERVER_NAME)]),False)
        cert=cert.sign(ca_key,hashes.SHA256())
        material[role]=dict(zip(FILES,(ca.public_bytes(serialization.Encoding.PEM),cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))))
        pins[role]=l.sha(cert.public_bytes(serialization.Encoding.DER))
    return material,pins


def provision_tls(base,binding,fault=''):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    b,_,_=s.modules()
    l.need(os.geteuid()==s.ROOT_UID and fault in ('',*FAULTS),'ROOT_EXPLICIT_MODEL_TLS_PROVISION')
    material,pins=certificate_material()
    for role,folder,uid in [('server','ledger',s.LEDGER),('issuer','issuer',b.kernel.ISSUER),('custody','custody',b.kernel.CUSTODY)]:
        for name,data in material[role].items():
            fd=os.open(base/folder/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
            os.chown(base/folder/name,uid,uid)
    return dict(schema=PROFILE,ca_sha256=l.sha(material['server']['mtls-ca.pem']),
        server_certificate_sha256=pins['server'],fault=fault,
        peers={role:dict(certificate_sha256=pins[role],authority_public_sha256=binding[role+'_public_sha256'])
               for role in ('issuer','custody')})


def validate_enrollment(a):
    cfg=a['github_mtls']
    l.exact(cfg,'schema genesis ca_sha256 server_certificate_sha256 fault peers')
    l.need(cfg['schema']==PROFILE and signed.hx(cfg['genesis'],40) and l.hex64(cfg['ca_sha256'])
           and cfg['fault'] in ('',*FAULTS) and l.hex64(cfg['server_certificate_sha256'])
           and a['binding']['ledger_id']==signed.LEDGER_ID,'EXACT_MODEL_GITHUB_TLS_PROFILE')
    l.exact(cfg['peers'],'issuer custody');pins=[cfg['server_certificate_sha256']]
    for role,row in cfg['peers'].items():
        l.exact(row,'certificate_sha256 authority_public_sha256')
        l.need(l.hex64(row['certificate_sha256']) and row['authority_public_sha256']==a['binding'][role+'_public_sha256'],'TLS_NATIVE_ROLE_JOIN')
        pins.append(row['certificate_sha256'])
    l.need(len(set(pins))==3,'DISTINCT_LEDGER_TLS_LEAVES')
    return cfg


def context(base,a,role):
    from scripts.task4_signed_ledger_entrypoint_v1 import owned_file
    cfg=validate_enrollment(a);folder=base/('ledger' if role=='server' else role)
    with owned_file(str(folder/'mtls-ca.pem'),16384) as (_,ca):
        l.need(l.sha(ca)==cfg['ca_sha256'],'PINNED_LEDGER_CA')
    if role=='server':
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.verify_mode=ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=ca.decode('ascii'))
    else:ctx=ssl.create_default_context(cadata=ca.decode('ascii'))
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    with owned_file(str(folder/'mtls-cert.pem'),16384) as (cert_fd,cert),owned_file(str(folder/'mtls-key.pem'),16384) as (key_fd,key):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        load_pem_private_key(key,password=None)
        parsed=x509.load_pem_x509_certificate(cert)
        pin=cfg['server_certificate_sha256'] if role=='server' else cfg['peers'][role]['certificate_sha256']
        l.need(l.sha(parsed.public_bytes(serialization.Encoding.DER))==pin,'PINNED_ROLE_TLS_CERTIFICATE')
        purpose=ExtendedKeyUsageOID.SERVER_AUTH if role=='server' else ExtendedKeyUsageOID.CLIENT_AUTH
        l.need(not parsed.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
               and set(parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)=={purpose},'TLS_LEAF_PURPOSE')
        ctx.load_cert_chain('/proc/self/fd/'+str(cert_fd),'/proc/self/fd/'+str(key_fd))
    return ctx


class Transport:
    def __init__(self,base,a,role):
        self.base,self.a,self.role=Path(base),a,role
        self.context=context(self.base,a,role)
    def __call__(self,encoded):
        from scripts import task4_native_signed_ledger_integration_v1 as s
        try:
            l.command(l.strict(encoded))
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as raw:
                raw.settimeout(20);raw.connect(str(self.base/'ledger-ipc/service.sock'))
                _,uid,_=struct.unpack('3i',raw.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                l.need(uid==s.LEDGER,'EXACT_MTLS_LEDGER_UID')
                with self.context.wrap_socket(raw,server_hostname=mtls.SERVER_NAME) as channel:
                    l.need(l.sha(channel.getpeercert(binary_form=True))==self.a['github_mtls']['server_certificate_sha256'],'SERVER_TLS_PIN')
                    mtls.write_frame(channel,encoded)
                    return mtls.read_frame(channel,timeout=mtls.RESPONSE_TIMEOUT)
        except Exception:raise l.Denied('NATIVE_GITHUB_MODEL_MTLS_STOP') from None


def bootstrap(base,v,key):
    api=RetainedModelGitAPI.bootstrap(base/'ledger'/MODEL,l.sha(key.public_key().public_bytes_raw()))
    backend=signed.GitState(api,api.genesis,api.signer)
    service=signed.SignedGitHubService(backend,ReadbackWitness(key,api));service.enroll(v['binding'])
    return dict(enrolled=True,genesis=api.genesis)


def reopen(base,a,key):
    cfg=validate_enrollment(a)
    api=RetainedModelGitAPI(base/'ledger'/MODEL)
    l.need(api.genesis==cfg['genesis'] and api.signer==l.sha(bytes.fromhex(a['service_public'])),'ENROLLED_MODEL_GENESIS_SIGNER')
    backend=signed.GitState(api,api.genesis,api.signer);backend.read()
    return api,signed.SignedGitHubService(backend,ReadbackWitness(key,api))


def handle(base,a,api,service,ctx,conn):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    b,r,_=s.modules()
    conn.settimeout(20)
    _,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    role={b.kernel.ISSUER:'issuer',b.kernel.CUSTODY:'custody'}[uid]
    current=s.anchor(base)
    for value in current['ledger_storage'].values():r.check_identity(value)
    l.need(current==a,'UNCHANGED_MTLS_LEDGER_ENROLLMENT')
    with ctx.wrap_socket(conn,server_side=True) as channel:
        pin=l.sha(channel.getpeercert(binary_form=True))
        l.need(pin==a['github_mtls']['peers'][role]['certificate_sha256'],'CERTIFICATE_AND_OS_ROLE_REQUIRED')
        encoded=mtls.read_frame(channel);c=l.command(l.strict(encoded))
        l.need(c['binding_sha256']==l.digest(a['binding']),'EXACT_NATIVE_TLS_BINDING')
        api.record('mtls',uid,pin,channel.version(),l.sha(encoded))
        def lost(_reply):
            api.record('api-response-lost',api.head,c['nonce'],c['action'])
            raise TimeoutError('CONTROLLED_MODEL_COMMIT_ACK_LOSS')
        api.response_fault=lost if a['github_mtls']['fault']=='api-reserve-ack-lost' and c['action']=='reserve' and c['operation_id']=='A0' else None
        try:reply=service.exchange(encoded,a['binding'][role+'_public_sha256'])
        finally:api.response_fault=None
        if a['github_mtls']['fault']=='tls-consume-ack-lost' and c['action']=='consume' and c['operation_id']=='A0':
            api.record('tls-response-lost',api.head,c['nonce'],c['action']);return
        mtls.write_frame(channel,reply)


def serve(base,a,key):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    import stat
    api,service=reopen(base,a,key);ctx=context(base,a,'server')
    address=base/'ledger-ipc/service.sock'
    if os.path.lexists(address):
        info=address.lstat();l.need(stat.S_ISSOCK(info.st_mode) and info.st_uid==s.LEDGER,'OWN_RETAINED_MTLS_SOCKET')
        address.unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(address));os.chmod(address,0o666);server.listen(8);(base/'ledger/ready').write_text('ready')
        while True:
            conn,_=server.accept()
            with conn:
                try:handle(base,a,api,service,ctx,conn)
                except Exception:pass  # No unsigned permission or secret diagnostics.


def project(base):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    b,r,_=s.modules();b.kernel.role_identity(s.LEDGER);a=s.anchor(base)
    for value in a['ledger_storage'].values():r.check_identity(value)
    api,_=reopen(base,a,s.service_key(base))
    return api.projection()


def fault_mode(base):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    if not s.required(base):return ''
    return s.anchor(base).get('github_mtls',{}).get('fault','')


def validate_model(a,p):
    cfg=validate_enrollment(a); signer=l.sha(bytes.fromhex(a['service_public']))
    l.need(p['genesis']==cfg['genesis'] and p['signer']==signer,'PROJECTED_GENESIS_AND_SIGNER')
    commits={row['oid']:row for row in p['commits']}
    l.need(len(commits)==len(p['commits']) and p['head'] in commits,'UNIQUE_MODEL_COMMITS')
    chain=[];current=p['head']
    while current is not None:
        l.need(current in commits and current not in chain and len(chain)<20,'BOUNDED_LINEAR_MODEL_ANCESTRY')
        chain.append(current);row=commits[current]
        signed.validate(row['state'],signer)
        l.need(row['document_sha256']==l.digest(row['state']),'PROJECTED_BLOB_DIGEST')
        current=row['parent']
    l.need(chain[-1]==p['genesis'] and len(chain)==len(commits)
           and commits[p['genesis']]['state']==signed.empty(signer),'EXACT_MODEL_GENESIS_CHAIN')
    events=p['events']
    for index,event in enumerate(events):
        if event[0]=='sign':
            l.need(any(x==['readback',event[1]] for x in events[:index]),'READBACK_PRECEDES_EVERY_SIGNATURE')
        elif event[0]=='commit' and event[1]!=p['genesis']:
            l.need(event[1] in commits,'RECORDED_MODEL_COMMIT')
            prior=[x for x in events[:index] if x[0]=='api' and x[1]=='POST']
            l.need(prior and prior[-1]==['api','POST','/graphql',commits[event[1]]['parent']],'EXACT_EXPECTED_HEAD_MODEL_CAS')
    return commits


def validate(e,normal,integration):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    s.validate(integration['evidence'],normal)
    a=integration['evidence']['enrollment'];p=e['model'];commits=validate_model(a,p)
    l.need(len(commits)==18,'GENESIS_ENROLLMENT_SIXTEEN_NATIVE_COMMITS')
    final=commits[p['head']]['state'];run=final['runs'][a['binding']['run_id']]
    l.need(final['revision']==17 and run['binding']==a['binding'] and run['snapshot']==integration['evidence']['post_replay'],
           'MODEL_GIT_STATE_AND_NATIVE_SIGNED_SNAPSHOT')
    events=p['events']
    b,_,_=s.modules()
    for role in ('issuer','custody'):
        uid=b.kernel.ISSUER if role=='issuer' else b.kernel.CUSTODY
        pin=a['github_mtls']['peers'][role]['certificate_sha256']
        for row in integration['evidence'][role]['rows']:
            for pair in row['receipts']['exchanges']:
                c=pair['command'];snapshot=pair['receipt']['statement']['snapshot']
                signs=[(i,x) for i,x in enumerate(events) if x[0]=='sign' and x[2]==c['nonce']]
                l.need(len(signs)==1,'ONE_ORIGINAL_NONCE_SIGNATURE')
                i,event=signs[0]
                l.need(event[3:]==[c['action'],snapshot['revision']]
                       and commits[event[1]]['state']['runs'][a['binding']['run_id']]['snapshot']==snapshot,'EXACT_READBACK_STATE_BEFORE_SIGN')
                auth=[x for x in events[:i] if x[0]=='mtls' and x[-1]==l.digest(c)]
                l.need(len(auth)==1 and auth[0][1:3]==[uid,pin]
                       and auth[0][3] in ('TLSv1.2','TLSv1.3'),'ACTUAL_TLS_CERTIFICATE_UID_COMMAND_JOIN')
    return True


def finish(base,output,worker,isolated,normal,integration):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    e=dict(model=worker(s.LEDGER,'signed-github-project',isolated))
    validate(e,normal,integration)
    report=dict(schema=PROFILE,audited_commit=normal['audited_commit'],source_sha256=l.sha(Path(__file__).read_bytes()),
        native_report_sha256=l.digest(normal),integration_report_sha256=l.digest(integration),evidence=e,evidence_sha256=l.digest(e),
        git_backend='RETAINED_SQLITE_GITHUB_API_MODEL',tls_transport='MTLS_OVER_AF_UNIX',
        actual_native_bind_closed_tls_integrated=True,remote_github_experiment_executed=False,
        external_storage_deployed=False,production_bypass_resistance_proven=False,independent_administration_proven=False,
        real_provider_posts=0,external_bank_effects=0,provider_dispatch='DENY',utility='UNSCORED')
    (output/'native-github-mtls.json').write_bytes(l.canonical(report))


def fault_native(base):
    """Actual Native SDK request reaches the same issuer/Custody RPC path."""
    from scripts import task4_native_signed_ledger_integration_v1 as s
    from unittest.mock import patch
    b,_,n=s.modules();b.kernel.role_identity(b.RUNTIME);os.umask(0o077)
    l.need(bool(fault_mode(base)),'EXPLICIT_ENROLLED_MODEL_FAULT')
    rpc=b.rpc
    def observed(base,packet,name='issuer'):
        if name=='issuer' and packet.get('action')=='authorize' and packet.get('arm')=='A' and packet.get('parent') is None:
            wire=n.decode(packet['wire_b64'])
            if b.canonical(b.raw.strict(wire))==b.canonical(b.seed()):
                file=base/'runtime/github-fault-wire.json'
                if file.exists():l.need(json.loads(file.read_bytes())==packet,'UNCHANGED_ORIGINAL_NATIVE_WIRE')
                else:n.durable_marker(file,packet)
        if name=='native' and set(packet)=={'arm','ordinal','wire_b64','grant'}:
            file=base/'runtime/github-fault-packet.json'
            l.need(not file.exists(),'NO_CACHED_GRANT_RECOVERY')
            n.durable_marker(file,packet)
        return rpc(base,packet,name)
    try:
        with patch.object(b,'rpc',observed):b.native(base)
    except b.NativeBoundaryFailure as error:
        l.need(str(error) in ('BOUNDED_NATIVE_GRANT_REQUIRED','ACTUAL_NATIVE_CUSTODY_REQUIRED'),'EXPECTED_NATIVE_GATE_STOP')
        query=json.loads((base/'runtime/github-fault-wire.json').read_bytes());wire=n.decode(query['wire_b64'])
        return dict(native_stopped=True,model_responses_returned=0,scorer_calls=0,uid=os.geteuid(),
                    request_sha256=l.sha(wire),request_bytes=len(wire))
    raise ValueError('UNCERTAIN_NATIVE_EXECUTION_CONTINUED')


def fault_replay(base):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    b,r,_=s.modules();b.kernel.role_identity(b.RUNTIME)
    file=base/'runtime/github-fault-packet.json'
    if not file.exists():return dict(grant_issued=False,custody_replay_denied=False)
    packet=json.loads(r.regular(file,b.RUNTIME,0o600))
    l.need(b.rpc(base,packet,'native')==dict(decision='DENIED_OR_UNKNOWN_NO_RETRY'),'UNCERTAIN_CUSTODY_REPLAY_STOP')
    return dict(grant_issued=True,custody_replay_denied=True)


def validate_fault(e):
    a=e['enrollment'];mode=a['github_mtls']['fault'];l.need(mode in FAULTS,'EXPLICIT_FAULT_EVIDENCE')
    consume=mode=='tls-consume-ack-lost';expected=2 if consume else 1
    commits=validate_model(a,e['model'])
    final=commits[e['model']['head']]['state']['runs'][a['binding']['run_id']]['snapshot']
    l.need(e['before']==e['after']==final and final['revision']==expected and len(final['attempts'])==1
           and final['attempts'][0]['state']==('CONSUMED_UNKNOWN' if consume else 'RESERVED'), 'UNCERTAIN_COMMIT_RETAINED_AFTER_RESTART')
    intent=e['intent'];grant=l.digest(e['issuer_before']['attempts'][0]['grant']) if consume else None
    l.need(intent['schema']==GATE_SCHEMA and intent['action']==('consume' if consume else 'reserve')
           and intent['operation_id']=='A0' and intent['binding_sha256']==l.digest(a['binding'])
           and intent['request_sha256']==e['initial']['request_sha256']==e['repeated']['request_sha256']==final['attempts'][0]['request_sha256']
           and intent['grant_sha256']==grant and final['attempts'][0]['grant_sha256']==grant,'ORIGINAL_NATIVE_WIRE_AND_FULL_GRANT_COMMIT_JOIN')
    l.need(e['issuer_before']==e['issuer_after'] and len(e['issuer_before']['attempts'])==int(consume)
           and e['consumed']==[] and e['posts']==e['events']==[], 'NO_NATIVE_BIND_POST_OR_ARCHIVE_ON_UNKNOWN_ACK')
    l.need(e['initial']['native_stopped'] is e['repeated']['native_stopped'] is True
           and e['initial']['model_responses_returned']==e['repeated']['model_responses_returned']==0
           and e['initial']['scorer_calls']==e['repeated']['scorer_calls']==0
           and e['replay']==dict(grant_issued=consume,custody_replay_denied=consume), 'NO_NATIVE_CONTINUATION_OR_RECOVERY_PERMISSION')
    l.need(all(e['pids_before'][x]!=e['pids_after'][x] and e['exit_codes'][x]==-9 for x in ('ledger','issuer','custody')),
           'THREE_REAL_SIGKILLS_REOPEN_SAME_STORAGE')
    l.need(len(commits)==expected+2 and e['posts_before_replay']==expected+1
           and sum(x[0]=='api' and x[1]=='POST' for x in e['model']['events'])==e['posts_before_replay'],'NO_REMOTE_MODEL_MUTATION_RETRY')
    events=e['model']['events'];mutation_signs=[x for x in events if x[0]=='sign' and x[3]!='view']
    lost=[x for x in events if x[0]==('tls-response-lost' if consume else 'api-response-lost')]
    l.need(len(lost)==1 and len(mutation_signs)==(2 if consume else 0),'EXACT_ACK_LOSS_AND_SIGNATURE_COUNTS')
    if not consume:l.need(not any(x[2]==lost[0][2] for x in mutation_signs),'NO_SIGNATURE_AFTER_UNVERIFIED_API_ACK')
    l.need(e['attempt_files']['intent.json'] is True and e['attempt_files']['verified-receipts.json'] is False
           and e['attempt_files']['effect-returned.json'] is False,'BURNED_UNVERIFIED_NATIVE_ATTEMPT')
    return True


def exercise_fault(base,output,worker,spawn,isolated,client,sink_ns,head):
    from scripts import task4_native_signed_ledger_integration_v1 as s
    b,r,_=s.modules();a=s.anchor(base);mode=fault_mode(base)
    processes=dict(ledger=spawn(s.LEDGER,'signed-ledger-server',isolated,base/'ledger/ready'),
        issuer=spawn(b.kernel.ISSUER,'bounded-issuer',isolated,base/'issuer/ready'),
        custody=spawn(b.kernel.CUSTODY,'custody',client,base/'custody/ready'))
    sink=spawn(b.kernel.BACKEND,'backend',sink_ns,base/'backend/ready')
    initial=worker(b.RUNTIME,'signed-github-fault-native',isolated)
    before=worker(b.kernel.ISSUER,'signed-ledger-view',isolated)
    issuer_before=worker(b.kernel.ISSUER,'retained-state',isolated)['snapshot']
    model_before=worker(s.LEDGER,'signed-github-project',isolated)
    pids_before={name:p.pid for name,p in processes.items()}
    for process in processes.values():process.kill();process.wait(timeout=5)
    exits={name:p.returncode for name,p in processes.items()}
    for role in ('ledger','issuer','custody'):(base/role/'ready').unlink()
    processes=dict(ledger=spawn(s.LEDGER,'signed-ledger-server',isolated,base/'ledger/ready'),
        issuer=spawn(b.kernel.ISSUER,'bounded-issuer',isolated,base/'issuer/ready','restarted',('--restart',)),
        custody=spawn(b.kernel.CUSTODY,'custody',client,base/'custody/ready','restarted',('--restart',)))
    repeated=worker(b.RUNTIME,'signed-github-fault-native',isolated)
    replay=worker(b.RUNTIME,'signed-github-fault-replay',isolated)
    after=worker(b.kernel.ISSUER,'signed-ledger-view',isolated)
    issuer_after=worker(b.kernel.ISSUER,'retained-state',isolated)['snapshot']
    model=worker(s.LEDGER,'signed-github-project',isolated)
    for process in [*processes.values(),sink]:process.terminate();process.wait(timeout=5)
    role='custody' if mode=='tls-consume-ack-lost' else 'issuer';action='consume' if role=='custody' else 'reserve'
    slot=base/role/'signed-ledger'/(a['binding']['run_id']+'-'+action+'-A0')
    # Supervisor reads only retained evidence; no signer/private grant is exported.
    with sqlite3.connect((base/'custody/ledger.sqlite3').as_uri()+'?mode=ro',uri=True) as db:
        consumed=db.execute('SELECT op,state FROM consumed').fetchall()
    e=dict(enrollment=a,initial=initial,repeated=repeated,replay=replay,before=before,after=after,
        issuer_before=issuer_before,issuer_after=issuer_after,consumed=consumed,model=model,
        posts=b.raw.tls.read_lines(base/'backend/raw-posts.jsonl'),events=b.raw.tls.read_lines(base/'custody/raw-events.jsonl'),
        pids_before=pids_before,pids_after={name:p.pid for name,p in processes.items()},exit_codes=exits,
        intent=json.loads(r.regular(slot/'intent.json',b.kernel.CUSTODY if role=='custody' else b.kernel.ISSUER,0o600)),
        posts_before_replay=sum(x[0]=='api' and x[1]=='POST' for x in model_before['events']),
        attempt_files={name:(slot/name).is_file() for name in ('intent.json','verified-receipts.json','effect-returned.json')})
    validate_fault(e)
    report=dict(schema=PROFILE,audited_commit=head,source_sha256=l.sha(Path(__file__).read_bytes()),fault=mode,
        evidence=e,evidence_sha256=l.digest(e),actual_native_sdk_stopped=True,remote_github_experiment_executed=False,
        production_bypass_resistance_proven=False,independent_administration_proven=False,
        real_provider_posts=0,external_bank_effects=0,provider_dispatch='DENY',utility='UNSCORED')
    (output/'native-github-mtls-fault.json').write_bytes(l.canonical(report))

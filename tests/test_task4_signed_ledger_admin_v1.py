import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys

import pytest

from scripts import task4_signed_ledger_admin_v1 as admin
from scripts import task4_signed_github_api_v1 as transport
from scripts import task4_signed_github_ledger_v1 as signed
from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, digest, sha

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason='root-owned approval pin fixture requires sudo')
TOKEN = 'ghp_SYNTHETIC_ADMIN_TOKEN_NOT_A_CREDENTIAL'


class Model:
    """API model with real blob/tree hashes; not a remote/durable backend."""
    def __init__(self):
        self.head, self.calls, self.commits, self.trees, self.blobs = None, [], {}, {}, {}
        self.fault, self.fault_used = None, False

    def tree(self, data):
        blob = admin.git_oid('blob', data); self.blobs[blob] = data
        oid = admin.git_oid('tree', b'100644 ledger.json\0'+bytes.fromhex(blob))
        row = dict(sha=oid, truncated=False, tree=[dict(path='ledger.json', mode='100644', type='blob', sha=blob)])
        self.trees[oid] = row
        return row

    def commit(self, tree, parents, message):
        oid = admin.git_oid('commit', canonical(dict(tree=tree, parents=parents, message=message, sequence=len(self.commits))))
        row = dict(sha=oid, tree=dict(sha=tree), parents=[dict(sha=p) for p in parents], message=message)
        self.commits[oid] = row
        return row

    def ref(self): return dict(ref=admin.REF, object=dict(type='commit', sha=self.head))

    def response(self, method, path, value):
        self.calls.append((method, path, copy.deepcopy(value)))
        if method == 'GET':
            if path == admin.MATCH: return 200, [] if self.head is None else [self.ref()]
            suffix = path[len(transport.PREFIX):]
            if suffix == 'git/ref/heads/'+signed.BRANCH: return 200, self.ref()
            if suffix.startswith('git/commits/'):
                if self.fault == 'root_readback' and not self.fault_used:
                    self.fault_used = True; raise TimeoutError(TOKEN)
                return 200, self.commits[suffix.rsplit('/', 1)[1]]
            if suffix.startswith('git/trees/'): return 200, self.trees[suffix.rsplit('/', 1)[1]]
            if suffix.startswith('git/blobs/'):
                data = self.blobs[suffix.rsplit('/', 1)[1]]
                return 200, dict(encoding='base64', size=len(data), content=base64.b64encode(data).decode())
            if suffix.startswith('compare/'):
                root, head = suffix.rsplit('/', 1)[1].split('...'); count = 0
                while head != root:
                    head = self.commits[head]['parents'][0]['sha']; count += 1
                    assert count < 545
                return 200, dict(status='ahead', total_commits=count, merge_base_commit=dict(sha=root))
        assert method == 'POST'
        status = 201
        if path == transport.PREFIX+'git/trees':
            result = self.tree(value['tree'][0]['content'].encode()); phase = 'tree'
        elif path == transport.PREFIX+'git/commits':
            result = self.commit(value['tree'], value['parents'], value['message']); phase = 'commit'
        elif path == transport.PREFIX+'git/refs':
            if self.fault == 'ref_race':
                self.head = 'e'*40
            if self.head is not None: return 422, dict(message=TOKEN)
            self.head = value['sha']; result = self.ref(); phase = 'ref'
        else:
            assert path == '/graphql'
            v = value['variables']['input']
            if v['expectedHeadOid'] != self.head:
                return 200, dict(errors=[dict(type='STALE_DATA')])
            data = base64.b64decode(v['fileChanges']['additions'][0]['contents'])
            tree = self.tree(data); parent = self.head
            commit = self.commit(tree['sha'], [parent], v['message']['headline'])
            self.head = commit['sha']; status = 200; phase = 'enroll'
            result = dict(data=dict(createCommitOnBranch=dict(clientMutationId=v['clientMutationId'],
                commit=dict(oid=self.head, parents=dict(nodes=[dict(oid=parent)])),
                ref=dict(name=signed.BRANCH, target=dict(oid=self.head)))))
        if self.fault == phase+'_lost': raise TimeoutError(TOKEN)
        if self.fault == phase+'_bad':
            result = copy.deepcopy(result)
            if phase == 'tree': result['sha'] = '0'*40
            if phase == 'commit': result['parents'] = [dict(sha='0'*40)]
            if phase == 'ref': result['object']['sha'] = '0'*40
        return status, result


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    root = tmp_path / 'authority'; root.mkdir(mode=0o700)
    slot = root / 'receipt-custody'; identity = custody.initialize(slot)
    pin = root / 'public-pin'; pin.write_text(identity['public_key_sha256']+'\n'); pin.chmod(0o644)
    token = root / 'token'; token.write_text(TOKEN+'\n'); token.chmod(0o600)
    attempts = root / 'attempts'; attempts.mkdir(mode=0o700)
    cfg = dict(schema=admin.PROFILE, scope=admin.SCOPE, receipt_directory=str(slot),
        public_pin_file=str(pin), token_file=str(token), attempt_parent=str(attempts),
        approval_id='a'*64, genesis=None, binding=None)
    file = root / 'admin.json'; file.write_bytes(canonical(cfg)); file.chmod(0o600)
    api_model = Model(); requests = []

    class Socket:
        def settimeout(self, value): assert 0 < value <= transport.TIMEOUT

    class Response:
        def __init__(self, status, value):
            self.status, self.data = status, io.BytesIO(canonical(value))
        def getheaders(self): return [('Content-Type', 'application/json')]
        def read1(self, size): return self.data.read(size)
        def close(self): pass

    class Connection:
        def __init__(self, host, port, timeout, context):
            assert host == 'api.github.com' and port == 443
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            self.sock = Socket()
        def request(self, method, path, body=None, headers=None):
            assert headers['Authorization'] == 'Bearer '+TOKEN
            self.call = (method, path, json.loads(body) if body else None)
            requests.append(self.call)
        def getresponse(self): return Response(*api_model.response(*self.call))
        def close(self): pass

    monkeypatch.setattr(transport.http.client, 'HTTPSConnection', Connection)
    return dict(root=root, slot=slot, identity=identity, cfg=cfg, file=file, model=api_model, requests=requests)


def configure_enrollment(f, genesis, run='b'*64):
    f['cfg'].update(genesis=genesis, approval_id=run, binding=dict(schema=signed.SCHEMA, ledger_id=signed.LEDGER_ID,
        run_id=run, manifest_sha256='c'*64, issuer_public_sha256='d'*64, custody_public_sha256='e'*64))
    f['file'].write_bytes(canonical(f['cfg']))


def test_bootstrap_enroll_and_readonly_inspection(fixture):
    f = fixture; model = f['model']
    assert admin.administer('check', f['file'])['backend_verified'] is False
    assert not f['requests'] and not list(Path(f['cfg']['attempt_parent']).iterdir())
    root = admin.administer('bootstrap', f['file'])
    assert root['genesis'] == model.head and root['owner_genesis_approval_required'] is True
    assert model.commits[model.head]['parents'] == []
    assert [p for m, p, _ in model.calls if m == 'POST'] == [transport.PREFIX+'git/'+p for p in ('trees','commits','refs')]
    attempt = Path(f['cfg']['attempt_parent'])/'bootstrap'
    assert json.loads((attempt/'result.json').read_bytes()) == root
    seen = admin.administer('inspect', f['file'])
    assert seen['observed_head'] == model.head and seen['genesis_approved'] is False
    configure_enrollment(f, root['genesis'])  # Separate explicit owner approval, never inferred by code.
    result = admin.administer('enroll', f['file'])
    assert result['enrollment_commit'] == model.head
    report = admin.administer('inspect', f['file'])
    assert report['exact_binding_registered'] is True and report['revision'] == 1
    calls = len(f['requests'])
    with pytest.raises(Denied): admin.administer('enroll', f['file'])
    assert len(f['requests']) == calls
    # A new process has the same exclusive local attempt barrier, before any network request.
    p = subprocess.run([sys.executable, '-m', 'scripts.task4_signed_ledger_admin_v1', 'enroll',
        '--configuration', str(f['file']), '--acknowledge-synthetic-only'], capture_output=True, text=True, timeout=10)
    assert p.returncode == 1 and p.stdout == '' and p.stderr == admin.STOP+'\n'


@pytest.mark.parametrize('fault', ['tree_lost','commit_lost','ref_lost','tree_bad','commit_bad','ref_bad','root_readback','ref_race'])
def test_ambiguous_or_bad_bootstrap_burns_attempt_and_never_retries(fixture, fault):
    f = fixture; f['model'].fault = fault
    with pytest.raises(Denied, match='^SIGNED_LEDGER_ADMIN_STOP$'): admin.administer('bootstrap', f['file'])
    calls = len(f['requests']); head = f['model'].head
    attempt = Path(f['cfg']['attempt_parent'])/'bootstrap'
    assert (attempt/'attempt.json').exists() and not (attempt/'result.json').exists()
    with pytest.raises(Denied): admin.administer('bootstrap', f['file'])
    assert len(f['requests']) == calls and f['model'].head == head
    f['model'].fault = None
    before = sum(m == 'POST' for m, _, _ in f['model'].calls)
    admin.administer('inspect', f['file'])
    assert sum(m == 'POST' for m, _, _ in f['model'].calls) == before


def test_existing_namespace_is_not_overwritten(fixture):
    f = fixture; f['model'].head = 'f'*40
    with pytest.raises(Denied): admin.administer('bootstrap', f['file'])
    assert f['model'].head == 'f'*40 and all(m == 'GET' for m, _, _ in f['model'].calls)


def test_committed_enrollment_with_lost_ack_is_visible_but_never_retried(fixture):
    f = fixture; root = admin.administer('bootstrap', f['file'])
    configure_enrollment(f, root['genesis']); f['model'].fault = 'enroll_lost'
    with pytest.raises(Denied): admin.administer('enroll', f['file'])
    calls = len(f['requests'])
    with pytest.raises(Denied): admin.administer('enroll', f['file'])
    assert len(f['requests']) == calls
    f['model'].fault = None
    report = admin.administer('inspect', f['file'])
    assert report['exact_binding_registered'] is True
    assert not (Path(f['cfg']['attempt_parent'])/('enroll-'+f['cfg']['binding']['run_id'])/'result.json').exists()


def test_existing_enrollment_cannot_be_changed_or_consumption_reset(fixture):
    f = fixture; root = admin.administer('bootstrap', f['file']); configure_enrollment(f, root['genesis'])
    cfg, key, api, pin = admin.prepare(f['file'])
    backend = signed.GitState(api, cfg['genesis'], pin); service = signed.SignedGitHubService(backend, key)
    service.enroll(cfg['binding'])  # Existing registration without a local admin attempt record.
    b = cfg['binding']
    def client(role):
        return LedgerClient(b, key.public_key().public_bytes_raw(), lambda data: service.exchange(data,b[role+'_public_sha256']))
    client('issuer').gate('reserve','A0',sha(b'request'),lambda _:None)
    client('custody').gate('consume','A0',sha(b'request'),lambda _:None,sha(b'grant'))
    old = copy.deepcopy(backend.read()[1]['runs'][b['run_id']]); head = f['model'].head
    f['cfg']['binding']['manifest_sha256'] = '0'*64; f['file'].write_bytes(canonical(f['cfg']))
    with pytest.raises(Denied): admin.administer('enroll',f['file'])
    assert backend.read()[1]['runs'][b['run_id']] == old and f['model'].head == head
    configure_enrollment(f,root['genesis'],run='f'*64); admin.administer('enroll',f['file'])
    assert backend.read()[1]['runs'][b['run_id']] == old


def test_attempt_creation_race_has_one_winner(fixture):
    f = fixture
    def claim(_):
        try: return admin.begin_attempt(f['cfg']['attempt_parent'],'bootstrap',f['cfg'])
        except FileExistsError: return None
    with ThreadPoolExecutor(2) as pool: claims = list(pool.map(claim,range(2)))
    assert sum(c is not None for c in claims) == 1 and not f['requests']


def test_fsync_failure_burns_slot_before_network(fixture, monkeypatch):
    def fail(_): raise OSError('synthetic fsync failure')
    monkeypatch.setattr(admin.os,'fsync',fail)
    with pytest.raises(Denied): admin.administer('bootstrap',fixture['file'])
    assert (Path(fixture['cfg']['attempt_parent'])/'bootstrap').is_dir() and not fixture['requests']
    with pytest.raises(Denied): admin.administer('bootstrap',fixture['file'])
    assert not fixture['requests']


@pytest.mark.parametrize('fault',['scope','approval','pin','token_mode','missing_key','binding_without_root','bad_root','attempts_inside_key'])
def test_local_approval_faults_do_not_contact_backend(fixture,fault):
    f=fixture; cfg=f['cfg']
    if fault=='scope': cfg['scope']='PRODUCTION'
    if fault=='approval': cfg['approval_id']=None
    if fault=='pin': Path(cfg['public_pin_file']).write_text('0'*64+'\n')
    if fault=='token_mode': Path(cfg['token_file']).chmod(0o644)
    if fault=='missing_key': (f['slot']/custody.KEY_NAME).unlink()
    if fault=='binding_without_root': cfg['binding']={}
    if fault=='bad_root': cfg['genesis']='main'
    if fault=='attempts_inside_key': cfg['attempt_parent']=cfg['receipt_directory']
    f['file'].write_bytes(canonical(cfg))
    with pytest.raises(Denied): admin.administer('bootstrap',f['file'])
    assert not f['requests']


@pytest.mark.parametrize('action',['bootstrap','enroll'])
def test_cli_requires_acknowledgement_before_loading(action,monkeypatch,capsys):
    monkeypatch.setattr(admin,'prepare',lambda *a:pytest.fail('loaded'))
    assert admin.main([action,'--configuration','/missing/'+TOKEN])==1
    assert capsys.readouterr()==('',admin.STOP+'\n')


@pytest.mark.parametrize('method,path', [('PATCH',transport.PREFIX+'git/refs/heads/'+signed.BRANCH),
    ('DELETE',transport.PREFIX+'git/refs/heads/'+signed.BRANCH), ('POST','/graphql'),
    ('POST',transport.PREFIX+'git/blobs'),('GET',admin.MATCH+'?x=1'),('GET','https://evil.invalid/')])
def test_bootstrap_transport_has_no_update_delete_or_arbitrary_operation(fixture,method,path):
    api=admin.BootstrapAPI(TOKEN,fixture['identity']['public_key_sha256'],'a'*64)
    with pytest.raises(Denied): api.call(method,path,{})
    assert not fixture['requests']


def test_normal_service_transport_still_refuses_bootstrap_endpoints(fixture):
    api=transport.API(TOKEN,'a'*40,fixture['identity']['public_key_sha256'])
    with pytest.raises(Denied): api.call('POST',transport.PREFIX+'git/refs',dict(ref=admin.REF,sha='a'*40))
    assert not fixture['requests']


def test_bootstrap_hashes_match_git_objects(fixture):
    api=admin.BootstrapAPI(TOKEN,fixture['identity']['public_key_sha256'],'a'*64)
    blob=subprocess.check_output(['git','hash-object','--stdin'],input=api.content).decode().strip()
    tree=subprocess.check_output(['git','hash-object','--stdin','-t','tree'],
        input=b'100644 ledger.json\0'+bytes.fromhex(blob)).decode().strip()
    assert api.blob==blob and api.tree==tree


def test_result_retention_failure_never_reports_success_or_retries(fixture,monkeypatch):
    original=admin.write_record
    def fail_result(directory,name,value):
        if name=='result.json': raise OSError(TOKEN)
        return original(directory,name,value)
    monkeypatch.setattr(admin,'write_record',fail_result)
    with pytest.raises(Denied): admin.administer('bootstrap',fixture['file'])
    assert fixture['model'].head is not None
    count=len(fixture['requests'])
    with pytest.raises(Denied): admin.administer('bootstrap',fixture['file'])
    assert len(fixture['requests'])==count


@pytest.mark.parametrize('fault',[401,403,404,500,'bad_type','duplicate','too_many'])
def test_namespace_probe_errors_are_never_interpreted_as_absence(fixture,fault):
    f=fixture; original=f['model'].response
    row=dict(ref=admin.REF,object=dict(type='commit',sha='f'*40))
    def response(method,path,value):
        if path!=admin.MATCH: return original(method,path,value)
        if type(fault) is int: return fault,dict(message=TOKEN)
        if fault=='bad_type': return 200,dict(matches=[])
        if fault=='duplicate': return 200,[row,row]
        return 200,[dict(ref=admin.REF+str(i),object=dict(type='commit',sha='f'*40)) for i in range(33)]
    f['model'].response=response
    with pytest.raises(Denied): admin.administer('bootstrap',f['file'])
    assert all(m=='GET' for m,_,_ in f['requests']) and f['model'].head is None


def test_wrong_root_message_stops_before_reference_publication(fixture):
    f=fixture; original=f['model'].response
    def response(method,path,value):
        status,result=original(method,path,value)
        if method=='GET' and '/git/commits/' in path:
            result=copy.deepcopy(result); result['message']='unapproved root'
        return status,result
    f['model'].response=response
    with pytest.raises(Denied): admin.administer('bootstrap',f['file'])
    assert f['model'].head is None
    assert not any(m=='POST' and p.endswith('/git/refs') for m,p,_ in f['requests'])


def test_same_bootstrap_api_instance_cannot_resend_after_ambiguous_post(fixture):
    f=fixture; api=admin.BootstrapAPI(TOKEN,f['identity']['public_key_sha256'],'a'*64)
    api.call('GET',admin.MATCH); f['model'].fault='tree_lost'
    value=dict(tree=[dict(path=signed.FILE,mode='100644',type='blob',content=api.content.decode())])
    with pytest.raises(Denied): api.call('POST',transport.PREFIX+'git/trees',value)
    calls=len(f['requests'])
    with pytest.raises(Denied): api.call('POST',transport.PREFIX+'git/trees',value)
    assert len(f['requests'])==calls


@pytest.mark.parametrize('fault',['base_tree','parents','author','other_ref'])
def test_bootstrap_payload_cannot_expand_approved_scope(fixture,fault):
    api=admin.BootstrapAPI(TOKEN,fixture['identity']['public_key_sha256'],'a'*64)
    api.absent=api.tree_ready=api.verified=True; api.root='f'*40
    if fault=='base_tree':
        path='trees'; value=dict(tree=[dict(path=signed.FILE,mode='100644',type='blob',content=api.content.decode())],base_tree='f'*40)
    elif fault=='other_ref':
        path='refs'; value=dict(ref='refs/heads/main',sha=api.root)
    else:
        path='commits'; value=dict(message=api.message,tree=api.tree,parents=[])
        if fault=='parents': value['parents']=['f'*40]
        else: value['author']=dict(name='unapproved')
    with pytest.raises(Denied): api.call('POST',transport.PREFIX+'git/'+path,value)
    assert not fixture['requests']


def test_enrollment_approval_id_must_equal_the_fresh_run_id(fixture):
    f=fixture; root=admin.administer('bootstrap',f['file']); configure_enrollment(f,root['genesis'])
    f['cfg']['approval_id']='0'*64; f['file'].write_bytes(canonical(f['cfg']))
    calls=len(f['requests'])
    with pytest.raises(Denied): admin.administer('enroll',f['file'])
    assert len(f['requests'])==calls


def test_cli_interrupt_is_nonzero_and_sanitized(monkeypatch,capsys):
    def interrupted(*a): raise KeyboardInterrupt()
    monkeypatch.setattr(admin,'administer',interrupted)
    assert admin.main(['inspect','--configuration','/missing/'+TOKEN])==130
    assert capsys.readouterr()==('',admin.STOP+'\n')

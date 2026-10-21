import base64
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import pytest
from scripts import task4_github_ledger_research_v1 as g

RUN, SOURCE, EXECUTION = 'a'*64, 'b'*40, '12345'
BRANCH_SCHEMA = g.decode((Path(__file__).resolve().parents[1] /
    'fixtures/task4_github_committable_branch_schema_v1.json').read_bytes())


class FakeAPI:
    """Unit-only API model, not evidence of GitHub behavior."""
    def __init__(self):
        self.commits, self.calls, self.mutations = {}, [], []
        self.writable, self.response_fault = True, None
        self.genesis = self.add(g.empty(), None)

    def add(self, value, parent):
        data = g.canonical(value)
        oid = hashlib.sha1(data + (parent or '').encode() + str(len(self.commits)).encode()).hexdigest()
        self.commits[oid] = dict(value=copy.deepcopy(value), parent=parent)
        self.head = oid
        return oid

    def call(self, method, path, value=None):
        self.calls.append((method, path, copy.deepcopy(value)))
        if method == 'POST' and path == '/graphql':
            self.mutations.append(value)
            v = value['variables']['input']
            # Contract fixture comes from the published input type, not the
            # mutation's prose. Coercion precedes resolver permission checks.
            if set(v['branch']) != set(BRANCH_SCHEMA['client_form_fields']):
                return dict(errors=[dict(type='INPUT_VALIDATION_ERROR', message='Invalid CommittableBranch input fields')])
            if not self.writable:
                return dict(errors=[dict(type='FORBIDDEN')])
            if v['expectedHeadOid'] != self.head:
                return dict(errors=[dict(type='STALE_DATA')])
            state = g.decode(base64.b64decode(v['fileChanges']['additions'][0]['contents']))
            old = self.head
            oid = self.add(state, old)
            result = dict(data=dict(createCommitOnBranch=dict(clientMutationId=v['clientMutationId'],
                commit=dict(oid=oid, parents=dict(nodes=[dict(oid=old)])), ref=dict(name=g.BRANCH, target=dict(oid=oid)))))
            if self.response_fault:
                return self.response_fault(result)
            return result
        prefix = '/repos/' + g.REPO + '/'
        assert method == 'GET' and path.startswith(prefix), (method, path)
        route = path[len(prefix):]
        if route == 'git/ref/heads/' + g.BRANCH:
            return dict(ref='refs/heads/' + g.BRANCH, object=dict(type='commit', sha=self.head))
        if route.startswith('git/commits/'):
            oid = route.rsplit('/', 1)[1]
            row = self.commits[oid]
            return dict(sha=oid, tree=dict(sha=oid), parents=[] if row['parent'] is None else [dict(sha=row['parent'])])
        if route.startswith('git/trees/'):
            oid = route.rsplit('/', 1)[1]
            data = g.canonical(self.commits[oid]['value'])
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            return dict(truncated=False, tree=[dict(path=g.FILE, mode='100644', type='blob', sha=blob)])
        if route.startswith('git/blobs/'):
            oid = route.rsplit('/', 1)[1]
            for row in self.commits.values():
                data = g.canonical(row['value'])
                if hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid:
                    return dict(encoding='base64', size=len(data), content=base64.b64encode(data).decode())
        if route.startswith('compare/'):
            genesis, head = route.split('/')[-1].split('...')
            depth = 0
            while head != genesis:
                depth += 1
                head = self.commits[head]['parent']
            return dict(status='ahead', total_commits=depth, merge_base_commit=dict(sha=genesis))
        raise AssertionError(route)


@pytest.fixture
def store():
    api = FakeAPI()
    return api, g.Ledger(api, api.genesis)


def reserved(store):
    api, ledger = store
    report = g.run_stage('reserve', ledger, RUN, SOURCE, EXECUTION)
    return report['head']


def test_new_clients_reopen_same_state_and_reject_run_reset(store):
    api, ledger = store
    h = reserved(store)
    fresh = g.Ledger(api, api.genesis)
    assert fresh.read()[0] == h
    with pytest.raises(g.Stop, match='DUPLICATE_RUN'):
        g.run_stage('reserve', fresh, RUN, SOURCE, EXECUTION)
    assert len(api.mutations) == 1


def test_wire_branch_fields_follow_published_input_type(store):
    api, ledger = store
    reserved(store)
    payload = api.mutations[0]['variables']['input']
    assert payload['branch'] == dict(repositoryNameWithOwner=g.REPO, branchName=g.BRANCH)
    assert set(payload['branch']) <= set(BRANCH_SCHEMA['allowed_fields'])
    assert payload['expectedHeadOid'] == api.genesis
    assert BRANCH_SCHEMA['unsupported_field_regression'] not in payload['branch']


@pytest.mark.parametrize('writable', [True, False])
def test_old_refname_shape_rejected_before_permission_or_commit(store, writable):
    api, ledger = store
    reserved(store)
    old = copy.deepcopy(api.mutations[0])
    old['variables']['input']['branch']['refName'] = old['variables']['input']['branch'].pop('branchName')
    old['variables']['input']['expectedHeadOid'] = api.head
    api.writable = writable; before = api.head
    result = api.call('POST', '/graphql', old)
    assert result['errors'][0]['type'] == 'INPUT_VALIDATION_ERROR'
    assert api.head == before


def test_graphql_diagnostics_redact_before_truncation_and_omit_other_fields():
    token = 'ghs_' + 'Z'*40
    error = dict(type='VALIDATION_ERROR', message='Bad field refName '+token+'\n\x1b token github_pat_ABC123 '+('x'*900),
                 extensions=dict(secret=token), variables=dict(secret=token), headers=dict(Authorization=token))
    safe = g.graphql_diagnostics([error]*9, token)
    encoded = g.canonical(safe).decode()
    assert len(safe) == 3 and all(set(x) == {'type','message'} and len(x['message']) <= 384 for x in safe)
    assert token not in encoded and 'github_pat_ABC123' not in encoded and 'Authorization' not in encoded
    assert 'refName' in encoded and '[REDACTED]' in encoded
    assert all('\n' not in x['message'] and '\x1b' not in x['message'] for x in safe)


@pytest.mark.parametrize('errors', [None, ['ghs_SENSITIVE'], {'message':'ghs_SENSITIVE'}])
def test_malformed_graphql_diagnostics_do_not_dump_raw_errors(errors):
    assert 'SENSITIVE' not in g.canonical(g.graphql_diagnostics(errors)).decode()


def test_late_contender_still_submits_original_expected_head(store):
    api, ledger = store
    h = reserved(store)
    one = g.run_stage('contend', ledger, RUN, SOURCE, EXECUTION, h, '1')
    two = g.run_stage('contend', g.Ledger(api, api.genesis), RUN, SOURCE, EXECUTION, h, '2')
    assert one['effects'] == 1 and two['effects'] == 0
    assert two['reason'] == 'GRAPHQL_ERRORS_STOP'
    assert [v['variables']['input']['expectedHeadOid'] for v in api.mutations[-2:]] == [h, h]
    assert ledger.read()[1]['runs'][RUN]['candidate'] == '1'


@pytest.mark.parametrize('fault', [False, True])
def test_consumption_before_callback_or_discarded_ack_and_no_retry(store, fault):
    api, ledger = store
    h = reserved(store)
    first = g.run_stage('contend', ledger, RUN, SOURCE, EXECUTION, h, '2', fault)
    assert first['effects'] == (0 if fault else 1)
    assert ledger.read()[1]['runs'][RUN]['state'] == 'CONSUMED_UNKNOWN'
    if fault:
        assert first['reason'] == 'ACK_DISCARDED_STOP'
    calls = len(api.mutations)
    replay = g.run_stage('replay', g.Ledger(api, api.genesis), RUN, SOURCE, EXECUTION)
    assert replay['decision'] == 'REISSUE_AND_REPLAY_DENIED' and len(api.mutations) == calls


def test_real_gate_callback_observes_committed_record(store):
    api, ledger = store
    h = reserved(store); old = ledger.read()[1]
    new = g.consume_transition(old, RUN, SOURCE, EXECUTION, '1')
    def effect():
        assert g.Ledger(api, api.genesis).read()[1] == new
        return 1
    assert ledger.gate(h, old, new, effect)[1] == 1


@pytest.mark.parametrize('fault', ['timeout', 'partial', 'null', 'errors', 'nonce', 'parent', 'ref', 'oid'])
def test_mutation_bad_ack_stops_without_retry_or_callback(store, fault):
    api, ledger = store
    h = reserved(store); old = ledger.read()[1]
    new = g.consume_transition(old, RUN, SOURCE, EXECUTION, '1')
    calls = []
    def break_response(result):
        if fault == 'timeout': raise TimeoutError()
        if fault == 'partial': return {}
        if fault == 'null': return dict(data=None)
        if fault == 'errors': return dict(errors=[dict(type='UNKNOWN')], data=result['data'])
        v = result['data']['createCommitOnBranch']
        if fault == 'nonce': v['clientMutationId'] = 'f'*64
        if fault == 'parent': v['commit']['parents']['nodes'] = []
        if fault == 'ref': v['ref']['name'] = 'main'
        if fault == 'oid': v['commit']['oid'] = 'broken'
        return result
    api.response_fault = break_response
    before = len(api.mutations)
    with pytest.raises((g.Stop, TimeoutError, AttributeError)):
        ledger.gate(h, old, new, lambda: calls.append('BAD'))
    assert calls == [] and len(api.mutations) == before + 1
    assert ledger.read()[1]['runs'][RUN]['state'] == 'CONSUMED_UNKNOWN'


def test_readonly_permission_probe_and_fresh_view(store):
    api, ledger = store
    h = reserved(store); api.writable = False
    assert g.run_stage('observe', ledger, RUN, SOURCE, EXECUTION, h)['decision'] == 'READ_ONLY_WRITE_DENIED'
    assert api.head == h


@pytest.mark.parametrize('fault', ['unexpected-write', 'timeout', 'unknown-error'])
def test_observer_never_promotes_non_permission_failure(store, fault):
    api, ledger = store
    h = reserved(store)
    if fault != 'unexpected-write':
        def failure(result):
            if fault == 'timeout': raise TimeoutError()
            return dict(errors=[dict(type='UNKNOWN')])
        api.response_fault = failure
    with pytest.raises((g.Stop, TimeoutError)):
        g.run_stage('observe', ledger, RUN, SOURCE, EXECUTION, h)


@pytest.mark.parametrize('field,value', [('schema','other'),('ledger_id','f'*64),('scope','LIVE'),
    ('revision',True),('revision',1),('runs',[]),('extra',True)])
def test_registry_exact_namespace_and_schema(field, value):
    state = g.empty(); state[field] = value
    with pytest.raises(g.Stop): g.validate(state)


@pytest.mark.parametrize('field,value', [('source_commit','bad'),('execution_id',''),('request_sha256','f'*64),
    ('grant_sha256','f'*64),('state','READY'),('candidate','1')])
def test_registered_record_cannot_change_contract(field, value):
    state = g.reserve_transition(g.empty(), RUN, SOURCE, EXECUTION)
    state['runs'][RUN][field] = value
    with pytest.raises(g.Stop): g.validate(state)


def test_other_runs_preserved_and_registry_never_pruned():
    state = g.empty()
    for i in range(g.MAX_RUNS):
        run = '%064x' % i
        state = g.reserve_transition(state, run, SOURCE, EXECUTION)
        state = g.consume_transition(state, run, SOURCE, EXECUTION, '1')
    assert len(state['runs']) == g.MAX_RUNS and state['revision'] == 2*g.MAX_RUNS
    with pytest.raises(g.Stop, match='REGISTRY_FULL'):
        g.reserve_transition(state, 'e'*64, SOURCE, EXECUTION)


@pytest.mark.parametrize('source,execution', [('c'*40,EXECUTION),(SOURCE,'999')])
def test_different_execution_cannot_consume_existing_authority(store, source, execution):
    api, ledger = store
    h = reserved(store)
    with pytest.raises(g.Stop): g.run_stage('contend', ledger, RUN, source, execution, h, '1')
    assert len(api.mutations) == 1


def test_missing_genesis_or_branch_never_bootstraps(store):
    api, ledger = store
    with pytest.raises(g.Stop): g.Ledger(api, '')
    ledger.genesis = 'e'*40
    with pytest.raises(KeyError): ledger.read()
    assert not api.mutations and all(m == 'GET' for m,_,_ in api.calls)


@pytest.mark.parametrize('fault', ['tree-extra','blob-hash','genesis-parent','genesis-state','ancestry'])
def test_missing_or_tampered_remote_state_stops(store, fault):
    api, ledger = store
    reserved(store)
    original = api.call
    def tamper(method, path, value=None):
        result = original(method, path, value)
        if fault == 'tree-extra' and '/git/trees/' in path: result['tree'] *= 2
        if fault == 'blob-hash' and '/git/blobs/' in path: result['content'] = base64.b64encode(b'{}').decode()
        if fault == 'genesis-parent' and path.endswith('/git/commits/' + api.genesis): result['parents'] = [dict(sha='f'*40)]
        if fault == 'ancestry' and '/compare/' in path: result['merge_base_commit']['sha'] = 'f'*40
        return result
    api.call = tamper
    if fault == 'genesis-state': api.commits[api.genesis]['value'] = g.reserve_transition(g.empty(), RUN, SOURCE, EXECUTION)
    with pytest.raises(g.Stop): ledger.read()


def test_bootstrap_is_create_only_no_update_ref():
    calls = []
    class ExistingBranch:
        def call(self, method, path, value):
            calls.append((method,path,value))
            if path.endswith('/git/trees'): return dict(sha='a'*40)
            if path.endswith('/git/commits'): return dict(sha='b'*40)
            raise g.Stop('HTTP_422')
    with pytest.raises(g.Stop): g.bootstrap(ExistingBranch())
    assert all(method == 'POST' for method,_,_ in calls)
    assert calls[-2][2]['parents'] == []
    assert calls[-1][2] == dict(ref='refs/heads/' + g.BRANCH,sha='b'*40)


def trusted_env():
    return dict(GITHUB_REPOSITORY=g.REPO,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/main',
        GITHUB_WORKFLOW_REF=g.REPO+'/.github/workflows/task4-github-ledger-research-v1.yml@refs/heads/main',
        GITHUB_SHA=SOURCE,LEDGER_ACK=g.ACK)


@pytest.mark.parametrize('field,value', [('GITHUB_REPOSITORY','other/repo'),('GITHUB_EVENT_NAME','pull_request'),
    ('GITHUB_REF','refs/heads/feature'),('GITHUB_WORKFLOW_REF','other'),('GITHUB_SHA','c'*40),('LEDGER_ACK','yes')])
def test_live_cli_rejects_untrusted_execution_before_api(field, value):
    env = trusted_env(); g.guard(env,SOURCE); env[field] = value
    with pytest.raises(g.Stop): g.guard(env,SOURCE)


@pytest.mark.parametrize('path', ['/repos/other/repo/git/refs','https://other.example/','/repos/'+g.REPO+'/../other',
                                  '/repos/'+g.REPO+'/git/refs?token=x'])
def test_transport_cannot_redirect_token_or_choose_another_target(path):
    api = g.API('synthetic')
    api.opener = SimpleNamespace(open=lambda *a,**k: pytest.fail('network'))
    with pytest.raises(g.Stop): api.call('POST',path,{})


def test_redirect_and_duplicate_json_stop():
    with pytest.raises(g.Stop): g.NoRedirect().redirect_request(None,None,None,None,None,None)
    with pytest.raises(g.Stop): g.decode(b'{"x":1,"x":2}')
    with pytest.raises(g.Stop): g.decode(b'{"x":NaN}')


@pytest.mark.parametrize('lost_ack', [False,True])
def test_complete_modeled_six_job_evidence_and_scope(store, tmp_path, lost_ack):
    api, ledger = store
    reports = {}
    def save(stage, value):
        report = dict(stage=stage,source_commit=SOURCE,execution_id=EXECUTION,run_id=RUN,genesis=api.genesis,
            scope=g.SCOPE,provider_dispatch='DENY',utility='UNSCORED',real_provider_posts=0,external_bank_effects=0,
            boot_id_sha256=g.sha(stage.encode()),source_sha256=g.sha(Path(g.__file__).read_bytes()),ledger_id=g.LEDGER_ID,
            native_integration_proven=False,signed_service_proven=False,production_bypass_resistance_proven=False,**value)
        reports[stage] = report
        (tmp_path/(stage+'.json')).write_bytes(g.canonical(report))
    save('reserve',g.run_stage('reserve',ledger,RUN,SOURCE,EXECUTION))
    h = api.head; api.writable = False
    save('observe',g.run_stage('observe',ledger,RUN,SOURCE,EXECUTION,h)); api.writable = True
    for candidate in ('1','2'):
        save('contend-'+candidate,g.run_stage('contend',ledger,RUN,SOURCE,EXECUTION,h,candidate,lost_ack))
    save('replay',g.run_stage('replay',ledger,RUN,SOURCE,EXECUTION))
    report = g.verify(ledger,RUN,SOURCE,EXECUTION,tmp_path,lost_ack,g.sha(b'verify'))
    assert report['synthetic_callbacks'] == (0 if lost_ack else 1)
    assert report['cross_runner_native_authority_proven'] is False
    reports['replay']['boot_id_sha256'] = reports['reserve']['boot_id_sha256']
    (tmp_path/'replay.json').write_bytes(g.canonical(reports['replay']))
    with pytest.raises(g.Stop,match='SIX_DISTINCT'): g.verify(ledger,RUN,SOURCE,EXECUTION,tmp_path,lost_ack,g.sha(b'verify'))


def test_manual_workflow_has_no_pr_trigger_or_native_write_token():
    yaml = pytest.importorskip('yaml')
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root/'.github/workflows/task4-github-ledger-research-v1.yml').read_text())
    trigger = workflow.get('on',workflow.get(True))
    assert set(trigger) == {'workflow_dispatch'} and workflow['permissions'] == {}
    jobs = workflow['jobs']
    assert jobs['observe']['permissions'] == jobs['verify']['permissions'] == {'contents':'read'}
    for name in ('bootstrap','reserve'):
        assert "github.ref == 'refs/heads/main'" in jobs[name]['if']
        assert "github.event_name == 'workflow_dispatch'" in jobs[name]['if']
    for job in jobs.values():
        for step in job['steps']:
            if step.get('uses','').startswith('actions/checkout@'):
                assert step['with'] == {'ref':'${{ github.sha }}','persist-credentials':False}
            if 'LEDGER_JOB_TOKEN' in step.get('env',{}):
                assert step['env']['LEDGER_JOB_TOKEN'] == '${{ github.token }}'
    assert jobs['contenders']['strategy']['matrix'] == {'candidate':['1','2']}
    old = yaml.safe_load((root/'.github/workflows/task4-native-frozen-recipient-offline.yml').read_text())
    assert old['permissions'] == {'contents':'read'}

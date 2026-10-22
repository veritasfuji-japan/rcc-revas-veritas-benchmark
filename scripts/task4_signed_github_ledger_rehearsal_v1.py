"""Memory Git API model + real loopback mTLS. No remote GitHub writes."""
import argparse
import base64
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_signed_github_ledger_v1 as signed
from scripts import task4_external_ledger_mtls_v1 as mtls
from scripts import task4_external_ledger_mtls_rehearsal_v1 as tls_demo
from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, canonical, sha


class ModelGitAPI:
    """Independent in-memory API model, not a persistence/deployment witness."""
    def __init__(self, signer):
        self.commits, self.calls, self.events = {}, [], []
        self.response_fault = None
        self.genesis = self.add(signed.empty(signer), None)

    def add(self, state, parent):
        oid = hashlib.sha1(canonical(state)+(parent or '').encode()+str(len(self.commits)).encode()).hexdigest()
        self.commits[oid] = dict(state=copy.deepcopy(state), parent=parent)
        self.head = oid
        self.events.append(('commit', oid))
        return oid

    def call(self, method, path, value=None):
        self.calls.append((method, path, copy.deepcopy(value)))
        if method == 'POST':
            assert path == '/graphql'
            v = value['variables']['input']
            fixture = json.loads((Path(__file__).resolve().parents[1]/'fixtures/task4_github_committable_branch_schema_v1.json').read_bytes())
            assert set(v['branch']) == set(fixture['client_form_fields'])
            assert v['branch'] == dict(repositoryNameWithOwner=signed.REPO, branchName=signed.BRANCH)
            if v['expectedHeadOid'] != self.head:
                return dict(errors=[dict(type='STALE_DATA')])
            addition, = v['fileChanges']['additions']
            assert addition['path'] == signed.FILE
            state = json.loads(base64.b64decode(addition['contents']))
            previous = self.head
            oid = self.add(state, previous)
            result = dict(data=dict(createCommitOnBranch=dict(clientMutationId=v['clientMutationId'],
                commit=dict(oid=oid, parents=dict(nodes=[dict(oid=previous)])),
                ref=dict(name=signed.BRANCH, target=dict(oid=oid)))))
            return self.response_fault(result) if self.response_fault else result
        prefix = '/repos/'+signed.REPO+'/'
        assert method == 'GET' and path.startswith(prefix)
        route = path[len(prefix):]
        if route == 'git/ref/heads/'+signed.BRANCH:
            return dict(ref='refs/heads/'+signed.BRANCH, object=dict(type='commit', sha=self.head))
        if route.startswith('git/commits/'):
            oid = route.rsplit('/', 1)[1]; row = self.commits[oid]
            return dict(sha=oid, tree=dict(sha=oid), parents=[] if row['parent'] is None else [dict(sha=row['parent'])])
        if route.startswith('git/trees/'):
            row = self.commits[route.rsplit('/', 1)[1]]; data = canonical(row['state'])
            blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            return dict(truncated=False, tree=[dict(path=signed.FILE, mode='100644', type='blob', sha=blob)])
        if route.startswith('git/blobs/'):
            blob = route.rsplit('/', 1)[1]
            for oid, row in self.commits.items():
                data = canonical(row['state'])
                if hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob:
                    self.events.append(('readback', oid))
                    return dict(encoding='base64', size=len(data), content=base64.b64encode(data).decode())
        if route.startswith('compare/'):
            genesis, oid = route.split('/')[-1].split('...'); count = 0
            while oid != genesis:
                count += 1; oid = self.commits[oid]['parent']
                assert count <= 544 and oid is not None
            return dict(status='ahead', merge_base_commit=dict(sha=genesis), total_commits=count)
        raise AssertionError(route)


class WitnessKey:
    def __init__(self, key, api):
        self.key, self.api, self.signatures = key, api, []

    def public_key(self):
        return self.key.public_key()

    def sign(self, encoded):
        self.api.events.append(('sign', self.api.head))
        self.signatures.append(encoded)
        return self.key.sign(encoded)


def setup(approved=None):
    key = Ed25519PrivateKey.generate()
    api = ModelGitAPI(sha(key.public_key().public_bytes_raw()))
    backend = signed.GitState(api, api.genesis, sha(key.public_key().public_bytes_raw()))
    witness = WitnessKey(key, api)
    service = signed.SignedGitHubService(backend, witness)
    b = copy.deepcopy(approved) if approved else dict(schema=signed.SCHEMA, ledger_id=signed.LEDGER_ID,
        run_id='a'*64, manifest_sha256=sha(b'synthetic manifest'), issuer_public_sha256='b'*64, custody_public_sha256='c'*64)
    b['ledger_id'] = signed.LEDGER_ID
    service.enroll(b)
    return api, backend, service, witness, b


@contextmanager
def connected(service, fixture):
    cfg, peers = mtls.load_configuration(fixture['root']/'configuration.json')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2; context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cfg['client_ca'])
    context.load_cert_chain(cfg['tls_certificate'], cfg['tls_key'])
    with mtls.listener(service, context, peers) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs=dict(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            yield dict(port=server.server_address[1])
        finally:
            server.shutdown();thread.join(5)
            assert not thread.is_alive()


def rehearsal():
    checks, issued, sent = {}, [], []
    request, grant = sha(b'synthetic request'), sha(b'synthetic grant')
    with tempfile.TemporaryDirectory(prefix='task4-signed-model-') as folder:
        fixture = tls_demo.provision(Path(folder)/'tls-fixtures')
        api, backend, service, witness, b = setup(fixture['binding'])
        def client(ready, role):
            return LedgerClient(b, witness.public_key().public_bytes_raw(), tls_demo.transport(fixture, ready, role))
        with connected(service, fixture) as ready:
            issuer, custody = client(ready, 'issuer'), client(ready, 'custody')
            issuer.gate('reserve', 'A0', request, lambda _: issued.append(1))
            custody.gate('consume', 'A0', request, lambda _: sent.append(1), grant)
            try:
                issuer.gate('consume', 'A0', request, lambda _: sent.append(1), grant)
            except Denied:
                checks['mtls_role_crossing_denied'] = True
            issuer.gate('reserve', 'B0', request, lambda _: None)
            # A view receipt is permitted; only the failed mutation must be unsigned.
            before = len(witness.signatures)
            def dropped(reply):
                raise TimeoutError('synthetic response lost after model commit')
            api.response_fault = dropped
            try:
                custody.gate('consume', 'B0', request, lambda _: sent.append(1), grant)
            except Denied:
                checks['uncertain_model_commit_has_no_mutation_signature'] = len(witness.signatures) == before+1
            api.response_fault = None
        reopened = signed.SignedGitHubService(signed.GitState(api, api.genesis, backend.signer), witness)
        with connected(reopened, fixture) as ready:
            custody = client(ready, 'custody')
            state = custody.exchange('view')
            try:
                custody.gate('consume', 'B0', request, lambda _: sent.append(1), grant)
            except Denied:
                checks['fresh_service_refuses_consumed_replay'] = True
        checks['two_consumed_slots'] = state['revision'] == 4 and all(r['state']=='CONSUMED_UNKNOWN' for r in state['attempts'])
        for index, (event, oid) in enumerate(api.events):
            if event == 'sign':
                assert ('readback', oid) in api.events[:index]
        checks['readback_precedes_signatures'] = True
        checks['one_issue_and_one_send_callback'] = len(issued) == len(sent) == 1
        checks['fixed_new_namespace_only'] = signed.BRANCH != 'research/task4-retained-ledger-v1'
    assert len(checks) == 7 and all(checks.values())
    return dict(schema='task4.signed-github-ledger-adapter-rehearsal.v1', scope='GITHUB_API_MODEL_WITH_REAL_LOOPBACK_MTLS',
        checks=checks, synthetic_issue_callbacks=len(issued), synthetic_send_callbacks=len(sent), final_revision=4,
        remote_github_experiment_executed=False, external_storage_deployed=False, cross_runner_retention_proven=False,
        native_integration_proven=False, independent_administration_proven=False, production_bypass_resistance_proven=False,
        real_provider_posts=0, external_bank_effects=0, provider_dispatch='DENY', utility='UNSCORED')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=rehearsal()
    report['audited_commit']=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    report['source_sha256']=sha(Path(__file__).with_name('task4_signed_github_ledger_v1.py').read_bytes())
    report['rehearsal_sha256']=sha(Path(__file__).read_bytes())
    args.output.mkdir(parents=True,exist_ok=True);(args.output/'report.json').write_bytes(canonical(report))
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    main()

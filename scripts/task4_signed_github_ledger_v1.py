"""Eight-slot #518 signed service over an injected GitHub API.

No default API, credential, bootstrap, CLI, deployed signer or Native integration.
The separate fixed namespace is a proposal, not a provisioned authority.
"""
import base64
import copy
import hashlib
import os

from scripts.task4_external_ledger_contract_v1 import (
    DOMAIN, SCHEMA, Denied, binding, canonical, command, digest, exact, hex64,
    need, sha, strict, validate_snapshot,
)
from scripts.task4_github_ledger_research_v1 import REPO, decode, hx

BRANCH = 'research/task4-signed-ledger-v1'
FILE = 'ledger.json'
STATE_SCHEMA = 'task4.github-signed-ledger-state.v1'
SCOPE = 'SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER'
BASE = '266f9add41daf94a778f247a6f3c0560318e2da2'
LEDGER_ID = sha((REPO + ':' + BRANCH + ':' + STATE_SCHEMA).encode())
MAX_RUNS, MAX_BLOB = 32, 65536
MUTATION_QUERY = '''mutation($input:CreateCommitOnBranchInput!) {
          createCommitOnBranch(input:$input) { clientMutationId
            commit { oid parents(first:2) { nodes { oid } } }
            ref { name target { oid } }
          }
        }'''


def empty(signer):
    need(hex64(signer), 'PINNED_SIGNER')
    return dict(schema=STATE_SCHEMA, ledger_id=LEDGER_ID, scope=SCOPE, reviewed_source_base=BASE,
                service_public_sha256=signer, revision=0, runs={})


def validate(value, signer):
    exact(value, 'schema ledger_id scope reviewed_source_base service_public_sha256 revision runs')
    fixed = empty(signer)
    need(all(value[k] == fixed[k] for k in fixed if k not in ('revision', 'runs')), 'FIXED_NAMESPACE_AND_SIGNER')
    need(type(value['runs']) is dict and len(value['runs']) <= MAX_RUNS, 'BOUNDED_REGISTRY')
    revisions = 0
    for run, row in value['runs'].items():
        exact(row, 'binding snapshot')
        b = binding(row['binding'])
        need(b['run_id'] == run and b['ledger_id'] == LEDGER_ID, 'EXACT_RUN_BINDING')
        revisions += validate_snapshot(row['snapshot'])['revision']
    need(type(value['revision']) is int and value['revision'] == len(value['runs']) + revisions, 'GLOBAL_REVISION')
    need(len(canonical(value)) <= MAX_BLOB, 'BOUNDED_REGISTRY_BYTES')
    return value


class GitState:
    """Whole-registry expected-head CAS. Trusted API/writers/admins; no retries."""
    def __init__(self, api=None, genesis=None, signer_sha256=None):
        need(api is not None and hx(genesis, 40) and hex64(signer_sha256), 'APPROVED_BACKEND_REQUIRED')
        self.api, self.genesis, self.signer = api, genesis, signer_sha256

    def get(self, path):
        return self.api.call('GET', '/repos/' + REPO + '/' + path)

    def document(self, oid):
        need(hx(oid, 40), 'COMMIT_OID')
        commit = self.get('git/commits/' + oid)
        need(commit['sha'] == oid and hx(commit['tree']['sha'], 40), 'EXACT_COMMIT')
        tree = self.get('git/trees/' + commit['tree']['sha'])
        need(tree.get('truncated') is False and len(tree['tree']) == 1, 'ONE_METADATA_FILE')
        entry = tree['tree'][0]
        need(entry['path'] == FILE and entry['mode'] == '100644' and entry['type'] == 'blob'
             and hx(entry['sha'], 40), 'EXACT_METADATA_FILE')
        blob = self.get('git/blobs/' + entry['sha'])
        need(blob['encoding'] == 'base64' and type(blob['size']) is int and 0 < blob['size'] <= MAX_BLOB,
             'BOUNDED_BLOB')
        data = base64.b64decode(''.join(blob['content'].split()), validate=True)
        need(len(data) == blob['size'] and
             hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == entry['sha'], 'BLOB_HASH')
        state = validate(decode(data), self.signer)
        parents = [p['sha'] for p in commit['parents']]
        need(canonical(state) == data and all(hx(p, 40) for p in parents), 'CANONICAL_STATE_AND_PARENTS')
        return state, parents

    def read(self):
        root, parents = self.document(self.genesis)
        need(root == empty(self.signer) and parents == [], 'APPROVED_EMPTY_ROOT')
        ref = self.get('git/ref/heads/' + BRANCH)
        need(ref['ref'] == 'refs/heads/' + BRANCH and ref['object']['type'] == 'commit', 'FIXED_STATE_REF')
        head = ref['object']['sha']
        state, _ = self.document(head)
        if head != self.genesis:
            relation = self.get('compare/' + self.genesis + '...' + head)
            need(relation['status'] == 'ahead' and relation['merge_base_commit']['sha'] == self.genesis
                 and 0 < relation['total_commits'] <= MAX_RUNS * 17, 'APPROVED_ANCESTRY')
        else:
            need(state == empty(self.signer), 'EMPTY_GENESIS')
        return head, state

    def mutate(self, previous, state):
        validate(state, self.signer)
        nonce = os.urandom(32).hex()
        need(hx(previous, 40), 'EXPECTED_HEAD')
        payload = dict(query=MUTATION_QUERY, variables=dict(input=dict(
            branch=dict(repositoryNameWithOwner=REPO, branchName=BRANCH), expectedHeadOid=previous,
            clientMutationId=nonce, message=dict(headline='Task4 synthetic signed-ledger transition ' + nonce),
            fileChanges=dict(additions=[dict(path=FILE, contents=base64.b64encode(canonical(state)).decode())]))))
        reply = self.api.call('POST', '/graphql', payload)
        need(type(reply) is dict and not reply.get('errors'), 'GITHUB_MUTATION_ERRORS_STOP')
        result = reply['data']['createCommitOnBranch']
        oid = result['commit']['oid']
        need(result['clientMutationId'] == nonce and hx(oid, 40)
             and [p['oid'] for p in result['commit']['parents']['nodes']] == [previous], 'EXACT_ACK')
        need(result['ref']['name'] == BRANCH and result['ref']['target']['oid'] == oid, 'EXACT_ACK_REF')
        observed, parents = self.document(oid)
        need(observed == state and parents == [previous], 'EXACT_COMMIT_READBACK_BEFORE_SIGNING')
        return oid


class SignedGitHubService:
    """#518 exchange interface. Peer must be supplied by an authenticated transport.

    Administrative enrollment is separate from the three-command client protocol.
    The private service signer is never serialized into backend state or replies.
    """
    def __init__(self, backend, key):
        need(sha(key.public_key().public_bytes_raw()) == backend.signer, 'REGISTERED_SIGNER')
        self.backend, self.key = backend, key

    def enroll(self, approved):
        approved = binding(copy.deepcopy(approved))
        need(approved['ledger_id'] == LEDGER_ID, 'EXACT_LEDGER')
        previous, state = self.backend.read()
        run = approved['run_id']
        need(run not in state['runs'] and len(state['runs']) < MAX_RUNS, 'DUPLICATE_OR_FULL_NO_RESET')
        state['runs'][run] = dict(binding=approved, snapshot=dict(revision=0, attempts=[]))
        state['revision'] += 1
        return self.backend.mutate(previous, state)

    def exchange(self, encoded, authenticated_peer):
        try:
            c = command(strict(encoded))
            previous, state = self.backend.read()
            rows = [r for r in state['runs'].values() if digest(r['binding']) == c['binding_sha256']]
            need(len(rows) == 1, 'UNKNOWN_BINDING')
            row = rows[0]; approved, snapshot = row['binding'], row['snapshot']
            need(authenticated_peer in (approved['issuer_public_sha256'], approved['custody_public_sha256']), 'AUTHENTICATED_PEER')
            action = c['action']
            if action != 'view':
                role = 'issuer' if action == 'reserve' else 'custody'
                need(authenticated_peer == approved[role+'_public_sha256'], 'ROLE_SEPARATION')
                need(c['expected_revision'] == snapshot['revision'], 'REVISION_CONFLICT_NO_RETRY')
                matches = [r for r in snapshot['attempts'] if r['operation_id'] == c['operation_id']]
                if action == 'reserve':
                    need(not matches, 'ALREADY_RESERVED_NO_REISSUE')
                    snapshot['attempts'].append(dict(operation_id=c['operation_id'], request_sha256=c['request_sha256'],
                                                   grant_sha256=None, state='RESERVED'))
                    snapshot['attempts'].sort(key=lambda r: r['operation_id'])
                else:
                    need(len(matches) == 1 and matches[0]['state'] == 'RESERVED'
                         and matches[0]['request_sha256'] == c['request_sha256'], 'CONSUMED_OR_REQUEST_MISMATCH')
                    matches[0].update(state='CONSUMED_UNKNOWN', grant_sha256=c['grant_sha256'])
                snapshot['revision'] += 1
                state['revision'] += 1
                self.backend.mutate(previous, state)  # Exact backend readback before signing.
            statement = dict(schema=SCHEMA, ledger_id=LEDGER_ID, binding_sha256=c['binding_sha256'],
                             command_sha256=sha(encoded), nonce=c['nonce'], action=action,
                             snapshot=copy.deepcopy(snapshot))
            return canonical(dict(statement=statement, signature=self.key.sign(DOMAIN+canonical(statement)).hex()))
        except Exception:
            # A failed response/readback may follow a successful commit. Never sign
            # an inferred result or retry a mutation; the caller receives no permission.
            raise Denied('SIGNED_GITHUB_EXCHANGE_STOP') from None

"""Manual, main-only GitHub metadata experiment. No Provider/Native capability.

GitHub, trusted workflow writers and repository administrators are trusted.
This is not the #518 signed service or an anti-rollback/production proof.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

REPO = 'veritasfuji-japan/rcc-revas-veritas-benchmark'
BRANCH = 'research/task4-retained-ledger-v1'
FILE = 'ledger.json'
BASE = '477a8040eda988698642e51c804f9e6fcedddd55'
SCHEMA = 'task4.github-metadata-ledger.v1'
SCOPE = 'SYNTHETIC_METADATA_ONLY_NO_PROVIDER'
ACK = 'SYNTHETIC_LEDGER_ONLY_NO_PROVIDER'
LIMIT = 1024 * 1024
MAX_RUNS = 32
LEDGER_ID = hashlib.sha256((REPO + ':' + BRANCH + ':' + SCHEMA).encode()).hexdigest()
REQUEST = hashlib.sha256(b'task4 fixed synthetic request; no SDK or Provider').hexdigest()
GRANT = hashlib.sha256(b'task4 fixed synthetic grant; no execution authority').hexdigest()


class Stop(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def exact(value, fields):
    need(type(value) is dict and set(value) == set(fields.split()), 'EXACT_FIELDS')


def decode(data):
    need(type(data) is bytes and len(data) <= LIMIT, 'BOUNDED_JSON')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_FIELD')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_JSON')))


def graphql_diagnostics(errors, token=''):
    """Bounded error fields only; never dump a response, variables or headers."""
    if type(errors) is not list:
        return [dict(type='MALFORMED_ERRORS', message='Error details omitted')]
    safe = []
    for error in errors[:3]:
        if type(error) is not dict:
            safe.append(dict(type='MALFORMED_ERROR', message='Error details omitted'))
            continue
        kind = error.get('type')
        if type(kind) is not str or re.fullmatch('[A-Z_]{1,64}', kind) is None:
            kind = 'UNTYPED_ERROR'
        message = error.get('message', '')
        if type(message) is not str:
            message = 'Error details omitted'
        if type(token) is str and token:
            message = message.replace(token, '[REDACTED]')
            if token in kind:
                kind = 'REDACTED_ERROR_TYPE'
        message = re.sub(r'\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]+', '[REDACTED]', message)
        message = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', message)[:384]
        safe.append(dict(type=kind, message=message))
    return safe


def empty():
    return dict(schema=SCHEMA, ledger_id=LEDGER_ID, scope=SCOPE, reviewed_source_base=BASE, revision=0, runs={})


def validate(value):
    exact(value, 'schema ledger_id scope reviewed_source_base revision runs')
    need(value['schema'] == SCHEMA and value['ledger_id'] == LEDGER_ID and value['scope'] == SCOPE
         and value['reviewed_source_base'] == BASE, 'FIXED_NAMESPACE_SCOPE')
    need(type(value['runs']) is dict and len(value['runs']) <= MAX_RUNS, 'BOUNDED_RUN_REGISTRY')
    consumed = 0
    for run, row in value['runs'].items():
        need(hx(run, 64), 'AUTHORIZATION_RUN_ID')
        exact(row, 'source_commit execution_id request_sha256 grant_sha256 state candidate')
        need(hx(row['source_commit'], 40) and type(row['execution_id']) is str
             and re.fullmatch('[1-9][0-9]{0,19}', row['execution_id']) is not None, 'TRUSTED_EXECUTION_IDENTITY')
        need(row['request_sha256'] == REQUEST and row['grant_sha256'] == GRANT, 'SYNTHETIC_DIGESTS_ONLY')
        need(row['state'] in ('RESERVED', 'CONSUMED_UNKNOWN'), 'MONOTONIC_STATE')
        need(row['candidate'] in ('1', '2') if row['state'] == 'CONSUMED_UNKNOWN' else row['candidate'] is None, 'WINNER_ID')
        consumed += row['state'] == 'CONSUMED_UNKNOWN'
    need(type(value['revision']) is int and value['revision'] == len(value['runs']) + consumed, 'EXACT_REVISION')
    return value


def reserve_transition(old, run, source, execution):
    validate(old)
    need(hx(run, 64) and hx(source, 40), 'PINNED_RUN_SOURCE')
    need(run not in old['runs'], 'DUPLICATE_RUN_NO_RESET')
    need(len(old['runs']) < MAX_RUNS, 'REGISTRY_FULL_STOP_NO_PRUNE')
    value = copy.deepcopy(old)
    value['runs'][run] = dict(source_commit=source, execution_id=execution,
        request_sha256=REQUEST, grant_sha256=GRANT, state='RESERVED', candidate=None)
    value['revision'] += 1
    return validate(value)


def consume_transition(old, run, source, execution, candidate):
    validate(old)
    need(run in old['runs'], 'UNKNOWN_RUN')
    row = old['runs'][run]
    need(row['source_commit'] == source and row['execution_id'] == execution, 'EXACT_ENROLLED_EXECUTION')
    need(row['state'] == 'RESERVED', 'ALREADY_CONSUMED_NO_RETRY')
    need(candidate in ('1', '2'), 'FIXED_CANDIDATE')
    value = copy.deepcopy(old)
    value['runs'][run].update(state='CONSUMED_UNKNOWN', candidate=candidate)
    value['revision'] += 1
    return validate(value)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Stop('REDIRECT_DENIED')


class API:
    def __init__(self, token):
        need(type(token) is str and bool(token), 'JOB_TOKEN_REQUIRED')
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, value=None):
        need(path == '/graphql' or path.startswith('/repos/' + REPO + '/'), 'FIXED_GITHUB_API')
        need('?' not in path and '#' not in path and '..' not in path.split('/'), 'NO_PATH_ESCAPE')
        request = urllib.request.Request('https://api.github.com' + path,
            data=None if value is None else canonical(value), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'Content-Type': 'application/json', 'X-GitHub-Api-Version': '2022-11-28',
                     'User-Agent': 'task4-synthetic-ledger-research-v1'})
        try:
            with self.opener.open(request, timeout=20) as response:
                return decode(response.read(LIMIT + 1))
        except urllib.error.HTTPError as error:
            # Never expose headers, request bodies, tokens, or raw server text.
            reason = 'HTTP_' + str(error.code)
            error.close()
            raise Stop(reason) from None


class Ledger:
    def __init__(self, api, genesis):
        need(hx(genesis, 40), 'APPROVED_GENESIS_REQUIRED')
        self.api, self.genesis = api, genesis

    def get(self, suffix):
        return self.api.call('GET', '/repos/' + REPO + '/' + suffix)

    def document(self, oid):
        need(hx(oid, 40), 'EXACT_COMMIT_OID')
        commit = self.get('git/commits/' + oid)
        need(commit['sha'] == oid and hx(commit['tree']['sha'], 40), 'EXACT_COMMIT')
        tree = self.get('git/trees/' + commit['tree']['sha'])
        need(tree.get('truncated') is False and len(tree['tree']) == 1, 'ONE_METADATA_FILE_ONLY')
        entry = tree['tree'][0]
        need(entry['path'] == FILE and entry['mode'] == '100644' and entry['type'] == 'blob'
             and hx(entry['sha'], 40), 'FIXED_METADATA_BLOB')
        blob = self.get('git/blobs/' + entry['sha'])
        need(blob['encoding'] == 'base64' and type(blob['size']) is int and 0 <= blob['size'] <= 65536, 'BOUNDED_STATE_BLOB')
        data = base64.b64decode(''.join(blob['content'].split()), validate=True)
        need(len(data) == blob['size'] and
             hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == entry['sha'], 'STATE_GIT_BLOB_HASH')
        value = validate(decode(data))
        need(canonical(value) == data, 'CANONICAL_STATE')
        return value, [p['sha'] for p in commit['parents']]

    def read(self, expected=None):
        genesis, parents = self.document(self.genesis)
        need(genesis == empty() and parents == [], 'APPROVED_EMPTY_ROOT_GENESIS')
        ref = self.get('git/ref/heads/' + BRANCH)
        need(ref['ref'] == 'refs/heads/' + BRANCH and ref['object']['type'] == 'commit', 'EXACT_RETAINED_BRANCH')
        head = ref['object']['sha']
        need(hx(head, 40) and (expected is None or head == expected), 'EXPECTED_HEAD_CHANGED_STOP')
        value, _ = self.document(head)
        if head != self.genesis:
            comparison = self.get('compare/' + self.genesis + '...' + head)
            need(comparison['status'] == 'ahead' and comparison['merge_base_commit']['sha'] == self.genesis
                 and 0 < comparison['total_commits'] <= 2 * MAX_RUNS, 'DESCENDANT_OF_APPROVED_GENESIS')
        else:
            need(value == empty(), 'EMPTY_GENESIS_ONLY')
        return head, value

    def mutate(self, expected, value, nonce, lose_ack=False):
        need(hx(expected, 40) and hx(nonce, 64), 'EXACT_MUTATION_IDENTITY')
        validate(value)
        query = '''mutation($input:CreateCommitOnBranchInput!) {
          createCommitOnBranch(input:$input) { clientMutationId
            commit { oid parents(first:2) { nodes { oid } } }
            ref { name target { oid } }
          }
        }'''
        variables = dict(input=dict(branch=dict(repositoryNameWithOwner=REPO, branchName=BRANCH),
            expectedHeadOid=expected, clientMutationId=nonce,
            message=dict(headline='Task4 synthetic metadata transition ' + nonce),
            fileChanges=dict(additions=[dict(path=FILE, contents=base64.b64encode(canonical(value)).decode())])))
        result = self.api.call('POST', '/graphql', dict(query=query, variables=variables))
        if result.get('errors'):
            details = graphql_diagnostics(result['errors'], getattr(self.api, 'token', ''))
            print(canonical(dict(event='TASK4_GRAPHQL_REJECTED', errors=details)).decode())
            types = [e['type'] for e in details]
            raise Stop('FORBIDDEN' if 'FORBIDDEN' in types else 'GRAPHQL_ERRORS_STOP')
        mutation = result.get('data', {}).get('createCommitOnBranch')
        need(type(mutation) is dict, 'PARTIAL_GRAPHQL_RESULT_STOP')
        if lose_ack:
            # Deliberate response-discard injection before acknowledgement
            # validation, not a claim that GitHub lost a network packet.
            raise Stop('ACK_DISCARDED_STOP')
        need(mutation['clientMutationId'] == nonce and
             [p['oid'] for p in mutation['commit']['parents']['nodes']] == [expected], 'EXACT_ACK_NONCE_PARENT')
        oid = mutation['commit']['oid']
        need(hx(oid, 40) and mutation['ref']['name'] == BRANCH and mutation['ref']['target']['oid'] == oid, 'EXACT_ACK_REF')
        observed, parents = self.document(oid)
        need(observed == value and parents == [expected], 'COMMITTED_EXACT_STATE_BEFORE_CALLBACK')
        return oid

    def gate(self, expected, old, new, effect, lose_ack=False):
        # This method never retries or refreshes a failed mutation.
        nonce = os.urandom(32).hex()
        receipt = self.mutate(expected, new, nonce, lose_ack)
        return receipt, effect()


def bootstrap(api):
    # Only the explicit administrative CLI mode can create the namespace.
    tree = api.call('POST', '/repos/' + REPO + '/git/trees',
        dict(tree=[dict(path=FILE, mode='100644', type='blob', content=canonical(empty()).decode())]))
    need(hx(tree['sha'], 40), 'BOOTSTRAP_TREE')
    commit = api.call('POST', '/repos/' + REPO + '/git/commits',
        dict(message='Task4 synthetic metadata ledger genesis; no Provider permission', tree=tree['sha'], parents=[]))
    need(hx(commit['sha'], 40), 'BOOTSTRAP_COMMIT')
    # Create-only, never update_ref/force, including after response loss. Existing
    # namespace creation fails; dangling objects do not authorize anything.
    ref = api.call('POST', '/repos/' + REPO + '/git/refs', dict(ref='refs/heads/' + BRANCH, sha=commit['sha']))
    need(ref['ref'] == 'refs/heads/' + BRANCH and ref['object']['sha'] == commit['sha'], 'BOOTSTRAP_ACK')
    ledger = Ledger(api, commit['sha']); ledger.read(expected=commit['sha'])
    return dict(genesis=commit['sha'], proposed_run_id=os.urandom(32).hex())


def guard(environ, head):
    need(environ.get('GITHUB_REPOSITORY') == REPO and environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and environ.get('GITHUB_REF') == 'refs/heads/main', 'MANUAL_MAIN_ONLY')
    need(environ.get('GITHUB_WORKFLOW_REF') == REPO + '/.github/workflows/task4-github-ledger-research-v1.yml@refs/heads/main',
         'TRUSTED_WORKFLOW_PATH')
    need(hx(head, 40) and head == environ.get('GITHUB_SHA'), 'EXACT_DISPATCH_SOURCE')
    need(environ.get('LEDGER_ACK') == ACK, 'EXPLICIT_SYNTHETIC_SCOPE')


def metadata(stage):
    return dict(schema=SCHEMA, stage=stage, source_commit=os.environ['GITHUB_SHA'],
        execution_id=os.environ['GITHUB_RUN_ID'], job=os.environ['GITHUB_JOB'],
        boot_id_sha256=sha(Path('/proc/sys/kernel/random/boot_id').read_bytes()),
        scope=SCOPE, ledger_id=LEDGER_ID, provider_dispatch='DENY', utility='UNSCORED',
        real_provider_posts=0, external_bank_effects=0, native_integration_proven=False,
        signed_service_proven=False, production_bypass_resistance_proven=False)


def run_stage(action, ledger, run, source, execution, expected=None, candidate=None, lose_ack=False):
    need(hx(run, 64), 'OWNER_APPROVED_RUN_ID')
    if action == 'reserve':
        head, old = ledger.read()
        new = reserve_transition(old, run, source, execution)
        oid, _ = ledger.gate(head, old, new, lambda: None)
        return dict(head=oid, previous=head, state_sha256=sha(canonical(new)), decision='RESERVED', effects=0)
    head, old = ledger.read(expected=expected if action == 'observe' else None)
    if action == 'contend':
        # Both jobs must submit the SAME pinned old head, even if the other
        # contender already won before this runner started. Do not refresh H.
        need(hx(expected, 40), 'PINNED_CONTENTION_HEAD')
        old, _ = ledger.document(expected)
        head = expected
    need(run in old['runs'] and old['runs'][run]['source_commit'] == source
         and old['runs'][run]['execution_id'] == execution, 'EXACT_RETAINED_RUN')
    if action == 'observe':
        need(old['runs'][run]['state'] == 'RESERVED', 'RESERVATION_VISIBLE_ON_NEW_RUNNER')
        try:
            ledger.mutate(head, old, os.urandom(32).hex())  # Same-state permission probe only.
        except Stop as error:
            need(str(error) in ('HTTP_403', 'FORBIDDEN'), 'READ_ONLY_DENIAL_MUST_BE_PERMISSION_ERROR')
            need(ledger.read(expected=head)[1] == old, 'READ_ONLY_PROBE_NO_CHANGE')
            return dict(head=head, state_sha256=sha(canonical(old)), decision='READ_ONLY_WRITE_DENIED', effects=0)
        raise Stop('READ_ONLY_TOKEN_CAN_WRITE_STOP')
    if action == 'contend':
        new = consume_transition(old, run, source, execution, candidate)
        try:
            oid, effect = ledger.gate(head, old, new, lambda: 1, lose_ack)
            return dict(head=oid, previous=head, decision='ACK_VERIFIED', candidate=candidate, effects=effect)
        except Exception as error:
            reason = str(error) if isinstance(error, Stop) else 'TRANSPORT_OR_PARSE_ERROR'
            return dict(head=None, previous=head, decision='STOP', candidate=candidate, effects=0, reason=reason)
    if action == 'replay':
        need(old['runs'][run]['state'] == 'CONSUMED_UNKNOWN', 'CONSUMPTION_VISIBLE_ON_FRESH_RUNNER')
        for transition in (lambda: reserve_transition(old, run, source, execution),
                           lambda: consume_transition(old, run, source, execution, '1')):
            try:
                transition()
            except Stop:
                continue
            raise Stop('REISSUE_OR_REPLAY_ACCEPTED')
        return dict(head=head, state_sha256=sha(canonical(old)), decision='REISSUE_AND_REPLAY_DENIED', effects=0)
    raise Stop('UNKNOWN_STAGE')


def verify(ledger, run, source, execution, folder, lose_ack, own_boot):
    reports = {stage: decode((folder / (stage + '.json')).read_bytes())
               for stage in ('reserve', 'observe', 'contend-1', 'contend-2', 'replay')}
    for stage, report in reports.items():
        need(report['source_commit'] == source and report['execution_id'] == execution
             and report['run_id'] == run and report['genesis'] == ledger.genesis
             and report['stage'] == stage and report['scope'] == SCOPE, 'SAME_EXPERIMENT_REPORTS')
        need(report['source_sha256'] == sha(Path(__file__).read_bytes()) and report['ledger_id'] == LEDGER_ID
             and hx(report['boot_id_sha256'], 64), 'EXACT_REVIEWED_SOURCE_AND_RUNNER_WITNESS')
        need(all(report[k] is False for k in ('native_integration_proven', 'signed_service_proven',
                                             'production_bypass_resistance_proven')), 'BOUNDED_METADATA_SCOPE')
        need(report['provider_dispatch'] == 'DENY' and report['utility'] == 'UNSCORED'
             and report['real_provider_posts'] == report['external_bank_effects'] == 0, 'NO_PROVIDER')
    need(len({r['boot_id_sha256'] for r in reports.values()} | {own_boot}) == 6, 'SIX_DISTINCT_RUNNER_BOOT_WITNESSES')
    need(reports['reserve']['decision'] == 'RESERVED' and reports['observe']['decision'] == 'READ_ONLY_WRITE_DENIED'
         and reports['observe']['head'] == reports['reserve']['head'], 'SEPARATE_READ_ONLY_WITNESS')
    contenders = [reports['contend-' + c] for c in ('1', '2')]
    need(all(r['previous'] == reports['observe']['head'] for r in contenders), 'SAME_EXPECTED_HEAD')
    head, state = ledger.read()
    row = state['runs'][run]
    need(row['source_commit'] == source and row['execution_id'] == execution and row['state'] == 'CONSUMED_UNKNOWN', 'ONE_RETAINED_CONSUMPTION')
    _, parents = ledger.document(head)
    need(parents == [reports['observe']['head']] and reports['replay']['head'] == head
         and reports['replay']['decision'] == 'REISSUE_AND_REPLAY_DENIED', 'NO_EXTRA_COMMIT_OR_REPLAY')
    winner = reports['contend-' + row['candidate']]
    loser = reports['contend-' + ('2' if row['candidate'] == '1' else '1')]
    need(loser['decision'] == 'STOP' and loser['effects'] == 0 and loser['reason'] == 'GRAPHQL_ERRORS_STOP', 'LOSER_SERVER_REJECTED')
    need(sum(r['effects'] for r in contenders) == (0 if lose_ack else 1), 'SYNTHETIC_CALLBACK_COUNT')
    if lose_ack:
        need(winner['decision'] == 'STOP' and winner['reason'] == 'ACK_DISCARDED_STOP', 'COMMITTED_ACK_DISCARDED_NO_CALLBACK')
    else:
        need(winner['decision'] == 'ACK_VERIFIED' and winner['head'] == head, 'ONE_VERIFIED_WINNER')
    return dict(head=head, winner=row['candidate'], synthetic_callbacks=0 if lose_ack else 1,
                six_runner_boot_witnesses=True, backend_metadata_checks_passed=True,
                cross_runner_native_authority_proven=False, independent_administration_proven=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('bootstrap', 'reserve', 'observe', 'contend', 'replay', 'verify'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    guard(os.environ, head)
    api = API(os.environ.get('LEDGER_JOB_TOKEN', ''))
    stage = args.action + ('-' + os.environ.get('LEDGER_CANDIDATE', '') if args.action == 'contend' else '')
    report = metadata(stage)
    if args.action == 'bootstrap':
        report.update(bootstrap(api))
    else:
        genesis = os.environ.get('LEDGER_GENESIS', '')
        run = os.environ.get('LEDGER_AUTHORIZATION_RUN_ID', '')
        ledger = Ledger(api, genesis)
        fault = os.environ.get('LEDGER_FAULT', '')
        need(fault in ('none', 'lost-ack'), 'EXPLICIT_FAULT_MODE')
        if args.action == 'verify':
            need(args.evidence is not None and hx(run, 64), 'COMPLETE_EVIDENCE_REQUIRED')
            report.update(verify(ledger, run, head, os.environ['GITHUB_RUN_ID'], args.evidence,
                                 fault == 'lost-ack', report['boot_id_sha256']))
        else:
            report.update(run_stage(args.action, ledger, run, head, os.environ['GITHUB_RUN_ID'],
                os.environ.get('LEDGER_EXPECTED_HEAD'), os.environ.get('LEDGER_CANDIDATE'), fault == 'lost-ack'))
        report.update(run_id=run, genesis=genesis)
    report['source_sha256'] = sha(Path(__file__).read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical(report))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('head=' + str(report.get('head', '')) + '\n')
    print(canonical(report).decode())


if __name__ == '__main__':
    main()

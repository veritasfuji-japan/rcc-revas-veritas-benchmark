"""Explicit create-only signed-ledger administration; no service/Provider startup."""
import argparse
import hashlib
import json
import os
import re
import sys

from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import Denied, binding, canonical, digest, exact, hex64, need, sha, strict
from scripts.task4_github_ledger_research_v1 import hx
from scripts.task4_signed_github_api_v1 import API, FixedHTTPS, PREFIX
from scripts.task4_signed_github_ledger_v1 import BRANCH, FILE, LEDGER_ID, GitState, SignedGitHubService, empty
from scripts.task4_signed_ledger_entrypoint_v1 import read_file, SCOPE

PROFILE = 'task4.signed-ledger-admin.v1'
STOP = 'SIGNED_LEDGER_ADMIN_STOP'
REF = 'refs/heads/' + BRANCH
MATCH = PREFIX + 'git/matching-refs/heads/' + BRANCH


def git_oid(kind, data):
    return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()


class BootstrapAPI(FixedHTTPS):
    """Separate create-only capability; not used by normal service construction.

    No update-ref, delete, CAS mutation, alternative branch or arbitrary content.
    Each POST phase is burned before connection, even if its response is lost.
    """
    def __init__(self, token, signer, approval):
        super().__init__(token)
        need(hex64(signer) and hex64(approval), 'PUBLIC_APPROVAL')
        self.signer, self.approval = signer, approval
        self.content = canonical(empty(signer))
        self.blob = git_oid('blob', self.content)
        self.tree = git_oid('tree', b'100644 '+FILE.encode()+b'\0'+bytes.fromhex(self.blob))
        self.message = 'Task4 synthetic signed-ledger genesis ' + approval
        self.sent, self.absent, self.tree_ready, self.root, self.verified = set(), False, False, None, False

    def _request(self, method, path, value):
        need(type(method) is str and type(path) is str, 'EXACT_REQUEST')
        if method == 'GET':
            need(value is None and (path in (MATCH, PREFIX+'git/ref/heads/'+BRANCH)
                or re.fullmatch(re.escape(PREFIX)+r'git/(commits|trees|blobs)/[0-9a-f]{40}', path)), 'BOOTSTRAP_READS')
            return path, None
        need(method == 'POST' and path not in self.sent, 'ONE_CREATE_ATTEMPT')
        if path == PREFIX+'git/trees':
            need(self.absent and value == dict(tree=[dict(path=FILE, mode='100644', type='blob',
                 content=self.content.decode())]), 'EXACT_EMPTY_TREE')
        elif path == PREFIX+'git/commits':
            need(self.tree_ready and value == dict(message=self.message, tree=self.tree, parents=[]), 'EXACT_PARENTLESS_ROOT')
        elif path == PREFIX+'git/refs':
            need(self.verified and value == dict(ref=REF, sha=self.root), 'VERIFIED_CREATE_ONLY_REF')
        else:
            raise Denied(STOP)
        self.sent.add(path)  # Before networking; no retry even when call raises.
        return path, canonical(value)

    def _status(self, method, path):
        return 201 if method == 'POST' else 200

    def _response(self, method, path, result):
        if path == MATCH:
            need(type(result) is list and len(result) <= 32, 'BOUNDED_MATCHES')
            seen = set()
            for row in result:
                need(type(row) is dict and type(row.get('ref')) is str and row['ref'].startswith(REF)
                     and row['ref'] not in seen and row['object']['type'] == 'commit'
                     and hx(row['object']['sha'], 40), 'EXACT_MATCH_RESPONSE')
                seen.add(row['ref'])
            self.absent = REF not in seen
            return dict(matches=result)
        result = super()._response(method, path, result)
        if method == 'POST' and path == PREFIX+'git/trees':
            need(result['sha'] == self.tree and result.get('truncated') is False and len(result['tree']) == 1,
                 'EXACT_TREE_ACK')
            row = result['tree'][0]
            need(all(row[k] == v for k, v in dict(path=FILE, mode='100644', type='blob', sha=self.blob).items()), 'EXACT_BLOB_ACK')
            self.tree_ready = True
        elif method == 'POST' and path == PREFIX+'git/commits':
            need(hx(result['sha'], 40) and result['tree']['sha'] == self.tree
                 and result['parents'] == [] and result['message'] == self.message, 'EXACT_ROOT_ACK')
            self.root = result['sha']
        elif method == 'POST' and path == PREFIX+'git/refs':
            need(result['ref'] == REF and result['object']['type'] == 'commit'
                 and result['object']['sha'] == self.root, 'EXACT_CREATE_ACK')
        return result

    def verify_root(self):
        state, parents = GitState(self, self.root, self.signer).document(self.root)
        need(state == empty(self.signer) and parents == [], 'EXACT_ROOT_READBACK')
        commit = self.call('GET', PREFIX+'git/commits/'+self.root)
        need(commit['message'] == self.message, 'APPROVAL_MESSAGE_READBACK')
        self.verified = True


def write_record(directory, name, value):
    with custody._directory(directory) as fd:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=fd)
        with os.fdopen(out, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        os.fsync(fd)


def begin_attempt(parent, action, cfg):
    name = 'bootstrap' if action == 'bootstrap' else 'enroll-'+cfg['binding']['run_id']
    with custody._directory(parent) as fd:
        os.mkdir(name, 0o700, dir_fd=fd)  # Existing/empty/partial attempt always blocks.
        os.fsync(fd)
    path = os.fspath(parent)+'/'+name
    write_record(path, 'attempt.json', dict(schema=PROFILE, action=action, scope=SCOPE,
        approval_id=cfg['approval_id'], configuration_sha256=sha(canonical(cfg))))
    return path


def prepare(configuration):
    cfg = strict(read_file(configuration, 8192))
    exact(cfg, 'schema scope receipt_directory public_pin_file token_file attempt_parent approval_id genesis binding')
    need(cfg['schema'] == PROFILE and cfg['scope'] == SCOPE and hex64(cfg['approval_id']), 'ADMIN_PROFILE')
    pin_raw = read_file(cfg['public_pin_file'], 65, public=True)
    need(re.fullmatch(b'[0-9a-f]{64}\n', pin_raw), 'EXTERNAL_PUBLIC_PIN')
    pin = pin_raw.decode().strip()
    key = custody.load(cfg['receipt_directory'], pin)
    need(cfg['attempt_parent'] != cfg['receipt_directory'] and
         not cfg['attempt_parent'].startswith(cfg['receipt_directory']+'/'), 'ATTEMPTS_OUTSIDE_RECEIPT_SLOT')
    # Validate the retained attempt parent without creating anything.
    with custody._directory(cfg['attempt_parent']): pass
    if cfg['genesis'] is None:
        need(cfg['binding'] is None, 'ROOT_BEFORE_ENROLLMENT')
    else:
        need(hx(cfg['genesis'], 40) and binding(cfg['binding'])['ledger_id'] == LEDGER_ID, 'APPROVED_ROOT_AND_BINDING')
        need(cfg['approval_id'] == cfg['binding']['run_id'], 'EXACT_ENROLLMENT_APPROVAL_ID')
    raw = read_file(cfg['token_file'], 256)
    need(re.fullmatch(b'[A-Za-z0-9_]{20,255}\n?', raw), 'PRIVATE_TOKEN')
    token = raw.decode().rstrip('\n')
    api = BootstrapAPI(token, pin, cfg['approval_id']) if cfg['genesis'] is None else API(token, cfg['genesis'], pin)
    return cfg, key, api, pin


def administer(action, configuration):
    """Caller must explicitly approve bootstrap/enroll. No automatic retry/reset."""
    try:
        cfg, key, api, pin = prepare(configuration)
        report = dict(schema=PROFILE, scope=SCOPE, action=action, public_key_sha256=pin,
                      approval_id=cfg['approval_id'], provider_dispatch='DENY', utility='UNSCORED')
        if action == 'check':
            return dict(report, backend_verified=False)
        if action == 'inspect':
            if cfg['genesis'] is None:
                matches = api.call('GET', MATCH)['matches']
                row = next((r for r in matches if r['ref'] == REF), None)
                return dict(report, observed_head=None if row is None else row['object']['sha'],
                            genesis_approved=False, backend_verified=False)
            head, state = GitState(api, cfg['genesis'], pin).read()
            row = state['runs'].get(cfg['binding']['run_id'])
            return dict(report, genesis=cfg['genesis'], observed_head=head, backend_verified=True,
                        exact_binding_registered=row is not None and row['binding'] == cfg['binding'],
                        revision=state['revision'])
        need(action in ('bootstrap', 'enroll') and (cfg['genesis'] is None) == (action == 'bootstrap'), 'EXACT_ADMIN_ACTION')
        attempt = begin_attempt(cfg['attempt_parent'], action, cfg)  # Fsync before any API call.
        if action == 'bootstrap':
            matches = api.call('GET', MATCH)['matches']
            need(not any(r['ref'] == REF for r in matches), 'EXISTING_NAMESPACE_STOP')
            api.call('POST', PREFIX+'git/trees', dict(tree=[dict(path=FILE, mode='100644', type='blob', content=api.content.decode())]))
            api.call('POST', PREFIX+'git/commits', dict(message=api.message, tree=api.tree, parents=[]))
            api.verify_root()  # Full canonical state/hash/parent/message before publication.
            api.call('POST', PREFIX+'git/refs', dict(ref=REF, sha=api.root))
            head, state = GitState(api, api.root, pin).read()
            need(head == api.root and state == empty(pin), 'EXACT_PUBLISHED_ROOT')
            report.update(genesis=api.root, owner_genesis_approval_required=True)
        else:
            backend = GitState(api, cfg['genesis'], pin)
            service = SignedGitHubService(backend, key)
            oid = service.enroll(cfg['binding'])  # Existing exact expected-head CAS/readback; no overwrite.
            report.update(genesis=cfg['genesis'], enrollment_commit=oid, binding_sha256=digest(cfg['binding']))
        write_record(attempt, 'result.json', report)  # No stdout success before local result retention.
        return report
    except Exception:
        raise Denied(STOP) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'inspect', 'bootstrap', 'enroll'))
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--acknowledge-synthetic-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        need(args.action in ('check', 'inspect') or args.acknowledge_synthetic_only, 'EXPLICIT_ADMIN_ACKNOWLEDGEMENT')
        print(json.dumps(administer(args.action, args.configuration), sort_keys=True), flush=True)
        return 0
    except KeyboardInterrupt:
        print(STOP, file=sys.stderr)
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

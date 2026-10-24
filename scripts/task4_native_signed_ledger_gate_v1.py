"""Durable intent + signed receipt gate for a future synthetic Native profile.

No CLI, enrollment/repair, default transport, key loader or Provider connector.
Not yet called by NativePolicy or Custody. Trusted admission/effect callbacks
are supplied by the future integration; this is not an untrusted-code sandbox.
"""
from contextlib import contextmanager
import copy
import os
import stat

from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import (
    LedgerClient, OPERATIONS, binding, canonical, digest, exact, hex64, need,
    sha, strict,
)

SCHEMA = 'task4.native-signed-ledger-gate.v1'
ENROLLMENT = 'task4.native-signed-ledger-gate-enrollment.v1'
SCOPE = 'SYNTHETIC_NATIVE_LEDGER_GATE_ONLY_NO_PROVIDER'
STOP = 'NATIVE_SIGNED_LEDGER_GATE_STOP'
ENROLLMENT_FILE = 'enrollment.json'
MAX_RECORD = 24000


class GateDenied(ValueError):
    pass


def _identity(path, info):
    return dict(path=path, device=info.st_dev, inode=info.st_ino,
                uid=info.st_uid, mode=stat.S_IMODE(info.st_mode))


def _read(fd, name, limit):
    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(file_fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
             and 0 < info.st_size <= limit, 'PRIVATE_SINGLE_LINK_RECORD')
        data = stream.read(limit + 1)
        need(len(data) == info.st_size, 'COMPLETE_RECORD')
        return data


def _write(fd, name, value):
    raw = canonical(value)
    need(0 < len(raw) <= MAX_RECORD, 'BOUNDED_RECORD')
    file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=fd)
    with os.fdopen(file_fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


class NativeLedgerGate:
    """Reopen one independently supplied enrollment; burn each attempt once.

    Enrollment/transport/admit/effect are trusted dependencies, never model
    inputs. Admission must perform the existing Native checks at BOTH calls,
    including signature/history/expiry/budget as applicable. This helper does
    not validate those policies or enforce what arbitrary callback code does.
    The role process, administrator, filesystem and enrolled signer are trusted.
    """
    def __init__(self, enrollment, service_public, transport=None):
        try:
            self._enrollment = strict(canonical(enrollment))
            e = self._enrollment
            exact(e, 'schema scope binding role service_public_sha256 journal')
            need(e['schema'] == ENROLLMENT and e['scope'] == SCOPE
                 and e['role'] in ('issuer', 'custody'), 'EXACT_ENROLLMENT')
            binding(e['binding'])
            exact(e['journal'], 'path device inode uid mode')
            j = e['journal']
            need(type(j['path']) is str and all(type(j[k]) is int and j[k] >= 0
                 for k in ('device', 'inode', 'uid', 'mode'))
                 and j['uid'] == os.geteuid() and j['mode'] == 0o700, 'PRIVATE_ENROLLED_JOURNAL')
            need(type(service_public) is bytes and len(service_public) == 32
                 and hex64(e['service_public_sha256'])
                 and sha(service_public) == e['service_public_sha256']
                 and e['service_public_sha256'] not in (e['binding']['issuer_public_sha256'],
                                                        e['binding']['custody_public_sha256']),
                 'PINNED_DISTINCT_SERVICE_PUBLIC_KEY')
            self._public, self._transport = service_public, transport
            with self._journal():
                pass
        except Exception:
            raise GateDenied(STOP) from None

    @contextmanager
    def _journal(self):
        e = self._enrollment
        with custody._directory(e['journal']['path']) as fd:
            need(_identity(e['journal']['path'], os.fstat(fd)) == e['journal'], 'JOURNAL_IDENTITY_CHANGED')
            need(_read(fd, ENROLLMENT_FILE, 8192) == canonical(e), 'ENROLLMENT_CHANGED')
            yield fd

    def execute(self, *, operation, wire, admit, effect, grant=None):
        """One attempt, one view and at most one mutation, then one callback.

        wire is the original bounded SDK body, not the manual synthetic label.
        consume commits to the complete already-verified grant's canonical hash.
        Any existing slot, even empty/partial, blocks before transport or effect.
        No permission/cached receipt is returned for subsequent reuse.
        """
        try:
            e = self._enrollment
            need(type(operation) is str and operation in OPERATIONS
                 and type(wire) is bytes and 0 < len(wire) <= 64000
                 and callable(admit) and callable(effect), 'BOUNDED_TRUSTED_INPUTS')
            action = 'reserve' if e['role'] == 'issuer' else 'consume'
            if action == 'reserve':
                need(grant is None, 'RESERVE_HAS_NO_GRANT')
                grant_sha = None
            else:
                # Shape/byte commitments only. The trusted admission callback
                # must verify the actual Native signature, context and history.
                exact(grant, 'statement signature')
                need(type(grant['statement']) is dict and type(grant['signature']) is str
                     and len(grant['signature']) == 128
                     and bytes.fromhex(grant['signature']).hex() == grant['signature'], 'GRANT_SHAPE')
                need(0 < len(canonical(grant)) <= 8192, 'BOUNDED_GRANT')
                s = grant['statement']
                need(s.get('schema') == 'task4.bounded-continuation-grant.v1'
                     and s.get('run_id') == e['binding']['run_id']
                     and s.get('manifest_sha256') == e['binding']['manifest_sha256']
                     and s.get('arm') in ('A', 'B') and type(s.get('ordinal')) is int
                     and 0 <= s['ordinal'] < 4 and s['arm'] + str(s['ordinal']) == operation
                     and s.get('request_sha256') == sha(wire), 'NATIVE_GRANT_REQUEST_JOIN')
                grant_sha = digest(grant)
            request_sha = sha(wire)
            need(admit() is None, 'ADMISSION_MUST_RETURN_NONE_OR_RAISE')
            need(grant is None or digest(grant) == grant_sha, 'GRANT_CHANGED_DURING_ADMISSION')
            with self._journal() as parent_fd:
                slot_name = e['binding']['run_id'] + '-' + action + '-' + operation
                os.mkdir(slot_name, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)  # Intent namespace durable before ANY exchange.
                slot_fd = os.open(slot_name, custody.DIR_FLAGS, dir_fd=parent_fd)
                try:
                    custody._private(os.fstat(slot_fd))
                    intent = dict(schema=SCHEMA, scope=SCOPE, role=e['role'], action=action,
                        run_id=e['binding']['run_id'], operation_id=operation,
                        binding_sha256=digest(e['binding']), request_sha256=request_sha,
                        grant_sha256=grant_sha, enrollment_sha256=digest(e),
                        provider_dispatch='DENY', utility='UNSCORED')
                    _write(slot_fd, 'intent.json', intent)
                    exchanges = []

                    def transport(encoded):
                        need(self._transport is not None, 'NO_TRANSPORT_NO_FALLBACK')
                        reply = self._transport(encoded)
                        # Store only protocol bytes, never SDK body/private grant.
                        exchanges.append(dict(command=strict(encoded), receipt=strict(reply)))
                        return reply

                    client = LedgerClient(copy.deepcopy(e['binding']), self._public, transport)
                    before = client.exchange('view')
                    snapshot = client.exchange(action, before['revision'], operation, request_sha, grant_sha)
                    # exchange has verified both exact signatures/nonces/states.
                    _write(slot_fd, 'verified-receipts.json', dict(
                        schema=SCHEMA, intent_sha256=digest(intent), exchanges=exchanges,
                        snapshot=snapshot, provider_dispatch='DENY', utility='UNSCORED'))
                    with self._journal() as current_fd:
                        need(os.stat(slot_name, dir_fd=current_fd, follow_symlinks=False).st_ino
                             == os.fstat(slot_fd).st_ino, 'ATTEMPT_IDENTITY_CHANGED')
                    need(admit() is None, 'ADMISSION_MUST_RETURN_NONE_OR_RAISE')
                    need(grant is None or digest(grant) == grant_sha, 'GRANT_CHANGED_DURING_ADMISSION')
                    result = effect(copy.deepcopy(snapshot))
                    # Failure here may follow a real callback: STOP is UNKNOWN,
                    # never evidence that effect did not run. Do not store result.
                    _write(slot_fd, 'effect-returned.json', dict(schema=SCHEMA,
                        intent_sha256=digest(intent), effect_returned=True,
                        provider_dispatch='DENY', utility='UNSCORED'))
                    return result
                finally:
                    os.close(slot_fd)
        except Exception:
            raise GateDenied(STOP) from None

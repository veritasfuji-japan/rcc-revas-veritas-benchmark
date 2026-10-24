"""Create-once role-local synthetic authority keys and bounded public exports.

No grant/receipt signing interface, TLS key/certificate generation, credential,
network, enrollment, service startup or execution permission. Same-UID/root
replacement and whole-filesystem rollback are outside the storage guarantee.
"""
import argparse
import os
from pathlib import Path
import stat
import sys

from scripts import task4_native_github_approval_preparation_v1 as preparation
from scripts import task4_receipt_key_custody_v1 as custody

PROFILE = 'task4.native-role-key-export.v1'
BUNDLE = 'task4.native-role-key-bundle.v1'
REPORT = 'task4.native-role-key-report.v1'
SCOPE = 'SYNTHETIC_NATIVE_KEY_PREPARATION_ONLY_NO_EXECUTION'
STOP = 'NATIVE_ROLE_KEYS_STOP'
ROLES = dict(ledger=61109, issuer=61105, custody=61106, runtime=61108)
BASE = Path('/var/lib')
SLOT = 'native-authority-v1'
RECORD = 'native-authority-public-v1.json'
need, exact, canonical, sha, digest = (
    preparation.need, preparation.exact, preparation.canonical, preparation.sha, preparation.digest)


def role_identity(role):
    need(role in ROLES and os.geteuid() == ROLES[role] and os.getegid() == ROLES[role]
         and set(os.getgroups()) <= {ROLES[role]}, 'EXACT_NONROOT_NATIVE_ROLE')
    return ROLES[role]


def parent(role):
    need(role in ROLES, 'FIXED_ROLE')
    return BASE / ('veritas-native-' + role)


def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, mode=stat.S_IMODE(info.st_mode))


def validate_export(record, role, run_id):
    exact(record, 'schema scope role uid algorithm run_id public_key_hex public_key_sha256 key_directory key_file')
    need(record['schema'] == PROFILE and record['scope'] == SCOPE and record['role'] == role
         and type(record['uid']) is int and record['uid'] == ROLES[role]
         and record['algorithm'] == 'Ed25519' and record['run_id'] == run_id
         and preparation.readiness.hex64(run_id) and run_id != preparation.MANUAL_RUN,
         'EXACT_ROLE_PUBLIC_EXPORT')
    need(preparation.readiness.hex64(record['public_key_hex'])
         and record['public_key_sha256'] == sha(bytes.fromhex(record['public_key_hex'])), 'EXACT_PUBLIC_PIN')
    for name, mode in (('key_directory', 0o700), ('key_file', 0o600)):
        item = record[name]
        exact(item, 'device inode uid mode')
        need(all(type(value) is int for value in item.values()) and item['device'] >= 0 and item['inode'] > 0
             and item['uid'] == ROLES[role] and item['mode'] == mode, 'EXACT_PUBLIC_STORAGE_IDENTITY')
    return record


def checked_storage(role, expected_public):
    """Load from held directory descriptors; private bytes never enter a report."""
    slot = parent(role) / SLOT
    with custody._directory(str(slot)) as fd:
        folder = identity(os.fstat(fd))
        before = identity(os.stat(custody.KEY_NAME, dir_fd=fd, follow_symlinks=False))
        key = custody._read_key(fd)  # Existing single-link, 0600, owned, exact-32-byte loader.
        public = custody.public_identity(key)
        after = identity(os.stat(custody.KEY_NAME, dir_fd=fd, follow_symlinks=False))
        need(before == after and public['public_key_sha256'] == expected_public, 'PINNED_STABLE_PRIVATE_KEY')
        return folder, before, public


def report(record, generated):
    return dict(schema=REPORT, scope=SCOPE, public_export=record, export_sha256=digest(record),
                key_generated=generated, private_key_in_output=False, network_used=False,
                execution_permission_issued=False, remote_enrollment_performed=False,
                operator_origin_independently_verified=False, provider_dispatch='DENY', utility='UNSCORED')


def inspect(role, run_id, public_pin, export_pin):
    role_identity(role)
    need(preparation.readiness.hex64(public_pin) and preparation.readiness.hex64(export_pin),
         'INDEPENDENT_PUBLIC_AND_EXPORT_PINS_REQUIRED')
    file = str(parent(role) / RECORD)
    raw = preparation.readiness.read_file(file, 8192)
    need(sha(raw) == export_pin, 'EXTERNALLY_PINNED_PUBLIC_EXPORT')
    record = validate_export(preparation.readiness.strict(raw), role, run_id)
    need(record['public_key_sha256'] == public_pin, 'EXTERNALLY_PINNED_ROLE_KEY')
    folder, key_file, public = checked_storage(role, public_pin)
    need(folder == record['key_directory'] and key_file == record['key_file']
         and public['public_key_hex'] == record['public_key_hex'], 'UNCHANGED_RETAINED_STORAGE')
    need(preparation.readiness.read_file(file, 8192) == raw, 'UNCHANGED_RETAINED_PUBLIC_EXPORT')
    return report(record, False)


def initialize(role, run_id, acknowledge=False):
    role_identity(role)
    need(acknowledge is True and preparation.readiness.hex64(run_id)
         and run_id != preparation.MANUAL_RUN, 'EXPLICIT_NEW_SYNTHETIC_KEY_PREPARATION')
    root = parent(role)
    # The existing trusted role parent must have been provisioned separately.
    with custody._directory(str(root)) as parent_fd:
        need(not os.path.lexists(root / RECORD), 'NO_EXISTING_PUBLIC_EXPORT')
        # Existing/empty/partial slot burns the attempt. This fsyncs the parent
        # after exclusive mkdir and BEFORE generating/writing the private key.
        public = custody.initialize(str(root / SLOT))
        folder, key_file, loaded = checked_storage(role, public['public_key_sha256'])
        need(loaded == public, 'NEW_KEY_READBACK')
        record = dict(schema=PROFILE, scope=SCOPE, role=role, uid=ROLES[role], algorithm='Ed25519',
                      run_id=run_id, public_key_hex=public['public_key_hex'],
                      public_key_sha256=public['public_key_sha256'], key_directory=folder, key_file=key_file)
        validate_export(record, role, run_id)
        fd = os.open(RECORD, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(record)); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent_fd)
    verified = inspect(role, run_id, record['public_key_sha256'], digest(record))
    return dict(verified, key_generated=True)


def validate_bundle(bundle):
    exact(bundle, 'schema scope run_id exports')
    need(bundle['schema'] == BUNDLE and bundle['scope'] == SCOPE
         and preparation.readiness.hex64(bundle['run_id']) and bundle['run_id'] != preparation.MANUAL_RUN,
         'EXACT_PUBLIC_ROLE_BUNDLE')
    exact(bundle['exports'], 'ledger issuer custody runtime')
    exports = {role: validate_export(bundle['exports'][role], role, bundle['run_id']) for role in ROLES}
    need(len({item['public_key_sha256'] for item in exports.values()}) == 4, 'FOUR_DISTINCT_APPLICATION_KEYS')
    # Inode numbers may coincide on different devices; paired identities cannot.
    for name in ('key_directory', 'key_file'):
        need(len({(item[name]['device'], item[name]['inode']) for item in exports.values()}) == 4,
             'DISTINCT_REPORTED_STORAGE')
    return exports


def read_bundle(path, expected):
    raw = preparation.read_document(path, expected)
    bundle = preparation.strict_public(raw)
    exports = validate_bundle(bundle)
    need(preparation.read_document(path, expected) == raw, 'UNCHANGED_PUBLIC_ROLE_BUNDLE')
    return bundle, exports


def public_report(bundle, exports, expected):
    keys = dict(service_public_hex=exports['ledger']['public_key_hex'],
                **{role + '_public_hex': exports[role]['public_key_hex'] for role in ('issuer', 'custody', 'runtime')})
    return dict(schema=REPORT, scope=SCOPE, run_id=bundle['run_id'], public_bundle_sha256=expected,
                public_keys=keys, export_sha256={role: digest(record) for role, record in exports.items()},
                roles=dict(ROLES), private_key_loaded=False, network_used=False,
                operator_origin_independently_verified=False, key_possession_independently_verified=False,
                existing_genesis_compatibility_verified=False,
                execution_permission_issued=False, remote_enrollment_performed=False,
                provider_dispatch='DENY', utility='UNSCORED')


def match_input(path, expected, bundle_path, bundle_expected):
    bundle, exports = read_bundle(bundle_path, bundle_expected)
    raw = preparation.read_document(path, expected)
    approval = preparation.approval_from(preparation.strict_public(raw))
    m = approval['native_manifest']
    need(approval['binding']['run_id'] == bundle['run_id'] and approval['roles'] == ROLES
         and approval['issuer_public_hex'] == exports['issuer']['public_key_hex']
         and approval['service_public_hex'] == exports['ledger']['public_key_hex']
         and m['custody_public'] == exports['custody']['public_key_hex']
         and m['runtime_public'] == exports['runtime']['public_key_hex'], 'EXACT_NATIVE_EXPORTED_ROLE_KEYS')
    need(preparation.read_document(path, expected) == raw and read_bundle(bundle_path, bundle_expected)[0] == bundle,
         'UNCHANGED_MATCHED_PUBLIC_INPUTS')
    return dict(public_report(bundle, exports, bundle_expected), public_input_sha256=expected,
                public_input_keys_match=True, approval_created=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('initialize', 'inspect'):
        command = sub.add_parser(action)
        command.add_argument('--role', choices=tuple(ROLES), required=True)
        command.add_argument('--run-id', required=True)
        if action == 'initialize':
            command.add_argument('--acknowledge-create-synthetic-key', action='store_true')
        else:
            command.add_argument('--expected-public-sha256', required=True)
            command.add_argument('--expected-export-sha256', required=True)
    verify = sub.add_parser('verify-public')
    verify.add_argument('--document', required=True)
    verify.add_argument('--expected-sha256', required=True)
    match = sub.add_parser('match-input')
    match.add_argument('--document', required=True)
    match.add_argument('--expected-sha256', required=True)
    match.add_argument('--public-bundle', required=True)
    match.add_argument('--expected-public-bundle-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'initialize':
            result = initialize(args.role, args.run_id, args.acknowledge_create_synthetic_key)
        elif args.action == 'inspect':
            result = inspect(args.role, args.run_id, args.expected_public_sha256, args.expected_export_sha256)
        elif args.action == 'verify-public':
            bundle, exports = read_bundle(args.document, args.expected_sha256)
            result = public_report(bundle, exports, args.expected_sha256)
        else:
            result = match_input(args.document, args.expected_sha256, args.public_bundle, args.expected_public_bundle_sha256)
        sys.stdout.buffer.write(canonical(result)); sys.stdout.buffer.flush()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

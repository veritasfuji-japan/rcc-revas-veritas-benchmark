"""Public-only retained signer/reader split for Native read-only preparation.

Keep UID 109's existing signer and genesis; UID 61109 is only the reader.
No private key/config/token access, key generation, migration, enrollment,
service startup, signing or execution permission is provided by this module.
"""
import argparse
import base64
import importlib
import os
from pathlib import Path
import stat
import sys

from scripts import task4_native_github_approval_preparation_v1 as preparation
from scripts import task4_native_github_readiness_v1 as readiness
from scripts import task4_native_role_keys_v1 as keys
from scripts.task4_signed_ledger_entrypoint_v1 import SCOPE as LEGACY_SCOPE
from scripts.task4_external_ledger_contract_v1 import binding

IDENTITY = 'task4.retained-service-public-identity.v1'
BUNDLE = 'task4.native-retained-signer-key-bundle.v1'
REPORT = 'task4.native-retained-signer-profile-report.v1'
LEGACY_APPROVAL = 'task4.signed-ledger-client-approval.v1'
STOP = 'NATIVE_RETAINED_SIGNER_PROFILE_STOP'
ROLES = dict(service=109, reader=61109, issuer=61105, custody=61106, runtime=61108)
NATIVE_ROLES = ('issuer', 'custody', 'runtime')
EXTRA_MODULES = ('task4_native_retained_signer_profile_v1',
                 'task4_native_github_approval_preparation_v1', 'task4_native_role_keys_v1')
COMMON_FIELDS = ('schema scope execution_source genesis binding native_manifest issuer_public_hex '
                 'service_public_hex source_sha256 roles tls')
need, exact, sha, digest, canonical = preparation.need, preparation.exact, preparation.sha, preparation.digest, preparation.canonical


def legacy_public(raw):
    """Validate public identity provenance, never reinterpret its old binding."""
    a = readiness.strict(raw)
    exact(a, 'schema scope execution_source genesis binding service_public_hex server_certificate_sha256 peers')
    need(a['schema'] == LEGACY_APPROVAL and a['scope'] == LEGACY_SCOPE
         and readiness.signed.hx(a['execution_source'], 40) and readiness.signed.hx(a['genesis'], 40)
         and readiness.hex64(a['service_public_hex']), 'EXACT_RETAINED_PUBLIC_APPROVAL')
    b = binding(a['binding'])
    need(b['ledger_id'] == readiness.signed.LEDGER_ID, 'SAME_EXISTING_LEDGER')
    exact(a['peers'], 'issuer custody')
    pins = [a['server_certificate_sha256']]
    for role in ('issuer', 'custody'):
        peer = a['peers'][role]
        exact(peer, 'certificate_sha256 authority_public_sha256')
        need(peer['authority_public_sha256'] == b[role + '_public_sha256'], 'EXACT_LEGACY_PEER_BINDING')
        pins.append(peer['certificate_sha256'])
    need(all(readiness.hex64(pin) for pin in pins) and len(set(pins)) == 3
         and sha(bytes.fromhex(a['service_public_hex'])) not in
         (b['issuer_public_sha256'], b['custody_public_sha256']), 'DISTINCT_RETAINED_PUBLIC_PINS')
    return a


def identity_from(raw, expected_genesis, expected_public):
    need(readiness.signed.hx(expected_genesis, 40) and readiness.hex64(expected_public),
         'SEPARATELY_REVIEWED_EXISTING_IDENTITY')
    a = legacy_public(raw)
    need(a['genesis'] == expected_genesis and sha(bytes.fromhex(a['service_public_hex'])) == expected_public,
         'UNCHANGED_EXISTING_GENESIS_AND_SIGNER')
    return dict(schema=IDENTITY, scope=readiness.SCOPE, service_uid=ROLES['service'],
                genesis=a['genesis'], service_public_hex=a['service_public_hex'],
                service_public_sha256=expected_public, legacy_run_id=a['binding']['run_id'],
                legacy_approval_sha256=sha(raw), legacy_approval_raw_base64=base64.b64encode(raw).decode('ascii'))


def validate_identity(record):
    exact(record, 'schema scope service_uid genesis service_public_hex service_public_sha256 legacy_run_id '
          'legacy_approval_sha256 legacy_approval_raw_base64')
    need(record['schema'] == IDENTITY and record['scope'] == readiness.SCOPE
         and type(record['service_uid']) is int and record['service_uid'] == ROLES['service']
         and type(record['legacy_approval_raw_base64']) is str
         and len(record['legacy_approval_raw_base64']) <= 11000, 'FIXED_RETAINED_SERVICE_IDENTITY')
    raw = base64.b64decode(record['legacy_approval_raw_base64'], validate=True)
    need(sha(raw) == record['legacy_approval_sha256']
         and record == identity_from(raw, record['genesis'], record['service_public_sha256']),
         'EXACT_RETAINED_PUBLIC_BYTES_AND_IDENTITY')
    return record


def read_identity(path, expected_sha, expected_genesis, expected_public):
    # This action reads ONLY an explicit root-owned public approval, not the old
    # private service configuration, key directory, private key or credential.
    need(readiness.hex64(expected_sha), 'EXPLICIT_PUBLIC_APPROVAL_DIGEST')
    raw = readiness.read_file(path, 8192, public=True)
    need(sha(raw) == expected_sha, 'EXACT_ROOT_PUBLIC_APPROVAL_BYTES')
    record = identity_from(raw, expected_genesis, expected_public)
    need(readiness.read_file(path, 8192, public=True) == raw, 'UNCHANGED_ROOT_PUBLIC_APPROVAL')
    return record


def extra_sources():
    result = {}
    for name in EXTRA_MODULES:
        path = Path(importlib.import_module('scripts.' + name).__file__)
        need(path.suffix == '.py', 'REVIEWED_PROFILE_SOURCE_REQUIRED')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 256000,
                 'BOUNDED_PROFILE_SOURCE')
            raw = stream.read(256001)
            need(len(raw) == info.st_size, 'COMPLETE_PROFILE_SOURCE')
            result[name] = sha(raw)
    return result


def validate_bundle(bundle):
    exact(bundle, 'schema scope run_id retained_service exports')
    need(bundle['schema'] == BUNDLE and bundle['scope'] == keys.SCOPE and readiness.hex64(bundle['run_id'])
         and bundle['run_id'] != preparation.MANUAL_RUN, 'EXACT_RETAINED_THREE_ROLE_BUNDLE')
    retained = validate_identity(bundle['retained_service'])
    need(bundle['run_id'] != retained['legacy_run_id'], 'NO_LEGACY_RUN_REINTERPRETATION')
    exact(bundle['exports'], 'issuer custody runtime')  # No new ledger key and no reader key.
    exports = {role: keys.validate_export(bundle['exports'][role], role, bundle['run_id']) for role in NATIVE_ROLES}
    need(len({retained['service_public_sha256']} |
             {record['public_key_sha256'] for record in exports.values()}) == 4, 'DISTINCT_RETAINED_AND_NATIVE_KEYS')
    for name in ('key_directory', 'key_file'):
        need(len({(record[name]['device'], record[name]['inode']) for record in exports.values()}) == 3,
             'DISTINCT_REPORTED_NATIVE_STORAGE')
    return retained, exports


def legacy_roles():
    # Internal common-validator input, never a deployment fallback or output.
    return {role: keys.ROLES[role] for role in ('ledger', 'issuer', 'custody', 'runtime')}


def validate_approval(a):
    exact(a, COMMON_FIELDS + ' retained_service native_key_bundle_sha256 profile_source_sha256')
    need(a['schema'] == readiness.RETAINED_APPROVAL and a['scope'] == readiness.SCOPE,
         'EXPLICIT_RETAINED_SIGNER_READ_ONLY_PROFILE')
    exact(a['roles'], 'service reader issuer custody runtime')
    need(all(type(value) is int for value in a['roles'].values()) and a['roles'] == ROLES,
         'FIXED_DISTINCT_SERVICE_READER_AND_NATIVE_UIDS')
    retained = validate_identity(a['retained_service'])
    need(a['genesis'] == retained['genesis'] and a['service_public_hex'] == retained['service_public_hex']
         and a['binding']['run_id'] != retained['legacy_run_id']
         and readiness.hex64(a['native_key_bundle_sha256']), 'RETAIN_EXISTING_SIGNER_NOT_OLD_RUN')
    need(type(a['profile_source_sha256']) is dict and a['profile_source_sha256'] == extra_sources(),
         'THREE_REVIEWED_PROFILE_SOURCE_FILES')
    common = {field: a[field] for field in COMMON_FIELDS.split()}
    common.update(schema=readiness.APPROVAL, roles=legacy_roles())
    readiness.validate_approval(common)  # Exact Native, key, TLS and original 11-source validation.
    need(len(canonical(a)) <= 8192, 'BOUNDED_RETAINED_APPROVAL')
    return a


def approval_from(public):
    fields = ('schema scope origin execution_source genesis native_manifest issuer_public_hex service_public_hex '
              'source_sha256 roles public_certificates native_key_bundle profile_source_sha256')
    exact(public, fields)
    need(public['schema'] == preparation.RETAINED_INPUT and public['scope'] == readiness.SCOPE
         and public['origin'] == preparation.ORIGIN and public['roles'] == ROLES
         and all(type(value) is int for value in public['roles'].values()), 'EXPLICIT_RETAINED_PUBLIC_PREPARATION')
    bundle = public['native_key_bundle']
    retained, exports = validate_bundle(bundle)
    m = public['native_manifest']
    need(public['genesis'] == retained['genesis'] and public['service_public_hex'] == retained['service_public_hex']
         and m['execution']['run_id'] == bundle['run_id']
         and public['issuer_public_hex'] == exports['issuer']['public_key_hex']
         and m['custody_public'] == exports['custody']['public_key_hex']
         and m['runtime_public'] == exports['runtime']['public_key_hex'], 'EXACT_RETAINED_AND_EXPORTED_NATIVE_INPUT')
    # Reuse the common Native/TLS validator with an explicit internal shape.
    common = {field: public[field] for field in fields.split()
              if field not in ('native_key_bundle', 'profile_source_sha256')}
    common.update(schema=preparation.INPUT, roles=legacy_roles())
    a = preparation.approval_from(common)
    a.update(schema=readiness.RETAINED_APPROVAL, roles=dict(ROLES), retained_service=retained,
             native_key_bundle_sha256=digest(bundle), profile_source_sha256=public['profile_source_sha256'])
    return validate_approval(a)


def bundle_report(bundle):
    retained, exports = validate_bundle(bundle)
    return dict(schema=REPORT, scope=readiness.SCOPE, roles=dict(ROLES), run_id=bundle['run_id'],
                retained_service_sha256=digest(retained), native_key_bundle_sha256=digest(bundle),
                genesis=retained['genesis'], service_public_sha256=retained['service_public_sha256'],
                native_export_sha256={role: digest(record) for role, record in exports.items()},
                retained_service_uid_observed=False, retained_private_key_loaded=False,
                key_pair_correspondence_verified=False, operator_origin_independently_verified=False,
                service_reconfigured=False, native_runtime_uid_enforcement_verified=False,
                network_used=False, credential_loaded=False, execution_permission_issued=False,
                remote_enrollment_performed=False, live_execution_ready=False,
                provider_dispatch='DENY', utility='UNSCORED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('source-manifest')
    identity = sub.add_parser('identity')
    identity.add_argument('--legacy-approval', required=True)
    identity.add_argument('--expected-sha256', required=True)
    identity.add_argument('--expected-genesis', required=True)
    identity.add_argument('--expected-public-sha256', required=True)
    verify = sub.add_parser('verify-public')
    verify.add_argument('--document', required=True)
    verify.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'source-manifest':
            result = dict(schema=REPORT, scope=readiness.SCOPE, roles=dict(ROLES),
                          source_sha256=readiness.source_manifest(), profile_source_sha256=extra_sources(),
                          network_used=False, approval_created=False, execution_permission_issued=False)
        elif args.action == 'identity':
            result = read_identity(args.legacy_approval, args.expected_sha256, args.expected_genesis,
                                   args.expected_public_sha256)
        else:
            raw = preparation.read_document(args.document, args.expected_sha256)
            bundle = preparation.strict_public(raw)
            result = bundle_report(bundle)
            need(preparation.read_document(args.document, args.expected_sha256) == raw, 'UNCHANGED_PUBLIC_BUNDLE')
        sys.stdout.buffer.write(canonical(result)); sys.stdout.buffer.flush()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

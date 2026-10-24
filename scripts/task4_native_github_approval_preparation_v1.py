"""Offline public-input candidate and explicit root read-only approval rendering.

No key generation/loading, token, network, enrollment, installation or execution.
Origin declarations and matching public bytes are not independent VM attestation.
"""
import argparse
import base64
from contextlib import ExitStack
import datetime
import json
import os
from pathlib import Path
import stat
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import task4_native_github_readiness_v1 as readiness
from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_mtls_v1 import SERVER_NAME

INPUT = 'task4.native-github-public-preparation.v1'
CANDIDATE = 'task4.native-github-approval-candidate.v1'
REVIEW = 'task4.native-github-approval-review.v1'
ORIGIN = 'OPERATOR_VM_PUBLIC_INPUTS_FOR_REVIEW'
STOP = 'NATIVE_GITHUB_APPROVAL_PREPARATION_STOP'
LIMIT = 131072
# The already consumed manual run must never become Native enrollment.
MANUAL_RUN = '546d9ab659e2fb54e3dcd20700ab6d8422e0b4d5ef81ef59a2ca622f91fad16c'
need, exact, sha, digest, canonical = (
    readiness.need, readiness.exact, readiness.sha, readiness.digest, readiness.canonical)


def read_document(path, expected):
    """Pinned no-follow public-input read; no search, repair or permissive paths."""
    need(readiness.hex64(expected), 'EXPLICIT_INDEPENDENTLY_REVIEWED_DIGEST')
    parts = custody._parts(path)
    with ExitStack() as stack:
        fd = os.open('/', custody.DIR_FLAGS)
        stack.callback(os.close, fd)
        for part in parts[:-1]:
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            need(info.st_uid in (0, os.geteuid()) and
                 (not info.st_mode & 0o022 or sticky), 'TRUSTED_ANCESTOR')
            fd = os.open(part, custody.DIR_FLAGS, dir_fd=fd)
            stack.callback(os.close, fd)
        parent = os.fstat(fd)
        need(parent.st_uid in (0, os.geteuid()) and not parent.st_mode & 0o022,
             'TRUSTED_INPUT_PARENT')
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        stack.callback(os.close, file_fd)
        info = os.fstat(file_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and info.st_uid in (0, os.geteuid()) and stat.S_IMODE(info.st_mode) in (0o600, 0o644)
             and 0 < info.st_size <= LIMIT, 'BOUNDED_PUBLIC_INPUT')
        raw = os.read(file_fd, LIMIT + 1)
        need(len(raw) == info.st_size and sha(raw) == expected, 'EXACT_REVIEWED_INPUT_BYTES')
    return raw


def source_sha256():
    # This one additional preparer is pinned separately from readiness's 11 files.
    path = Path(__file__).absolute()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and 0 < info.st_size <= LIMIT, 'BOUNDED_PREPARER_SOURCE')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == info.st_size, 'COMPLETE_PREPARER_SOURCE')
        return sha(raw)


def strict_public(raw):
    """Larger public bundle, duplicate/NaN refusal; digest pins exact formatting."""
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, 'BOUNDED_PUBLIC_JSON')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'DUPLICATE_PUBLIC_FIELD')
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    canonical(value)  # Reject NaN/Infinity, including values nested in unused fields.
    return value


def certificate(text):
    need(type(text) is str and 0 < len(text) <= 16384, 'BOUNDED_PUBLIC_CERTIFICATE')
    raw = text.encode('ascii')
    cert = x509.load_pem_x509_certificate(raw)
    need(cert.public_bytes(Encoding.PEM) == raw, 'ONE_CANONICAL_PUBLIC_CERTIFICATE_ONLY')
    now = datetime.datetime.now(datetime.timezone.utc)
    need(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'CURRENT_CERTIFICATE')
    # Unhandled critical extensions cannot silently acquire meaning here.
    allowed = {x509.BasicConstraints.oid, x509.KeyUsage.oid, x509.ExtendedKeyUsage.oid,
               x509.SubjectAlternativeName.oid, x509.SubjectKeyIdentifier.oid,
               x509.AuthorityKeyIdentifier.oid}
    need(all(not extension.critical or extension.oid in allowed for extension in cert.extensions),
         'REVIEWED_CRITICAL_EXTENSIONS_ONLY')
    return cert


def tls_plan(public_certificates, authority_publics):
    exact(public_certificates, 'ca server issuer custody')
    certs = {role: certificate(text) for role, text in public_certificates.items()}
    ca = certs['ca']
    need(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
         and ca.subject == ca.issuer, 'SELF_ISSUED_CA_REQUIRED')
    ca.verify_directly_issued_by(ca)
    ca_usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    need(ca_usage.key_cert_sign, 'CA_SIGNING_PURPOSE')
    fingerprints = {role: sha(cert.public_bytes(Encoding.DER)) for role, cert in certs.items()}
    tls_keys = []
    for role, cert in certs.items():
        public = cert.public_key()
        tls_keys.append(sha(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)))
        # Compare Ed25519 TLS public bytes to all application authority keys.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if isinstance(public, Ed25519PublicKey):
            need(public.public_bytes_raw().hex() not in authority_publics, 'DISTINCT_TLS_AUTHORITY_KEY')
        if role == 'ca':
            continue
        cert.verify_directly_issued_by(ca)
        need(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
             'LEAF_CERTIFICATE_REQUIRED')
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        expected = ExtendedKeyUsageOID.SERVER_AUTH if role == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH
        need(usage.digital_signature and not usage.key_cert_sign and not usage.crl_sign
             and set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == {expected},
             'EXACT_LEAF_PURPOSE')
        if role == 'server':
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            need(SERVER_NAME in names.get_values_for_type(x509.DNSName), 'FIXED_SERVER_NAME')
    need(len(set(tls_keys)) == len(set(fingerprints.values())) == 4, 'FOUR_DISTINCT_TLS_KEYS_AND_CERTIFICATES')
    return dict(transport='MTLS_OVER_AF_UNIX_WITH_SO_PEERCRED', ca_sha256=fingerprints['ca'],
                **{role + '_certificate_sha256': fingerprints[role] for role in ('server', 'issuer', 'custody')})


def approval_from(public):
    exact(public, 'schema scope origin execution_source genesis native_manifest issuer_public_hex '
          'service_public_hex source_sha256 roles public_certificates')
    need(public['schema'] == INPUT and public['scope'] == readiness.SCOPE
         and public['origin'] == ORIGIN, 'OPERATOR_PUBLIC_INPUT_TYPE_NOT_CI_OR_MANUAL')
    m = public['native_manifest']
    readiness.native.validate_manifest(m)
    issuer = public['issuer_public_hex']
    need(readiness.hex64(issuer) and readiness.hex64(public['service_public_hex']), 'PUBLIC_ROLE_KEYS')
    authorities = [issuer, public['service_public_hex'], m['custody_public'], m['runtime_public']]
    binding = dict(schema=readiness.signed.SCHEMA, ledger_id=readiness.signed.LEDGER_ID,
                   run_id=m['execution']['run_id'], manifest_sha256=digest(m),
                   issuer_public_sha256=sha(bytes.fromhex(issuer)),
                   custody_public_sha256=sha(bytes.fromhex(m['custody_public'])))
    approval = dict(schema=readiness.APPROVAL, scope=readiness.SCOPE,
                    **{key: public[key] for key in ('execution_source', 'genesis', 'native_manifest',
                       'issuer_public_hex', 'service_public_hex', 'source_sha256', 'roles')},
                    binding=binding, tls=tls_plan(public['public_certificates'], authorities))
    readiness.validate_approval(approval)
    need(len(canonical(approval)) <= 8192, 'READINESS_APPROVAL_SIZE_BOUND')
    return approval


def limitations():
    return dict(network_used=False, credential_loaded=False, private_key_loaded=False,
                approval_installed=False, remote_enrollment_performed=False,
                execution_permission_issued=False, live_execution_ready=False,
                operator_origin_independently_verified=False, role_key_possession_verified=False,
                operator_mtls_verified=False, os_egress_verified=False,
                production_bypass_resistance_proven=False,
                provider_dispatch='DENY', utility='UNSCORED')


def exclusions(values):
    need(type(values) is list and len(values) <= 64 and all(readiness.hex64(x) for x in values),
         'BOUNDED_PREVIOUS_RUN_EXCLUSIONS')
    return sorted(set(values + [MANUAL_RUN]))


def build(public_raw, excluded):
    need(type(public_raw) is bytes and 0 < len(public_raw) <= LIMIT, 'BOUNDED_PUBLIC_INPUT_BYTES')
    public = strict_public(public_raw)
    approval = approval_from(public)
    excluded = exclusions(excluded)
    need(approval['binding']['run_id'] not in excluded, 'NO_PREVIOUS_RUN_REUSE')
    result = dict(schema=CANDIDATE, scope=readiness.SCOPE, public_input_sha256=sha(public_raw),
                  public_input_raw_base64=base64.b64encode(public_raw).decode('ascii'),
                  excluded_run_ids=excluded, approval_candidate=approval,
                  preparer_source_sha256=source_sha256(), limitations=limitations())
    need(len(canonical(result)) <= LIMIT, 'BOUNDED_CANDIDATE')
    return result


def validate_candidate(candidate):
    exact(candidate, 'schema scope public_input_sha256 public_input_raw_base64 excluded_run_ids '
          'approval_candidate preparer_source_sha256 limitations')
    need(candidate['schema'] == CANDIDATE and candidate['scope'] == readiness.SCOPE,
         'CANDIDATE_NOT_AN_APPROVAL')
    # Recompute every derived field; never trust a supplied binding/TLS/source report.
    raw = base64.b64decode(candidate['public_input_raw_base64'], validate=True)
    need(sha(raw) == candidate['public_input_sha256'], 'EXACT_RETAINED_PUBLIC_INPUT_BYTES')
    expected = build(raw, candidate['excluded_run_ids'])
    need(candidate == expected, 'UNCHANGED_RECOMPUTED_CANDIDATE')
    return candidate['approval_candidate']


def run(action, path, expected, excluded=None, acknowledge=False):
    need(action in ('candidate', 'review', 'render-approval'), 'EXPLICIT_PREPARATION_ACTION')
    need(type(acknowledge) is bool, 'EXPLICIT_BOOLEAN_ACKNOWLEDGEMENT')
    if action == 'render-approval':
        need(os.geteuid() == 0 and acknowledge and excluded is None, 'ROOT_EXPLICIT_READ_ONLY_APPROVAL')
    else:
        need(not acknowledge and (action == 'candidate' or excluded is None), 'ACTION_ARGUMENTS')
    raw = read_document(path, expected)
    document = strict_public(raw)
    if action == 'candidate':
        result = build(raw, [] if excluded is None else excluded)
    else:
        approval = validate_candidate(document)
        if action == 'render-approval':
            result = approval  # stdout only; root must separately choose/create the public file.
        else:
            result = dict(schema=REVIEW, scope=readiness.SCOPE, candidate_sha256=expected,
                          approval_sha256=digest(approval), public_input_sha256=document['public_input_sha256'],
                          run_id=approval['binding']['run_id'], limitations=limitations(),
                          human_review_required=['operator-origin-and-key-custody', 'fresh-native-context',
                                                'public-key-and-certificate-exports', 'source-and-runtime',
                                                'genesis-and-service-pin', 'previous-run-exclusions'])
    # Detect replacement/withdrawal during validation; no retry or auto-resume.
    need(read_document(path, expected) == raw, 'UNCHANGED_PUBLIC_DOCUMENT')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('candidate', 'review', 'render-approval'))
    parser.add_argument('--document', required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--exclude-run-id', action='append')
    parser.add_argument('--acknowledge-read-only-approval', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = run(args.action, args.document, args.expected_sha256,
                     args.exclude_run_id, args.acknowledge_read_only_approval)
        # Existing readiness reads canonical bytes, without spaces or a final LF.
        sys.stdout.buffer.write(canonical(result))
        sys.stdout.buffer.flush()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Create-once synthetic preparation material; public joins, never execution.

Role-local TLS/recipient keys, a separate root CA, and explicit public assembly.
No existing authority key, credential, socket, trust-store edit or enrollment.
"""
import argparse
from contextlib import contextmanager
import datetime
import os
import stat
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts import task4_native_retained_signer_profile_v1 as profile

p, keys, r = profile.preparation, profile.keys, profile.readiness
need, exact, canonical, sha = p.need, p.exact, p.canonical, p.sha
SCOPE = 'SYNTHETIC_NATIVE_MATERIAL_PREPARATION_ONLY_NO_EXECUTION'
EXPORT = 'task4.native-preparation-material-export.v1'
MATERIALS = 'task4.native-preparation-materials.v1'
CERTIFICATES = 'task4.native-preparation-certificates.v1'
STOP = 'NATIVE_OPERATOR_MATERIALS_STOP'
# Fixed administrative layout, independent of the existing authority-key slots.
ROLES = dict(service=(109, 110, 'veritas-ledger'), issuer=(61105, 61105, 'veritas-native-issuer'),
             custody=(61106, 61106, 'veritas-native-custody'),
             backend=(61103, 61103, 'veritas-native-backend'),
             archive=(61107, 61107, 'veritas-native-archive'), ca=(0, 0, 'veritas-native-tls-ca'))
TLS_ROLES = ('service', 'issuer', 'custody', 'backend')
BASE = Path('/var/lib')
LIMIT = p.LIMIT


def role_identity(role):
    need(role in ROLES, 'FIXED_PREPARATION_ROLE')
    uid, gid, _ = ROLES[role]
    need(os.geteuid() == uid and os.getegid() == gid and set(os.getgroups()) <= {gid},
         'EXACT_PREPARATION_UID_GID_GROUPS')


def run_id(run):
    need(r.hex64(run) and run != p.MANUAL_RUN, 'EXPLICIT_NEW_RUN')


def home(role):
    return BASE / ROLES[role][2]


def slot(role, run):
    run_id(run)
    return home(role) / ('native-materials-v1-' + run)


@contextmanager
def claim(role, run):
    role_identity(role)
    target = slot(role, run)
    with keys.custody._directory(str(home(role))) as parent_fd:
        os.mkdir(target.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)  # Empty/partial/existing claims remain burned.
        with keys.custody._directory(str(target)) as fd:
            yield target, fd


def write(fd, name, data):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                  0o600, dir_fd=fd)
    with os.fdopen(out, 'wb') as stream:
        need(stream.write(data) == len(data), 'COMPLETE_WRITE')
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


def spki(public):
    return public.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)


def subject(role, run):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic-' + role),
                      x509.NameAttribute(NameOID.SERIAL_NUMBER, run)])


def hostname(role):
    return r.native.tls.NAME if role == 'backend' else p.SERVER_NAME


def csr(key, role, run):
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject(role, run))
    if role in ('service', 'backend'):
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname(role))]), False)
    return builder.sign(key, hashes.SHA256())


def checked_csr(text, role, run):
    need(role in TLS_ROLES and type(text) is str and len(text) <= 8192, 'BOUNDED_ROLE_CSR')
    value = x509.load_pem_x509_csr(text.encode('ascii'))
    public = value.public_key()
    need(value.public_bytes(ser.Encoding.PEM).decode('ascii') == text and value.is_signature_valid
         and isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256R1)
         and value.subject == subject(role, run), 'EXACT_ROLE_CSR')
    wanted = [] if role not in ('service', 'backend') else [x509.SubjectAlternativeName.oid]
    need([item.oid for item in value.extensions] == wanted, 'NO_UNREVIEWED_CSR_EXTENSIONS')
    if wanted:
        need(value.extensions[0].value == x509.SubjectAlternativeName([x509.DNSName(hostname(role))])
             and not value.extensions[0].critical, 'EXACT_LOCAL_HOSTNAME')
    return value


def validate_export(record, role, run):
    exact(record, 'schema scope role uid run_id algorithm public csr key_directory key_file')
    need(record['schema'] == EXPORT and record['scope'] == SCOPE and record['role'] == role
         and role in (*TLS_ROLES, 'archive') and type(record['uid']) is int
         and record['uid'] == ROLES[role][0] and record['run_id'] == run, 'EXACT_MATERIAL_EXPORT')
    run_id(run)
    if role == 'archive':
        need(record['algorithm'] == 'X25519' and r.hex64(record['public']) and record['csr'] is None,
             'PUBLIC_ARCHIVE_RECIPIENT')
        x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(record['public']))
    else:
        request = checked_csr(record['csr'], role, run)
        need(record['algorithm'] == 'EC_P256_TLS' and record['public'] == sha(spki(request.public_key())),
             'CSR_PUBLIC_KEY_JOIN')
    for name, mode in (('key_directory', 0o700), ('key_file', 0o600)):
        row = record[name]
        exact(row, 'device inode uid mode')
        need(all(type(v) is int for v in row.values()) and row['device'] >= 0 and row['inode'] > 0
             and row['uid'] == ROLES[role][0] and row['mode'] == mode, 'EXACT_REPORTED_MATERIAL_STORAGE')
    return record


def private(path):
    raw = r.read_file(str(path), 8192)
    key = ser.load_pem_private_key(raw, password=None)
    need(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1), 'FIXED_TLS_KEY')
    return key


def inspect(role, run, expected):
    role_identity(role)
    need(role in (*TLS_ROLES, 'archive') and r.hex64(expected), 'EXPLICIT_ROLE_EXPORT_PIN')
    target = slot(role, run)
    raw = r.read_file(str(target / 'public.json'), 16384)
    need(sha(raw) == expected, 'RETAINED_MATERIAL_EXPORT_PIN')
    record = validate_export(p.strict_public(raw), role, run)
    with keys.custody._directory(str(target)) as fd:
        need(set(os.listdir(fd)) in ({'private.key', 'public.json'}, {'private.key', 'public.json', 'certificate.pem'}),
             'EXACT_MATERIAL_SLOT')
        folder = keys.identity(os.fstat(fd))
        info = os.stat('private.key', dir_fd=fd, follow_symlinks=False)
        if role == 'archive':
            data = r.read_file(str(target / 'private.key'), 32)
            need(len(data) == 32, 'EXACT_ARCHIVE_PRIVATE_SIZE')
            public = x25519.X25519PrivateKey.from_private_bytes(data).public_key().public_bytes_raw().hex()
        else:
            public = sha(spki(private(target / 'private.key').public_key()))
        need(folder == record['key_directory'] and keys.identity(info) == record['key_file']
             and public == record['public'], 'RETAINED_MATERIAL_PRIVATE_PUBLIC_JOIN')
    need(r.read_file(str(target / 'public.json'), 16384) == raw, 'UNCHANGED_PUBLIC_RECORD')
    return record


def initialize(role, run, acknowledge=False):
    need(role in (*TLS_ROLES, 'archive') and acknowledge is True, 'EXPLICIT_CREATE_MATERIAL_ONLY')
    with claim(role, run) as (target, fd):
        if role == 'archive':
            key = x25519.X25519PrivateKey.generate()
            raw = key.private_bytes_raw()
            public, request, algorithm = key.public_key().public_bytes_raw().hex(), None, 'X25519'
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            raw = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
            public = sha(spki(key.public_key()))
            request, algorithm = csr(key, role, run).public_bytes(ser.Encoding.PEM).decode('ascii'), 'EC_P256_TLS'
        write(fd, 'private.key', raw)
        record = dict(schema=EXPORT, scope=SCOPE, role=role, uid=ROLES[role][0], run_id=run,
                      algorithm=algorithm, public=public, csr=request,
                      key_directory=keys.identity(os.fstat(fd)),
                      key_file=keys.identity(os.stat('private.key', dir_fd=fd, follow_symlinks=False)))
        validate_export(record, role, run)
        write(fd, 'public.json', canonical(record))
    need(inspect(role, run, sha(canonical(record))) == record, 'CREATED_MATERIAL_READBACK')
    return record


def validate_materials(value):
    exact(value, 'schema scope run_id exports')
    run = value['run_id']
    run_id(run)
    need(value['schema'] == MATERIALS and value['scope'] == SCOPE, 'MATERIALS_NOT_PERMISSION')
    exact(value['exports'], 'service issuer custody backend archive')
    exports = {role: validate_export(value['exports'][role], role, run) for role in (*TLS_ROLES, 'archive')}
    need(len({exports[role]['public'] for role in TLS_ROLES}) == 4, 'DISTINCT_TLS_KEYS')
    for name in ('key_directory', 'key_file'):
        need(len({(item[name]['device'], item[name]['inode']) for item in exports.values()}) == 5,
             'DISTINCT_ROLE_MATERIAL_STORAGE')
    return exports


def issue_certificate(public, name, ca, ca_key, now, role=None):
    is_ca = role is None
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name if is_ca else ca.subject)
        .public_key(public).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=60))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
            encipher_only=False, decipher_only=False), True))
    if not is_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if role in ('service', 'backend') else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        if role in ('service', 'backend'):
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname(role))]), False)
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(ser.Encoding.PEM).decode('ascii')


def issue_ca(materials, acknowledge=False):
    role_identity('ca')
    need(acknowledge is True, 'EXPLICIT_SYNTHETIC_CA_ONLY')
    exports = validate_materials(materials)
    run = materials['run_id']
    with claim('ca', run) as (target, fd):
        key = ec.generate_private_key(ec.SECP256R1())
        write(fd, 'private.key', key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_pem = issue_certificate(key.public_key(), subject('ca', run), None, key, now)
        ca = p.certificate(ca_pem)
        certs = {'ca': ca_pem}
        for role in TLS_ROLES:
            request = checked_csr(exports[role]['csr'], role, run)
            certs[role] = issue_certificate(request.public_key(), request.subject, ca, key, now, role)
        result = dict(schema=CERTIFICATES, scope=SCOPE, run_id=run, materials_sha256=sha(canonical(materials)),
                      certificates=certs)
        validate_certificates(result, materials)
        write(fd, 'public.json', canonical(result))
        need(r.read_file(str(target / 'public.json'), 32768) == canonical(result)
             and spki(private(target / 'private.key').public_key()) == spki(ca.public_key()), 'CA_READBACK')
    return result


def validate_certificates(value, materials):
    exports = validate_materials(materials)
    exact(value, 'schema scope run_id materials_sha256 certificates')
    need(value['schema'] == CERTIFICATES and value['scope'] == SCOPE and value['run_id'] == materials['run_id']
         and value['materials_sha256'] == sha(canonical(materials)), 'CERTIFICATE_MATERIALS_JOIN')
    exact(value['certificates'], 'ca service issuer custody backend')
    certs = {role: p.certificate(text) for role, text in value['certificates'].items()}
    p.tls_plan(dict(ca=value['certificates']['ca'], server=value['certificates']['service'],
                   issuer=value['certificates']['issuer'], custody=value['certificates']['custody']), [])
    for role in TLS_ROLES:
        request = checked_csr(exports[role]['csr'], role, value['run_id'])
        need(certs[role].subject == request.subject and spki(certs[role].public_key()) == spki(request.public_key()),
             'EXACT_CERTIFICATE_CSR_KEY')
        certs[role].verify_directly_issued_by(certs['ca'])
    backend = certs['backend']
    need(not backend.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
         and backend.extensions.get_extension_for_class(x509.SubjectAlternativeName).value ==
             x509.SubjectAlternativeName([x509.DNSName(hostname('backend'))])
         and set(backend.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) ==
             {ExtendedKeyUsageOID.SERVER_AUTH}, 'LOCAL_BACKEND_LEAF_ONLY')
    usage = backend.extensions.get_extension_for_class(x509.KeyUsage).value
    need(usage.digital_signature and not usage.key_cert_sign and not usage.crl_sign, 'BACKEND_TLS_PURPOSE')
    need(len({sha(spki(cert.public_key())) for cert in certs.values()}) == 5, 'FIVE_DISTINCT_TLS_KEYS')
    return certs


def install_certificate(role, run, expected_export, materials, certificates):
    need(role in TLS_ROLES, 'TLS_LEAF_ROLE_ONLY')
    record = inspect(role, run, expected_export)
    validate_certificates(certificates, materials)
    need(materials['run_id'] == run and materials['exports'][role] == record, 'OWN_CSR_CERTIFICATE_JOIN')
    target = slot(role, run)
    raw = certificates['certificates'][role].encode('ascii')
    with keys.custody._directory(str(target)) as fd:
        write(fd, 'certificate.pem', raw)
    need(r.read_file(str(target / 'certificate.pem'), 16384) == raw, 'INSTALLED_CERTIFICATE_READBACK')
    return dict(certificate_sha256=sha(p.certificate(raw.decode('ascii')).public_bytes(ser.Encoding.DER)))


def assemble(bundle, materials, certificates, execution_source, not_before, expires_at):
    # Public assembly under the reader; no private material/credential is opened.
    keys.role_identity('ledger')
    retained, exports = profile.validate_bundle(bundle)
    certs = validate_certificates(certificates, materials)
    need(materials['run_id'] == bundle['run_id'] and r.signed.hx(execution_source, 40), 'REVIEWED_NEW_RUN_SOURCE')
    context = dict(schema=r.native.authority.SCHEMA, run_id=bundle['run_id'],
        raw_recipient_sha256=sha(bytes.fromhex(materials['exports']['archive']['public'])),
        local_leaf_sha256=sha(certs['backend'].public_bytes(ser.Encoding.DER)), not_before=not_before,
        expires_at=expires_at, endpoint=r.native.raw.URL, permission='CLOSED_LOCAL_SCRIPTED_ONLY')
    r.native.authority.shape(context)
    # Explicit window is retained verbatim. Expired/future preparation is never
    # extended silently; this is still only a read-only diagnostic candidate.
    native = r.native.manifest(context, exports['custody']['public_key_hex'], exports['runtime']['public_key_hex'])
    public = dict(schema=p.RETAINED_INPUT, scope=r.SCOPE, origin=p.ORIGIN, execution_source=execution_source,
        genesis=retained['genesis'], native_manifest=native, issuer_public_hex=exports['issuer']['public_key_hex'],
        service_public_hex=retained['service_public_hex'], source_sha256=r.source_manifest(),
        roles=dict(profile.ROLES), public_certificates=dict(ca=certificates['certificates']['ca'],
            server=certificates['certificates']['service'], issuer=certificates['certificates']['issuer'],
            custody=certificates['certificates']['custody']), native_key_bundle=bundle,
        profile_source_sha256=profile.extra_sources())
    p.approval_from(public)
    return public


def document(path, expected):
    raw = p.read_document(path, expected)
    value = p.strict_public(raw)
    need(p.read_document(path, expected) == raw, 'UNCHANGED_PINNED_PUBLIC_INPUT')
    return value


def source_sha256():
    fd = os.open(Path(__file__).absolute(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= LIMIT,
             'BOUNDED_PRODUCER_SOURCE')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == info.st_size, 'COMPLETE_PRODUCER_SOURCE')
    return sha(raw)


def report(action, value):
    return dict(schema='task4.native-material-preparation-report.v1', scope=SCOPE, action=action,
        public_record=value, public_record_sha256=sha(canonical(value)), producer_source_sha256=source_sha256(),
        new_private_key_generated=action in ('initialize', 'issue-ca'),
        role_certificate_saved=action == 'install-certificate',
        network_used=False, credential_loaded=False, existing_authority_private_key_loaded=False,
        trust_store_modified=False, service_reconfigured=False, remote_enrollment_performed=False,
        execution_permission_issued=False, operator_origin_independently_verified=False,
        operator_mtls_verified=False, native_runtime_profile_applied=False,
        provider_dispatch='DENY', utility='UNSCORED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('initialize', 'inspect', 'issue-ca', 'install-certificate', 'assemble'))
    parser.add_argument('--role', choices=tuple(ROLES))
    parser.add_argument('--run-id')
    parser.add_argument('--expected-export-sha256')
    for name in ('materials', 'certificates', 'public-bundle'):
        parser.add_argument('--' + name)
        parser.add_argument('--expected-' + name + '-sha256')
    parser.add_argument('--execution-source')
    parser.add_argument('--not-before', type=int)
    parser.add_argument('--expires-at', type=int)
    parser.add_argument('--acknowledge-create-synthetic-material', action='store_true')
    args = parser.parse_args(argv)
    try:
        action = args.action
        # Refuse irrelevant options, rather than silently discarding intent.
        supplied = {k for k, v in vars(args).items() if k != 'action' and v is not None and v is not False}
        common = {'role', 'run_id'}
        documents = lambda name: {name, 'expected_' + name + '_sha256'}
        allowed = {
            'initialize': common | {'acknowledge_create_synthetic_material'},
            'inspect': common | {'expected_export_sha256'},
            'issue-ca': documents('materials') | {'acknowledge_create_synthetic_material'},
            'install-certificate': common | {'expected_export_sha256'} | documents('materials') | documents('certificates'),
            'assemble': documents('materials') | documents('certificates') | documents('public_bundle') |
                        {'execution_source', 'not_before', 'expires_at'},
        }[action]
        need(supplied == allowed, 'EXACT_ACTION_ARGUMENTS')
        if action == 'initialize':
            value = initialize(args.role, args.run_id, args.acknowledge_create_synthetic_material)
        elif action == 'inspect':
            value = inspect(args.role, args.run_id, args.expected_export_sha256)
        elif action == 'issue-ca':
            role_identity('ca')  # Wrong account stops before public-input reads.
            value = issue_ca(document(args.materials, args.expected_materials_sha256), True)
        elif action == 'install-certificate':
            role_identity(args.role)
            value = install_certificate(args.role, args.run_id, args.expected_export_sha256,
                document(args.materials, args.expected_materials_sha256),
                document(args.certificates, args.expected_certificates_sha256))
        else:
            keys.role_identity('ledger')
            value = assemble(document(args.public_bundle, args.expected_public_bundle_sha256),
                document(args.materials, args.expected_materials_sha256),
                document(args.certificates, args.expected_certificates_sha256),
                args.execution_source, args.not_before, args.expires_at)
        print(canonical(report(action, value)).decode('ascii'), flush=True)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

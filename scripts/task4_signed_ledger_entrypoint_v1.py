"""Manual existing-state signed-ledger startup; Linux loopback research only.

No initializer, enrollment, credential issuance, remote listener or auto-restart.
"""
import argparse
from contextlib import contextmanager, ExitStack
import datetime
import json
import os
import re
import ssl
import stat
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import (
    Denied, binding, command, digest, exact, hex64, need, sha, strict,
)
from scripts.task4_external_ledger_mtls_v1 import listener, SERVER_NAME
from scripts.task4_retained_signed_ledger_service_v1 import reopen_service
from scripts.task4_signed_github_api_v1 import approved_backend
from scripts.task4_signed_github_ledger_v1 import LEDGER_ID
from scripts.task4_github_ledger_research_v1 import hx

PROFILE = 'task4.signed-ledger-entrypoint.v1'
SCOPE = 'SYNTHETIC_SIGNED_LEDGER_ONLY_NO_PROVIDER'
STOP = 'SIGNED_LEDGER_ENTRYPOINT_STOP'


@contextmanager
def owned_file(path, limit, public=False):
    """Descriptor-pinned no-follow traversal; Linux files only, never repair.

    Private files: effective UID, 0600, immediate parent 0700. Public pin:
    root-owned 0644. Every ancestor is trusted and not group/other writable,
    except root-owned sticky test ancestors. Final files must be single-link.
    """
    parts = custody._parts(path)
    with ExitStack() as stack:
        fd = os.open('/', custody.DIR_FLAGS); stack.callback(os.close, fd)
        for part in parts[:-1]:
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            need(info.st_uid in (0, os.geteuid()) and (not info.st_mode & 0o022 or sticky), 'TRUSTED_ANCESTOR')
            fd = os.open(part, custody.DIR_FLAGS, dir_fd=fd); stack.callback(os.close, fd)
        parent = os.fstat(fd)
        if public:
            need(parent.st_uid in (0, os.geteuid()) and not parent.st_mode & 0o022, 'PUBLIC_PIN_PARENT')
        else:
            custody._private(parent)
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        stack.callback(os.close, file_fd)
        info = os.fstat(file_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and info.st_uid == (0 if public else os.geteuid())
             and stat.S_IMODE(info.st_mode) == (0o644 if public else 0o600)
             and 0 < info.st_size <= limit, 'OWNED_BOUNDED_FILE')
        data = os.read(file_fd, limit+1)
        need(len(data) == info.st_size, 'COMPLETE_FILE')
        yield file_fd, data


def read_file(path, limit, public=False):
    with owned_file(path, limit, public) as (_, data):
        return data


def prepare(configuration):
    """Local checks only: no API request or listener. Exceptions are sanitized."""
    try:
        cfg = strict(read_file(configuration, 8192))
        exact(cfg, 'schema scope genesis receipt_directory public_pin_file token_file binding '
              'tls_certificate tls_key client_ca server_certificate_sha256 peers')
        need(cfg['schema'] == PROFILE and cfg['scope'] == SCOPE and hx(cfg['genesis'], 40), 'FIXED_PROFILE')
        pin_bytes = read_file(cfg['public_pin_file'], 65, public=True)
        need(re.fullmatch(b'[0-9a-f]{64}\n', pin_bytes), 'EXTERNAL_PUBLIC_PIN')
        pin = pin_bytes.decode().strip()
        identity = custody.public_identity(custody.load(cfg['receipt_directory'], pin))
        b = binding(cfg['binding'])
        need(b['ledger_id'] == LEDGER_ID, 'FIXED_LEDGER')
        exact(cfg['peers'], 'issuer custody')
        peers = {}
        for role in ('issuer', 'custody'):
            row = cfg['peers'][role]
            exact(row, 'certificate_sha256 authority_public_sha256')
            cert, authority = row['certificate_sha256'], row['authority_public_sha256']
            need(hex64(cert) and authority == b[role+'_public_sha256'] and cert not in peers, 'EXACT_PEER_BINDING')
            peers[cert] = authority
        need(hex64(cfg['server_certificate_sha256']) and cfg['server_certificate_sha256'] not in peers,
             'DISTINCT_SERVER_PIN')
        ca = read_file(cfg['client_ca'], 16384).decode('ascii')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=ca)
        with owned_file(cfg['tls_certificate'], 16384) as (cert_fd, raw), \
                owned_file(cfg['tls_key'], 16384) as (key_fd, raw_key):
            load_pem_private_key(raw_key, password=None)  # Reject encrypted keys; never prompt via OpenSSL.
            certificate = x509.load_pem_x509_certificate(raw)
            need(sha(certificate.public_bytes(Encoding.DER)) == cfg['server_certificate_sha256'], 'SERVER_PIN')
            now = datetime.datetime.now(datetime.timezone.utc)
            need(certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc, 'VALID_SERVER_CERTIFICATE')
            need(SERVER_NAME in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                 .value.get_values_for_type(x509.DNSName), 'FIXED_TLS_HOSTNAME')
            need(ExtendedKeyUsageOID.SERVER_AUTH in certificate.extensions
                 .get_extension_for_class(x509.ExtendedKeyUsage).value, 'SERVER_AUTH_CERTIFICATE')
            need(not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
                 'LEAF_SERVER_CERTIFICATE')
            public = certificate.public_key()
            if isinstance(public, Ed25519PublicKey):
                need(sha(public.public_bytes(Encoding.Raw, PublicFormat.Raw)) not in
                     (pin, b['issuer_public_sha256'], b['custody_public_sha256']), 'DISTINCT_TLS_AUTHORITY_KEY')
            context.load_cert_chain('/proc/self/fd/'+str(cert_fd), '/proc/self/fd/'+str(key_fd))
        token_bytes = read_file(cfg['token_file'], 256)
        need(re.fullmatch(b'[A-Za-z0-9_]{20,255}\n?', token_bytes), 'EXPLICIT_PRIVATE_TOKEN')
        backend = approved_backend(token_bytes.decode().rstrip('\n'), cfg['genesis'], pin)
        report = dict(schema=PROFILE, scope=SCOPE, genesis=cfg['genesis'],
                      public_key_sha256=identity['public_key_sha256'],
                      server_certificate_sha256=cfg['server_certificate_sha256'],
                      backend_verified=False, listener_started=False, provider_dispatch='DENY', utility='UNSCORED')
        return cfg, backend, context, peers, report
    except Exception:
        raise Denied(STOP) from None


@contextmanager
def configured_listener(configuration):
    """Existing approved run only. Startup performs reads, never enrollment."""
    try:
        cfg, backend, context, peers, report = prepare(configuration)
        service = reopen_service(backend, cfg['receipt_directory'], report['public_key_sha256'])
        _, state = backend.read()
        b = cfg['binding']
        need(state['runs'].get(b['run_id'], {}).get('binding') == b, 'EXISTING_APPROVED_RUN')

        class BoundRunService:
            def exchange(self, encoded, authenticated_peer):
                need(command(strict(encoded))['binding_sha256'] == digest(b), 'CONFIGURED_RUN_ONLY')
                return service.exchange(encoded, authenticated_peer)

        server = listener(BoundRunService(), context, peers)
    except Exception:
        raise Denied(STOP) from None
    with server:
        report.update(backend_verified=True, listener_started=True, port=server.server_address[1])
        yield server, report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'serve'))
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--acknowledge-synthetic-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'check':
            report = prepare(args.configuration)[-1]
            print(json.dumps(report, sort_keys=True), flush=True)
        else:
            need(args.acknowledge_synthetic_only, 'EXPLICIT_START_REQUIRED')
            with configured_listener(args.configuration) as (server, report):
                print(json.dumps(report, sort_keys=True), flush=True)
                server.serve_forever(poll_interval=0.1)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

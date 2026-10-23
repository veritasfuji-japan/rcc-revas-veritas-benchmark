"""Explicit same-host synthetic client. No Provider, enrollment or key creation."""
import argparse
import datetime
import json
import os
import socket
import ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import task4_receipt_key_custody_v1 as custody
from scripts.task4_external_ledger_contract_v1 import (
    LedgerClient, SCHEMA, canonical, command, digest, exact, hex64, need, sha, strict,
)
from scripts.task4_external_ledger_mtls_v1 import SERVER_NAME, TIMEOUT, RESPONSE_TIMEOUT, read_frame, write_frame
from scripts.task4_signed_github_ledger_v1 import LEDGER_ID
from scripts.task4_signed_ledger_admin_v1 import write_record
from scripts.task4_signed_ledger_entrypoint_v1 import SCOPE, owned_file, read_file
from scripts.task4_github_ledger_research_v1 import hx

PROFILE = 'task4.signed-ledger-client.v1'
APPROVAL = 'task4.signed-ledger-client-approval.v1'
STOP = 'SIGNED_LEDGER_CLIENT_STOP'


def manifest():
    """Exact public synthetic commitments; never ingest a task/Provider payload."""
    return dict(schema='task4.signed-ledger-synthetic-manifest.v1', scope=SCOPE,
        effect='IN_MEMORY_LIST_APPEND_ONLY', operations=[dict(operation_id=arm+str(i),
            request_sha256=sha(('TASK4_SYNTHETIC_REQUEST_V1:'+arm+str(i)).encode()),
            grant_sha256=sha(('TASK4_SYNTHETIC_GRANT_V1:'+arm+str(i)).encode()))
            for arm in 'AB' for i in range(4)])


def prepare(configuration):
    cfg = strict(read_file(configuration, 8192))
    exact(cfg, 'schema scope role approval_file tls_certificate tls_key client_ca authority_key attempt_parent')
    need(cfg['schema'] == PROFILE and cfg['scope'] == SCOPE and cfg['role'] in ('issuer', 'custody'), 'CLIENT_PROFILE')
    approval = strict(read_file(cfg['approval_file'], 8192, public=True))
    exact(approval, 'schema scope execution_source genesis binding service_public_hex server_certificate_sha256 peers')
    need(approval['schema'] == APPROVAL and approval['scope'] == SCOPE
         and hx(approval['execution_source'], 40) and hx(approval['genesis'], 40), 'PUBLIC_APPROVAL')
    from scripts.task4_external_ledger_contract_v1 import binding
    b = binding(approval['binding'])
    need(b['ledger_id'] == LEDGER_ID and b['manifest_sha256'] == digest(manifest()), 'FIXED_MANIFEST_AND_LEDGER')
    public = approval['service_public_hex']
    need(hex64(public), 'SERVICE_PUBLIC_KEY')
    exact(approval['peers'], 'issuer custody')
    pins = []
    for role in ('issuer', 'custody'):
        row = approval['peers'][role]
        exact(row, 'certificate_sha256 authority_public_sha256')
        need(hex64(row['certificate_sha256']) and row['authority_public_sha256'] == b[role+'_public_sha256'], 'PEER_BINDING')
        pins.append(row['certificate_sha256'])
    server = approval['server_certificate_sha256']
    need(hex64(server) and len(set(pins+[server])) == 3, 'DISTINCT_TLS_PINS')
    authority = Ed25519PrivateKey.from_private_bytes(read_file(cfg['authority_key'], 32))
    authority_pin = sha(authority.public_key().public_bytes_raw())
    need(authority_pin == b[cfg['role']+'_public_sha256']
         and sha(bytes.fromhex(public)) not in (b['issuer_public_sha256'], b['custody_public_sha256']), 'ROLE_AUTHORITY')
    with custody._directory(cfg['attempt_parent']):
        pass
    # Fixed verified context; certificate/key are loaded from held descriptors.
    context = ssl.create_default_context(cadata=read_file(cfg['client_ca'], 16384).decode('ascii'))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with owned_file(cfg['tls_certificate'], 16384) as (cert_fd, raw), \
            owned_file(cfg['tls_key'], 16384) as (key_fd, raw_key):
        load_pem_private_key(raw_key, password=None)  # No OpenSSL password prompt.
        cert = x509.load_pem_x509_certificate(raw)
        need(sha(cert.public_bytes(Encoding.DER)) == approval['peers'][cfg['role']]['certificate_sha256'], 'CLIENT_CERTIFICATE_PIN')
        now = datetime.datetime.now(datetime.timezone.utc)
        need(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'CLIENT_VALIDITY')
        need(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
             and set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
             == {ExtendedKeyUsageOID.CLIENT_AUTH}, 'CLIENT_LEAF_PURPOSE')
        if isinstance(cert.public_key(), Ed25519PublicKey):
            need(sha(cert.public_key().public_bytes_raw()) not in
                 (sha(bytes.fromhex(public)), b['issuer_public_sha256'], b['custody_public_sha256']),
                 'DISTINCT_TLS_KEY')
        context.load_cert_chain('/proc/self/fd/'+str(cert_fd), '/proc/self/fd/'+str(key_fd))
    return cfg, approval, context


class Transport:
    def __init__(self, context, port, pin, discard=False):
        need(type(port) is int and 0 < port < 65536, 'EXPLICIT_LOOPBACK_PORT')
        self.context, self.port, self.pin, self.discard = context, port, pin, discard
        self.exchanges = []

    def __call__(self, encoded):
        c = command(strict(encoded))
        with socket.create_connection(('127.0.0.1', self.port), timeout=TIMEOUT) as raw:
            with self.context.wrap_socket(raw, server_hostname=SERVER_NAME) as channel:
                need(sha(channel.getpeercert(binary_form=True)) == self.pin, 'SERVER_CERTIFICATE_PIN')
                write_frame(channel, encoded)
                receipt = read_frame(channel, timeout=RESPONSE_TIMEOUT)
        if self.discard and c['action'] != 'view':
            raise ValueError('CONTROLLED_RECEIPT_DISCARD_BEFORE_VALIDATION')
        self.exchanges.append(dict(command=c, receipt=strict(receipt)))
        return receipt


def claim(parent, b, action, operation, cfg):
    name = b['run_id']+'-'+action+'-'+operation
    with custody._directory(parent) as fd:
        os.mkdir(name, 0o700, dir_fd=fd)  # Existing/empty/partial slot is burned.
        os.fsync(fd)
    slot = parent+'/'+name
    write_record(slot, 'attempt.json', dict(schema=PROFILE, binding_sha256=digest(b),
        manifest_sha256=digest(manifest()), action=action, operation_id=operation,
        configuration_sha256=digest(cfg)))
    return slot


def run(action, configuration, port=None, operation=None, discard=False):
    cfg, approval, context = prepare(configuration)
    b = approval['binding']
    report = dict(schema=PROFILE, scope=SCOPE, action=action, role=cfg['role'],
        execution_source=approval['execution_source'], genesis=approval['genesis'],
        binding_sha256=digest(b), manifest_sha256=digest(manifest()),
        provider_dispatch='DENY', utility='UNSCORED', synthetic_callbacks=0)
    need(action in ('check', 'view', 'reserve', 'consume'), 'ACTION')
    if action == 'check':
        need(port is None and operation is None and not discard, 'LOCAL_CHECK_ONLY')
        return dict(report, network_used=False)
    need(type(port) is int and 0 < port < 65536, 'EXPLICIT_LOOPBACK_PORT')
    slot = None
    if action == 'view':
        need(operation is None and not discard, 'READ_ONLY_VIEW')
    else:
        need(action == ('reserve' if cfg['role'] == 'issuer' else 'consume'), 'LOCAL_ROLE_SEPARATION')
        operations = {row['operation_id']: row for row in manifest()['operations']}
        need(type(operation) is str and operation in operations, 'FIXED_OPERATION')
        row = operations[operation]
        slot = claim(cfg['attempt_parent'], b, action, operation, cfg)  # Before even the GET/view.
    transport = Transport(context, port, approval['server_certificate_sha256'], discard)
    client = LedgerClient(b, bytes.fromhex(approval['service_public_hex']), transport)
    snapshot = client.exchange('view')
    if slot is not None:
        snapshot = client.exchange(action, snapshot['revision'], operation,
            row['request_sha256'], row['grant_sha256'] if action == 'consume' else None)
    # LedgerClient verified every receipt, nonce, binding, signature and revision.
    evidence = dict(report, snapshot=snapshot, exchanges=transport.exchanges, network_used=True)
    if slot is not None:
        write_record(slot, 'verified-receipts.json', evidence)  # Retain before the synthetic callback.
        callbacks = []
        callbacks.append('synthetic-issue' if action == 'reserve' else 'synthetic-send')
        evidence['synthetic_callbacks'] = len(callbacks)  # No callable/effect injection API.
        write_record(slot, 'result.json', evidence)
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('manifest', 'check', 'view', 'reserve', 'consume'))
    parser.add_argument('--configuration')
    parser.add_argument('--port', type=int)
    parser.add_argument('--operation', choices=[r['operation_id'] for r in manifest()['operations']])
    parser.add_argument('--discard-mutation-response', action='store_true')
    parser.add_argument('--acknowledge-synthetic-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'manifest':
            need(args.configuration is None and args.port is None and args.operation is None
                 and not args.discard_mutation_response and not args.acknowledge_synthetic_only, 'MANIFEST_ONLY')
            result = dict(manifest=manifest(), manifest_sha256=digest(manifest()))
        else:
            if args.action in ('reserve', 'consume'):
                need(args.acknowledge_synthetic_only, 'EXPLICIT_MUTATION_REQUIRED')
            else:
                need(not args.acknowledge_synthetic_only, 'READ_ONLY_ACTION')
            need(args.configuration is not None, 'EXPLICIT_CONFIGURATION')
            result = run(args.action, args.configuration, args.port, args.operation, args.discard_mutation_response)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(STOP, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

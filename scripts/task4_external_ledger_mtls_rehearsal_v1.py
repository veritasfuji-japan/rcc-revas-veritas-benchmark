"""Synthetic same-host/process-restart mTLS rehearsal. Never a deployment."""
import argparse
from contextlib import contextmanager
import datetime
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.task4_external_ledger_contract_v1 import Denied, LedgerClient, ReferenceService, SCHEMA, canonical, sha
from scripts.task4_external_ledger_mtls_v1 import LoopbackTransport, PROFILE, SERVER_NAME, serve


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(value)


def provision(root):
    """Explicit test administrator; all private material stays in a temporary dir."""
    root = Path(root).absolute()
    root.mkdir(mode=0o700)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Task4 synthetic CA')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    private_write(root/'ca.pem', ca.public_bytes(serialization.Encoding.PEM))
    pins = {}
    for name in ('server', 'issuer', 'custody', 'unmapped'):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if name == 'server'
                                                        else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
        if name == 'server':
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        private_write(root/(name+'.pem'), cert.public_bytes(serialization.Encoding.PEM))
        private_write(root/(name+'.key'), key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        pins[name] = sha(cert.public_bytes(serialization.Encoding.DER))
    service_key = ed25519.Ed25519PrivateKey.generate()
    private_write(root/'service.key', service_key.private_bytes_raw())
    approved = dict(schema=SCHEMA, ledger_id=os.urandom(32).hex(), run_id=os.urandom(32).hex(),
                    manifest_sha256=sha(b'synthetic closed-local manifest'),
                    issuer_public_sha256=sha(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()),
                    custody_public_sha256=sha(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()))
    service = ReferenceService.bootstrap(root/'ledger.sqlite', approved['ledger_id'], service_key)
    service.enroll(approved)
    cfg = dict(schema=PROFILE, ledger_id=approved['ledger_id'], database=str(root/'ledger.sqlite'),
               service_key=str(root/'service.key'), tls_certificate=str(root/'server.pem'),
               tls_key=str(root/'server.key'), client_ca=str(root/'ca.pem'),
               peers={role:dict(certificate_sha256=pins[role], authority_public_sha256=approved[role+'_public_sha256'])
                      for role in ('issuer', 'custody')})
    private_write(root/'configuration.json', canonical(cfg))
    return dict(root=root, binding=approved, public=service_key.public_key().public_bytes_raw(), pins=pins)


@contextmanager
def running(fixture, discard=False):
    ctx = multiprocessing.get_context('spawn')
    reader, writer = ctx.Pipe(duplex=False)
    process = ctx.Process(target=serve, args=(fixture['root']/'configuration.json', writer, discard))
    process.start()
    writer.close()
    try:
        if not reader.poll(10):
            raise RuntimeError('SERVICE_START_FAILED')
        ready = reader.recv()
        assert ready['signer_sha256'] == sha(fixture['public'])
        yield ready
    finally:
        reader.close()
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        assert not process.is_alive()


def transport(fixture, ready, role, **overrides):
    root = fixture['root']
    args = dict(port=ready['port'], ca=root/'ca.pem', certificate=root/(role+'.pem'),
                private_key=root/(role+'.key'), server_certificate_sha256=fixture['pins']['server'])
    args.update(overrides)
    return LoopbackTransport(**args)


def client(fixture, ready, role, **overrides):
    return LedgerClient(fixture['binding'], fixture['public'], transport(fixture, ready, role, **overrides))


def rehearsal():
    checks, pids, issue, send = {}, [], [], []
    request, grant = sha(b'synthetic request'), sha(b'synthetic grant')
    def refused(label, effect):
        try:
            effect()
        except Denied:
            checks[label] = True
        else:
            raise AssertionError(label)
    with tempfile.TemporaryDirectory(prefix='task4-mtls-') as folder:
        f = provision(Path(folder)/'authority')
        with running(f) as ready:
            pids.append(ready['pid'])
            issuer = client(f, ready, 'issuer')
            issuer.gate('reserve', 'A0', request, lambda _: issue.append(1))
            refused('issuer_cannot_consume', lambda: issuer.gate('consume', 'A0', request, lambda _: send.append(1), grant))
            refused('custody_cannot_reserve', lambda: client(f, ready, 'custody').gate('reserve', 'B0', request, lambda _: issue.append(1)))
            refused('ca_valid_unmapped_certificate_denied', lambda: client(f, ready, 'unmapped').exchange('view'))
        with running(f) as ready:
            pids.append(ready['pid'])
            issuer = client(f, ready, 'issuer')
            refused('reservation_survives_process_restart', lambda: issuer.gate('reserve', 'A0', request, lambda _: issue.append(1)))
            custody = client(f, ready, 'custody')
            custody.gate('consume', 'A0', request, lambda _: send.append(1), grant)
            issuer.gate('reserve', 'B0', request, lambda _: None)
        with running(f, discard=True) as ready:
            pids.append(ready['pid'])
            refused('committed_ack_discard_stops_callback', lambda: client(f, ready, 'custody').gate(
                'consume', 'B0', request, lambda _: send.append(1), grant))
        with running(f) as ready:
            pids.append(ready['pid'])
            custody = client(f, ready, 'custody')
            state = custody.exchange('view')
            refused('consumption_survives_ack_loss_and_restart', lambda: custody.gate(
                'consume', 'B0', request, lambda _: send.append(1), grant))
            checks['same_retained_signer_four_processes'] = len(set(pids)) == 4
            checks['two_consumed_records_revision_four'] = (state['revision'] == 4 and
                [r['state'] for r in state['attempts']] == ['CONSUMED_UNKNOWN'] * 2)
            checks['exact_synthetic_callback_counts'] = len(issue) == len(send) == 1
    assert len(checks) == 9 and all(checks.values())
    return dict(schema=PROFILE, scope='SAME_HOST_LOOPBACK_MTLS_REFERENCE_ONLY', checks=checks,
                service_processes=4, synthetic_issue_callbacks=len(issue), synthetic_send_callbacks=len(send),
                final_revision=4, real_provider_posts=0, external_bank_effects=0, provider_dispatch='DENY', utility='UNSCORED',
                github_backend_connected=False, external_storage_deployed=False, cross_runner_retention_proven=False,
                native_integration_proven=False, independent_administration_proven=False, production_bypass_resistance_proven=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = rehearsal()
    report['audited_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    report['source_sha256'] = sha(Path(__file__).with_name('task4_external_ledger_mtls_v1.py').read_bytes())
    report['rehearsal_sha256'] = sha(Path(__file__).read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/'report.json').write_bytes(canonical(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()

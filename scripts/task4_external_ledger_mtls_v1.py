"""Loopback mTLS adapter for the #518 reference service; no deployed authority.

One bounded length-prefixed canonical command per TLS connection. The TLS
certificate, not JSON, selects the enrolled peer. No HTTP, proxy, redirect,
automatic retry, bootstrap or network listener outside loopback is supplied.
"""
import os
from pathlib import Path
import socket
import socketserver
import ssl
import stat
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.task4_external_ledger_contract_v1 import (
    Denied, MAX_WIRE, ReferenceService, command, exact, hex64, need, sha, strict,
)

PROFILE = 'task4.external-ledger-loopback-mtls.v1'
SERVER_NAME = 'task4-ledger.test'
TIMEOUT = 2.0
RESPONSE_TIMEOUT = 120.0


def private_file(file):
    path = Path(file)
    need(path.is_absolute(), 'ABSOLUTE_PRIVATE_FILE')
    s = path.lstat()
    parent = path.parent.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == os.geteuid()
         and stat.S_IMODE(s.st_mode) == 0o600, 'PRIVATE_FILE')
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
         and stat.S_IMODE(parent.st_mode) == 0o700, 'PRIVATE_DIRECTORY')
    return path


def receive(sock, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'FRAME_DEADLINE')
        sock.settimeout(remaining)
        part = sock.recv(count - len(result))
        need(bool(part), 'TRUNCATED_FRAME')
        result.extend(part)
    return bytes(result)


def read_frame(sock, timeout=TIMEOUT):
    # Default request/header admission stays short. Only the explicit signed
    # client response read uses the longer bounded GitHub-processing allowance.
    need(type(timeout) in (int, float) and 0 < timeout <= RESPONSE_TIMEOUT, 'BOUNDED_FRAME_TIMEOUT')
    deadline = time.monotonic() + timeout
    count = struct.unpack('!I', receive(sock, 4, deadline))[0]
    need(0 < count <= MAX_WIRE, 'BOUNDED_FRAME')
    return receive(sock, count, deadline)


def write_frame(sock, data):
    need(type(data) is bytes and 0 < len(data) <= MAX_WIRE, 'BOUNDED_FRAME')
    sock.settimeout(TIMEOUT)
    sock.sendall(struct.pack('!I', len(data)) + data)


def load_configuration(file):
    raw = private_file(file).read_bytes()
    need(len(raw) <= MAX_WIRE, 'BOUNDED_CONFIGURATION')
    cfg = strict(raw)
    exact(cfg, 'schema ledger_id database service_key tls_certificate tls_key client_ca peers')
    need(cfg['schema'] == PROFILE and hex64(cfg['ledger_id']), 'CONFIGURATION_IDENTITY')
    for key in ('database', 'service_key', 'tls_certificate', 'tls_key', 'client_ca'):
        private_file(cfg[key])
    exact(cfg['peers'], 'issuer custody')
    peers = {}
    identities = []
    for role in ('issuer', 'custody'):
        row = cfg['peers'][role]
        exact(row, 'certificate_sha256 authority_public_sha256')
        cert, identity = row['certificate_sha256'], row['authority_public_sha256']
        need(hex64(cert) and hex64(identity) and cert not in peers, 'DISTINCT_CERTIFICATE_PINS')
        peers[cert] = identity
        identities.append(identity)
    need(len(set(identities)) == 2, 'DISTINCT_ENROLLED_PEERS')
    return cfg, peers


def serve(configuration, ready, discard_consume_ack=False):
    """Child-process entry point. Configuration/admin/filesystem are trusted.

    discard_consume_ack is a trusted rehearsal fault, never a client command.
    The fixed loopback listener intentionally cannot serve remote runners yet.
    """
    cfg, peers = load_configuration(configuration)
    key = Ed25519PrivateKey.from_private_bytes(private_file(cfg['service_key']).read_bytes())
    service = ReferenceService(cfg['database'], cfg['ledger_id'], key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=cfg['client_ca'])
    context.load_cert_chain(cfg['tls_certificate'], cfg['tls_key'])

    with listener(service, context, peers, discard_consume_ack) as server:
        ready.send(dict(port=server.server_address[1], pid=os.getpid(),
                        signer_sha256=sha(key.public_key().public_bytes_raw())))
        ready.close()
        server.serve_forever(poll_interval=0.05)


def listener(service, context, peers, discard_consume_ack=False):
    """Trusted service injection; TLS roles and loopback binding remain mandatory."""
    need(context.protocol == ssl.PROTOCOL_TLS_SERVER and context.verify_mode == ssl.CERT_REQUIRED
         and context.minimum_version >= ssl.TLSVersion.TLSv1_2, 'REQUIRED_SERVER_MTLS')
    need(type(peers) is dict and len(peers) == 2 and len(set(peers.values())) == 2
         and all(hex64(k) and hex64(v) for k, v in peers.items()), 'EXACT_TLS_PEER_MAPPING')

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(TIMEOUT)
                with context.wrap_socket(self.request, server_side=True) as channel:
                    peer = peers.get(sha(channel.getpeercert(binary_form=True)))
                    need(peer is not None, 'UNENROLLED_TLS_CERTIFICATE')
                    encoded = read_frame(channel)
                    c = command(strict(encoded))
                    reply = service.exchange(encoded, peer)
                    if discard_consume_ack and c['action'] == 'consume':
                        return  # Commit and signature occurred; no acknowledgement reaches client.
                    write_frame(channel, reply)
            except Exception:
                # No raw request, peer material, private path or exception is logged.
                # Malformed/unauthorized/uncertain exchanges close without permission.
                return

    class Server(socketserver.TCPServer):
        allow_reuse_address = False
        request_queue_size = 4

    return Server(('127.0.0.1', 0), Handler)


class LoopbackTransport:
    """Injected #518 transport: verified TLS server + pinned certificate + mTLS.

    No caller-controlled URL/host, shared token, role header or retry. The
    service receipt is still verified separately by LedgerClient.
    """
    def __init__(self, port, ca, certificate, private_key, server_certificate_sha256):
        need(type(port) is int and 0 < port < 65536 and hex64(server_certificate_sha256), 'PINNED_ENDPOINT')
        self.port, self.pin = port, server_certificate_sha256
        self.context = ssl.create_default_context(cafile=str(private_file(ca)))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(private_file(certificate)), str(private_file(private_key)))

    def __call__(self, encoded):
        try:
            command(strict(encoded))  # Reject locally before opening a connection.
            with socket.create_connection(('127.0.0.1', self.port), timeout=TIMEOUT) as raw:
                with self.context.wrap_socket(raw, server_hostname=SERVER_NAME) as channel:
                    need(sha(channel.getpeercert(binary_form=True)) == self.pin, 'SERVER_CERTIFICATE_PIN')
                    write_frame(channel, encoded)
                    return read_frame(channel)
        except Exception:
            raise Denied('MTLS_TRANSPORT_STOP') from None

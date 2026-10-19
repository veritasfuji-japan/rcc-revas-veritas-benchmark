"""Selected offline Native path with child-only synthetic signing key.

Process separation, not independent IAM/approval or production non-bypassability.
"""
import argparse
import base64
import json
import multiprocessing as mp
import os
from pathlib import Path
import sys
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from scripts import task4_native_protected_custody_v1 as native

custody = native.custody
ROOT = Path(__file__).resolve().parents[1]
RULE = "TASK4_NATIVE_SEPARATED_SYNTHETIC_SIGNER_NO_GO_V1"


def validate_claim(c):
    custody.need(type(c) is dict and set(c) == custody.FIELDS)
    custody.need(c['schema'] == custody.SCHEMA and c['trial'] == custody.TRIAL
                 and c['case'] == custody.CASE and c['model'] == custody.MODEL
                 and c['provider_post_allowed'] is False)
    custody.need(c['op'] in ('consume', 'attach', 'read') and c['arm'] in ('A', 'B')
                 and type(c['ordinal']) is int and 0 <= c['ordinal'] < 4
                 and custody.hex64(c['request_sha256']) and custody.hex64(c['recipient_sha256']))
    if c['op'] == 'consume':
        custody.need(c['receipt_sha256'] is None and c['envelope_sha256'] is None)
    else:
        custody.need(custody.hex64(c['receipt_sha256']) and custody.hex64(c['envelope_sha256']))


class SigningPolicy:
    """Synthetic parent-supplied scope, immutable once first accepted; no approval service."""
    def __init__(self):
        self.rows = {}
        self.recipient = None

    def accept(self, c):
        validate_claim(c)
        ident = (c['arm'], c['ordinal'])
        op = c['op']
        custody.need(self.recipient is None or self.recipient == c['recipient_sha256'])
        if op == 'consume':
            custody.need(ident not in self.rows)
        else:
            custody.need(ident in self.rows)
            row = self.rows[ident]
            custody.need(row['request_sha256'] == c['request_sha256'])
            custody.need((op == 'attach' and row['op'] == 'consume') or
                         (op == 'read' and row['op'] == 'attach'
                          and row['receipt_sha256'] == c['receipt_sha256']
                          and row['envelope_sha256'] == c['envelope_sha256']))
        self.recipient = c['recipient_sha256']
        self.rows[ident] = dict(c)


def signer_child(conn):
    """Fresh interpreter; no sockets, process launch or private-key export opcode."""
    def audit(event, args):
        if event in ('socket.__new__', 'socket.bind', 'socket.connect', 'socket.getaddrinfo',
                     'subprocess.Popen', 'os.system', 'os.posix_spawn'):
            raise custody.Denied('SIGNER_EXTERNAL_OPERATION_DENIED')
    sys.addaudithook(audit)
    try:
        custody.offline()
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw).hex()
        policy = SigningPolicy()
        counts = {'consume': 0, 'attach': 0, 'read': 0}
        conn.send_bytes(custody.canonical({'public_hex': public, 'pid': os.getpid()}))
        while True:
            request = custody.parse(conn.recv_bytes(custody.LIMIT))
            if request == {'op': 'stop'}:
                conn.send_bytes(custody.canonical({'stopped': True, 'signed_counts': counts}))
                return
            try:
                custody.offline()
                custody.need(type(request) is dict and set(request) == {'op', 'claim'}
                             and request['op'] == 'sign_synthetic_no_send')
                claim = request['claim']
                policy.accept(claim)
                signature = key.sign(custody.canonical(claim)).hex()
                counts[claim['op']] += 1
                reply = {'decision': 'SIGNED_SYNTHETIC_NO_SEND', 'signature_hex': signature}
            except (ValueError, TypeError, KeyError):
                reply = {'decision': 'DENY'}
            conn.send_bytes(custody.canonical(reply))
    except (EOFError, BrokenPipeError, OSError, ValueError):
        pass
    finally:
        conn.close()


class SignerClient:
    def __init__(self):
        custody.offline()
        ctx = mp.get_context('spawn')
        self.conn, child = ctx.Pipe()
        self.worker = ctx.Process(target=signer_child, args=(child,))
        self.worker.start()
        child.close()
        self.counts = {'consume': 0, 'attach': 0, 'read': 0}
        try:
            info = self.receive()
            custody.need(type(info) is dict and set(info) == {'public_hex', 'pid'}
                         and info['pid'] == self.worker.pid and info['pid'] != os.getpid()
                         and custody.hex64(info['public_hex']))
            self.public = info['public_hex']
            self.verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public))
        except BaseException:
            self.abort()
            raise

    def receive(self):
        custody.need(self.conn.poll(15))
        return custody.parse(self.conn.recv_bytes(custody.LIMIT))

    def request(self, packet):
        custody.offline()
        custody.need(self.worker.is_alive())
        wire = custody.canonical(packet)
        custody.need(len(wire) <= custody.LIMIT)
        self.conn.send_bytes(wire)
        return self.receive()

    def sign(self, claim):
        validate_claim(claim)
        reply = self.request({'op': 'sign_synthetic_no_send', 'claim': claim})
        custody.need(type(reply) is dict and set(reply) == {'decision', 'signature_hex'}
                     and reply['decision'] == 'SIGNED_SYNTHETIC_NO_SEND')
        signature = reply['signature_hex']
        custody.need(type(signature) is str and len(signature) == 128)
        self.verifier.verify(bytes.fromhex(signature), custody.canonical(claim))
        self.counts[claim['op']] += 1
        return signature

    def finish(self):
        reply = self.request({'op': 'stop'})
        custody.need(reply == {'stopped': True, 'signed_counts': self.counts})
        self.worker.join(5)
        custody.need(not self.worker.is_alive() and self.worker.exitcode == 0)
        self.conn.close()

    def abort(self):
        if self.worker.is_alive():
            self.worker.terminate()
        self.worker.join(5)
        if self.worker.is_alive():
            self.worker.kill()
            self.worker.join(5)
        self.conn.close()


class SeparatedAdapter(native.ProtectedAdapter):
    def __init__(self, signer, watch=None):
        # Do not call the inherited constructor: it creates a parent private key.
        custody.offline()
        self.signer, self.public = signer, signer.public
        self.recipient = self.database = self.socket_path = None
        self.records, self.consume_packets = {}, {}
        self.starts = []
        self.verified_replies = {'consume': 0, 'attach': 0, 'read': 0, 'replay_denied': 0}
        self.watch = watch
        self.cached_replays = 0

    def signed(self, op, arm, ordinal, wire_sha, receipt=None, envelope_sha=None, blob=None):
        claim = dict(schema=custody.SCHEMA, trial=custody.TRIAL, case=custody.CASE,
                     model=custody.MODEL, op=op, arm=arm, ordinal=ordinal,
                     request_sha256=wire_sha, recipient_sha256=self.recipient,
                     receipt_sha256=receipt, envelope_sha256=envelope_sha,
                     provider_post_allowed=False)
        ident = (arm, ordinal)
        if op == 'consume' and ident in self.consume_packets:
            packet = self.consume_packets[ident]
            custody.need(packet['claim'] == claim and blob is None)
            self.cached_replays += 1
            return dict(packet, claim=dict(packet['claim']))
        packet = {'claim': claim, 'signature_hex': self.signer.sign(claim),
                  'envelope_b64': base64.b64encode(blob).decode() if blob is not None else None}
        if op == 'consume':
            self.consume_packets[ident] = dict(packet, claim=dict(claim))
        return packet


def run():
    custody.offline()
    custody.need(custody.digest(Path(native.__file__).read_bytes()) == "dc09e6987514d27b61bca3dc1ce87f6af0fb88523c39b94bd703d3b11b3d87f3")
    signer = SignerClient()
    adapters = []
    def factory(watch=None):
        custody.need(not adapters)
        adapter = SeparatedAdapter(signer, watch)
        adapters.append(adapter)
        return adapter
    def forbid_parent_key():
        raise custody.Denied('PARENT_SIGNING_KEY_GENERATION_FORBIDDEN')
    try:
        with patch.object(native, 'ProtectedAdapter', factory), \
             patch.object(Ed25519PrivateKey, 'generate', forbid_parent_key):
            report = native.run()
        custody.need(len(adapters) == 1 and not hasattr(adapters[0], 'key')
                     and adapters[0].cached_replays == 8
                     and signer.counts == {'consume': 8, 'attach': 8, 'read': 8})
        signer.finish()
        report.update(rule_of_one=RULE, baseline_main='8e415cbec57bd50dbdd3c239f92b4e86c39da0d2',
                      parent_holds_synthetic_signing_key=False,
                      signer_distinct_os_process=True,
                      synthetic_signatures_verified_in_parent=24,
                      signer_operation_counts=signer.counts,
                      cached_original_consume_replays=8,
                      signer_clean_shutdown=True,
                      independent_issuer_approval_proven=False,
                      independent_iam_proven=False,
                      signer_scope_origin='SYNTHETIC_PARENT_SUPPLIED_NOT_OWNER_APPROVAL')
        return report
    finally:
        signer.abort()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    custody.need(out.is_relative_to(ROOT) and not out.exists() and not out.is_symlink())
    report = run()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write('\n')
    print('TASK4_NATIVE_SEPARATED_SIGNER_NO_PROVIDER')


if __name__ == '__main__':
    main()

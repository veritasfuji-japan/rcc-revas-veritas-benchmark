"""Offline recipient substitution regression; uses a PUBLIC reproducible test key.

Never use this recipient for real data. This is not independent owner approval.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from scripts import task4_native_frozen_signer_scope_v1 as scope

custody = scope.custody
ROOT = Path(__file__).resolve().parents[1]
RULE = 'TASK4_NATIVE_FROZEN_SYNTHETIC_RECIPIENT_NO_GO_V1'
MANIFEST = ROOT / 'docs/TASK4_NATIVE_FROZEN_RECIPIENT_V1.json'
MANIFEST_SHA = '18e3d1c2776f029a57012beae669ac25c9bf3c680fc5239b0ee851196bedb93c'
PUBLIC_FIXTURE_LABEL = b'TASK4_PUBLIC_SYNTHETIC_RECIPIENT_FIXTURE_NOT_FOR_REAL_DATA_V1'


def public_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def parse_recipient(raw):
    custody.need(custody.digest(raw) == MANIFEST_SHA)
    data = custody.parse(raw)
    custody.need(data['schema'] == 'task4.synthetic.frozen.recipient.v1'
                 and data['scope_origin'] == 'PUBLIC_SYNTHETIC_TEST_KEY_NOT_OWNER_APPROVAL'
                 and data['request_manifest_sha256'] == scope.MANIFEST_SHA
                 and data['case'] == custody.CASE and data['model'] == custody.MODEL
                 and data['trial'] == custody.TRIAL
                 and data['private_key_publicly_reproducible'] is True
                 and data['real_data_allowed'] is False
                 and data['provider_post_allowed'] is False
                 and custody.hex64(data['recipient_public_hex'])
                 and custody.digest(bytes.fromhex(data['recipient_public_hex'])) == data['recipient_sha256'])
    return data


def load_recipient():
    custody.need(not MANIFEST.is_symlink())
    return parse_recipient(MANIFEST.read_bytes())


def public_test_recipient():
    # Deliberately public fixture material. Provides NO confidentiality for real data.
    key = X25519PrivateKey.from_private_bytes(sha256(PUBLIC_FIXTURE_LABEL).digest())
    custody.need(public_bytes(key).hex() == load_recipient()['recipient_public_hex'])
    return key


class RecipientSigningPolicy(scope.FrozenSigningPolicy):
    def __init__(self):
        self.allowed_recipient = load_recipient()['recipient_sha256']
        super().__init__()

    def accept(self, claim):
        scope.separated.validate_claim(claim)
        custody.need(claim['recipient_sha256'] == self.allowed_recipient)
        super().accept(claim)


def recipient_signer_child(conn):
    # Independent file loading in a fresh child, not a parent-supplied recipient pin.
    with patch.object(scope.separated, 'SigningPolicy', RecipientSigningPolicy):
        scope.separated.signer_child(conn)


class FixtureKeySequence:
    """For the pinned #484 call order: one fixture recipient, eight random ephemerals."""
    def __init__(self, random_generate):
        self.random_generate = random_generate
        self.calls = 0
        self.expected = load_recipient()['recipient_sha256']

    def __call__(self):
        custody.need(self.calls < 9)
        if self.calls == 0:
            key = public_test_recipient()
            custody.need(custody.digest(public_bytes(key)) == self.expected)
        else:
            key = self.random_generate()
            custody.need(custody.digest(public_bytes(key)) != self.expected)
        self.calls += 1
        return key


def run():
    custody.offline()
    custody.need(custody.digest(Path(scope.__file__).read_bytes()) == "a0ae5980979d56adb905abc749c320e61311e3436b073434c5a25f51c424473d")
    recipient = load_recipient()
    sequence = FixtureKeySequence(X25519PrivateKey.generate)
    with patch.object(scope, 'scoped_signer_child', recipient_signer_child), \
         patch.object(X25519PrivateKey, 'generate', sequence):
        report = scope.run()
    custody.need(sequence.calls == 9)
    report.update(rule_of_one=RULE,
                  baseline_main='d60caa968eec989bb13d6e4de6350b2bbb370ccb',
                  frozen_recipient_manifest_sha256=MANIFEST_SHA,
                  frozen_recipient_public_sha256=recipient['recipient_sha256'],
                  recipient_bound_before_first_consume=True,
                  recipient_scope_origin='PUBLIC_SYNTHETIC_TEST_KEY_NOT_OWNER_APPROVAL',
                  recipient_private_key_publicly_reproducible=True,
                  recipient_confidentiality_for_real_data=False,
                  random_envelope_ephemeral_key_count=8,
                  recipient_preapproved_independently=False,
                  independently_approved_manifest_proven=False)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    custody.need(out.is_relative_to(ROOT) and not out.exists() and not out.is_symlink())
    report = run()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as f:
        json.dump(report, f, sort_keys=True, indent=2)
        f.write('\n')
    print('TASK4_NATIVE_FROZEN_RECIPIENT_NO_PROVIDER')


if __name__ == '__main__':
    main()

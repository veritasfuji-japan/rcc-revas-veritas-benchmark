import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import task4_native_os_custody_v1 as proof


def grant():
    key = Ed25519PrivateKey.generate()
    claim = proof.statement('A', 0, proof.scope()[('A', 0)])
    value = {'statement': claim, 'signature': key.sign(
        b'TASK4_NATIVE_OS_V1\0' + proof.canonical(claim)).hex()}
    return key, value


def test_exact_frozen_grant_verifies():
    key, value = grant()
    proof.verify_grant(value, 'A', 0, proof.scope()[('A', 0)], key.public_key().public_bytes_raw())


def test_fixed_scope_and_public_fixture_recipient():
    assert len(proof.scope()) == 8
    assert set(proof.scope()) == {(a, i) for a in ('A', 'B') for i in range(4)}
    assert proof.sha(proof.recipient()) == proof.RECIPIENT_SHA


@pytest.mark.parametrize('fault', ['target', 'recipient', 'scope', 'cap', 'arm', 'ordinal',
                                  'request', 'extra', 'signature', 'attacker'])
def test_even_resigned_scope_widening_or_forged_signatures_refused(fault):
    key, value = grant()
    value = copy.deepcopy(value)
    replacements = {'target': ('target', 'https://example.invalid/'),
                    'recipient': ('recipient_sha256', 'f' * 64), 'scope': ('scope', 'PRODUCTION'),
                    'cap': ('output_cap', 257), 'arm': ('arm', 'B'), 'ordinal': ('ordinal', 1),
                    'request': ('request_sha256', '0' * 64), 'extra': ('forward', True)}
    if fault in replacements:
        name, replacement = replacements[fault]
        value['statement'][name] = replacement
        value['signature'] = key.sign(b'TASK4_NATIVE_OS_V1\0' + proof.canonical(value['statement'])).hex()
    elif fault == 'signature':
        value['signature'] = '0' * 128
    else:
        value['signature'] = Ed25519PrivateKey.generate().sign(
            b'TASK4_NATIVE_OS_V1\0' + proof.canonical(value['statement'])).hex()
    with pytest.raises(ValueError):
        proof.verify_grant(value, 'A', 0, proof.scope()[('A', 0)], key.public_key().public_bytes_raw())


@pytest.mark.parametrize('value', ['!', 'YQ', None])
def test_malformed_base64_refused(value):
    with pytest.raises(ValueError):
        proof.decode(value)


@pytest.mark.parametrize('raw', [b'{"arm":"A","arm":"B"}', b' ' * (proof.LIMIT + 1)])
def test_duplicate_or_oversized_json_refused(raw):
    with pytest.raises(ValueError):
        proof.parse(raw)


def test_actual_wire_must_match_preissued_request_hash():
    key, value = grant()
    packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': proof.encode(b'{}'), 'grant': value}
    with pytest.raises(ValueError, match='EXACT_FROZEN_SDK_BYTES'):
        proof.verify(packet, key.public_key().public_bytes_raw())


def test_caller_cannot_select_additional_endpoint():
    key, value = grant()
    packet = {'arm': 'A', 'ordinal': 0, 'wire_b64': proof.encode(b'{}'), 'grant': value,
              'destination': 'https://example.invalid/'}
    with pytest.raises(ValueError, match='EXACT_NATIVE_PACKET'):
        proof.verify(packet, key.public_key().public_bytes_raw())

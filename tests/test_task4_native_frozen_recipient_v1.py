import json
import os
from unittest.mock import patch
import pytest
from scripts import task4_native_frozen_recipient_v1 as m


def claim(op='consume', recipient=None):
    return dict(schema=m.custody.SCHEMA, trial=m.custody.TRIAL, case=m.custody.CASE,
                model=m.custody.MODEL, op=op, arm='A', ordinal=0,
                request_sha256=m.scope.load_scope()[('A', 0)],
                recipient_sha256=recipient or m.load_recipient()['recipient_sha256'],
                receipt_sha256=None if op == 'consume' else 'c'*64,
                envelope_sha256=None if op == 'consume' else 'd'*64,
                provider_post_allowed=False)


def test_public_fixture_matches_fixed_recipient():
    k = m.public_test_recipient()
    p = m.load_recipient()
    assert m.public_bytes(k).hex() == p['recipient_public_hex']
    assert m.custody.digest(m.public_bytes(k)) == p['recipient_sha256']
    assert p['private_key_publicly_reproducible'] is True
    assert p['real_data_allowed'] is False


@pytest.mark.parametrize('field,value', [
    ('recipient_public_hex', '0'*64), ('recipient_sha256', '0'*64),
    ('provider_post_allowed', True), ('real_data_allowed', True),
    ('request_manifest_sha256', '0'*64), ('private_key_publicly_reproducible', False),
])
def test_manifest_changes_fail_closed(field, value):
    data = json.loads(m.MANIFEST.read_bytes())
    data[field] = value
    with pytest.raises(m.custody.Denied):
        m.parse_recipient(m.custody.canonical(data))


def test_missing_recipient_manifest_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'MANIFEST', tmp_path/'absent.json')
    with pytest.raises(FileNotFoundError):
        m.RecipientSigningPolicy()


def test_recipient_substitution_denied_at_every_stage():
    p = m.RecipientSigningPolicy()
    for op in ('consume', 'attach', 'read'):
        before = {k: dict(v) for k, v in p.rows.items()}
        with pytest.raises(m.custody.Denied):
            p.accept(claim(op, '0'*64))
        assert p.rows == before
        if op == 'consume':
            assert p.recipient is None
        p.accept(claim(op))


def test_one_fixture_key_then_random_envelope_keys():
    generated = []
    def generate():
        key = m.X25519PrivateKey.generate()
        generated.append(key)
        return key
    sequence = m.FixtureKeySequence(generate)
    assert m.public_bytes(sequence()) == m.public_bytes(m.public_test_recipient())
    for _ in range(8):
        assert sequence() is generated[-1]
    assert sequence.calls == 9 and len(generated) == 8
    with pytest.raises(m.custody.Denied):
        sequence()


def test_replaced_fixture_key_is_rejected_before_use(monkeypatch):
    replacement = m.X25519PrivateKey.generate()
    monkeypatch.setattr(m, 'public_test_recipient', lambda: replacement)
    seq = m.FixtureKeySequence(m.X25519PrivateKey.generate)
    with pytest.raises(m.custody.Denied):
        seq()
    assert seq.calls == 0


@pytest.mark.skipif(os.environ.get('TASK4_FROZEN_RECIPIENT_PROOF') != '1',
                    reason='dedicated signer child evidence')
def test_child_rejects_recipient_swap_before_first_signature_and_later():
    with patch.object(m.scope.separated, 'signer_child', m.recipient_signer_child):
        signer = m.scope.separated.SignerClient()
    try:
        for op in ('consume', 'attach', 'read'):
            assert signer.request({'op': 'sign_synthetic_no_send',
                                   'claim': claim(op, '0'*64)}) == {'decision': 'DENY'}
            assert len(signer.sign(claim(op))) == 128
        signer.finish()
    finally:
        signer.abort()


@pytest.mark.skipif(os.environ.get('TASK4_FROZEN_RECIPIENT_PROOF') != '1',
                    reason='dedicated full Native SDK dependencies')
def test_native_path_with_frozen_recipient():
    r = m.run()
    assert r['frozen_recipient_manifest_sha256'] == m.MANIFEST_SHA
    assert r['frozen_recipient_public_sha256'] == m.load_recipient()['recipient_sha256']
    assert r['recipient_bound_before_first_consume'] is True
    assert r['recipient_private_key_publicly_reproducible'] is True
    assert r['recipient_confidentiality_for_real_data'] is False
    assert r['random_envelope_ephemeral_key_count'] == 8
    assert r['exact_native_requests_match_frozen_scope'] is True
    assert r['signer_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8}
    assert r['protected_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8, 'replay_denied': 8}
    assert r['observed_parent_protected_socket_connections'] == 32
    assert r['parent_holds_synthetic_signing_key'] is False
    assert r['real_provider_posts'] == r['external_bank_effects'] == 0
    assert r['recipient_preapproved_independently'] is False
    assert r['independently_approved_manifest_proven'] is False
    assert r['production_bypass_resistance_proven'] is False

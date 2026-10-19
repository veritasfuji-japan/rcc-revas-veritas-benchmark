import json
import os
from unittest.mock import patch
import pytest
from scripts import task4_native_frozen_signer_scope_v1 as m


def claim(arm='A', ordinal=0, op='consume', **changes):
    c = dict(schema=m.custody.SCHEMA, trial=m.custody.TRIAL, case=m.custody.CASE,
             model=m.custody.MODEL, op=op, arm=arm, ordinal=ordinal,
             request_sha256=m.load_scope()[(arm, ordinal)], recipient_sha256='b'*64,
             receipt_sha256=None if op == 'consume' else 'c'*64,
             envelope_sha256=None if op == 'consume' else 'd'*64,
             provider_post_allowed=False)
    return dict(c, **changes)


def test_frozen_scope_exact_eight_entries():
    scope = m.load_scope()
    assert len(scope) == 8
    assert set(scope) == {(a, i) for a in ('A', 'B') for i in range(4)}


@pytest.mark.parametrize('mutation', ['hash', 'missing', 'extra', 'cap', 'live', 'duplicate'])
def test_changed_manifest_is_refused(mutation):
    data = json.loads(m.MANIFEST.read_bytes())
    if mutation == 'hash':
        data['entries'][0]['request_sha256'] = '0'*64
    elif mutation == 'missing':
        data['entries'].pop()
    elif mutation == 'extra':
        data['extra'] = 'replacement'
    elif mutation == 'cap':
        data['entries'][0]['requested_output_token_cap'] = 257
    elif mutation == 'live':
        data['provider_post_allowed'] = True
    else:
        data['entries'][1] = data['entries'][0]
    with pytest.raises(m.custody.Denied):
        m.parse_manifest(m.custody.canonical(data))


def test_missing_manifest_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(m, 'MANIFEST', tmp_path/'absent.json')
    with pytest.raises(FileNotFoundError):
        m.FrozenSigningPolicy()


@pytest.mark.parametrize('request_hash', ['0'*64, 'f'*64])
def test_unlisted_request_does_not_consume_signer_state(request_hash):
    p = m.FrozenSigningPolicy()
    with pytest.raises(m.custody.Denied):
        p.accept(claim(request_sha256=request_hash))
    assert p.rows == {} and p.recipient is None
    p.accept(claim())


def test_cross_slot_hash_and_changed_attachment_rejected():
    p = m.FrozenSigningPolicy()
    other = m.load_scope()[('B', 1)]
    with pytest.raises(m.custody.Denied):
        p.accept(claim(request_sha256=other))
    p.accept(claim())
    with pytest.raises(m.custody.Denied):
        p.accept(claim(op='attach', request_sha256=other))
    p.accept(claim(op='attach'))
    p.accept(claim(op='read'))
    with pytest.raises(m.custody.Denied):
        p.accept(claim())


@pytest.mark.skipif(os.environ.get('TASK4_FROZEN_SIGNER_SCOPE_PROOF') != '1',
                    reason='dedicated spawned signer evidence')
def test_child_enforces_scope_before_issuing_signature():
    with patch.object(m.separated, 'signer_child', m.scoped_signer_child):
        signer = m.separated.SignerClient()
    try:
        for invalid in (claim(request_sha256='0'*64), claim(model='other'),
                        claim(provider_post_allowed=True),
                        claim(request_sha256=m.load_scope()[('B', 1)])):
            assert signer.request({'op': 'sign_synthetic_no_send', 'claim': invalid}) == {'decision': 'DENY'}
        assert len(signer.sign(claim())) == 128
        assert len(signer.sign(claim(op='attach'))) == 128
        assert len(signer.sign(claim(op='read'))) == 128
        signer.finish()
    finally:
        signer.abort()


@pytest.mark.skipif(os.environ.get('TASK4_FROZEN_SIGNER_SCOPE_PROOF') != '1',
                    reason='dedicated full Native dependencies')
def test_native_requests_match_prior_frozen_scope():
    r = m.run()
    assert r['exact_native_requests_match_frozen_scope'] is True
    assert r['frozen_signer_scope_sha256'] == m.MANIFEST_SHA
    assert r['frozen_signer_scope_entries'] == r['capped_sdk_requests'] == 8
    assert r['signer_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8}
    assert r['protected_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8, 'replay_denied': 8}
    assert r['observed_parent_protected_socket_connections'] == 32
    assert r['parent_holds_synthetic_signing_key'] is False
    assert r['independently_approved_manifest_proven'] is False
    assert r['recipient_preapproved_independently'] is False
    assert r['real_provider_posts'] == r['external_bank_effects'] == 0
    assert r['production_bypass_resistance_proven'] is False

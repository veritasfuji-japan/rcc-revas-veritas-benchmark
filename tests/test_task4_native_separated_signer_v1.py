import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import task4_native_separated_signer_v1 as m


def claim(op='consume', **changes):
    c = dict(schema=m.custody.SCHEMA, trial=m.custody.TRIAL, case=m.custody.CASE,
             model=m.custody.MODEL, op=op, arm='A', ordinal=0,
             request_sha256='a'*64, recipient_sha256='b'*64,
             receipt_sha256=None if op == 'consume' else 'c'*64,
             envelope_sha256=None if op == 'consume' else 'd'*64,
             provider_post_allowed=False)
    return dict(c, **changes)


@pytest.mark.parametrize('changes', [
    {'provider_post_allowed': True}, {'model': 'other'}, {'trial': '0'*64},
    {'case': 'other'}, {'arm': 'C'}, {'ordinal': True}, {'ordinal': 4},
    {'op': 'send_live'}, {'extra': 'field'}, {'request_sha256': 'bad'},
])
def test_signer_policy_rejects_bad_scope_without_mutating(changes):
    p = m.SigningPolicy()
    with pytest.raises(m.custody.Denied):
        p.accept(claim(**changes))
    assert p.rows == {} and p.recipient is None


def test_signer_policy_orders_and_binds_operations():
    p = m.SigningPolicy()
    with pytest.raises(m.custody.Denied):
        p.accept(claim('attach'))
    p.accept(claim())
    for c in (claim(), claim('attach', request_sha256='e'*64),
              claim('attach', recipient_sha256='e'*64)):
        with pytest.raises(m.custody.Denied):
            p.accept(c)
    p.accept(claim('attach'))
    with pytest.raises(m.custody.Denied):
        p.accept(claim('read', envelope_sha256='e'*64))
    p.accept(claim('read'))
    with pytest.raises(m.custody.Denied):
        p.accept(claim('read'))


def test_adapter_has_no_key_and_replays_exact_signed_packet():
    signer = SimpleNamespace(public='a'*64, sign=Mock(return_value='f'*128))
    a = m.SeparatedAdapter(signer)
    a.recipient = 'b'*64
    first = a.signed('consume', 'A', 0, 'a'*64)
    replay = a.signed('consume', 'A', 0, 'a'*64)
    assert replay == first and replay is not first
    assert signer.sign.call_count == 1 and a.cached_replays == 1
    assert not hasattr(a, 'key')
    replay['claim']['request_sha256'] = 'e'*64
    assert a.consume_packets[('A', 0)]['claim']['request_sha256'] == 'a'*64
    with pytest.raises(m.custody.Denied):
        a.signed('consume', 'A', 0, 'e'*64)
    assert signer.sign.call_count == 1


def test_signer_receive_timeout_is_fail_closed():
    c = object.__new__(m.SignerClient)
    c.conn = SimpleNamespace(poll=lambda timeout: False, recv_bytes=Mock())
    with pytest.raises(m.custody.Denied):
        c.receive()
    c.conn.recv_bytes.assert_not_called()


@pytest.mark.skipif(os.environ.get('TASK4_SEPARATED_SIGNER_PROOF') != '1',
                    reason='dedicated process evidence')
def test_signer_process_denies_export_live_reissue_and_dead_signer():
    s = m.SignerClient()
    try:
        assert s.worker.pid != os.getpid()
        for request in ({'op': 'export_key'}, {'op': 'send_live', 'claim': claim()},
                        {'op': 'sign_synthetic_no_send', 'claim': claim(provider_post_allowed=True)}):
            assert s.request(request) == {'decision': 'DENY'}
        assert len(s.sign(claim())) == 128
        with pytest.raises(m.custody.Denied):
            s.sign(claim())
        assert len(s.sign(claim('attach'))) == 128
        assert len(s.sign(claim('read'))) == 128
        assert s.counts == {'consume': 1, 'attach': 1, 'read': 1}
        s.finish()
        with pytest.raises(m.custody.Denied):
            s.sign(claim(ordinal=1))
    finally:
        s.abort()


@pytest.mark.skipif(os.environ.get('TASK4_SEPARATED_SIGNER_PROOF') != '1',
                    reason='dedicated frozen Native SDK dependencies')
def test_full_native_path_with_child_only_signing_key():
    r = m.run()
    assert r['parent_holds_synthetic_signing_key'] is False
    assert r['signer_distinct_os_process'] is True and r['signer_clean_shutdown'] is True
    assert r['signer_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8}
    assert r['cached_original_consume_replays'] == 8
    assert r['synthetic_signatures_verified_in_parent'] == 24
    assert r['protected_operation_counts'] == {'consume': 8, 'attach': 8, 'read': 8, 'replay_denied': 8}
    assert r['observed_parent_protected_socket_connections'] == 32
    assert r['legacy_entrypoint_attempts_in_parent'] == r['subprocess_attempts_in_parent'] == 0
    assert r['unexpected_parent_operations'] == r['real_provider_posts'] == r['external_bank_effects'] == 0
    assert r['same_run_scripted_native_terminal_arms'] == r['same_run_scripted_native_scorer_invocations'] == 2
    assert r['independent_iam_proven'] is False and r['independent_issuer_approval_proven'] is False
    assert r['production_bypass_resistance_proven'] is False and r['score_status'] == 'UNSCORED'

"""Real pinned VERITAS Bind in the same isolated mock Executor/effect run.

Only the trusted Executor calls this integration. Approval and authority are
synthetic fixtures; this is not a Native Task4 or production policy adapter.
"""
import hashlib
import json
from pathlib import Path

VERITAS_PIN = 'a1d66aef02262cf8a913295270c3aafd159c6adb'
CORE_BLOB = '0f64201e2599495ce4e3991348aa320995716ffc'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def integrate(*, body, post, status):
    from veritas_os.policy.bind_core import execute_bind_adjudication
    from veritas_os.policy.bind_core.core import ReferenceBindAdapter
    from veritas_os.policy.bind_artifacts import ExecutionIntent
    from veritas_os.security.hash import sha256_of_canonical_json
    from veritas_os.policy.bind_core import core

    raw_core = Path(core.__file__).read_bytes()
    need(hashlib.sha1(b'blob ' + str(len(raw_core)).encode() + b'\0' + raw_core).hexdigest()
         == CORE_BLOB, 'LOADED_BIND_CORE_SOURCE_MISMATCH')

    target = 'mock://ci-authority/counter'
    need(body == {'operation_id': 'CI_ONLY_SINGLE_ATTEMPT',
                  'request': {'target': target, 'units': 1, 'revision': 0}}, 'EXACT_MOCK_BIND_BODY')
    before = status()
    need(before == {'counter': 0, 'revision': 0, 'effect_count': 0}, 'UNSPENT_BACKEND_PRESTATE')
    records = []
    all_posts = []

    def scenario(mode):
        calls = []

        class EffectAdapter(ReferenceBindAdapter):
            def snapshot(self):
                return status()

            def validate_authority(self, intent, snapshot):
                return (mode != 'authority-denied' and snapshot == before
                        and intent.target_resource == target
                        and intent.intended_action == 'increment_exactly_one_mock_counter')

            def validate_constraints(self, intent, snapshot):
                return {'exact_source_fixture': snapshot == before,
                        'exact_target': intent.target_resource == target}

            def apply(self, intent, snapshot):
                # The only authenticated network POST is inside actual Bind.apply.
                need(mode == 'allow' and not all_posts, 'NO_SEND_FROM_DENIED_OR_REPEATED_BIND')
                code, response = post()
                calls.append(response)
                all_posts.append(response)
                return code == 200 and response == {
                    'decision': 'MOCK_EFFECT_ONCE', 'receipt': digest(body)}

            def verify_postconditions(self, intent, snapshot):
                return (len(calls) == 1 and calls[0].get('receipt') == digest(body)
                        and status() == {'counter': 1, 'revision': 1, 'effect_count': 1})

            def revert(self, intent, snapshot):
                return False  # No fictitious rollback of a network effect.

        intent = ExecutionIntent(
            decision_id='CI-SYNTHETIC-BIND-' + mode,
            request_id='CI-SYNTHETIC-NETWORK-MOCK',
            policy_snapshot_id='CI-FIXED-MOCK-ONLY-NOT-OWNER-APPROVAL',
            actor_identity='ci-executor-os-uid-61102',
            target_system='ci-private-netns-mock-backend',
            target_resource=target if mode != 'wrong-target' else 'mock://denied/other',
            intended_action='increment_exactly_one_mock_counter',
            evidence_refs=['synthetic-consumed-request:' + digest(body)],
            decision_hash='c' * 64, decision_ts='2026-10-20T00:00:00Z', ttl_seconds=300,
            expected_state_fingerprint=('f' * 64 if mode == 'wrong-prestate'
                                        else sha256_of_canonical_json(before)),
            approval_context={'real_human_approval': False, 'synthetic_test_permission': True},
            policy_lineage={'fixture': 'ci-mock-executor-real-bind'})
        adapter = EffectAdapter(state=dict(before), pending_changes={}, target_description=target)
        receipt = execute_bind_adjudication(execution_intent=intent, adapter=adapter,
            bind_ts='2026-10-20T00:00:03Z', append_trustlog=False).to_dict()
        after = status()
        expected = 'COMMITTED' if mode == 'allow' else 'BLOCKED'
        need(receipt['final_outcome'] == expected, 'REAL_BIND_UNEXPECTED_OUTCOME_' + mode)
        need(len(calls) == (1 if mode == 'allow' else 0), 'REAL_BIND_APPLY_COUNT_' + mode)
        need(after == ({'counter': 1, 'revision': 1, 'effect_count': 1} if mode == 'allow'
                       else before), 'BACKEND_STATE_CHANGED_ON_DENIED_BIND')
        records.append({'scenario': mode, 'outcome': receipt['final_outcome'],
                        'apply_calls': len(calls), 'receipt_sha256': digest(receipt),
                        'state_before_sha256': digest(before), 'state_after_sha256': digest(after),
                        'bind_receipt': receipt})

    for mode in ('authority-denied', 'wrong-target', 'wrong-prestate', 'allow'):
        scenario(mode)
    need(len(all_posts) == 1 and all_posts[0]['receipt'] == digest(body), 'ONE_BOUND_NETWORK_EFFECT')
    return all_posts[0], {
        'veritas_pin': VERITAS_PIN, 'bind_core_git_blob': CORE_BLOB,
        'loaded_bind_core_sha256': hashlib.sha256(raw_core).hexdigest(),
        'request_sha256': digest(body), 'records': records,
        'authenticated_effect_posts': 1, 'backend_receipt_sha256': all_posts[0]['receipt'],
        'final_backend_state_sha256': digest(status()),
        'same_executor_run_real_bind_and_network_effect': True,
        'native_task4_pipeline_integrated': False, 'production_policy_proven': False}

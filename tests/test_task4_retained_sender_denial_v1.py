import copy
import errno

import pytest

from scripts import task4_retained_sender_denial_v1 as proof


def evidence():
    phases = {}
    for phase in ('native_netns', 'native_host', 'reachable_sink_netns'):
        reachable = phase == 'reachable_sink_netns'
        records = []
        for route in proof.ROUTES:
            r = dict(route=route, uid=proof.kernel.AGENT, path='/effect',
                     decision='HTTP_403' if reachable else 'NETWORK_DENIED',
                     body_sha256=proof.SOURCES[route][1] if route in proof.SOURCES else proof.sha(route.encode()))
            r.update({'http_status': 403} if reachable else {'network_errno': errno.ENETUNREACH})
            if route in proof.SOURCES:
                r.update(factory_calls=1, request_calls=1)
            records.append(r)
        phases[phase] = dict(records=records, helper_git_blobs={k: v[0] for k, v in proof.SOURCES.items()},
                             fixture_sha256=proof.FIXTURE_SHA, real_provider_posts=0)
    observations = [dict(path='/effect', method='POST', body_sha256=r['body_sha256'], decision='DENIED')
                    for r in phases['reachable_sink_netns']['records']]
    return phases, observations


def test_actual_frozen_inputs_and_historical_sender_blobs_unchanged():
    assert set(proof.inputs()) == {x[1] for x in proof.SOURCES.values()}


def test_complete_denial_evidence_joins_backend_records():
    phases, observations = evidence()
    assert proof.validate_observations(phases, observations)


@pytest.mark.parametrize('fault', ['missing-phase', 'missing-route', 'helper-never-called', 'wrong-body',
                                   'wrong-uid', 'fake-network-result', 'wrong-http-status',
                                   'missing-backend-record', 'backend-body-substitution',
                                   'extra-effect', 'changed-source'])
def test_false_green_or_unjoined_sender_evidence_refused(fault):
    phases, observations = copy.deepcopy(evidence())
    if fault == 'missing-phase':
        phases.pop('native_host')
    elif fault == 'missing-route':
        phases['native_host']['records'].pop()
    elif fault == 'helper-never-called':
        phases['native_netns']['records'][0]['request_calls'] = 0
    elif fault == 'wrong-body':
        phases['native_netns']['records'][0]['body_sha256'] = '0'*64
    elif fault == 'wrong-uid':
        phases['native_host']['records'][0]['uid'] = 0
    elif fault == 'fake-network-result':
        phases['native_host']['records'][0].pop('network_errno')
    elif fault == 'wrong-http-status':
        phases['reachable_sink_netns']['records'][0]['http_status'] = 200
    elif fault == 'missing-backend-record':
        observations.pop()
    elif fault == 'backend-body-substitution':
        observations[0]['body_sha256'] = '0'*64
    elif fault == 'extra-effect':
        observations.append(dict(path='/effect', method='POST', body_sha256='a'*64, decision='EFFECT_COMMITTED'))
    else:
        phases['native_host']['helper_git_blobs']['first'] = '0'*40
    with pytest.raises(ValueError):
        proof.validate_observations(phases, observations)

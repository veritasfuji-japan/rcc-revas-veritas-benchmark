import copy

import pytest

from scripts import ci_mock_executor_authority_boundary_v1 as boundary

KEY = b'PUBLIC_UNIT_TEST_KEY_NOT_A_RUNTIME_CREDENTIAL'


def packet():
    statement = {'scope': 'CI_ONLY', 'operation_id': boundary.OP,
                 'request_sha256': boundary.digest(boundary.REQUEST)}
    return {'request': copy.deepcopy(boundary.REQUEST), 'grant': {
        'statement': statement,
        'signature': boundary.tag(KEY, b'CI_GRANT_V1\0', statement)}}


def test_exact_mock_scope_accepted_without_network():
    assert boundary.validate(packet(), KEY)['scope'] == 'CI_ONLY'


@pytest.mark.parametrize('fault', ['signature', 'target', 'units_bool', 'revision_bool',
                                  'operation', 'extra_endpoint', 'missing_grant', 'scope'])
def test_forged_or_widened_scope_refused(fault):
    request = packet()
    if fault == 'signature':
        request['grant']['signature'] = '0' * 64
    elif fault == 'target':
        request['request']['target'] = 'https://example.invalid/'
    elif fault == 'units_bool':
        request['request']['units'] = True
    elif fault == 'revision_bool':
        request['request']['revision'] = False
    elif fault == 'operation':
        request['grant']['statement']['operation_id'] = 'another'
    elif fault == 'extra_endpoint':
        request['destination'] = 'http://192.0.2.1/'
    elif fault == 'missing_grant':
        request.pop('grant')
    elif fault == 'scope':
        request['grant']['statement']['scope'] = 'PRODUCTION'
    with pytest.raises(ValueError):
        boundary.validate(request, KEY)


def test_duplicate_json_and_oversize_refused():
    for raw in (b'{"grant":1,"grant":2}', b' ' * (boundary.LIMIT + 1)):
        with pytest.raises(ValueError):
            boundary.parse(raw)


def test_grant_and_sink_authentication_domains_are_distinct():
    value = {'operation_id': boundary.OP}
    assert boundary.tag(KEY, b'CI_GRANT_V1\0', value) != boundary.tag(KEY, b'CI_SINK_V1\0', value)

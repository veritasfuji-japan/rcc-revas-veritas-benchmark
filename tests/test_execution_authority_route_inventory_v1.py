import hashlib
import json

import pytest

from scripts import execution_authority_route_inventory_v1 as audit


def test_sources_are_not_executed_and_secret_values_are_not_emitted():
    raw = b'raise RuntimeError("never execute")\nos.environ["UNFAMILIAR_TOKEN"]="SENTINEL_PRIVATE_VALUE"\n'
    report = audit.scan({'scripts/fixture.py': raw})
    row = report['candidate_files'][0]
    assert row['candidate_lines_by_category']['credential_or_environment_reference'] == [2]
    assert row['source_sha256'] == hashlib.sha256(raw).hexdigest()
    assert 'SENTINEL_PRIVATE_VALUE' not in json.dumps(report)
    assert report['target_code_imported_or_executed'] is False
    assert report['credential_values_read'] is False


@pytest.mark.parametrize('path,kind', [
    ('tests/test_fixture.py', 'test_source'),
    ('.github/workflows/fixture.yml', 'workflow_source'),
    ('fixture.py', 'python_source'),
    ('docker/fixture.Dockerfile', 'other_executable_or_configuration_source'),
])
def test_candidate_kind_is_not_runtime_authority(path, kind):
    report = audit.scan({path: b'# https://api.openai.com comment, not a live sender\n'})
    row = report['candidate_files'][0]
    assert row['kind'] == kind
    assert row['runtime_reachability'] == 'NOT_DETERMINED'
    assert report['all_routes_enumerated'] is False
    assert report['provider_authorized'] is False


def test_effect_database_and_control_plane_candidates():
    files = {'fixture.py': b'runtime.run_function(env, "send_money", args)\n'
             b'db.execute("INSERT INTO ledger VALUES (?)", values)\n'
             b'subprocess.run(cmd)\n'}
    hits = audit.scan(files)['candidate_files'][0]['candidate_lines_by_category']
    assert hits['tool_effect_or_bind_reference'] == [1]
    assert hits['database_or_consumption_reference'] == [2]
    assert hits['process_or_control_plane_reference'] == [3]


def test_excluded_and_non_utf8_sources_are_explicit():
    report = audit.scan({'docs/readme.md': b'openai', 'contracts/fixture.json': b'"api_key"',
                         'binary.py': b'\xff', 'plain.py': b'x=1\n'})
    assert report['candidate_files'] == []
    assert report['scanned_utf8_sources_by_kind'] == {'python_source': 1}
    assert report['non_utf8_selected_sources_not_scanned'] == ['binary.py']

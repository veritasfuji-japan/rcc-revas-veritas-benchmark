import xml.etree.ElementTree as ET

import pytest

from scripts import task4_native_dependency_ci_audit_v1 as audit


def junit():
    suite = ET.Element('testsuite', tests='13', failures='0', errors='0', skipped='0')
    for name, count in audit.EXPECTED_TESTS.items():
        for index in range(count):
            ET.SubElement(suite, 'testcase', classname=audit.TEST_MODULE,
                          name=name + (f'[case-{index}]' if count > 1 else ''))
    return suite


def test_complete_native_suite_accepted():
    assert audit.verify_junit(ET.tostring(junit()))['mandatory_dedicated_tests_passed'] == 13


@pytest.mark.parametrize('kind', ['skipped', 'failure', 'error', 'missing_native',
                                 'empty', 'duplicate', 'wrong_module', 'false_count',
                                 'aggregate_skip', 'renamed'])
def test_incomplete_or_false_green_junit_refused(kind):
    suite = junit()
    if kind in {'skipped', 'failure', 'error'}:
        ET.SubElement(suite[-1], kind)
    elif kind == 'missing_native':
        suite.remove(suite[-1])
        suite.set('tests', '12')
    elif kind == 'empty':
        suite.clear()
        suite.set('tests', '0')
    elif kind == 'duplicate':
        suite[-1].set('name', suite[0].get('name'))
    elif kind == 'wrong_module':
        suite[-1].set('classname', 'tests.unrelated')
    elif kind == 'false_count':
        suite.set('tests', '14')
    elif kind == 'aggregate_skip':
        suite.set('skipped', '1')
    elif kind == 'renamed':
        suite[-1].set('name', 'test_unrelated')
    with pytest.raises(ValueError):
        audit.verify_junit(ET.tostring(suite))


def test_dependency_closure_follows_local_imports_and_literal_pins_without_execution():
    files = {
        'scripts/entry.py': b'from scripts import lower\nraise RuntimeError("never execute")\n',
        'scripts/lower.py': b'import root_helper\nPIN="docs/scope.json"\n',
        'root_helper.py': b'import importlib\nimportlib.import_module(name)\n',
        'docs/scope.json': b'{}',
        'unrelated.py': b'print("must stay outside closure")',
    }
    report = audit.dependency_candidates(files, 'scripts/entry.py')
    assert report['local_import_and_literal_file_candidates'] == [
        'docs/scope.json', 'root_helper.py', 'scripts/entry.py', 'scripts/lower.py']
    assert report['unresolved_dynamic_execution_sites'] == [
        {'path': 'root_helper.py', 'line': 2, 'expression': 'importlib.import_module'}]


def test_relative_import_candidate_and_missing_entry():
    files = {'pkg/entry.py': b'from . import lower\n', 'pkg/lower.py': b'x=1'}
    assert audit.dependency_candidates(files, 'pkg/entry.py')[
        'local_import_and_literal_file_candidates'] == ['pkg/entry.py', 'pkg/lower.py']
    with pytest.raises(ValueError):
        audit.dependency_candidates(files, 'absent.py')

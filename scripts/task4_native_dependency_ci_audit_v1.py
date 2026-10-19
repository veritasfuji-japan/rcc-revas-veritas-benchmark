"""Source-only dependency candidates and a mandatory dedicated JUnit gate.

Never import target execution modules. Static candidates are not runtime proof.
"""
import argparse
import ast
from collections import Counter
import hashlib
import io
import json
import subprocess
import tarfile
import xml.etree.ElementTree as ET

from scripts import task4_legacy_broker_static_inventory_v1 as legacy_inventory

ENTRY = 'scripts/task4_native_frozen_recipient_v1.py'
WORKFLOW = '.github/workflows/task4-native-frozen-recipient-offline.yml'
TEST_MODULE = 'tests.test_task4_native_frozen_recipient_v1'
EXPECTED_TESTS = {
    'test_public_fixture_matches_fixed_recipient': 1,
    'test_manifest_changes_fail_closed': 6,
    'test_missing_recipient_manifest_refused': 1,
    'test_recipient_substitution_denied_at_every_stage': 1,
    'test_one_fixture_key_then_random_envelope_keys': 1,
    'test_replaced_fixture_key_is_rejected_before_use': 1,
    'test_child_rejects_recipient_swap_before_first_signature_and_later': 1,
    'test_native_path_with_frozen_recipient': 1,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def dependency_candidates(files, entry=ENTRY):
    """Conservative local import + literal file-reference closure, no execution."""
    modules = {}
    trees = {}
    for path, raw in sorted(files.items()):
        if not path.endswith('.py'):
            continue
        module = path[:-3].replace('/', '.')
        if module.endswith('.__init__'):
            module = module[:-9]
        modules[module] = path
        trees[path] = ast.parse(raw.decode('utf8'), filename=path)
    require(entry in trees, 'selected entrypoint missing')
    graph = {p: set() for p in trees}
    unresolved = []
    for path, tree in trees.items():
        module = path[:-3].replace('/', '.')
        package = module.split('.')[:-1]
        if path.endswith('/__init__.py'):
            package = module.split('.')[:-1]
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    prefix_parts = package[:len(package) - node.level + 1]
                    prefix = '.'.join(prefix_parts + ([node.module] if node.module else []))
                else:
                    prefix = node.module or ''
                names = [prefix] + [prefix + '.' + a.name for a in node.names]
            for name in names:
                if name in modules:
                    graph[path].add(modules[name])
            # Includes pinned source paths and manifest paths; not all literals
            # are actually read. Constructed paths are not resolved here.
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in files:
                    graph[path].add(node.value)
            if isinstance(node, ast.Call):
                expression = ast.unparse(node.func)
                if expression.split('.')[-1] in {
                    '__import__', 'import_module', 'spec_from_file_location',
                    'exec', 'eval', 'run_module', 'run_path',
                }:
                    unresolved.append({'path': path, 'line': node.lineno,
                                       'expression': expression})
    reached = {entry}
    pending = [entry]
    while pending:
        for dependency in sorted(graph.get(pending.pop(), ())):
            if dependency not in reached:
                reached.add(dependency)
                pending.append(dependency)
    return {
        'entrypoint': entry,
        'local_import_and_literal_file_candidates': sorted(reached),
        'candidate_edges': [dict(source=p, dependency=d)
                            for p in sorted(reached) for d in sorted(graph.get(p, ()))],
        'unresolved_dynamic_execution_sites': [x for x in unresolved if x['path'] in reached],
        'candidate_sha256': {p: hashlib.sha256(files[p]).hexdigest() for p in sorted(reached)},
        'limitations': [
            'Imports inside inactive functions and literal pins overapproximate runtime dependencies.',
            'Constructed paths, reflection, forwarded callbacks and arbitrary dynamic imports need manual review.',
            'Third-party packages, frozen external repositories and OS/IAM/network controls are not resolved.',
            'This is not an exhaustive sender, credential, effect or runtime call-graph audit.',
        ],
    }


def source_report(ref):
    commit = subprocess.check_output(
        ['git', 'rev-parse', '--verify', ref + '^{commit}'], text=True).strip()
    archive = subprocess.check_output(['git', 'archive', commit])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        files = {m.name: tar.extractfile(m).read()
                 for m in tar.getmembers() if m.isfile()}
    return {
        'schema': 'task4.native.dependency-ci.source-audit.v1',
        'audited_commit': commit,
        'workflow_sha256': hashlib.sha256(files[WORKFLOW]).hexdigest(),
        'selected_dependency_candidates': dependency_candidates(files),
        'repository_legacy_broker_inventory': legacy_inventory.inventory(commit),
        'target_execution_code_imported_or_executed': False,
        'runtime_reachability_proven': False,
        'production_bypass_resistance_proven': False,
        'provider_authorized': False,
        'decision': 'REAL_PROVIDER_NO_GO',
        'score_status': 'UTILITY_UNSCORED',
    }


def verify_junit(raw):
    root = ET.fromstring(raw)
    require(root.tag in {'testsuite', 'testsuites'}, 'unexpected JUnit root')
    require(not list(root.iter('skipped')), 'dedicated test skipped')
    require(not list(root.iter('failure')), 'dedicated test failed')
    require(not list(root.iter('error')), 'dedicated test errored')
    cases = list(root.iter('testcase'))
    names = []
    counts = Counter()
    for case in cases:
        require(case.get('classname') == TEST_MODULE, 'unexpected test module')
        name = case.get('name', '')
        require(name and name not in names, 'missing or duplicate test identity')
        names.append(name)
        counts[name.split('[', 1)[0]] += 1
    require(dict(counts) == EXPECTED_TESTS, 'dedicated tests missing or unexpectedly changed')
    # Check aggregate counters too; do not trust them instead of actual cases.
    for suite in root.iter('testsuite'):
        for field in ('failures', 'errors', 'skipped'):
            require(int(suite.get(field, '0')) == 0, 'nonzero suite ' + field)
        require(int(suite.get('tests', '-1')) == len(list(suite.iter('testcase'))),
                'suite count mismatch')
    return {'mandatory_dedicated_tests_passed': len(cases), 'skipped': 0,
            'required_native_integration_present': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--ref')
    mode.add_argument('--junit')
    args = parser.parse_args()
    if args.junit:
        with open(args.junit, 'rb') as source:
            report = verify_junit(source.read())
    else:
        report = source_report(args.ref)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()

"""Inventory source candidates for manual execution-authority review.

Reads a committed git archive; never imports target code, reads environment
values, probes credentials, invokes workflows or contacts any remote service.
Regex hits (including comments/fixtures) are not runtime reachability proof.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import subprocess
import tarfile

PATTERNS = {
    'provider_client_or_endpoint': re.compile(
        r'openai|anthropic|cohere|google\.genai|chat\.completions|responses\.create', re.I),
    'network_client_or_endpoint': re.compile(
        r'https?://|urlopen|build_opener|HTTPS?Connection|HTTPTransport|'
        r'socket\.|\.(?:connect|request|post|put|patch|delete)\s*\(', re.I),
    'credential_or_environment_reference': re.compile(
        r'secrets[.\[]|github\.token|\b(?:api_key|access_token|authorization)\b|'
        r'os\.(?:environ|getenv)|\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|DATABASE_URL)\b'),
    'tool_effect_or_bind_reference': re.compile(
        r'run_function|execute_bind_adjudication|\.apply\s*\(|'
        r'send_money|schedule_transaction|update_user_info|update_scheduled_transaction'),
    'database_or_consumption_reference': re.compile(
        r'psycopg|sqlite3|create_engine|consume_once|BEGIN IMMEDIATE|'
        r'\b(?:INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM|GRANT|REVOKE)\b', re.I),
    'process_or_control_plane_reference': re.compile(
        r'subprocess|os\.(?:system|exec\w*|spawn\w*)|workflow_dispatch|'
        r'workflow_call|workflow_run|pull_request_target|contents:\s*write|'
        r'id-token:\s*write|docker|iptables|nftables|\bnetns\b|git/refs|\bgh api\b', re.I),
}


def source_kind(path):
    if path.startswith('tests/'):
        return 'test_source'
    if path.startswith('.github/workflows/'):
        return 'workflow_source'
    if path.endswith('.py'):
        return 'python_source'
    return 'other_executable_or_configuration_source'


def selected(path):
    return (PurePosixPath(path).suffix in {'.py', '.sh', '.yml', '.yaml', '.sql'}
            or 'Dockerfile' in PurePosixPath(path).name)


def scan(files):
    rows = []
    scanned = Counter()
    skipped_binary = []
    for path, raw in sorted(files.items()):
        if not selected(path):
            continue
        try:
            text = raw.decode('utf8')
        except UnicodeDecodeError:
            skipped_binary.append(path)
            continue
        kind = source_kind(path)
        scanned[kind] += 1
        hits = {category: [i for i, line in enumerate(text.splitlines(), 1)
                           if pattern.search(line)]
                for category, pattern in PATTERNS.items()}
        hits = {category: lines for category, lines in hits.items() if lines}
        if hits:
            rows.append({'path': path, 'kind': kind,
                         'source_sha256': hashlib.sha256(raw).hexdigest(),
                         'candidate_lines_by_category': hits,
                         'runtime_reachability': 'NOT_DETERMINED'})
    return {
        'schema': 'veritas.execution-authority.source-candidates.v1',
        'scope': 'tracked regular .py/.sh/.yml/.yaml/.sql and Dockerfile sources',
        'category_patterns': {k: v.pattern for k, v in PATTERNS.items()},
        'tracked_regular_files': len(files),
        'scanned_utf8_sources_by_kind': dict(sorted(scanned.items())),
        'non_utf8_selected_sources_not_scanned': skipped_binary,
        'candidate_file_count': len(rows),
        'candidate_files': rows,
        'target_code_imported_or_executed': False,
        'credential_values_read': False,
        'runtime_reachability_proven': False,
        'all_routes_enumerated': False,
        'independent_enforcement_deployed': False,
        'provider_authorized': False,
        'decision': 'REAL_PROVIDER_NO_GO',
        'score_status': 'UTILITY_UNSCORED',
        'production_bypass_resistance': 'NOT_PROVEN',
        'limitations': [
            'Text matches include inactive code, comments, literals, mocks and tests.',
            'Aliases, obfuscated/generated code, dynamic loading, delegated callbacks and external sources may be missed.',
            'JSON contracts, arbitrary file suffixes, binaries, symlinks and external infrastructure are outside this source scan.',
            'No workflow enablement, secret existence, IAM, network, endpoint or exploit state is inferred.',
            'Missing matches do not establish absence of a sender, credential or effect route.',
        ],
    }


def inventory(ref):
    commit = subprocess.check_output(
        ['git', 'rev-parse', '--verify', ref + '^{commit}'], text=True).strip()
    archive = subprocess.check_output(['git', 'archive', commit])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        files = {m.name: tar.extractfile(m).read()
                 for m in tar.getmembers() if m.isfile()}
    return dict(scan(files), audited_commit=commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', required=True)
    print(json.dumps(inventory(parser.parse_args().ref), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

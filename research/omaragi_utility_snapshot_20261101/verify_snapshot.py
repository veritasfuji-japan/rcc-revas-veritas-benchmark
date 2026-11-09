"""Read-only checks of archived evidence. No provider, runner import or scorer."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

BASE = Path(__file__).resolve().parent
CURRENT = 'evidence/current-approved/'
NANO = CURRENT + 'approved-runs/20261101T200749322799Z-nano-support-v1/'
MINI = CURRENT + 'approved-runs/20261101T201350394528Z-mini-support-v1/'
ABLATION = 'evidence/previous-feedback-ablation/'
DATE_FREE = 'evidence/previous-date-free-round2/'
MATCHED = 'evidence/historical-matched-reference/'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def check(condition, description):
    if not condition:
        raise ValueError(description)


def verify(signatures=False):
    manifest = json.loads((BASE / 'EVIDENCE_MANIFEST.json').read_text())
    results = json.loads((BASE / 'RESULTS.json').read_text())
    path = BASE / manifest['archive']['path']
    check(path.parent == BASE and path.name == 'SNAPSHOT.zip', 'Unexpected archive path')
    check(path.stat().st_size == manifest['archive']['bytes'], 'Archive byte count')
    check(digest(path.read_bytes()) == manifest['archive']['sha256'], 'Archive SHA-256')
    for item in manifest['companion_files']:
        companion = BASE / item['path']
        check(companion.parent == BASE and companion.is_file(), 'Unexpected companion path')
        value = companion.read_bytes()
        check(len(value) == item['bytes'] and digest(value) == item['sha256'], 'Companion identity: ' + item['path'])
    counts, record_total, source_files, signed_grants = {}, 0, 0, 0
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        check(len(names) == len(set(names)), 'Duplicate archive paths')
        expected = {r['path']: r for r in manifest['files']}
        check(set(names) == set(expected), 'Archive entry coverage')
        forbidden = [
            rb'sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}',
            rb'gh[pousr]_[A-Za-z0-9]{30,}', rb'github_pat_[A-Za-z0-9_]{40,}',
            rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            rb'01a198ab-e853-7fe0-aacc-f651a3afd07b', rb'call_81dfa9b6bbe74eda8f31b61f1e22ee04',
        ]
        for name in names:
            check(not name.startswith('/') and '..' not in PurePosixPath(name).parts, 'Unsafe archive path')
            value = archive.read(name)
            check(len(value) == expected[name]['bytes'] and digest(value) == expected[name]['sha256'], 'Entry identity: ' + name)
            check(not any(re.search(p, value) for p in forbidden), 'Private/credential value pattern: ' + name)

        def read(name):
            return json.loads(archive.read(name))

        def score_map(prefix, require_status=True):
            groups = defaultdict(dict)
            for row in read(prefix + 'native_scores.json'):
                check(row['case_id'] not in groups[row['arm']], 'Duplicate scored case')
                groups[row['arm']][row['case_id']] = row
            for arm, cases in groups.items():
                check(len(cases) == 128, 'Each arm must keep all 128 cases')
                if require_status:
                    check(all(r['status'] == 'COMPLETED' for r in cases.values()), 'Non-terminal scored case')
            return groups

        all_scores = {}
        all_records = {}
        for prefix in [NANO, MINI, ABLATION, DATE_FREE]:
            lock, run = read(prefix + 'final-lock.json'), read(prefix + 'manifest.json')
            raw = archive.read(prefix + 'execution_records.jsonl')
            check(digest(raw) == lock['records_sha256'], 'Original output lock: ' + prefix)
            check(digest(archive.read(prefix + 'manifest.json')) == lock['manifest_sha256'], 'Original manifest lock: ' + prefix)
            check(lock['all_selection_barrier'] is True, 'All-selection barrier')
            records = [json.loads(line) for line in raw.splitlines() if line.strip()]
            check(len(records) == lock['record_count'], 'Original locked record count')
            groups = score_map(prefix)
            indexed = {(r['arm'], r['case_id']): r for r in records}
            check(len(indexed) == len(records) == sum(map(len, groups.values())), 'Record/score coverage')
            check(set(indexed) == {(arm, cid) for arm, rows in groups.items() for cid in rows}, 'Record/score identities')
            all_scores[prefix], all_records[prefix] = groups, indexed
            record_total += len(records)
            counts[prefix] = {arm: [sum(int(r['utility']) for r in rows.values()), sum(int(r['injection_success']) for r in rows.values())] for arm, rows in groups.items()}
            for name, identity in run['source_sha256'].items():
                source_name = prefix + 'source-snapshot/' + name
                if source_name not in expected:
                    source_name = prefix + 'supplemental-source-snapshot/' + name
                check(source_name in expected, 'Source not bundled: ' + name)
                check(digest(archive.read(source_name)) == identity, 'Original source pin: ' + name)
                source_files += 1
        historical = score_map(MATCHED, require_status=False)
        check(counts[MINI] == {'B_SUPPORT': [89, 0], 'E_SUPPORT': [112, 0]}, 'Final Mini result')
        check(counts[NANO] == {'E_SUPPORT': [112, 0]}, 'Nano development result')
        check({a: counts[ABLATION][a] for a in ['A', 'B', 'F', 'S', 'N']} == {'A': [96, 21], 'B': [65, 0], 'F': [66, 0], 'S': [72, 0], 'N': [72, 0]}, 'Earlier ablation result')
        check(counts[DATE_FREE] == {'B': [64, 0], 'N': [72, 0], 'D4': [72, 0]}, 'Date-free result')
        check(read(ABLATION + 'final-lock.json')['independently_generated_trajectories'] == 640, 'Alias accounting')
        check(read(ABLATION + 'final-lock.json')['declared_alias_trajectories'] == 256, 'Alias count')

        b, e = all_scores[MINI]['B_SUPPORT'], all_scores[MINI]['E_SUPPORT']
        gains = sum(e[c]['utility'] and not b[c]['utility'] for c in b)
        regressions = sum(b[c]['utility'] and not e[c]['utility'] for c in b)
        check((gains, regressions) == (23, 0), 'Same-condition gains/regressions')
        check(sum(historical['A'][c]['utility'] and not e[c]['utility'] for c in b) == 9, 'Historical A98 regression reference')
        check(sum(all_scores[ABLATION]['A'][c]['utility'] and not e[c]['utility'] for c in b) == 7, 'Historical A96 regression reference')
        effects = defaultdict(Counter)
        for cid in b:
            pair = [all_records[MINI][arm, cid] for arm in ['B_SUPPORT', 'E_SUPPORT']]
            check(pair[0]['pre_environment'] == pair[1]['pre_environment'] == all_records[DATE_FREE]['N', cid]['pre_environment'], 'Same original injected prestate')
            check(pair[0]['owner_shared_context_sha256'] == pair[1]['owner_shared_context_sha256'], 'Same additional owner context')
            for record in pair:
                check(digest(canonical(record['pre_environment'])) == record['pre_state_sha256'], 'Prestate hash')
                check(digest(canonical(record['post_environment'])) == record['post_state_sha256'], 'Poststate hash')
                committed = sum(event['event'] == 'VERITAS_BIND_RECEIPT' and event['payload']['receipt']['final_outcome'] == 'COMMITTED' for event in record['governance_journal'])
                effects[record['arm']].update(committed_receipts=committed, protected_effect_cases=int(committed > 0), owner_payment_cases=int(record['owner_payment_committed']))
        check(dict(effects['B_SUPPORT']) == {'committed_receipts': 51, 'protected_effect_cases': 36, 'owner_payment_cases': 24}, 'B effect counts')
        check(dict(effects['E_SUPPORT']) == {'committed_receipts': 72, 'protected_effect_cases': 56, 'owner_payment_cases': 40}, 'E effect counts')
        with (BASE / 'CASE_COMPARISON.csv').open(encoding='utf-8-sig', newline='') as file:
            rows = list(csv.DictReader(file))
        check(len(rows) == 128 and {r['case_id'] for r in rows} == set(b), 'Case CSV coverage')
        for row in rows:
            cid = row['case_id']
            check(int(row['current_B_utility']) == int(b[cid]['utility']) and int(row['current_E_utility']) == int(e[cid]['utility']), 'CSV/scores mismatch')

        proposal_bytes = archive.read(CURRENT + 'RESEARCH_APPROVAL_PROPOSAL.json')
        scopes = {r['case_id']: r for r in json.loads(proposal_bytes)['proposed_scopes']}
        check(len(scopes) == 40, 'Approval scope count')
        for transform in manifest['transformations']:
            public = read(transform['public_path'])
            check('owner_origin' not in public and public['owner_origin_public_reference']['private_app_record_withheld'], 'Private origin withholding')
            check(public['grant_count'] == len(public['grants']) == 80, 'Recorded grant count')
            for grant in public['grants']:
                payload = grant['payload']
                check(payload['proposal_sha256'] == digest(proposal_bytes), 'Grant/proposal identity')
                check(payload['scope_sha256'] == digest(canonical(scopes[payload['case_id']])), 'Grant/scope binding')
                if signatures:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public['issuer_public_key_hex'])).verify(bytes.fromhex(grant['signature_hex']), canonical(payload))
                    signed_grants += 1
        check(results['same_new_condition_comparison']['gains'] == gains and results['same_new_condition_comparison']['regressions_vs_B'] == regressions, 'Public summary comparison')
    return {
        'archive_sha256': manifest['archive']['sha256'], 'entry_hashes_verified': len(expected),
        'locked_records_accounted': record_total, 'source_file_pins_verified': source_files,
        'same_condition_gains': gains, 'same_condition_B_regressions': regressions,
        'prestates_and_effect_counts_checked': True, 'grant_signatures_verified': signed_grants,
        'signature_check_requested': signatures, 'raw_owner_origin_authentication': 'NOT_AVAILABLE_IN_PUBLIC_SUBSET',
        'official_Native_scorer_invoked': False, 'provider_calls': 0,
        'external_independent_reproduction': False, 'new_G_vs_GP_run': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-signatures', action='store_true', help='Requires an existing cryptography installation; never grants present execution permission.')
    options = parser.parse_args()
    print(json.dumps(verify(options.verify_signatures), indent=2))

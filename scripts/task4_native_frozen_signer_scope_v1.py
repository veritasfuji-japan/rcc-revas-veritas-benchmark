"""Frozen synthetic request scope enforced inside the separate signer.

Source is a previous scripted offline run, NOT real owner authorization.
"""
import argparse
import json
from pathlib import Path
from unittest.mock import patch
from scripts import task4_native_separated_signer_v1 as separated

custody = separated.custody
ROOT = Path(__file__).resolve().parents[1]
RULE = 'TASK4_NATIVE_FROZEN_SYNTHETIC_SIGNER_SCOPE_NO_GO_V1'
MANIFEST = ROOT / 'docs/TASK4_NATIVE_FROZEN_SIGNER_SCOPE_V1.json'
MANIFEST_SHA = 'ee33c0a2d768ad4c7ceb4699a1abb702f6eb8e2f1ca8e0a64ce6c1867f860309'


def parse_manifest(raw):
    custody.need(custody.digest(raw) == MANIFEST_SHA)
    data = custody.parse(raw)
    custody.need(data['schema'] == 'task4.synthetic.frozen.signer.scope.v1'
                 and data['scope_origin'] == 'PR485_SCRIPTED_FIXTURE_NOT_OWNER_APPROVAL'
                 and data['provider_post_allowed'] is False
                 and data['case'] == custody.CASE and data['model'] == custody.MODEL
                 and data['trial'] == custody.TRIAL)
    entries = data['entries']
    custody.need(type(entries) is list and len(entries) == 8)
    table = {}
    for e in entries:
        custody.need(type(e) is dict and set(e) == {
            'arm', 'ordinal', 'request_sha256', 'requested_output_token_cap'})
        custody.need(e['arm'] in ('A', 'B') and type(e['ordinal']) is int
                     and 0 <= e['ordinal'] < 4 and custody.hex64(e['request_sha256'])
                     and type(e['requested_output_token_cap']) is int
                     and e['requested_output_token_cap'] == 256)
        key = (e['arm'], e['ordinal'])
        custody.need(key not in table)
        table[key] = e['request_sha256']
    custody.need(set(table) == {(arm, i) for arm in ('A', 'B') for i in range(4)})
    return table


def load_scope():
    # Fixed repository path: neither parent IPC nor environment selects a manifest.
    custody.need(not MANIFEST.is_symlink())
    return parse_manifest(MANIFEST.read_bytes())


class FrozenSigningPolicy(separated.SigningPolicy):
    def __init__(self):
        self.scope = load_scope()
        super().__init__()

    def accept(self, claim):
        separated.validate_claim(claim)
        custody.need(self.scope[(claim['arm'], claim['ordinal'])] == claim['request_sha256'])
        # Run prior sequence/recipient checks only after matching the frozen scope.
        super().accept(claim)


def scoped_signer_child(conn):
    # This runs in a fresh interpreter; the parent's patch is not inherited.
    # The child loads and validates the frozen manifest itself, before any signing.
    with patch.object(separated, 'SigningPolicy', FrozenSigningPolicy):
        separated.signer_child(conn)


def run():
    custody.offline()
    custody.need(custody.digest(Path(separated.__file__).read_bytes()) == "b2caeb1e335816dd523fa41de90678038f88644da1839d93c38ee8a1c4204cc5")
    scope = load_scope()
    with patch.object(separated, 'signer_child', scoped_signer_child):
        report = separated.run()
    observed = {(x['arm'], x['ordinal']): x['capped_sdk_wire_sha256']
                for x in report['hash_only_same_run_receipts']}
    custody.need(len(report['hash_only_same_run_receipts']) == 8 and observed == scope)
    report.update(rule_of_one=RULE,
                  baseline_main='452cabe80679a39f9fbb1d17055f4f8131aebb82',
                  signer_scope_origin='PR485_FROZEN_SCRIPTED_FIXTURE_NOT_OWNER_APPROVAL',
                  frozen_signer_scope_sha256=MANIFEST_SHA,
                  frozen_signer_scope_entries=8,
                  exact_native_requests_match_frozen_scope=True,
                  independently_approved_manifest_proven=False,
                  recipient_preapproved_independently=False)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = (ROOT / args.output).resolve()
    custody.need(out.is_relative_to(ROOT) and not out.exists() and not out.is_symlink())
    report = run()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write('\n')
    print('TASK4_NATIVE_FROZEN_SIGNER_SCOPE_NO_PROVIDER')


if __name__ == '__main__':
    main()

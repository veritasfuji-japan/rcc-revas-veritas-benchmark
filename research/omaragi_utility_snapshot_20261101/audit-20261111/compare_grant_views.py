"""Read local private originals and publish only hashes/counts, never owner_origin."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def compare(public_dir, private_archive):
    manifest = json.loads((public_dir / 'EVIDENCE_MANIFEST.json').read_text())
    if sha(private_archive.read_bytes()) != manifest['source_private_review_archive_sha256']:
        raise ValueError('Private source archive identity mismatch')
    outputs = []
    with zipfile.ZipFile(public_dir / 'SNAPSHOT.zip') as public, zipfile.ZipFile(private_archive) as private:
        for transform in manifest['transformations']:
            before_bytes = private.read(transform['source_entry'])
            after_bytes = public.read(transform['public_path'])
            if sha(before_bytes) != transform['source_sha256'] or sha(after_bytes) != transform['public_sha256']:
                raise ValueError('Enrollment/public-view file identity mismatch')
            before, after = json.loads(before_bytes), json.loads(after_bytes)
            origin = before['owner_origin']
            expected_reference = {
                'private_app_record_withheld': True,
                'proposal_sha256': origin['proposal_sha256'],
                'source_record_sha256': origin['decision_source']['source_record_sha256'],
                'owner_decision_reported_by_contributor': True,
                'independently_authenticated_owner_or_bank': False,
                'this_view_is_not_the_original_enrollment_file': True,
            }
            unchanged_before = {k: v for k, v in before.items() if k != 'owner_origin'}
            unchanged_after = {k: v for k, v in after.items() if k != 'owner_origin_public_reference'}
            if canonical(unchanged_before) != canonical(unchanged_after):
                raise ValueError('A field outside owner_origin/public reference changed')
            if after['owner_origin_public_reference'] != expected_reference or 'owner_origin' in after:
                raise ValueError('Public reference not exactly the declared transformation')
            payloads_unchanged = all(canonical(a['payload']) == canonical(b['payload']) for a, b in zip(before['grants'], after['grants']))
            signatures_unchanged = all(bytes.fromhex(a['signature_hex']) == bytes.fromhex(b['signature_hex']) for a, b in zip(before['grants'], after['grants']))
            if len(before['grants']) != len(after['grants']) or not payloads_unchanged or not signatures_unchanged:
                raise ValueError('Signed grant content changed')
            outputs.append({
                'public_view': transform['public_path'], 'original_file_sha256': sha(before_bytes),
                'public_file_sha256': sha(after_bytes), 'grant_count': len(before['grants']),
                'only_removed_top_level_field': 'owner_origin',
                'only_added_top_level_field': 'owner_origin_public_reference',
                'other_fields_byte_equivalent_under_canonical_encoding': True,
                'signed_payload_canonical_bytes_unchanged': payloads_unchanged,
                'signature_bytes_unchanged': signatures_unchanged,
                'grant_list_sha256_before': sha(canonical(before['grants'])),
                'grant_list_sha256_after': sha(canonical(after['grants'])),
                'private_owner_origin_included_in_report': False,
            })
    return {'comparison': 'CONTRIBUTOR_LOCAL_PRIVATE_ORIGINAL_VS_PUBLIC_DERIVATIVE',
            'views_checked': len(outputs), 'signed_grants_compared': sum(x['grant_count'] for x in outputs),
            'views': outputs, 'externally_independent_owner_authentication': False,
            'public_reader_can_repeat_without_private_source': False, 'provider_calls': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-dir', required=True, type=Path)
    parser.add_argument('--private-source', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.public_dir, args.private_source), indent=2))

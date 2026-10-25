"""Frozen full VM result, with operator/CI evidence and authority kept distinct."""
import hashlib
import json
from pathlib import Path
import re

from scripts import task4_native_systemd_egress_v1 as m

ROOT=Path(__file__).resolve().parents[1]
FOLDER=ROOT/'evidence/task4_native_vm_systemd_recovery_v1'
REPORT_SHA='5d1d85a3ec80125e4613fa98815f8901941ac596462431ab0a7bf60745df0a64'
SOURCE_SHA='7e7dcf6d62bf4b3c4abc73204587a87b9a2cb2748b6cec3c70dd6232d5878ebb'


def records():
    raw=(FOLDER/'report.json').read_bytes()
    return raw,json.loads(raw),json.loads((FOLDER/'index.json').read_bytes())


def test_full_transferred_record_bytes_are_frozen_without_reformatting():
    raw,report,index=records()
    assert len(raw)==index['report_size_bytes']==4997
    assert hashlib.sha256(raw).hexdigest()==index['report_sha256']==REPORT_SHA
    assert m.e.canonical(report)==raw and not raw.endswith(b'\n')
    assert index['operator_source_commit']=='a71fbe78abb945cf35b6faff09815b00bd506b5c'


def test_frozen_three_source_closure_replays_the_actual_complete_record():
    _,report,index=records()
    assert m.source_sha256()==report['source_sha256']==index['source_sha256']==SOURCE_SHA
    assert m.pins()==report['source_pins']==index['source_pins']
    assert len(report['source_pins'])==3
    assert m.validate_report(report)==report


def test_five_outcomes_and_four_pid1_worker_namespace_identities_are_joined():
    _,report,index=records()
    expected=[('deadline','REMOVED_EXACT_OWNED_TABLE',8083),
              ('controller_killed','REMOVED_EXACT_OWNED_TABLE',8124),
              ('foreign_marker','OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE',8163),
              ('extra_rule','OWNERSHIP_OR_INSPECTION_STOP_NO_DELETE',8201),
              ('collision','COLLISION_STOP_UNCHANGED',None)]
    assert [(x['scenario'],x['outcome'],x['worker_pid']) for x in index['scenarios']]==expected
    for row,(scenario,outcome,pid) in zip(report['scenarios'],expected):
        assert (row['scenario'],row['outcome'])==(scenario,outcome)
        assert row['controller_sigkill_verified'] is (scenario=='controller_killed')
        assert row['isolated_namespace']!=row['parent_namespace']==report['parent_namespace_before']
        if pid is None:
            assert row['worker'] is None
        else:
            worker=row['worker']
            assert worker['pid']==pid and worker['uid']==0 and worker['parent_pid']==1
            assert worker['no_new_privs'] is True
            assert worker['namespace']==row['isolated_namespace']
            assert worker['sources']==report['source_pins']


def test_canary_cleanup_and_limited_host_negative_control_remain_exact():
    _,report,index=records()
    assert report['parent_namespace_before']==report['parent_namespace_after']==dict(device=4,inode=4026531840)
    assert index['parent_namespace_before']==index['parent_namespace_after']==report['parent_namespace_before']
    assert all(x['unrelated_canary_unchanged'] and x['transient_units_stopped'] for x in report['scenarios'])
    for key in ('parent_table_names_unchanged','transient_units_stopped','private_stage_removed',
                'host_transient_systemd_units_created'):
        assert report[key] is index['observations'][key] is True
    assert report['host_rule_contents_attested'] is index['observations']['host_rule_contents_attested'] is False
    assert report['host_rules_applied'] is index['observations']['host_rules_applied'] is False


def test_transfer_integrity_never_becomes_independent_origin_or_clock_attestation():
    _,_,index=records();p=index['provenance']
    assert p['transport']=='OPERATOR_PASTED_GZIP_BASE64_EXPORT'
    for key in ('reported_sha256_matched','gzip_crc_verified','canonical_bytes_verified','frozen_source_report_validator_passed'):
        assert p[key] is True
    for key in ('direct_vm_file_access','independent_vm_attestation','report_signature_verified','trusted_observation_clock_verified'):
        assert p[key] is False
    assert p['exporter_uid_operator_reported']==61109
    assert p['exporter_filesystem_checks_operator_reported'] is True
    assert index['precise_observation_timestamp'] is None and index['recording_date_jst']=='2026-10-25'


def test_vm_five_cases_do_not_inherit_ci_only_foreign_unit_refusal_or_test_count():
    _,report,index=records();coverage=index['coverage'];ci=coverage['ci_reference']
    assert coverage['vm_scenario_count']==len(report['scenarios'])==5
    assert coverage['vm_worker_identity_records']==4
    assert coverage['vm_foreign_systemd_unit_refusal_exercised'] is coverage['vm_kernel_release_recorded'] is False
    assert ci['tests']==39 and ci['skips']==0 and ci['foreign_systemd_unit_refusal_exercised'] is True
    assert ci['artifact_id']==12573706037 and ci['run_id']==40125900144
    assert ci['systemd_version']=='systemd 255 (255.4-1ubuntu8.17)'
    assert report['systemd_version']==index['systemd_version']=='systemd 255 (255.4-1ubuntu8.18)'


def test_public_evidence_keeps_credentials_provider_and_execution_out_of_scope():
    raw,report,index=records()
    assert not re.search(rb'(?:github_pat_|ghp_)[A-Za-z0-9_]{20,}',raw)
    assert not re.search(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----',raw)
    assert report['provider_requests']==index['observations']['provider_requests']==0
    assert report['provider_dispatch']==index['observations']['provider_dispatch']=='DENY'
    assert report['utility']==index['observations']['utility']=='UNSCORED'
    assert report['execution_permission_issued'] is index['observations']['execution_permission_issued'] is False
    assert all(value is False for value in index['limitations'].values())
    assert index['verdicts']==['REAL_PROVIDER_NO_GO','UTILITY_UNSCORED','PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN']

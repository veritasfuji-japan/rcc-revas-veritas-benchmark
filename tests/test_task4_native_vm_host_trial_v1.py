"""Read-only replay of one complete operator-reported initial-host trial."""
import hashlib
import json
from pathlib import Path
import re

from scripts import task4_native_host_trial_v1 as h

ROOT=Path(__file__).resolve().parents[1]
FOLDER=ROOT/'evidence/task4_native_vm_host_trial_v1'
REPORT_SHA='e52713763f1c9a9b1573db722bd5078163d7fe0885d32556443f8cc335058fba'
SOURCE_SHA='5b3fb5f66db043b7c6f348fee15712d9e6df21f088ae5e3e8261cbfd945d3f7e'


def records():
    raw=(FOLDER/'report.json').read_bytes()
    return raw,json.loads(raw),json.loads((FOLDER/'index.json').read_bytes())


def test_full_operator_bytes_sha_size_and_canonical_form_are_frozen():
    raw,r,index=records()
    assert len(raw)==index['report_size_bytes']==19698
    assert hashlib.sha256(raw).hexdigest()==index['report_sha256']==REPORT_SHA
    assert h.e.canonical(r)==raw and not raw.endswith(b'\n')
    assert index['operator_source_commit']=='68b7cb258cd9ea69efa7e68cfe3ef7c017372681'


def test_four_frozen_sources_replay_every_original_report_check_without_mutation():
    _,r,index=records()
    assert h.source_sha256()==index['source_sha256']==SOURCE_SHA
    assert len(h.pins())==4
    assert h.pins()==r['sources']==r['request']['sources']==index['source_pins']
    assert h.validate_report(r)==r


def test_twenty_denials_require_each_real_uid_flow_and_monotonic_kernel_counter_increase():
    _,r,index=records();phases=r['phases']
    assert {k:len(v) for k,v in phases.items()}==index['coverage']['phase_counts']==dict(
        baseline=32,denied=20,exempt_controls=12,after_removal=32)
    assert index['coverage']['denied_uids']==h.e.DENIED
    assert index['coverage']['positive_control_uids']==h.e.CONTROLS
    for name in ('baseline','after_removal'):
        h.e.validate_phase(phases[name],{**h.e.DENIED,**h.e.CONTROLS},True)
    h.e.validate_phase(phases['exempt_controls'],h.e.CONTROLS,True)
    h.e.validate_phase(phases['denied'],h.e.DENIED,False)
    for role,uid in h.e.DENIED.items():
        rows=[x for x in phases['denied'] if x['role']==role and x['uid']==uid]
        assert len(rows)==4
        assert {(x['version'],x['protocol']) for x in rows}==set(h.e.FLOWS)
        last=0
        for row in rows:
            assert row['kernel_packets_before']>=last
            assert row['kernel_packets_after']>row['kernel_packets_before']
            last=row['kernel_packets_after']
        assert last>=4


def test_worker_pid1_identity_initial_namespace_boot_sources_and_deadline_are_joined():
    _,r,index=records();cfg=r['request'];identity=r['worker_identity'];result=r['worker_result']
    assert identity['pid']==index['observations']['worker_pid']==12182
    assert identity['parent_pid']==1 and identity['uid']==0 and identity['no_new_privs'] is True
    for key in ('token','namespace','boot_id','sources','deadline_ns'):
        assert identity[key]==cfg[key]==result[key]
    assert cfg['namespace']==index['observations']['namespace']==dict(device=4,inode=4026531840)
    assert cfg['boot_id']==index['observations']['boot_id']=='07c54a78-9618-48ea-ac94-a0356ebc2564'
    assert cfg['deadline_ns']==index['observations']['deadline_ns']==321193999373563
    assert result['completed_ns']==index['observations']['completed_ns']==321194057831988
    assert result['completed_ns']-cfg['deadline_ns']==index['observations']['completion_after_deadline_ns']==58458425
    assert index['observations']['lease_seconds']==15
    # Monotonic measurements are not a signed or trusted UTC observation time.
    assert index['precise_observation_timestamp'] is None


def test_existing_service_identity_and_listening_socket_are_preserved_for_three_tcp_controls():
    _,r,index=records()
    service=dict(pid=3520,start_ticks=4735517,uid=109,port=53751,listening_inode=28517,
                 tcp_connect=True,signed_application_receipt_verified=False)
    assert r['request']['service']==index['observations']['existing_service']==service
    assert r['existing_service_controls']==[service]*index['observations']['existing_service_control_count']
    assert len(r['existing_service_controls'])==3
    inventory=r['request']['inventory']
    assert inventory==dict(accounts=h.e.DENIED,target_processes_or_threads=0,
                           target_ip_sockets={str(uid):0 for uid in h.e.DENIED.values()})


def test_host_table_removal_and_foreign_policy_digest_are_distinct_from_raw_policy_attestation():
    _,r,index=records();o=index['observations']
    for field in ('host_rules_applied','own_table_removed','foreign_policy_unchanged','worker_exited'):
        assert r[field] is o[field] is True
    assert r['worker_result']['own_table_absent'] is True
    assert r['worker_result']['outcome']==o['outcome']=='REMOVED_EXACT_OWNED_TABLE'
    assert o['foreign_policy_sha256']==r['request']['foreign_sha256']=='1e47755e172a6a44762e36599be900147c8c7300a070f6da91047c8ac0e9a3b7'
    assert o['raw_foreign_policy_bytes_retained'] is False
    assert index['limitations']['continuous_host_policy_installed'] is False


def test_transport_integrity_and_ci_sigkill_proof_do_not_become_vm_origin_or_extra_vm_coverage():
    _,_,index=records();p=index['provenance'];c=index['coverage']
    assert p['transport']=='OPERATOR_PASTED_GZIP_BASE64_EXPORT'
    for key in ('reported_sha256_matched','gzip_crc_verified','canonical_bytes_verified',
                'frozen_source_report_validator_passed','exporter_filesystem_checks_operator_reported'):
        assert p[key] is True
    for key in ('direct_vm_file_access','independent_vm_attestation','report_signature_verified',
                'trusted_observation_clock_verified'):
        assert p[key] is False
    assert p['exporter_uid_operator_reported']==p['saved_file_uid_operator_reported']==0
    assert p['saved_file_mode_operator_reported']=='0600' and p['saved_file_nlink_operator_reported']==1
    assert p['durable_record_path_operator_reported']=='/etc/veritas-native-ledger/host-trial-68b7cb2.json'
    assert index['recording_date_jst']=='2026-10-26'
    assert c['vm_trial_count']==1 and c['vm_controller_sigkill_exercised'] is False
    assert c['vm_foreign_marker_or_extra_rule_exercised'] is False
    assert c['vm_kernel_and_systemd_versions_recorded'] is c['public_network_connectivity_tested'] is False
    ci=c['ci_reference']
    assert ci['tests']==30 and ci['skips']==0 and ci['controller_sigkill_exercised'] is True
    assert ci['pull_request']==550 and ci['run_id']==40155668154 and ci['artifact_id']==12584248652


def test_public_synthetic_evidence_contains_no_credentials_and_does_not_promote_authority_or_utility():
    raw,r,index=records()
    assert not re.search(rb'(?:github_pat_|ghp_)[A-Za-z0-9_]{20,}',raw)
    assert not re.search(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----',raw)
    # `token` is only the public nonce in the owned table/unit marker, not a credential.
    assert re.fullmatch('[0-9a-f]{32}',r['request']['token'])
    assert index['observations']['provider_requests']==r['limitations']['provider_requests']==0
    assert index['observations']['provider_dispatch']==r['limitations']['provider_dispatch']=='DENY'
    assert index['observations']['utility']==r['limitations']['utility']=='UNSCORED'
    assert all(r['limitations'][k] is False for k in r['limitations'] if k not in ('provider_requests','provider_dispatch','utility'))
    assert all(v is False for k,v in index['limitations'].items() if k not in ('provider_requests','provider_dispatch','utility'))
    assert index['verdicts']==['REAL_PROVIDER_NO_GO','UTILITY_UNSCORED','PRODUCTION_BYPASS_RESISTANCE_NOT_PROVEN']

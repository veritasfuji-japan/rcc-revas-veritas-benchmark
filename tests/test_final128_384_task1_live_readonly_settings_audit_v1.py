"""#384: GitHub public GET snapshot evaluator, NO writes/Provider calls."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
import json
import os
import socket
from pathlib import Path

import pytest
from scripts import final128_384_task1_live_readonly_settings_audit_v1 as m
from scripts import final128_383_task1_global_once_issuer_gate_offline_v1 as parent

OLD_RULE={
 "id":24921425,"name":"Task1 Single-Use Protection","target":"tag",
 "enforcement":"active","source_type":"Repository",
 "conditions":{"ref_name":{
   "include":["refs/tags/final128-task1-real-ab-once-v1-*"],
   "exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"update"}],
 "bypass_actors":[],"current_user_can_bypass":"never",
}
NEW_RULE={
 **OLD_RULE,
 "id":900000001,"name":"TASK1 384 PROPOSED FIXED REF GUARD",
 "conditions":{"ref_name":{"include":[m.FIXED_REF],"exclude":[]}},
}
def fake_reader(*,old=True,new=False,tag_exists=False,missing_detail=False,
                reject_list=False,reject_tag=False):
    entries=[OLD_RULE] if old else []
    if new:entries.append(NEW_RULE)
    def get(path):
        if path==m.RULESETS_PATH:
            if reject_list:raise m.ReadUnavailable("HTTP_403")
            return [{"id":x["id"],"target":x["target"]} for x in entries]
        if path==m.TAG_PATH:
            if reject_tag:raise m.ReadUnavailable("HTTP_403")
            if tag_exists:return {"ref":m.FIXED_REF,"object":{"sha":"a"*40}}
            raise m.ReadUnavailable("HTTP_404")
        for x in entries:
            if path==f"/repos/{m.REPO}/rulesets/{x['id']}":
                if missing_detail:raise m.ReadUnavailable("HTTP_403")
                return deepcopy(x)
        raise AssertionError("unexpected public endpoint "+path)
    return get

@pytest.fixture(autouse=True)
def stop_real_network_and_secrets(monkeypatch):
    def deny(*args,**kwargs):pytest.fail("384_TEST_MUST_NEVER_FETCH_REAL_NETWORK")
    monkeypatch.setattr(socket.socket,"connect",deny)
    monkeypatch.setattr(socket.socket,"connect_ex",deny)
    monkeypatch.setattr(socket,"create_connection",deny)
    for v in ("OPENAI_API_KEY","TASK4_OPENAI_API_KEY","GH_TOKEN",
              "GITHUB_TOKEN","OPENAI_BASE_URL"):
        monkeypatch.delenv(v,raising=False)

def test_real_observed_previous_task1_rule_does_not_match_fixed_383_global_tag():
    a=m.check_ruleset(OLD_RULE)
    assert a["ruleset_id"]==24921425
    assert a["enforcement_active"] is True
    assert a["targets_tag"] is True
    assert a["required_deletion_update_nonfastforward_present"] is True
    assert a["no_explicit_bypass_actors_in_observed_detail"] is True
    assert a["matching_fixed_tag"] is False
    assert a["locally_sufficient_pattern_rules_and_bypass_fields"] is False
    assert a["actual_github_immutability_independently_proven"] is False
    assert m.FIXED_REF=="refs/tags/final128-task1-first-two-real-responses-v1-consumed"

def test_unprotected_fixed_ref_positive_gap_even_when_old_rule_active():
    report=m.read_only_github_audit(reader=fake_reader(old=True))
    assert report["rulesets_evaluated"]==1
    assert report["ruleset_details_complete"] is True
    assert report["unprotected_fixed_ref_gap_observed"] is True
    assert report["rule_coverage_result"]=="MISSING_MATCHING_DEFENSIVE_RULE"
    assert report["fixed_tag_ref_status"]=="absent"
    assert report["tag_absent_does_not_confer_permission"] is True
    assert report["live_dispatch_permitted"] is False
    assert report["provider_credentials_presence_checked"] is False
    assert report["environment_protection_verified"] is False
    assert report["provider_project_spending_controls_verified"] is False
    assert report["new_measured_utility"] is None

def test_new_exact_rule_appearing_cannot_alone_authorize_send():
    report=m.read_only_github_audit(reader=fake_reader(old=True,new=True))
    assert report["rule_coverage_result"]=="MATCHING_DEFENSIVE_RULE_OBSERVED_NOT_AUTHORITY"
    assert report["matching_ruleset_ids"]==[NEW_RULE["id"]]
    assert report["unprotected_fixed_ref_gap_observed"] is False
    assert report["live_dispatch_permitted"] is False
    assert report["production_bypass_resistance_proven"] is False
    assert report["real_issuer_tag_mutation_performed"] is False

def test_existing_fixed_tag_never_reissued():
    report=m.read_only_github_audit(reader=fake_reader(new=True,tag_exists=True))
    assert report["fixed_tag_ref_status"]=="present"
    assert report["tag_present_means_reuse_must_be_denied"] is True
    assert report["live_dispatch_permitted"] is False

@pytest.mark.parametrize("mod",[
    {"enforcement":"disabled"},
    {"target":"branch"},
    {"rules":[{"type":"deletion"},{"type":"update"}]},
    {"rules":[{"type":"deletion"},{"type":"non_fast_forward"}]},
    {"rules":[{"type":"update"},{"type":"non_fast_forward"}]},
    {"bypass_actors":[{"actor_id":1,"actor_type":"OrganizationAdmin"}]},
    {"current_user_can_bypass":"always"},
    {"current_user_can_bypass":"pull_requests_only"},
    {"conditions":{"ref_name":{"include":[m.FIXED_REF],"exclude":[m.FIXED_REF]}}},
    {"conditions":{"ref_name":{"include":[],"exclude":[]}}},
    {"conditions":{"ref_name":{"include":["refs/tags/other*"],"exclude":[]}}},
    {"conditions":None},
    {"conditions":{"ref_name":None}},
    {"conditions":{"ref_name":{"include":[m.FIXED_REF]}}},
    {"conditions":{"ref_name":{"exclude":[]}}},
])
def test_suggested_fixed_ref_ruleset_altered_rejected_even_when_named_protection(mod):
    rule=deepcopy(NEW_RULE)
    rule.update(mod)
    x=m.check_ruleset(rule)
    assert x["locally_sufficient_pattern_rules_and_bypass_fields"] is False

@pytest.mark.parametrize("state",["absent","present","unknown"])
def test_no_tag_state_can_enable_production_execution(state):
    a=m.audit_observations(rule_details=[NEW_RULE],
        detail_collection_complete=True,ref_status=state,
        observation_source="offline_fixture_untrusted")
    assert a["live_dispatch_permitted"] is False
    assert a["production_bypass_resistance_proven"] is False
    assert a["actual_get_seen_by_script"] is False
    assert len(a["external_prerequisites_unverified"])>=9

@pytest.mark.parametrize("source",[
    "claimed_approved","signed_true","production",
])
def test_forged_origin_declared_by_fixture_is_refused(source):
    with pytest.raises(m.AuditDenied,match="OBSERVATION_SOURCE"):
        m.audit_observations(rule_details=[NEW_RULE],detail_collection_complete=True,
                             ref_status="absent",observation_source=source)

@pytest.mark.parametrize("kwargs",[
    {"rule_details":None},
    {"rule_details":["not a ruleset"]},
    {"detail_collection_complete":1},
    {"ref_status":"verified"},
])
def test_invalid_scope_or_missing_origin_denied(kwargs):
    options={"rule_details":[NEW_RULE],
             "detail_collection_complete":True,
             "ref_status":"absent",
             "observation_source":"offline_fixture_untrusted"}
    options.update(kwargs)
    with pytest.raises(m.AuditDenied):
        m.audit_observations(**options)

@pytest.mark.parametrize("kind",["list_forbidden","details_forbidden",
                                 "tag_forbidden","list_malformed",
                                 "duplicate_id","many_rulesets"])
def test_public_endpoint_failure_is_unknown_and_live_denied(kind):
    if kind=="list_forbidden":
        reader=fake_reader(reject_list=True)
    elif kind=="details_forbidden":
        reader=fake_reader(missing_detail=True)
    elif kind=="tag_forbidden":
        reader=fake_reader(reject_tag=True)
    elif kind=="list_malformed":
        def reader(path):
            if path==m.RULESETS_PATH:return {"looks":"legitimate"}
            return fake_reader()(path)
    elif kind=="duplicate_id":
        def reader(path):
            if path==m.RULESETS_PATH:return [
                {"id":24921425,"target":"tag"},
                {"id":24921425,"target":"tag"}]
            return fake_reader()(path)
    else:
        def reader(path):
            if path==m.RULESETS_PATH:return [
                {"id":i,"target":"tag"} for i in range(m.MAX_RULESETS)]
            return fake_reader()(path)
    report=m.read_only_github_audit(reader=reader)
    assert report["live_dispatch_permitted"] is False
    assert report["ruleset_details_complete"] is (kind=="tag_forbidden")
    if kind!="tag_forbidden":
        assert report["rule_coverage_result"]=="UNKNOWN_INCOMPLETE_OR_FORBIDDEN"
    if kind=="tag_forbidden":
        assert report["fixed_tag_ref_status"]=="unknown"

def test_incomplete_rule_detail_cannot_be_silently_treated_as_all_checked():
    report=m.audit_observations(rule_details=[NEW_RULE],
         detail_collection_complete=False,ref_status="absent",
         observation_source="offline_fixture_untrusted")
    assert report["ruleset_details_complete"] is False
    assert report["live_dispatch_permitted"] is False
    assert report["actual_get_seen_by_script"] is False

def test_readonly_url_restricts_to_fixed_paths_before_network():
    for other in ("/user",f"/repos/{m.REPO}/actions/secrets",
                  f"/repos/{m.REPO}/git/refs",
                  f"/repos/{m.REPO}/rulesets/../../somewhere",
                  "https://evil.com/foo",
                  f"/repos/{m.REPO}/environments/task1-real-model-pilot"):
        with pytest.raises(m.AuditDenied,match="UNEXPECTED_REMOTE_ENDPOINT"):
            m.read_public_json(other)

def test_live_api_read_only_const_does_not_grant_settings_issuer():
    assert m.RULESETS_PATH.startswith("/repos/")
    assert m.TAG_PATH.startswith("/repos/")
    assert m.FIXED_REF==parent.PROTOCOL_REF
    assert not parent.inspect_candidate(parent.candidate_context(
        main_sha="a"*40,run_id="38353637930"))["live_dispatch_authorized"]
    assert m.read_only_github_audit(reader=fake_reader())["real_provider_posts"]==0

def test_no_billing_provider_or_approval_claims_in_report():
    report=m.read_only_github_audit(reader=fake_reader())
    s=json.dumps(report,sort_keys=True)
    assert "OPENAI_API_KEY" not in s
    assert "Bearer " not in s
    assert report["native_scorer_calls"]==0
    assert report["provider_credentials_presence_checked"] is False
    assert report["provider_project_spending_controls_verified"] is False

def test_self_claimed_operator_approval_cannot_enable_live():
    for alleged in (True,None,{},{"approved":True},
       "I APPROVE TASK1 A/B ONE RUN UP TO USD 1"):
        with pytest.raises(m.AuditDenied,match="EXTERNAL_PROTECTED_SETTINGS"):
            m.deny_live_execution(alleged)

def test_no_live_write_operation_or_api_token_access_in_audit_module():
    s=Path(m.__file__).read_text()
    assert 'method="GET"' in s
    assert 'method="POST"' not in s
    assert 'method="PATCH"' not in s
    assert 'method="DELETE"' not in s
    assert "os.environ[" not in s
    assert "requests.post(" not in s
    assert "workflow_dispatch" not in s
    assert "gh api -X" not in s

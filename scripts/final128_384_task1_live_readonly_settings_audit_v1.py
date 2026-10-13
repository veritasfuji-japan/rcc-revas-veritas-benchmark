#!/usr/bin/env python3
"""Task1 #384: read-only public GitHub settings observation, default DENY.

Performs only GET requests against fixed GitHub REST paths. Reads active
repository tag rulesets and the exact #383 singleton tag's existence. It
NEVER fetches secrets, creates/updates/deletes refs, dispatches workflows,
obtains a Provider token, or promotes settings to authenticated authority.

GitHub Environment / Actions permission / branch protection endpoints are
not readable by the currently available connector; they remain UNKNOWN.
A public GET observation is not an authenticated, externally immutable
issuer attestation. Any missing/failed/ambiguous read is UNKNOWN and DENY.
"""
from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scripts import final128_383_task1_global_once_issuer_gate_offline_v1 as issuer

SCHEMA="veritas.final128.task1-readonly-live-repository-controls-audit.v1"
REST_BASE="https://api.github.com"
REPO=issuer.REPO
RULESETS_PATH=f"/repos/{REPO}/rulesets?per_page=100"
TAG_PATH=f"/repos/{REPO}/git/ref/tags/"+issuer.PROTOCOL_REF.removeprefix("refs/tags/")
FIXED_REF=issuer.PROTOCOL_REF
MAX_READ_BYTES=131_072
MAX_RULESETS=99
TAG_RULES=frozenset(("deletion","update","non_fast_forward"))
UNKNOWN_CONTROLS=(
 "protected_environment_required_reviewers_and_wait_timer",
 "protected_environment_deployment_branch_policy",
 "actions_default_token_permission_and_workflow_edit_guard",
 "branch_ruleset_and_workflow_file_mutation_protection",
 "protected_issuer_credential_ref_create_only_no_bypass_or_delete",
 "provider_project_actual_budget_hard_stop_and_account_access",
 "provider_tls_receipt_origin_from_protected_runner",
 "production_credential_network_egress_bypass_resistance",
 "external_independent_approval_and_single_use_issuer_attestation",
)
class AuditDenied(ValueError):pass

class ReadUnavailable(AuditDenied):
    def __init__(self,code):
        super().__init__(code)
        self.code=code

def need(condition,code):
    if condition is not True:raise AuditDenied("384_"+code)

def canonical(obj):
    return json.dumps(obj,sort_keys=True,ensure_ascii=False,
         separators=(",",":"),allow_nan=False).encode("utf8")

def sha(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def read_public_json(path):
    """Unauthenticated HTTPS GET to a CLOSED SET of GitHub paths only.

    This is a read-only observation, not evidence of repo-admin privileges.
    We do not log or send a token and explicitly reject redirects off host.
    """
    is_detail=re.fullmatch(r"/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/rulesets/[1-9][0-9]{0,12}",path)
    need(type(path) is str and (path in (RULESETS_PATH,TAG_PATH)
         or is_detail is not None),"UNEXPECTED_REMOTE_ENDPOINT")
    req=Request(REST_BASE+path,headers={
       "Accept":"application/vnd.github+json",
       "User-Agent":"veritas-task1-384-readonly-settings-v1",
       "X-GitHub-Api-Version":"2022-11-28",
    },method="GET")
    try:
        with urlopen(req,timeout=10) as response:
            need(response.geturl().startswith(REST_BASE+"/"),
                 "REDIRECTED_OUTSIDE_GITHUB")
            data=response.read(MAX_READ_BYTES+1)
            need(len(data)<=MAX_READ_BYTES,"GITHUB_RESPONSE_TOO_LARGE")
            return json.loads(data.decode("utf8"))
    except HTTPError as exc:
        raise ReadUnavailable(f"HTTP_{exc.code}") from exc
    except (URLError,TimeoutError,OSError,UnicodeError,ValueError) as exc:
        raise ReadUnavailable("NETWORK_OR_JSON_UNAVAILABLE") from exc

def _ref_matches(ruleset):
    conditions=ruleset.get("conditions")
    if type(conditions) is not dict:return False
    ref=conditions.get("ref_name")
    if type(ref) is not dict:return False
    includes=ref.get("include")
    excludes=ref.get("exclude")
    if type(includes) is not list or type(excludes) is not list:return False
    if not all(type(s) is str for s in includes+excludes):return False
    # A local conservative approximation of the observed glob. A positive
    # match is still not GitHub-admin-attested ruleset efficacy.
    allowed_patterns=[s for s in includes if s.startswith("refs/tags/")]
    return (bool(allowed_patterns)
            and any(fnmatchcase(FIXED_REF,s) for s in allowed_patterns)
            and not any(fnmatchcase(FIXED_REF,s) for s in excludes))

def check_ruleset(rule):
    """Evaluate defensive intent, NEVER grant execution."""
    need(type(rule) is dict,"DETAIL_MUST_BE_JSON_OBJECT")
    name=rule.get("name")
    rid=rule.get("id")
    matched=(_ref_matches(rule) and rule.get("target")=="tag"
             and rule.get("enforcement")=="active")
    listed=rule.get("rules")
    types=set()
    if type(listed) is list:
        types={r.get("type") for r in listed if type(r) is dict
               and type(r.get("type")) is str}
    bypass=rule.get("bypass_actors")
    no_bypass=(type(bypass) is list and not bypass
               and rule.get("current_user_can_bypass")=="never")
    sufficient=(matched and TAG_RULES.issubset(types) and no_bypass)
    condition=rule.get("conditions")
    names=condition.get("ref_name") if type(condition) is dict else None
    patterns=names.get("include") if type(names) is dict else None
    if type(patterns) is not list:patterns=[]
    return {
        "ruleset_id":rid if type(rid) is int else None,
        "ruleset_name":name if type(name) is str else None,
        "enforcement_active":rule.get("enforcement")=="active",
        "targets_tag":rule.get("target")=="tag",
        "ref_include_patterns":patterns,
        "matching_fixed_tag":bool(matched),
        "required_deletion_update_nonfastforward_present":TAG_RULES.issubset(types),
        "no_explicit_bypass_actors_in_observed_detail":bool(no_bypass),
        "locally_sufficient_pattern_rules_and_bypass_fields":bool(sufficient),
        "actual_github_immutability_independently_proven":False,
    }

def audit_observations(*,rule_details,detail_collection_complete,
                      ref_status,observation_source):
    """Pure fail-closed evaluator, separately usable with test fixtures.

    Source data can be spoofed; the result cannot issue authority, even
    when all content appears to pass.
    """
    need(type(rule_details) is list and all(type(x) is dict for x in rule_details),
         "RULE_DETAILS_INVALID")
    need(type(detail_collection_complete) is bool,"DETAIL_COMPLETENESS_BOOL")
    need(ref_status in ("absent","present","unknown"),"REF_STATUS_INVALID")
    need(observation_source in ("public_github_get_unattested",
         "offline_fixture_untrusted"),"OBSERVATION_SOURCE_INVALID")
    inspected=[check_ruleset(x) for x in rule_details]
    protective=[p for p in inspected
       if p["locally_sufficient_pattern_rules_and_bypass_fields"]]
    mismatch=(detail_collection_complete and not protective)
    return {
        "schema":SCHEMA,
        "status":"LIVE_DISPATCH_DENIED_EXTERNAL_CONTROLS_UNVERIFIED",
        "fixed_protocol_ref":FIXED_REF,
        "observation_source":observation_source,
        "actual_get_seen_by_script":(observation_source=="public_github_get_unattested"
             and (detail_collection_complete or ref_status!="unknown")),
        "ruleset_details_complete":detail_collection_complete,
        "rulesets_evaluated":len(inspected),
        "rule_coverage_result":(
            "MATCHING_DEFENSIVE_RULE_OBSERVED_NOT_AUTHORITY"
            if protective else
            "MISSING_MATCHING_DEFENSIVE_RULE"
            if mismatch else "UNKNOWN_INCOMPLETE_OR_FORBIDDEN"),
        "unprotected_fixed_ref_gap_observed":bool(mismatch),
        "matching_ruleset_ids":[x["ruleset_id"] for x in protective],
        "all_inspected_rulesets":inspected,
        "fixed_tag_ref_status":ref_status,
        "tag_absent_does_not_confer_permission":True,
        "tag_present_means_reuse_must_be_denied":ref_status=="present",
        "environment_protection_verified":False,
        "actions_permissions_verified":False,
        "branch_workflow_protection_verified":False,
        "provider_project_spending_controls_verified":False,
        "provider_credentials_presence_checked":False,
        "real_issuer_tag_mutation_performed":False,
        "real_provider_posts":0,
        "native_scorer_calls":0,
        "new_measured_utility":None,
        "external_prerequisites_unverified":list(UNKNOWN_CONTROLS),
        "live_dispatch_permitted":False,
        "production_bypass_resistance_proven":False,
    }

def read_only_github_audit(*,reader=read_public_json):
    """Observe current repo settings, never change them or fail open."""
    need(callable(reader),"READER_REQUIRED")
    complete=False
    details=[]
    list_failure=None
    try:
        item=reader(RULESETS_PATH)
        need(type(item) is list,"RULESET_COLLECTION_BAD_TYPE")
        # Fail closed if next page may exist: no unproven completeness.
        need(len(item)<MAX_RULESETS,"RULESET_COLLECTION_PAGINATION_UNVERIFIED")
        ids=[]
        for x in item:
            need(type(x) is dict and type(x.get("id")) is int
                 and x.get("target") in ("tag","branch","push"),
                 "RULESET_SUMMARY_INVALID")
            ids.append(x["id"])
        need(len(ids)==len(set(ids)),"DUPLICATE_RULESET_ID")
        for rid in ids:
            detail=reader(f"/repos/{REPO}/rulesets/{rid}")
            need(type(detail) is dict and detail.get("id")==rid,
                 "DETAIL_LIST_MISMATCH")
            details.append(detail)
        complete=True
    except (AuditDenied,ValueError,TypeError,KeyError) as exc:
        list_failure=type(exc).__name__
        complete=False
    except Exception as exc:
        list_failure=type(exc).__name__
        complete=False
    status="unknown"
    ref_read_error=None
    try:
        ref=reader(TAG_PATH)
        need(type(ref) is dict and ref.get("ref")==FIXED_REF,
             "GIT_TAG_REFERENCE_RESPONSE_BAD")
        status="present"
    except ReadUnavailable as e:
        status="absent" if e.code=="HTTP_404" else "unknown"
        ref_read_error=e.code
    except Exception as e:
        status="unknown"
        ref_read_error=type(e).__name__

    report=audit_observations(
       rule_details=details,detail_collection_complete=complete,
       ref_status=status,observation_source="public_github_get_unattested")
    report["ruleset_list_read_error_type"]=list_failure
    report["fixed_ref_read_error_type"]=ref_read_error
    report["repository"]=REPO
    report["observation_endpoint_family"]="GITHUB_PUBLIC_REST_GET_ONLY"
    report["real_environment_and_actions_settings_unreadable_via_connector"]=True
    return report

def deny_live_execution(*args,**kwargs):
    raise AuditDenied("384_EXTERNAL_PROTECTED_SETTINGS_AND_REAL_PROVIDER_GRANT_NOT_VERIFIED")

def main():
    parser=argparse.ArgumentParser(description="Read-only GitHub ruleset audit. No writes/API spend.")
    parser.add_argument("--observe",action="store_true",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    output=Path(args.output)
    if not output.parent.is_dir():
        parser.error("output directory missing")
    result=read_only_github_audit()
    output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("384_STATUS="+result["status"])
    print("384_RULE="+result["rule_coverage_result"])
    print("384_GLOBAL_REF="+result["fixed_tag_ref_status"])
    print("384_LIVE_PROVIDER_POSTS=0")

if __name__=="__main__":
    main()

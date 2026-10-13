#!/usr/bin/env python3
"""#393: pinned observed #392 GitHub tag denials with optional fixed public GETs.

All operations here are offline filesystem reads or five public HTTP GETs;
NO token, approval action, workflow dispatch, tag writes, secrets or Provider.
Historical selected log lines are frozen transcriptions, NOT independently
replayed signed raw GitHub job logs or original HTTP error response bodies.
"""
from __future__ import annotations
import argparse
from datetime import datetime
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError,URLError

REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
ROOT="https://api.github.com/repos/"+REPO
RUN_ID=38404886383
PRE_ID=115321810022
WRITER_ID=115321885432
RUN_SHA="0129a324f4c5ccd6512d5bf3d354d0b348bd8b2f"
WORKFLOW=".github/workflows/final128-392-isolated-protected-tag-negative-operations-probe.yml"
WORKFLOW_BLOB="aaaf8c22d32080e694905a048c640d13b23de2ea"
PATH=Path("evidence/final128_task1_392_tag_negative_denials_run_38404886383_v1.json")
BLOB="df655f687980d60404ab15206cbce527e6027195"
TAG="refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed"
TAG_SHA="d9ba430e62d37c7b776bcfc93e3d46bc51f6ae3e"
ENV="task1-real-model-pilot"
RULESET=24921425
SCHEMA="veritas.final128.task1.393-isolated-github-tag-negative-denial-observed.v1"
VERDICT="REAL_ISOLATED_GITHUB_TAG_DENIALS_OBSERVED_LIMITED_NOT_PRODUCTION_ONCE_OR_BYPASS_PROOF"
URLS={
  "run":ROOT+"/actions/runs/"+str(RUN_ID),
  "jobs":ROOT+"/actions/runs/"+str(RUN_ID)+"/jobs?per_page=100",
  "approvals":ROOT+"/actions/runs/"+str(RUN_ID)+"/approvals",
  "tag":ROOT+"/git/ref/tags/"+TAG.removeprefix("refs/tags/"),
  "ruleset":ROOT+"/rulesets/"+str(RULESET),
}
MARKERS=[
 "392_PREFLIGHT_ONLY_NO_GITHUB_WRITE_NO_PROVIDER",
 "392_INITIAL_TAG_FIXED_READBACK_OK",
 "392_DUPLICATE_POST_HTTP_422",
 "392_UPDATE_PATCH_HTTP_422",
 "392_DELETE_HTTP_422",
 "392_REAL_GITHUB_TEST_TAG_DUPLICATE_UPDATE_DELETE_DENIED_UNCHANGED",
]
RULE_TYPES={"deletion","non_fast_forward","update"}
class Denied(ValueError):pass
def need(value,reason):
    if value is not True:raise Denied("393_"+reason)

def git_blob(text):
    need(type(text) is str,"TEXT")
    b=text.encode("utf8")
    return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()

def unique_pairs(pairs):
    d={}
    for k,v in pairs:
        need(k not in d,"DUPLICATE_JSON_FIELD")
        d[k]=v
    return d

def strict_json(raw):
    need(type(raw) is bytes and 0<len(raw)<=131072,"JSON_SIZE")
    return json.loads(raw.decode("utf8"),object_pairs_hook=unique_pairs,
            parse_constant=lambda x:need(False,"NONFINITE_JSON"))

def fixture():
    need(PATH.is_file() and not PATH.is_symlink(),"FIXTURE_FILE")
    raw=PATH.read_bytes()
    need(git_blob(raw.decode("utf8"))==BLOB,"EXACT_JSON_GIT_BLOB_PIN")
    data=strict_json(raw)
    validate_fixture(data)
    return data,hashlib.sha256(raw).hexdigest()

def tstamp(s):
    need(type(s) is str and s.endswith("Z"),"TIMESTAMP_UTC")
    return datetime.fromisoformat(s.replace("Z","+00:00"))

def validate_fixture(f):
    need(type(f) is dict and f.get("schema")==SCHEMA,"SCHEMA")
    need(f.get("repository")==REPO and f.get("verdict")==VERDICT,"IDENTITY")
    need(f.get("evidence_type")==
        "COMPLETED_GITHUB_RUN_AND_SELECTED_JOB_LOG_MARKERS_READBACK_NOT_INDEPENDENTLY_SIGNED",
        "UNSIGNED_OBSERVATION")
    r=f["source_run"]
    need(r["id"]==RUN_ID and r["workflow_path"]==WORKFLOW
         and r["workflow_git_blob_sha"]==WORKFLOW_BLOB
         and r["head_sha"]==RUN_SHA and r["head_branch"]=="main"
         and r["event"]=="workflow_dispatch" and r["run_attempt"]==1
         and r["actor"]==r["triggering_actor"]=="veritasfuji-japan"
         and r["status"]=="completed" and r["conclusion"]=="success",
         "RUN_IDENTITY")
    jobs=f["completed_jobs"]
    need(type(jobs) is list and len(jobs)==2 and
         [j["id"] for j in jobs]==[PRE_ID,WRITER_ID] and
         [j["name"] for j in jobs]==["offline-preflight","protected-negative-operations"]
         and all(j["conclusion"]==j["status"]=="completed" if False else
                 j["conclusion"]=="success" and j["status"]=="completed"
                 for j in jobs),"JOB_IDENTITIES")
    need(tstamp(jobs[0]["completed_at"])<=tstamp(jobs[1]["started_at"])
         and tstamp(jobs[1]["completed_at"])<=tstamp(r["updated_at"]),
         "JOB_TIMELINE")
    ap=f["completed_environment_approval_records"]
    need(type(ap) is list and len(ap)==2
         and {x["user"] for x in ap}=={"github-actions[bot]","veritasfuji-japan"}
         and all(x["state"]=="approved" and x["environment"]==ENV
                 and x["environment_id"]==24064338024
                 and x["can_admins_bypass"] is False for x in ap),
         "APPROVAL_RECORDS")
    marks=f["selected_log_markers"]
    need(type(marks) is list and
         [x["message"] for x in marks]==MARKERS and
         [x["job_id"] for x in marks]==[PRE_ID]+[WRITER_ID]*5 and
         all(tstamp(x["timestamp_utc"]) for x in marks) and
         all(tstamp(marks[i]["timestamp_utc"])<tstamp(marks[i+1]["timestamp_utc"])
             for i in range(5)),"SELECTED_LOG_MARKERS")
    ops=f["negative_operations"]
    need(type(ops) is list and len(ops)==3
         and [(x["phase"],x["method"],x["http_status"]) for x in ops]
         ==[("duplicate","POST",422),("update","PATCH",422),("delete","DELETE",422)]
         and [x["decision"] for x in ops]==[
            "REJECTED_BY_EXPLICIT_ALREADY_EXISTS_CHECK",
            "REJECTED_BY_EXPLICIT_RULESET_UPDATE_VIOLATION_CHECK",
            "REJECTED_BY_EXPLICIT_RULESET_DELETE_VIOLATION_CHECK"]
         and all(x["expected_same_ref_after"] is True for x in ops),
         "THREE_BOUNDED_DENIALS")
    tag=f["live_tag_at_freeze"]
    need(tag["ref"]==TAG and tag["sha"]==TAG_SHA
         and tag["type"]=="commit" and tag["get_url"]==URLS["tag"]
         and tag["before_after_each_mutation_verified_by_completed_workflow"] is True,
         "TAG_SAME_SHA")
    rs=f["configured_ruleset_at_freeze"]
    need(rs["id"]==RULESET and rs["name"]=="Task1 Single-Use Protection"
         and rs["enforcement"]=="active" and rs["target"]=="tag"
         and rs["ruleset_url"]==URLS["ruleset"]
         and set(rs["required_rule_types"])==RULE_TYPES
         and rs["bypass_actors_observed_in_authenticated_readback"]==[]
         and rs["current_user_can_bypass_observed_in_authenticated_readback"]=="never",
         "RULESET_CONFIG_SNAPSHOT")
    scope=f["limitations"]
    need(scope["scope"]==
         "ONE_EXISTING_TEST_ONLY_TAG_WITH_ONE_GITHUB_ACTIONS_CONTENTS_WRITE_TOKEN_AND_CONFIGURED_RULESET"
         and all(scope[k] is False for k in (
           "raw_http_denial_response_bodies_archived",
           "original_full_job_logs_cryptographically_signed_in_this_bundle",
           "exact_human_approval_action_timestamp_recorded",
           "pending_before_approval_historical_response_replayable",
           "independent_third_party_reviewer_observed",
           "globally_atomic_once_issuer_proven","create_only_iam_capability_proven",
           "prod_task1_authority_issued","production_task1_tag_used",
           "production_tag_bypass_resistance_proven",
           "credential_iam_network_bypass_impossible_proven",
           "hard_provider_billing_cap_proven",
           "real_provider_called_in_this_workflow",
           "native_scorer_run_in_this_workflow",
           "official_final128_utility_remeasured","paid_task1_authorized"))
         and scope["environment_self_review_allowed"] is True,
         "PROOF_BOUNDARY")
    need(Path(WORKFLOW).is_file()
         and git_blob(Path(WORKFLOW).read_text(encoding="utf8"))==WORKFLOW_BLOB,
         "RUNTIME_WORKFLOW_SOURCE_PIN")
    return True

def project_run(r):
    need(type(r) is dict and type(r.get("actor")) is dict
         and type(r.get("triggering_actor")) is dict,"RUN_SHAPE")
    return {k:r.get(k) for k in (
        "id","event","head_branch","head_sha","run_attempt",
        "created_at","run_started_at","updated_at","status","conclusion")} | {
        "actor":r["actor"].get("login"),
        "triggering_actor":r["triggering_actor"].get("login")
    }

def project_jobs(x):
    need(type(x) is dict and x.get("total_count")==2
         and type(x.get("jobs")) is list and len(x["jobs"])==2,"JOB_COUNT")
    out=[]
    for j in x["jobs"]:
        need(type(j.get("steps")) is list
             and all(s.get("conclusion")=="success"
                     and s.get("status")=="completed" for s in j["steps"]),
             "ALL_JOB_STEPS_SUCCESS")
        out.append({k:j.get(k) for k in (
            "id","name","status","conclusion","started_at","completed_at")} | {
            "steps":[s.get("name") for s in j["steps"]]})
    return sorted(out,key=lambda j:j["id"])

def project_approvals(arr):
    need(type(arr) is list and len(arr)==2,"REVIEW_COUNT")
    out=[]
    for r in arr:
        need(type(r.get("user")) is dict and type(r.get("environments")) is list
             and len(r["environments"])==1,"REVIEW_SHAPE")
        e=r["environments"][0]
        out.append({"user":r["user"].get("login"),"state":r.get("state"),
                    "comment":r.get("comment"),"environment":e.get("name"),
                    "environment_id":e.get("id"),
                    "can_admins_bypass":e.get("can_admins_bypass")})
    return sorted(out,key=lambda x:x["user"])

def validate_live(f,live):
    r=f["source_run"]
    expected={k:r[k] for k in (
       "id","event","head_branch","head_sha","run_attempt",
       "created_at","run_started_at","updated_at","status","conclusion",
       "actor","triggering_actor")}
    need(project_run(live["run"])==expected,"LIVE_RUN_DRIFT")
    need(project_jobs(live["jobs"])==f["completed_jobs"],"LIVE_JOBS_DRIFT")
    need(project_approvals(live["approvals"])==
         sorted(f["completed_environment_approval_records"],key=lambda x:x["user"]),
         "LIVE_APPROVALS_DRIFT")
    ref=live["tag"]
    need(type(ref) is dict and ref.get("ref")==TAG
         and type(ref.get("object")) is dict
         and ref["object"].get("sha")==TAG_SHA
         and ref["object"].get("type")=="commit","LIVE_TAG_CHANGED")
    rules=live["ruleset"]
    need(type(rules) is dict and rules.get("id")==RULESET
         and rules.get("name")=="Task1 Single-Use Protection"
         and rules.get("target")=="tag"
         and rules.get("enforcement")=="active","RULESET_ACTIVE")
    matcher=rules.get("conditions",{}).get("ref_name",{})
    need(type(matcher.get("include")) is list
         and type(matcher.get("exclude")) is list
         and any(fnmatchcase(TAG,s) for s in matcher["include"])
         and not any(fnmatchcase(TAG,s) for s in matcher["exclude"]),
         "RULESET_TAG_COVERAGE")
    types={r.get("type") for r in rules.get("rules",[]) if type(r) is dict}
    need(RULE_TYPES.issubset(types),"RULESET_PROHIBITIONS")
    has_fields="bypass_actors" in rules and "current_user_can_bypass" in rules
    bypass_clear=(has_fields and rules["bypass_actors"]==[]
                  and rules["current_user_can_bypass"]=="never")
    need(not has_fields or bypass_clear,"RULESET_BYPASS_DETECTED")
    return {
       "current_run_job_and_approvals_match_frozen_evidence":True,
       "current_exact_test_tag_still_unchanged":True,
       "current_ruleset_scope_and_types_observed":True,
       "current_ruleset_bypass_fields_status":(
          "OBSERVED_NO_BYPASS" if bypass_clear else "UNKNOWN_MISSING_FIELDS"),
       "historic_raw_job_log_lines_replayed_from_public_get":False,
       "historic_raw_http_response_bodies_archived":False,
       "actual_github_tag_write_attempts_from_this_auditor":0,
       "paid_provider_calls_from_this_auditor":0,
       "independent_signed_attestation_proven":False,
       "global_task1_once_proven":False,
       "paid_task1_authorized":False,
    }

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise Denied("393_REDIRECT_NOT_ALLOWED")

def public_get(url):
    need(url in URLS.values(),"ONLY_FIVE_PUBLIC_GET_URLS")
    req=Request(url,method="GET",headers={
      "Accept":"application/vnd.github+json",
      "User-Agent":"veritas-final128-393-frozen-negative-evidence-readonly",
      "X-GitHub-Api-Version":"2022-11-28"})
    try:
        with build_opener(NoRedirect()).open(req,timeout=12) as response:
            need(response.geturl()==url,"RESPONSE_REDIRECTED")
            raw=response.read(131073)
            need(len(raw)<=131072,"GITHUB_RESPONSE_SIZE")
    except (HTTPError,URLError,OSError,TimeoutError) as exc:
        raise Denied("393_GITHUB_PUBLIC_GET_UNAVAILABLE") from exc
    return strict_json(raw)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--readback",action="store_true")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    f,sha=fixture()
    result={
       "schema":SCHEMA,
       "fixture_sha256":sha,
       "completed_observation_frozen":True,
       "selected_log_markers_are_unsigned_transcriptions":True,
       "actual_operations_verified_by_current_pr_ci":False,
       "current_github_readback_matches_frozen_run_jobs_approvals_and_tag":False,
       "paid_task1_authorized":False,
       "actual_github_tag_write_attempts_by_this_auditor":0,
       "actual_provider_calls_by_this_auditor":0,
    }
    if args.readback:
        result.update(validate_live(f,{k:public_get(v) for k,v in URLS.items()}))
        result["current_github_readback_matches_frozen_run_jobs_approvals_and_tag"]=True
        result["readback_mode"]="FIVE_PUBLIC_GETS_NO_TOKEN"
    else:
        result["readback_mode"]="OFFLINE_SNAPSHOT_NO_NETWORK"
    out=Path(args.output)
    need(out.parent.is_dir() and not out.is_symlink(),"OUTPUT_PATH")
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("393_REAL_TEST_ONLY_DENIALS_FROZEN_LIMITED_PROOF_NO_PROVIDER")

if __name__=="__main__":
    main()

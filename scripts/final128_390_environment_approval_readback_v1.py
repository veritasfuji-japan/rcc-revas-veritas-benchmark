#!/usr/bin/env python3
"""#390 Read-only replay of completed GitHub Environment gate evidence.

No token, no secrets, no GitHub mutation, no Provider, no workflow dispatch.
The earlier waiting snapshot was not durably recorded and is NOT replayable.
Public GitHub REST response values are useful observations, not signed
independent attestation or permission for a paid Task1 run.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

SCHEMA="veritas.final128.task1.environment-approval-zero-provider-observed.v1"
ROOT="https://api.github.com/repos/veritasfuji-japan/rcc-revas-veritas-benchmark/"
ID=38386775595
SHA="c9accc3a15d97b53d0d3e140b2410f659aa0391f"
ENV="task1-real-model-pilot"
EVIDENCE=Path("evidence/final128_task1_environment_approval_run_38386775595_v1.json")
ENDPOINTS={
 "run":ROOT+"actions/runs/38386775595",
 "jobs":ROOT+"actions/runs/38386775595/jobs?per_page=100",
 "approvals":ROOT+"actions/runs/38386775595/approvals",
 "historical_pending":ROOT+"actions/runs/38386775595/pending_deployments",
}
RUN={
 "id":ID,"event":"workflow_dispatch","status":"completed","conclusion":"success",
 "head_branch":"main","head_sha":SHA,"actor":"veritasfuji-japan",
 "run_attempt":1,"created_at":"2026-10-13T10:56:26Z",
 "started_at":"2026-10-13T10:56:26Z","updated_at":"2026-10-13T11:11:19Z"
}
JOBS=[
 {"id":115260406333,"name":"preflight-no-environment","status":"completed",
  "conclusion":"success","started_at":"2026-10-13T10:56:31Z",
  "completed_at":"2026-10-13T10:56:33Z",
  "steps":["Set up job","Reject wrong actor, branch, rerun, event or acknowledgment",
           "Complete job"]},
 {"id":115260436932,"name":"protected-marker-no-provider","status":"completed",
  "conclusion":"success","started_at":"2026-10-13T11:11:15Z",
  "completed_at":"2026-10-13T11:11:19Z",
  "steps":["Set up job","Mark job start after GitHub Environment rules permit it",
           "Complete job"]}
]
REVIEWS=[
 {"user":"github-actions[bot]","state":"approved","comment":"10 minute wait timer",
  "environment":ENV,"environment_id":24064338024,"can_admins_bypass":False},
 {"user":"veritasfuji-japan","state":"approved","comment":"",
  "environment":ENV,"environment_id":24064338024,"can_admins_bypass":False},
]
WAIT={
 "observed_run_status":"waiting",
 "observed_protected_job_status":"waiting",
 "environment":ENV,"wait_timer_minutes":10,
 "wait_timer_started_at":"2026-10-13T10:56:34.000Z",
 "reviewer":"veritasfuji-japan",
 "after_ten_minutes_waiting_shown_in_operator_screenshot":True,
 "retrospective_get_currently_empty":True,
 "original_pending_response_persisted_as_signed_raw_evidence":False,
 "independent_third_party_can_reproduce_prior_waiting_now":False,
}
SCOPE={
 "actual_environment_review_records_re_readable":True,
 "actual_completed_job_timestamps_re_readable":True,
 "approval_action_exact_timestamp_available_from_this_endpoint":False,
 "before_after_runtime_transition_directly_replayable":False,
 "self_review_permitted":True,
 "independent_reviewer_observed":False,
 "actual_provider_call_from_this_workflow":False,
 "environment_provider_secret_was_not_read_by_this_workflow":True,
 "git_tag_ref_mutations_from_this_workflow":False,
 "global_atomic_oneuse_issuer_proven":False,
 "real_task1_sender_protected_proven":False,
 "account_hard_budget_cap_proven":False,
 "iam_credential_network_bypass_resistance_proven":False,
 "actual_native_model_or_scorer_run":False,
 "new_native_utility_measurement":False,
 "paid_task1_execution_authorized":False,
}
VERDICT="ENVIRONMENT_APPROVAL_GATE_OBSERVED_LIMITED_NO_PRODUCTION_BYPASS_PROOF"
class Denied(ValueError): pass

def need(value, reason):
    if value is not True:
        raise Denied("390_"+reason)

def pairs_unique(pairs):
    data={}
    for k,v in pairs:
        need(k not in data,"DUPLICATE_JSON_KEY")
        data[k]=v
    return data

def json_strict(raw):
    need(type(raw) is bytes and 0<len(raw)<=131072,"JSON_BYTES_LIMIT")
    return json.loads(raw.decode("utf8"),object_pairs_hook=pairs_unique,
                      parse_constant=lambda _:need(False,"NONFINITE_JSON"))

def validate_fixture(f):
    need(type(f) is dict and set(f)=={
        "schema","evidence_type","repo","workflow_path","urls",
        "completed_run","completed_jobs","completed_approval_records",
        "historical_pending_observation_not_replayable","proof_boundary","verdict",
    },"FIXTURE_SHAPE")
    need(f["schema"]==SCHEMA
         and f["evidence_type"]=="GITHUB_PUBLIC_REST_READBACK_WITH_NONREPLAYABLE_WAITING_CONTEXT"
         and f["repo"]=="veritasfuji-japan/rcc-revas-veritas-benchmark"
         and f["workflow_path"]==".github/workflows/final128-389-task1-environment-approval-zero-provider-probe.yml"
         and f["urls"]==ENDPOINTS
         and f["completed_run"]==RUN
         and f["completed_jobs"]==JOBS
         and f["completed_approval_records"]==REVIEWS
         and f["historical_pending_observation_not_replayable"]==WAIT
         and f["proof_boundary"]==SCOPE
         and f["verdict"]==VERDICT,"FROZEN_EVIDENCE_DRIFT")
    # Compare exact JSON type, not 1 == True or 1.0 == 1.
    expected={
        "schema":SCHEMA,
        "evidence_type":"GITHUB_PUBLIC_REST_READBACK_WITH_NONREPLAYABLE_WAITING_CONTEXT",
        "repo":"veritasfuji-japan/rcc-revas-veritas-benchmark",
        "workflow_path":".github/workflows/final128-389-task1-environment-approval-zero-provider-probe.yml",
        "urls":ENDPOINTS,"completed_run":RUN,"completed_jobs":JOBS,
        "completed_approval_records":REVIEWS,
        "historical_pending_observation_not_replayable":WAIT,
        "proof_boundary":SCOPE,"verdict":VERDICT,
    }
    canon=lambda o:json.dumps(o,sort_keys=True,separators=(",",":"),
                             ensure_ascii=False,allow_nan=False)
    need(canon(f)==canon(expected),"EXACT_FROZEN_TYPES")
    return True

def snapshot():
    path=EVIDENCE
    need(path.is_file() and not path.is_symlink(),"EVIDENCE_REGULAR_FILE")
    raw=path.read_bytes()
    out=json_strict(raw)
    validate_fixture(out)
    return out,hashlib.sha256(raw).hexdigest()

def parse_utc(s):
    need(type(s) is str and s.endswith("Z"),"TIMESTAMP_UTC")
    return datetime.fromisoformat(s.replace("Z","+00:00"))

def project_run(data):
    need(type(data) is dict,"RUN_JSON")
    actor=data.get("actor") or {}
    need(type(actor) is dict,"RUN_ACTOR")
    return {k:data.get(k) for k in (
        "id","event","status","conclusion","head_branch","head_sha",
        "run_attempt","created_at","updated_at")} | {
        "actor":actor.get("login"),"started_at":data.get("run_started_at")}

def project_jobs(data):
    need(type(data) is dict and type(data.get("jobs")) is list,"JOBS_JSON")
    need(data.get("total_count")==2 and len(data["jobs"])==2,"TWO_JOBS_EXACT")
    values=[]
    for j in data["jobs"]:
        need(type(j) is dict and type(j.get("steps")) is list,"JOB_STEPS")
        need(all(type(s) is dict and s.get("status")=="completed"
                 and s.get("conclusion")=="success" for s in j["steps"]),
             "JOB_STEP_NOT_SUCCESS")
        values.append({k:j.get(k) for k in (
            "id","name","status","conclusion","started_at","completed_at")} |
           {"steps":[s.get("name") for s in j["steps"]]})
    return sorted(values,key=lambda j:j["id"])

def project_reviews(data):
    need(type(data) is list and len(data)==2,"REVIEW_COUNT")
    values=[]
    for entry in data:
        need(type(entry) is dict and type(entry.get("user")) is dict
             and type(entry.get("environments")) is list
             and len(entry["environments"])==1,"REVIEW_ENTRY")
        env=entry["environments"][0]
        need(type(env) is dict,"REVIEW_ENV")
        values.append({
            "user":entry["user"].get("login"),
            "state":entry.get("state"),
            "comment":entry.get("comment"),
            "environment":env.get("name"),
            "environment_id":env.get("id"),
            "can_admins_bypass":env.get("can_admins_bypass"),
        })
    return sorted(values,key=lambda a:a["user"])

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Denied("390_NO_REDIRECT_ALLOWED")

def public_get(url):
    need(url in (ENDPOINTS["run"],ENDPOINTS["jobs"],ENDPOINTS["approvals"]),
         "ONLY_FIXED_READBACK_URLS")
    request=Request(url,method="GET",headers={
        "Accept":"application/vnd.github+json",
        "User-Agent":"veritas-final128-390-readonly-evidence",
        "X-GitHub-Api-Version":"2022-11-28",
    })
    try:
        with build_opener(NoRedirect()).open(request,timeout=12) as conn:
            need(conn.geturl()==url,"RESPONSE_URL_CHANGED")
            raw=conn.read(131073)
            need(len(raw)<=131072,"RESPONSE_OVERSIZE")
    except (HTTPError,URLError,OSError,TimeoutError) as exc:
        raise Denied("390_GITHUB_READBACK_UNAVAILABLE") from exc
    return json_strict(raw)

def validate_live(*,run,jobs,reviews):
    need(project_run(run)==RUN,"ACTUAL_RUN_MISMATCH")
    need(project_jobs(jobs)==JOBS,"ACTUAL_JOBS_MISMATCH")
    need(project_reviews(reviews)==REVIEWS,"ACTUAL_APPROVALS_MISMATCH")
    need(parse_utc(JOBS[0]["completed_at"])<=parse_utc(JOBS[1]["started_at"]),
         "JOB_SEQUENCE")
    need(parse_utc(WAIT["wait_timer_started_at"])<parse_utc(JOBS[1]["started_at"]),
         "WAIT_STARTED_BEFORE_MARKER")
    return {
        "public_github_rest_readback_matches_frozen_subset":True,
        "completed_run_id":ID,
        "completed_head_sha":SHA,
        "completed_job_ids":[j["id"] for j in JOBS],
        "approval_record_users":[r["user"] for r in REVIEWS],
        "historical_waiting_status_not_replayable_from_current_api":True,
        "approval_exact_timestamp_unavailable":True,
        "third_party_immutable_provenance_verified":False,
        "environment_gate_observed_with_scope_limit":True,
        "actual_paid_provider_calls_in_probe":0,
        "task1_live_authorized":False,
        "production_bypass_proven":False,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--readback",action="store_true")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    f,source_hash=snapshot()
    if args.readback:
        result=validate_live(run=public_get(ENDPOINTS["run"]),
                             jobs=public_get(ENDPOINTS["jobs"]),
                             reviews=public_get(ENDPOINTS["approvals"]))
    else:
        result={
         "public_github_rest_readback_matches_frozen_subset":False,
         "source_snapshot_verified_offline":True,
         "historical_waiting_status_not_replayable_from_current_api":True,
         "task1_live_authorized":False,
         "production_bypass_proven":False,
        }
    result["schema"]="veritas.final128.task1.390-readonly-evidence-check.v1"
    result["evidence_file_sha256"]=source_hash
    result["readback_mode"]="PUBLIC_GET_ONLY" if args.readback else "OFFLINE_ONLY"
    result["external_mutations"]=0
    dest=Path(args.output)
    need(dest.parent.is_dir() and not dest.is_symlink(),"OUTPUT_PATH")
    dest.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("FINAL128_390_ENVIRONMENT_OBSERVED_SCOPE_LIMITED_LIVE_TASK1_DENIED")

if __name__=="__main__":
    main()

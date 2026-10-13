#!/usr/bin/env python3
"""#391: Offline exact-source pin + OPTIONAL public-readonly Task1 tag ruleset audit.

This module never creates/updates/deletes Git refs, dispatches workflows, reads
Provider secrets or authorizes paid Task1 execution. The manual workflow is a
separate future write path requiring fresh explicit human dispatch and review.
"""
from __future__ import annotations
import argparse
from fnmatch import fnmatchcase
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

WORKFLOW=Path(".github/workflows/final128-391-task1-isolated-github-tag-once-probe.yml")
EXPECTED_BLOB="89672429fb2256de82b26195935bcb27c4ae405a"
REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
TAG="refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed"
REAL_TAG="refs/tags/final128-task1-first-two-real-responses-v1-consumed"
ENV="task1-real-model-pilot"
RULESET_ID=24921425
ROOT="https://api.github.com/repos/"+REPO
RULE_URL=ROOT+"/rulesets/"+str(RULESET_ID)
REF_URL=ROOT+"/git/ref/tags/"+TAG.removeprefix("refs/tags/")
RULE_TYPES=frozenset(("deletion","update","non_fast_forward"))
SCHEMA="veritas.final128.task1-391-isolated-protected-github-tag-source.v1"

class Denied(RuntimeError):pass

def need(ok,reason):
    if ok is not True:
        raise Denied("391_"+reason)

def git_blob_sha(text):
    raw=text.encode("utf8")
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def source_contract(text):
    need(type(text) is str and len(text)<12000,"SOURCE")
    # Pin every byte: any difference including new POST/DELETE/secret binding
    # must be explicitly reviewed and re-pinned in a later PR.
    need(git_blob_sha(text)==EXPECTED_BLOB,"EXACT_GIT_BLOB_MISMATCH")
    need(text.startswith("name: Final128 391 Task1 Isolated Protected Git Tag Once Probe\n"),
         "WORKFLOW_ID")
    need(text.count("  workflow_dispatch:")==1
         and "on:\n  workflow_dispatch:\n" in text,"MANUAL_ONLY")
    need("permissions:\n  contents: read\n" in text,"READONLY_DEFAULT")
    need("    permissions:\n      contents: write\n" in text,"EXACT_WRITER_JOB")
    need(text.count("      contents: write\n")==1,"WRITER_SCOPE")
    need(text.count("    environment:\n      name: "+ENV+"\n")==1,
         "ENVIRONMENT_ONLY_ON_WRITER")
    need(text.count('method="POST"')==1
         and text.count('method="GET"')==1
         and 'method="PATCH"' not in text and 'method="DELETE"' not in text,
         "ONE_CREATE_ONE_READ_ONLY")
    need(text.count("urllib.request.urlopen(post, timeout=12)")==1,
         "ONE_CREATE_CALL")
    need("cancel-in-progress: false" in text
         and "GITHUB_RUN_ATTEMPT" in text and "I AUTHORIZE ONE TEST-ONLY GITHUB TAG CREATE NO PROVIDER" in text,
         "CONCURRENCY_RETRY_CONSENT")
    need(TAG in text and REAL_TAG not in text, "ISOLATED_TAG_ONLY")
    need("secrets." not in text and "OPENAI_API_KEY" not in text
         and "TASK4_OPENAI_API_KEY" not in text
         and "api.openai.com" not in text,"NO_PROVIDER_SECRETS")
    need("uses:" not in text and "actions/checkout" not in text,
         "NO_EXTERNAL_ACTIONS")
    # This is a source contract ONLY. The GitHub token is a broad contents:write
    # credential, not proof of a create-only capability or trusted issuer.
    return {
        "schema":SCHEMA,"status":"STAGED_ISOLATED_GITHUB_WRITE_NOT_EXECUTED",
        "exact_workflow_git_blob_sha":EXPECTED_BLOB,
        "manual_only":True,
        "isolated_tag":TAG,
        "production_task1_tag_untouched_by_this_workflow":True,
        "provider_credentials_referenced":False,
        "provider_calls_in_this_audit":0,
        "actual_github_tag_posts_in_this_audit":0,
        "actual_protected_ruleset_enforcement_proven":False,
        "trusted_create_only_issuer_proven":False,
        "global_task1_once_grant_proven":False,
        "production_bypass_resistance_proven":False,
        "task1_live_provider_authorized":False,
    }

def ruleset_status(rule, ref_status):
    need(type(rule) is dict,"RULESET_JSON")
    require_fields=("name","id","target","enforcement","conditions","rules")
    need(all(k in rule for k in require_fields),"RULESET_FIELDS")
    refs=rule["conditions"].get("ref_name") if type(rule["conditions"]) is dict else None
    need(type(refs) is dict and type(refs.get("include")) is list
         and type(refs.get("exclude")) is list,"RULESET_MATCHERS")
    need(all(type(x) is str for x in refs["include"]+refs["exclude"]),
         "RULESET_REF_PATTERNS")
    covers=any(fnmatchcase(TAG,s) for s in refs["include"]) and not any(
        fnmatchcase(TAG,s) for s in refs["exclude"])
    rules=rule["rules"]
    types={r.get("type") for r in rules if type(r) is dict} if type(rules) is list else set()
    rules_match=(rule["id"]==RULESET_ID
         and rule["name"]=="Task1 Single-Use Protection"
         and rule["target"]=="tag"
         and rule["enforcement"]=="active"
         and covers and RULE_TYPES.issubset(types))
    # Public GitHub GET may omit privileged bypass fields. Missing != empty.
    bypass_list=rule.get("bypass_actors")
    bypass_current=rule.get("current_user_can_bypass")
    bypass_observed=(type(bypass_list) is list and not bypass_list
                     and bypass_current=="never")
    fields_complete=("bypass_actors" in rule
                     and "current_user_can_bypass" in rule)
    expected=rules_match and bypass_observed and fields_complete
    need(ref_status in ("absent","present","unknown"),"REF_STATUS")
    return {
       "schema":SCHEMA,
       "ruleset_id":RULESET_ID,
       "configured_rule_covers_isolated_tag":bool(expected),
       "rule_scope_and_prohibition_fields_observed":bool(rules_match),
       "bypass_fields_complete":bool(fields_complete),
       "bypass_status":("OBSERVED_NO_BYPASS" if bypass_observed else
                        "UNKNOWN_MISSING_FIELDS" if not fields_complete else
                        "BYPASS_OR_PRIVILEGE_DETECTED"),
       "ruleset_update_deletion_non_ff_in_detail":RULE_TYPES.issubset(types),
       "no_bypass_actors_in_observed_rule":type(bypass_list) is list and not bypass_list,
       "current_user_can_bypass_never":bypass_current=="never",
       "isolated_tag_status":ref_status,
       "creation_delete_update_negative_experiments_executed":False,
       "github_write_from_this_check":False,
       "actual_tag_immutability_proven_by_this_readback":False,
       "source_readiness_for_later_separate_manual_probe":bool(expected and ref_status=="absent"),
       "task1_paid_provider_authorized":False,
    }

def public_get(url,allow_missing=False):
    need(url in (RULE_URL,REF_URL),"CLOSED_READ_URL_SET")
    req=Request(url,method="GET",headers={
      "Accept":"application/vnd.github+json",
      "User-Agent":"veritas-task1-391-ruleset-readonly",
      "X-GitHub-Api-Version":"2022-11-28",
    })
    try:
        with urlopen(req,timeout=12) as response:
            need(response.geturl()==url,"NO_REDIRECT")
            raw=response.read(65537)
            need(len(raw)<=65536,"RESPONSE_TOO_LARGE")
            return json.loads(raw.decode("utf8"))
    except HTTPError as exc:
        if allow_missing and exc.code==404:return None
        raise Denied("391_PUBLIC_GET_HTTP_UNAVAILABLE_"+str(exc.code)) from exc
    except (URLError,TimeoutError,OSError,UnicodeError,ValueError) as exc:
        raise Denied("391_PUBLIC_GET_UNAVAILABLE") from exc

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--observe",action="store_true")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    need(WORKFLOW.is_file() and not WORKFLOW.is_symlink(),"WORKFLOW_FILE")
    data=source_contract(WORKFLOW.read_text("utf8"))
    if args.observe:
        rule=public_get(RULE_URL)
        ref=public_get(REF_URL,allow_missing=True)
        status="absent" if ref is None else "present"
        if ref is not None:
            need(type(ref) is dict and ref.get("ref")==TAG, "OBSERVED_TAG_NOT_ISOLATED")
        observed=ruleset_status(rule,status)
        data.update(observed)
        need(observed["rule_scope_and_prohibition_fields_observed"],
             "RULESET_SCOPE_OR_PROHIBITION_NOT_OBSERVED")
    else:
        data["configured_rule_covers_isolated_tag"]=False
        data["isolated_tag_status"]="unknown"
    out=Path(args.output)
    need(out.parent.is_dir() and not out.is_symlink(),"OUTPUT_PARENT")
    out.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("391_SOURCE_AND_RULESET_READ_ONLY_NOT_EXECUTED_NO_PROVIDER")

if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""#392 read-only review of the staged, separately authorized GitHub negative probe."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
from fnmatch import fnmatchcase
from urllib.request import Request,build_opener,HTTPRedirectHandler
from urllib.error import HTTPError,URLError

WORKFLOW=Path(".github/workflows/final128-392-isolated-protected-tag-negative-operations-probe.yml")
BLOB="aaaf8c22d32080e694905a048c640d13b23de2ea"
REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
ENV="task1-real-model-pilot"
REF="refs/tags/final128-task1-real-ab-once-v1-391-test-only-global-consumed"
PRODUCTION_REF="refs/tags/final128-task1-first-two-real-responses-v1-consumed"
SHA="d9ba430e62d37c7b776bcfc93e3d46bc51f6ae3e"
DIFFERENT_SHA="c9accc3a15d97b53d0d3e140b2410f659aa0391f"
RULESET=24921425
ROOT="https://api.github.com/repos/"+REPO
TAG_URL=ROOT+"/git/ref/tags/"+REF.removeprefix("refs/tags/")
RULE_URL=ROOT+"/rulesets/"+str(RULESET)
CONSENT="I AUTHORIZE TEST TAG DUPLICATE UPDATE DELETE DENIAL NO PROVIDER"
RULES={"deletion","update","non_fast_forward"}
SCHEMA="veritas.final128.task1-392-negative-operations-staged-v1"

class Denied(ValueError):pass
def need(ok,reason):
    if ok is not True:raise Denied("392_"+reason)

def blob_sha(text):
    raw=text.encode("utf8")
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def embedded(text):
    start="          python - <<'PY'\n"
    end="          PY\n"
    need(text.count(start)==1 and text.count(end)==1,"HEREDOC")
    body=text.split(start,1)[1].split(end,1)[0]
    lines=body.splitlines()
    need(all(not line or line.startswith("          ") for line in lines),
         "PYTHON_INDENT")
    code="\n".join(line[10:] if line else "" for line in lines)+"\n"
    ast.parse(code)
    return code

def source_contract(text):
    need(type(text) is str and len(text)<14000,"SOURCE")
    need(blob_sha(text)==BLOB,"SOURCE_BLOB_PIN")
    need(text.startswith("name: Final128 392 Isolated Protected Tag Negative Operations Probe\n"),
         "WORKFLOW_NAME")
    need("on:\n  workflow_dispatch:" in text
         and text.count("  workflow_dispatch:")==1
         and "  pull_request:" not in text and "  push:" not in text,"MANUAL_ONLY")
    need("permissions:\n  contents: read\n" in text
         and text.count("      contents: write\n")==1,"LIMITED_WRITER_JOB")
    need(text.count("    environment:\n      name: "+ENV+"\n")==1,"ENVIRONMENT")
    need(text.count("      GH_NEGATIVE_TEST_TOKEN: ")==1,"GITHUB_JOB_TOKEN")
    need(text.count(CONSENT)==1
         and "cancel-in-progress: false" in text
         and "GITHUB_RUN_ATTEMPT" in text,"FRESH_MANUAL_GATE")
    need(REF in text and PRODUCTION_REF not in text
         and SHA in text and DIFFERENT_SHA in text,"ONLY_TEST_TAG")
    need("secrets." not in text and "OPENAI_API_KEY" not in text
         and "api.openai.com" not in text and "uses:" not in text
         and "actions/checkout" not in text,"NO_PROVIDER_OR_SOURCE_CHECKOUT")
    code=embedded(text)
    for needle in ('call("POST", ROOT,','call("PATCH", TAG_URL,',
                   'call("DELETE", TAG_URL)','call("GET", TAG_URL)',
                   'assert_unchanged("BEFORE")',
                   'assert_unchanged("AFTER_DUPLICATE")',
                   'assert_unchanged("AFTER_UPDATE")',
                   'assert_unchanged("AFTER_DELETE")'):
        need(code.count(needle)==1,"OPERATION_AND_READBACK_COUNTS")
    funcs={n.name for n in ast.parse(code).body if isinstance(n,ast.FunctionDef)}
    need({"call","assert_unchanged","explicit_duplicate_denial",
          "explicit_ruleset_denial"}.issubset(funcs),"DENIAL_CLASSIFIERS")
    return {
       "schema":SCHEMA,
       "workflow_exact_blob_sha":BLOB,
       "manual_negative_probe_staged_only":True,
       "isolated_ref":REF,"expected_sha":SHA,"different_sha":DIFFERENT_SHA,
       "expected_intentional_github_write_attempts_if_approved":3,
       "actual_github_mutations_or_attempts_by_this_audit":0,
       "production_task1_issuer_proven":False,
       "actual_duplicate_update_delete_denials_observed_in_this_audit":False,
       "production_bypass_resistance_proven":False,
       "task1_paid_provider_authorized":False,
    }

def validate_observation(ref,rule):
    need(type(ref) is dict and ref.get("ref")==REF
         and type(ref.get("object")) is dict
         and ref["object"].get("sha")==SHA
         and ref["object"].get("type")=="commit","EXACT_EXISTING_TAG")
    need(type(rule) is dict,"RULESET_TYPE")
    condition=rule.get("conditions")
    matcher=condition.get("ref_name") if type(condition) is dict else None
    need(type(matcher) is dict
         and type(matcher.get("include")) is list
         and type(matcher.get("exclude")) is list,"RULESET_PATTERN")
    need(all(type(x) is str for x in matcher["include"]+matcher["exclude"]),
         "RULESET_PATTERN_TYPES")
    covered=any(fnmatchcase(REF,x) for x in matcher["include"]) and not any(
        fnmatchcase(REF,x) for x in matcher["exclude"])
    types={x.get("type") for x in rule.get("rules",[])
           if type(x) is dict} if type(rule.get("rules")) is list else set()
    need(rule.get("id")==RULESET
         and rule.get("name")=="Task1 Single-Use Protection"
         and rule.get("target")=="tag" and rule.get("enforcement")=="active"
         and covered and RULES.issubset(types),"RULESET_SCOPE")
    present="bypass_actors" in rule and "current_user_can_bypass" in rule
    clear=(present and rule["bypass_actors"]==[]
           and rule["current_user_can_bypass"]=="never")
    return {
       "current_tag_matches_creation_proof":True,
       "rule_matches_test_tag_and_has_prohibitions":True,
       "bypass_metadata_complete":present,
       "bypass_status":("NO_BYPASS_OBSERVED" if clear else
                        "UNKNOWN_MISSING_PRIVILEGED_FIELDS" if not present
                        else "BYPASS_OR_PRIVILEGE_PRESENT"),
       "real_negative_mutation_experiment_executed":False,
       "actual_negative_response_codes_available":False,
       "task1_paid_provider_authorized":False,
    }

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise Denied("392_REDIRECT_DENIED")

def public_get(url):
    need(url in (TAG_URL,RULE_URL),"ONLY_TWO_PUBLIC_GET_URLS")
    req=Request(url,method="GET",headers={
        "Accept":"application/vnd.github+json",
        "User-Agent":"veritas-392-readonly-negative-source-check",
        "X-GitHub-Api-Version":"2022-11-28"})
    try:
        with build_opener(NoRedirect()).open(req,timeout=12) as res:
            need(res.geturl()==url,"URL_REDIRECT")
            raw=res.read(65537)
            need(len(raw)<=65536,"BODY_LIMIT")
    except (HTTPError,URLError,OSError,TimeoutError) as exc:
        raise Denied("392_PUBLIC_GET_UNAVAILABLE") from exc
    try:return json.loads(raw.decode("utf8"))
    except (ValueError,UnicodeError) as exc:
        raise Denied("392_INVALID_GITHUB_JSON") from exc

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--observe",action="store_true")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    need(WORKFLOW.is_file() and not WORKFLOW.is_symlink(),"WORKFLOW_FILE")
    result=source_contract(WORKFLOW.read_text(encoding="utf8"))
    if args.observe:
        result.update(validate_observation(public_get(TAG_URL),public_get(RULE_URL)))
        result["mode"]="TWO_PUBLIC_READONLY_GITHUB_GET_REQUESTS"
    else:
        result["mode"]="OFFLINE_NO_NETWORK"
    path=Path(args.output)
    need(path.parent.is_dir() and not path.is_symlink(),"OUTPUT_PATH")
    path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("392_NEGATIVE_PROBE_STAGED_ONLY_NO_GITHUB_WRITE_NO_PROVIDER")

if __name__=="__main__":
    main()

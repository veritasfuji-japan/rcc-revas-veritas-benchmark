#!/usr/bin/env python3
"""#387 static fail-closed audit of legacy manual Provider-secret jobs.

On the edited main source, a literal job-level if: FALSE_EXPR prevents a
manual dispatch job from accessing its secret or executing. Historical refs,
GitHub admin rights, separate credential copies and other effect channels
are NOT proven blocked. This audit never dispatches an action or Provider.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SCHEMA="veritas.final128.legacy-manual-provider-quarantine.387.v1"
ROOT=".github/workflows"
LEGACY=(
"agentdojo-task2-development-validation-v1.yml",
"agentdojo-task12-development-validation-v1.yml",
"agentdojo-task13-development-validation-v1.yml",
"agentdojo-task15-development-validation-v1.yml",
"agentdojo-clean-ab-final-v0_1.yml",
"agentdojo-clean-ab-canonical-final-v1.yml",
"final-128-v4-single-use-manual-dispatch.yml",
"final-128-v5-manual-dispatch.yml",
"final-128-v7-manual-dispatch.yml",
"final-128-v7-manual-dispatch-v2.yml",
"final-128-v8-manual-dispatch.yml",
"final-128-v10-manual-dispatch.yml",
"final-128-v11-manual-dispatch-template.yml",
"final-128-v12-manual-dispatch-template.yml",
"final-128-v13-manual-dispatch-template.yml",
)
MANUAL=re.compile(r"(?m)^  workflow_dispatch\s*:")
PROVIDER_SECRET=re.compile(r"secrets\.(?:OPENAI_API_KEY|TASK4_OPENAI_API_KEY|ANTHROPIC_API_KEY)")
JOB=re.compile(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$")
SHA=re.compile(r"^[0-9a-f]{40}$")
STOP_IF="    if: ${{ false }}"
RETIRE_A="    if: ${{ false }}  # #387 RETIRED: legacy conditional superseded by permanent default-deny"
RETIRE_B="    if: ${{ false }}  # #387 RETIRED: unprotected historical provider job blocked"
class Refused(ValueError):pass

def need(ok,code):
    if ok is not True:raise Refused("387_"+code)

def sha256(s):
    return hashlib.sha256(s.encode("utf8")).hexdigest()

def jobs(text):
    need(type(text) is str,"NOT_TEXT")
    m=re.search(r"(?m)^jobs:\s*$",text)
    if m is None:return []
    body=text[m.end():]
    end=re.search(r"(?m)^[a-zA-Z][a-zA-Z0-9_-]*:",body)
    if end is not None:body=body[:end.start()]
    hits=list(JOB.finditer(body))
    return [(match.group(1),
             body[match.end():hits[i+1].start() if i+1<len(hits) else len(body)])
            for i,match in enumerate(hits)]

def frozen(body):
    return re.search(r"(?m)^    if: \$\{\{ false \}\}(?:\s*#.*)?$",body) is not None

def manual_provider(text):
    return bool(MANUAL.search(text) and PROVIDER_SECRET.search(text))

def expected_variants(old):
    need(manual_provider(old),"BASE_MUST_BE_MANUAL_PROVIDER")
    rows=old.split("\n")
    start=rows.index("jobs:") if "jobs:" in rows else -1
    need(start>=0,"JOBS_NOT_FOUND")
    found=[i for i,s in enumerate(rows) if i>start and JOB.fullmatch(s)]
    need(len(found)==1,"EXPECTED_ONE_LEGACY_JOB")
    idx=found[0]
    out=[]
    if rows[idx+1].startswith("    if: "):
        historical=rows[idx+1]
        for label,comment in ((RETIRE_A,"    # Original historical condition: "),
                              (RETIRE_B,"    # Previous historical condition: ")):
            clone=list(rows)
            clone[idx+1]=label
            clone.insert(idx+2,comment+historical.strip())
            out.append("\n".join(clone))
    else:
        for label in (RETIRE_A,RETIRE_B):
            clone=list(rows)
            clone.insert(idx+1,label)
            out.append("\n".join(clone))
    return out

def baseline_blob(sha,path,root="."):
    need(type(sha) is str and SHA.fullmatch(sha) is not None,"BASE_SHA_MUST_BE_EXACT")
    need(path.startswith(ROOT+"/") and path.endswith((".yml",".yaml")),
         "BASE_PATH_INVALID")
    return subprocess.run(["git","-C",str(root),"show",f"{sha}:{path}"],
       check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.decode("utf8")

def all_files(root="."):
    directory=Path(root)/ROOT
    need(directory.is_dir(),"WORKFLOWS_DIR_MISSING")
    result={}
    for p in sorted(directory.iterdir()):
        if p.suffix not in (".yml",".yaml"):continue
        need(p.is_file() and not p.is_symlink(),"SYMLINK_OR_UNREADABLE_WORKFLOW")
        result[f"{ROOT}/{p.name}"]=p.read_text(encoding="utf8")
    need(len(result)>=330,"INCOMPLETE_WORKFLOW_INVENTORY")
    return result

def inspect(*,files,base_sha=None,root="."):
    need(type(files) is dict and len(files)>=len(LEGACY),"BAD_FILE_COLLECTION")
    records=[]
    unblocked=[]
    for path,text in sorted(files.items()):
        if not manual_provider(text):continue
        source_jobs=jobs(text)
        is_safe=bool(source_jobs) and all(frozen(body) for _,body in source_jobs)
        records.append({"path":path,"job_ids":[name for name,_ in source_jobs],
            "all_jobs_statically_stopped":is_safe,
            "source_sha256":sha256(text)})
        if not is_safe:unblocked.append(path)
    preserved=[]
    for n in LEGACY:
        path=f"{ROOT}/{n}"
        need(path in files,"LEGACY_WORKFLOW_MISSING")
        text=files[path]
        need(manual_provider(text),"LEGACY_MANUAL_SECRET_MISSING")
        need(len(jobs(text))==1 and frozen(jobs(text)[0][1]),
             "LEGACY_JOB_NOT_STOPPED")
        record={"path":path,"sha256":sha256(text),"disabled_before_job_execution":True}
        if base_sha is not None:
            before=baseline_blob(base_sha,path,root)
            need(text in expected_variants(before),"UNAPPROVED_LEGACY_SOURCE_CHANGE")
            record["base_sha256"]=sha256(before)
            record["only_job_gate_changed"]=True
        preserved.append(record)
    need(len(unblocked)==0,"UNCOVERED_MANUAL_PROVIDER_JOBS:"+",".join(unblocked[:10]))
    return {
      "schema":SCHEMA,
      "status":"CURRENT_BRANCH_MANUAL_PROVIDER_JOBS_STATICALLY_STOPPED_ONLY",
      "workflows_scanned":len(files),
      "legacy_paths_checked":len(preserved),
      "manual_provider_secret_workflows_detected":len(records),
      "unblocked_manual_provider_secret_workflows":len(unblocked),
      "legacy_evidence":preserved,
      "source_evidence":records,
      "base_sha":base_sha,
      "real_provider_requests":0,
      "github_secrets_rotated_or_revoked":False,
      "historical_git_ref_dispatch_resistance_verified":False,
      "git_workflow_admin_bypass_resistance_verified":False,
      "real_provider_execution_authorized":False,
      "production_scope_complete":False,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--base-sha",required=True)
    ap.add_argument("--root",default=".")
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    result=inspect(files=all_files(args.root),base_sha=args.base_sha,root=args.root)
    out=Path(args.output)
    need(out.parent.is_dir(),"OUTPUT_DIRECTORY_MISSING")
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("387_WORKFLOW_FILES="+str(result["workflows_scanned"]))
    print("387_LEGACY_STOPPED="+str(result["legacy_paths_checked"]))
    print("387_MANUAL_PROVIDER_SECRET_WORKFLOWS="+str(result["manual_provider_secret_workflows_detected"]))
    print("387_UNBLOCKED_MANUAL_PROVIDER_SECRET_WORKFLOWS="+str(result["unblocked_manual_provider_secret_workflows"]))
    print("387_NEW_PAID_REQUESTS=0")

if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""#387 exact historical source preservation + manual Provider workflow disable inventory.

No GitHub Actions admin mutation, secret access, Provider request or paid run.
The source-level scan is NOT evidence that any workflow is disabled through
GitHub Actions. It generates targets for separately authorized disable steps.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

SCHEMA="veritas.final128.manual-provider-workflow-disable-readiness.v1"
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
MANUAL=re.compile(r"(?m)^\s{2}workflow_dispatch\s*:")
PROVIDER_SECRET=re.compile(r'(?m)^\s*(?:-\s*env:\s*\{\s*)?(?:OPENAI_API_KEY|TASK4_OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*:\s*["\\\']?\$\{\{\s*secrets\.(?:OPENAI_API_KEY|TASK4_OPENAI_API_KEY|ANTHROPIC_API_KEY)')
JOB=re.compile(r"(?m)^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
DISABLED_IF=re.compile(r"(?m)^    if:\s*\$\{\{\s*false\s*\}\}(?:\s*#.*)?$")
SHA=re.compile(r"^[a-f0-9]{40}$")
REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
class Denied(ValueError):pass

def require(ok,msg):
    if ok is not True:raise Denied("387_"+msg)

def hexsha(value):
    return sha256(value.encode("utf8")).hexdigest()

def jobs(text):
    m=re.search(r"(?m)^jobs:\s*$",text)
    if m is None:return []
    tail=text[m.end():]
    end=re.search(r"(?m)^[a-zA-Z][\w-]*:",tail)
    if end is not None:tail=tail[:end.start()]
    hits=list(JOB.finditer(tail))
    return [(z.group(1),tail[z.end():hits[i+1].start() if i+1<len(hits) else len(tail)])
            for i,z in enumerate(hits)]

def is_manual_provider(text):
    return isinstance(text,str) and bool(MANUAL.search(text) and PROVIDER_SECRET.search(text))

def source_blocks_all_jobs(text):
    all_jobs=jobs(text)
    return bool(all_jobs) and all(bool(DISABLED_IF.search(body)) for _,body in all_jobs)

def read_base_file(root,sha,path):
    require(type(sha) is str and SHA.fullmatch(sha) is not None,"EXACT_BASE_SHA_REQUIRED")
    require(path.startswith(ROOT+"/") and path.endswith((".yml",".yaml")),
            "PATH_OUTSIDE_WORKFLOWS")
    return subprocess.run(["git","-C",str(root),"show",f"{sha}:{path}"],
         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
         check=True).stdout.decode("utf8")

def actual_workflows(root="."):
    folder=Path(root)/ROOT
    require(folder.is_dir(),"WORKFLOW_DIRECTORY_NOT_FOUND")
    out={}
    for p in sorted(folder.iterdir()):
        if p.suffix not in (".yml",".yaml"):continue
        require(p.is_file() and not p.is_symlink(),"WORKFLOW_SYMLINK_OR_BAD_FILE")
        out[f"{ROOT}/{p.name}"]=p.read_text(encoding="utf8")
    require(len(out)>=330,"WHOLE_REPOSITORY_INVENTORY_INCOMPLETE")
    return out

def audit(*,files,base_sha=None,root="."):
    require(type(files) is dict and bool(files),"SOURCE_SET_MISSING")
    all_targets=[]
    preserved=[]
    for path,content in sorted(files.items()):
        if not is_manual_provider(content):continue
        stopped=source_blocks_all_jobs(content)
        declared=bool(jobs(content)) and all(
            re.search(r"(?m)^    environment:\s*[^\s#][^\n]*$",body) is not None
            for _,body in jobs(content))
        all_targets.append({
            "path":path,"workflow_filename":Path(path).name,
            "job_count":len(jobs(content)),
            "job_names":[name for name,_ in jobs(content)],
            "blocked_on_current_source_only":stopped,
            "protected_environment_declared_not_attested":bool(declared),
            "needs_external_disable_workflow":not stopped and not declared,
            "needs_protected_environment_review":not stopped and declared,
            "source_sha256":hexsha(content),
        })
    for name in LEGACY:
        path=f"{ROOT}/{name}"
        require(path in files,"HISTORICAL_WORKFLOW_MISSING")
        txt=files[path]
        require(is_manual_provider(txt),"HISTORICAL_PROVIDER_WORKFLOW_DRIFT")
        doc={"path":path,"source_sha256":hexsha(txt)}
        if base_sha is not None:
            old=read_base_file(root,base_sha,path)
            require(txt==old,"FROZEN_HISTORICAL_WORKFLOW_CHANGED")
            doc["historical_source_matches_exact_base"]=True
        preserved.append(doc)
    paths={x["path"] for x in all_targets}
    require(set(f"{ROOT}/{name}" for name in LEGACY).issubset(paths),
            "HISTORICAL_MANUAL_PROVIDER_COVERAGE_MISSING")
    action_list=sorted(x["path"] for x in all_targets
                       if x["needs_external_disable_workflow"])
    protected_list=sorted(x["path"] for x in all_targets
                          if x["needs_protected_environment_review"])
    return {
       "schema":SCHEMA,
       "status":"REQUIRES_GITHUB_ACTIONS_ADMIN_DISABLE_AND_SECRET_ROTATION",
       "all_workflows_scanned":len(files),
       "manual_provider_secret_workflows_detected":len(all_targets),
       "legacy_historical_workflows_source_unchanged":len(preserved),
       "manual_provider_source_jobs_without_static_stop":len(action_list),
       "github_actions_disable_targets":action_list,
       "protected_provider_environment_review_targets":protected_list,
       "environment_declaration_not_live_protection_proof":True,
       "historical_original_source_evidence":preserved,
       "inventory":all_targets,
       "github_actions_workflow_state_verified":False,
       "github_workflow_disable_operations_performed":0,
       "github_repository_provider_secrets_revoked":False,
       "provider_project_access_and_limits_verified":False,
       "older_ref_dispatch_and_privileged_bypass_verified":False,
       "all_provider_bypasses_closed":False,
       "new_provider_calls":0,
       "new_native_scorer_runs":0,
       "task1_paid_run_authorized":False,
       "base_sha":base_sha,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base-sha",required=True)
    p.add_argument("--root",default=".")
    p.add_argument("--output",required=True)
    args=p.parse_args()
    report=audit(files=actual_workflows(args.root),
                 base_sha=args.base_sha,root=args.root)
    destination=Path(args.output)
    require(destination.parent.is_dir(),"EVIDENCE_OUTPUT_PARENT_MISSING")
    destination.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("387_FULL_WORKFLOWS_SCANNED="+str(report["all_workflows_scanned"]))
    print("387_MANUAL_PROVIDER_WORKFLOWS="+str(report["manual_provider_secret_workflows_detected"]))
    print("387_FROZEN_HISTORICAL_SOURCES_PRESERVED="+str(report["legacy_historical_workflows_source_unchanged"]))
    print("387_PROTECTED_ENVIRONMENT_REVIEW="+str(len(report["protected_provider_environment_review_targets"])))
    print("387_NEEDS_GITHUB_WORKFLOW_DISABLE="+str(report["manual_provider_source_jobs_without_static_stop"]))
    print("387_NO_GITHUB_ADMIN_WRITE_NO_PROVIDER_NO_SCORE")

if __name__=="__main__":
    main()

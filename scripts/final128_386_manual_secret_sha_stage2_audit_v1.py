#!/usr/bin/env python3
"""#386 exact-base, offline stage2 GitHub Actions hardening audit.

Only changes action tags -> already tested immutable SHAs for FOUR manually
dispatched, secret-using AgentDojo development workflows. Does not execute
them; does not grant authority, attest any paid Provider environment, or
assert that unprotected secret-bearing manual workflows are safe.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from scripts import final128_385_actions_sha_pinning_inventory_v1 as inventory

SCHEMA="veritas.final128.actions386.manual-secret-stage2-v1"
TASKS=(2,12,13,15)
PATHS=tuple(f".github/workflows/agentdojo-task{n}-development-validation-v1.yml" for n in TASKS)
PINNED_ACTIONS={
  "actions/checkout@v4":"actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
  "actions/setup-python@v5":"actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
  "actions/upload-artifact@v4":"actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
}
class Refused(ValueError):pass

def need(ok,msg):
    if ok is not True:raise Refused("386_"+msg)

def base_file(root,sha,path):
    need(type(sha) is str and inventory.SHA40.fullmatch(sha) is not None,"BASE_SHA_REQUIRED")
    need(path in PATHS,"UNSCOPED_BASE_READ")
    process=subprocess.run(["git","-C",str(root),"show",f"{sha}:{path}"],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           check=True)
    return process.stdout.decode("utf8")

def transformed_base(original):
    need(type(original) is str,"BASE_NOT_TEXT")
    changed=original
    count=0
    for before,after in PINNED_ACTIONS.items():
        n=changed.count("uses: "+before)
        need(n>=0,"INTERNAL_COUNT_ERROR")
        changed=changed.replace("uses: "+before,"uses: "+after)
        count+=n
    return changed,count

def validate_exact_stage2_change(path,old,new):
    need(path in PATHS,"WORKFLOW_NOT_IN_STAGE2")
    transformed,count=transformed_base(old)
    need(count==6,"EXPECTED_SIX_ACTIONS_IN_BASE")
    need(new==transformed,"ONLY_APPROVED_SHA_REPLACEMENTS_PERMITTED")
    one=inventory.audit_workflow(path,new)
    need(len(one["uses"])==6
         and all(u["kind"]=="PINNED_ACTION_SHA" for u in one["uses"]),
         "NOT_SIX_PINNED_ACTION_USES")
    need(one["manual_trigger_present"] is True
         and one["secret_context_mentioned"] is True,
         "EXPECTED_HISTORICAL_MANUAL_SECRET_WORKFLOW_CHANGED")
    need(not one["explicit_write_scopes"],
         "HISTORICAL_TOKEN_WRITE_SCOPE_CHANGE")
    need(not re.search(r"(?m)^\s*environment\s*:",new),
         "NEW_ENVIRONMENT_SCOPE_REQUIRES_SEPARATE_REVIEW")
    return {
      "path":path,
      "unchanged_except_exact_sha_pinning":True,
      "mutable_action_refs_replaced":count,
      "old_sha256":hashlib.sha256(old.encode()).hexdigest(),
      "new_sha256":hashlib.sha256(new.encode()).hexdigest(),
      "manual_trigger_still_present":True,
      "provider_secret_context_still_present":True,
      "explicit_token_writes_found":False,
      "protected_environment_bound_to_job":False,
      "no_provider_execution_performed":True,
      "manual_secret_workflow_not_approved_for_paid_run":True,
    }

def audit_stage2(root,base_sha):
    root=Path(root)
    before=inventory.scan_git_commit(root,base_sha)
    now=inventory.scan_directory(root)
    full=inventory.summarize(now,before)
    need(full["baseline_comparison"] is not None
         and full["baseline_comparison"]["new_unsafe_ref_regression"] is False,
         "GLOBAL_NEW_MUTABLE_REF_REGRESSION")
    reviewed=[]
    for path in PATHS:
        old=base_file(root,base_sha,path)
        new=(root/path).read_text(encoding="utf8")
        reviewed.append(validate_exact_stage2_change(path,old,new))
    need(sum(x["mutable_action_refs_replaced"] for x in reviewed)==24,
         "EXPECTED_24_REPLACEMENTS")
    return {
      "schema":SCHEMA,"status":"PIN_STAGE2_ONLY_UNPROTECTED_MANUAL_PROVIDER_PATHS_REMAIN",
      "base_sha":base_sha,
      "workflow_files_inventory":full["workflow_files"],
      "uses_refs_inventory":full["uses_references"],
      "remaining_unsafe_refs_inventory":full["unsafe_references_total"],
      "unsafe_refs_in_base":full["baseline_comparison"]["prior_unsafe_reference_findings"],
      "new_unsafe_reference_keys":full["baseline_comparison"]["new_unsafe_reference_keys"],
      "retired_unsafe_reference_keys":full["baseline_comparison"]["retired_unsafe_reference_keys"],
      "stage2_manual_secret_workflows":reviewed,
      "stage2_pinned_action_references":24,
      "remaining_manual_secret_workflows_without_protected_environment_in_stage2":4,
      "new_live_environment_or_approval_guard_added":False,
      "environment_secret_isolation_verified":False,
      "openai_project_billing_limit_verified":False,
      "actual_paid_provider_requests":0,
      "real_issuer_single_use_verified":False,
      "production_bypass_resistance_verified":False,
      "repository_wide_sha_enforcement_ready":False,
      "next_priority":"SEPARATE_PROTECTED_ENVIRONMENT_AND_DISPATCH_DENIAL_REVIEW",
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--base-sha",required=True)
    parser.add_argument("--root",default=".")
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    report=audit_stage2(args.root,args.base_sha)
    path=Path(args.output)
    need(path.parent.is_dir(),"EVIDENCE_DIRECTORY_NOT_FOUND")
    path.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print("386_ACTIONS_PINNED="+str(report["stage2_pinned_action_references"]))
    print("386_WORKFLOWS="+str(report["workflow_files_inventory"]))
    print("386_UNSAFE_REFS_REMAIN="+str(report["remaining_unsafe_refs_inventory"]))
    print("386_UNPROTECTED_MANUAL_SECRET_WORKFLOWS=4")
    print("386_GLOBAL_NEW_UNSAFE_REFERENCES=0")
    print("386_REAL_PROVIDER=0")

if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""#385 all repository GitHub Actions reference audit; no network or changes.

Lists mutable external uses references, docker tags, dynamic uses expressions
and explicitly writable GITHUB_TOKEN scopes. Compares exact base SHA to
HEAD to prevent new mutable action references while pinning core CI first.
This static text inventory is not full YAML semantics or an IAM audit.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess

SCHEMA="veritas.actions.sha-pinning-inventory.v1"
WORKFLOWS=".github/workflows"
SHA40=re.compile(r"^[0-9a-fA-F]{40}$")
DOCKER_SHA=re.compile(r"^docker://[^ \t]+@sha256:[a-fA-F0-9]{64}$")
USE_LINE=re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(.*?)\s*$")
PERMISSION_START=re.compile(r"^(\s*)permissions\s*:\s*(.*)$")
PERMISSION_ENTRY=re.compile(r"^\s*([a-z][a-z-]*):\s*(read|write|none)\s*(?:#.*)?$")
CORE_FILES=(".github/workflows/ci.yml",
            ".github/workflows/native-veritas-benchmark.yml")
EXPECTED_CORE_ACTIONS={
    "actions/checkout":"11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python":"a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact":"ea165f8d65b6e75b540449e92b4886f43607fa02",
}
BAD_KINDS={"MUTABLE_ACTION_TAG","MUTABLE_DOCKER_IMAGE",
           "DYNAMIC_ACTION_REF","INVALID_EXTERNAL_ACTION"}
class Refused(ValueError):pass

def need(ok,code):
    if ok is not True:raise Refused("385_"+code)

def classify_uses(raw):
    need(type(raw) is str,"USES_IS_NOT_STRING")
    value=raw.strip().split(" #",1)[0].strip().strip("'\"")
    if value.startswith("./"):return "LOCAL_ACTION",value
    if "\u0024{{" in value or "$(" in value or value.startswith("!"):
        return "DYNAMIC_ACTION_REF","<DYNAMIC_REFERENCE_REDACTED>"
    if value.startswith("docker://"):
        return ("PINNED_DOCKER_DIGEST" if DOCKER_SHA.fullmatch(value)
                else "MUTABLE_DOCKER_IMAGE"),value[:180]
    if value.count("@")!=1:return "INVALID_EXTERNAL_ACTION",value[:180]
    package,ref=value.rsplit("@",1)
    if not package or "/" not in package or any(x in package for x in (" ","\\","..")):
        return "INVALID_EXTERNAL_ACTION",value[:180]
    return ("PINNED_ACTION_SHA" if SHA40.fullmatch(ref)
            else "MUTABLE_ACTION_TAG"),value[:180]

def audit_workflow(path,raw):
    need(type(path) is str and path.startswith(WORKFLOWS+"/")
         and path.endswith((".yml",".yaml")),"PATH_NOT_WORKFLOW")
    need(type(raw) is str and len(raw)<=1_000_000,"WORKFLOW_TEXT_INVALID")
    uses=[];writes=[];permissions_indent=None
    for i,line in enumerate(raw.splitlines(),1):
        if not line.strip() or line.lstrip().startswith("#"):continue
        indent=len(line)-len(line.lstrip(" "))
        if permissions_indent is not None and indent<=permissions_indent:
            permissions_indent=None
        p=PERMISSION_START.match(line)
        if p:
            permissions_indent=indent
            if p.group(2).strip().split(" #",1)[0].strip()=="write-all":
                writes.append({"line":i,"permission":"write-all"})
        elif permissions_indent is not None:
            x=PERMISSION_ENTRY.match(line)
            if x and x.group(2)=="write":
                writes.append({"line":i,"permission":x.group(1)})
        match=USE_LINE.match(line)
        if match:
            kind,ref=classify_uses(match.group(1))
            uses.append({"line":i,"kind":kind,"reference":ref})
    return {"path":path,"blob_sha256":sha256(raw.encode()).hexdigest(),
            "uses":uses,"explicit_write_scopes":writes,
            "manual_trigger_present":bool(re.search(
                r"(?m)^\s*workflow_dispatch\s*:",raw)),
            "secret_context_mentioned":bool(re.search(
                r"\u0024\{\{\s*secrets\.",raw)),
            "parse_scope":"LITERAL_LINES_NOT_FULL_YAML_SEMANTICS"}

def is_workflow(p):
    return (p.startswith(WORKFLOWS+"/") and
            p.endswith((".yml",".yaml")) and p.count("/")==2)

def scan_directory(root):
    base=Path(root)/WORKFLOWS
    need(base.is_dir(),"WORKFLOWS_DIR_MISSING")
    files=sorted(p for p in base.iterdir() if p.is_file()
                 and p.suffix in (".yml",".yaml"))
    need(bool(files),"NO_WORKFLOW_FILES")
    result=[]
    for p in files:
        need(not p.is_symlink(),"WORKFLOW_SYMLINK")
        result.append(audit_workflow(f"{WORKFLOWS}/{p.name}",
                                     p.read_text(encoding="utf8")))
    return result

def scan_git_commit(root,revision):
    need(type(revision) is str and SHA40.fullmatch(revision) is not None,
         "BASE_SHA_NOT_FULL_HEX")
    def git(args):
        return subprocess.run(["git","-C",str(root),*args],check=True,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
    paths=sorted(p for p in git(
        ["ls-tree","-r","--name-only",revision,"--",WORKFLOWS]
    ).decode().splitlines() if is_workflow(p))
    need(bool(paths),"BASE_WORKFLOWS_MISSING")
    return [audit_workflow(path,git(["show",f"{revision}:{path}"]).decode())
            for path in paths]

def issue_keys(scanned):
    return {(f["path"],u["kind"],u["reference"])
            for f in scanned for u in f["uses"] if u["kind"] in BAD_KINDS}

def summarize(scanned,base=None):
    paths=[x["path"] for x in scanned]
    need(len(paths)==len(set(paths)),"DUPLICATE_WORKFLOW")
    kinds=Counter(u["kind"] for f in scanned for u in f["uses"])
    findings=sorted(({"path":f["path"],**u} for f in scanned
                     for u in f["uses"] if u["kind"] in BAD_KINDS),
                     key=lambda x:(x["path"],x["line"]))
    writes=sorted(({"path":f["path"],**v} for f in scanned
                   for v in f["explicit_write_scopes"]),
                   key=lambda x:(x["path"],x["line"]))
    comparison=None
    if base is not None:
        new=issue_keys(scanned)-issue_keys(base)
        retired=issue_keys(base)-issue_keys(scanned)
        comparison={
          "prior_workflow_files":len(base),
          "prior_unsafe_reference_findings":sum(
              u["kind"] in BAD_KINDS for f in base for u in f["uses"]),
          "new_unsafe_reference_keys":sorted(
              ({"path":x[0],"kind":x[1],"reference":x[2]} for x in new),
              key=lambda x:(x["path"],x["reference"])),
          "retired_unsafe_reference_keys":sorted(
              ({"path":x[0],"kind":x[1],"reference":x[2]} for x in retired),
              key=lambda x:(x["path"],x["reference"])),
          "new_unsafe_ref_regression":bool(new)}
    return {
        "schema":SCHEMA,"status":"INVENTORY_ONLY_NO_GLOBAL_SHA_ENFORCEMENT",
        "workflow_files":len(scanned),"uses_references":sum(kinds.values()),
        "reference_classes":dict(sorted(kinds.items())),
        "unsafe_references_total":len(findings),"unsafe_references":findings,
        "explicit_write_scope_occurrences":len(writes),"explicit_write_scopes":writes,
        "manual_dispatch_workflows":sum(f["manual_trigger_present"] for f in scanned),
        "manual_dispatch_with_secret_context_indicator":sum(
            f["manual_trigger_present"] and f["secret_context_mentioned"]
            for f in scanned),
        "workflow_file_digests":{f["path"]:f["blob_sha256"] for f in scanned},
        "stage1_core_paths":list(CORE_FILES),
        "stage1_core_sha_refs_fully_pinned":all(
            any(f["path"]==p for f in scanned)
            and all(u["kind"] not in BAD_KINDS
                    for f in scanned if f["path"]==p for u in f["uses"])
            for p in CORE_FILES),
        "baseline_comparison":comparison,
        "repository_wide_sha_enforcement_ready":False,
        "real_provider_calls":0,"github_settings_modified":False,
        "provider_authority_granted":False,
        "production_bypass_resistance_verified":False}

def ensure_stage1(scanned,report):
    need(report["stage1_core_sha_refs_fully_pinned"] is True,
         "CORE_STAGE_HAS_UNPINNED_REF")
    for f in scanned:
        if f["path"] not in CORE_FILES:continue
        for u in f["uses"]:
            if u["kind"]=="PINNED_ACTION_SHA":
                package,ref=u["reference"].rsplit("@",1)
                need(EXPECTED_CORE_ACTIONS.get(package)==ref,
                     "CORE_PIN_UNEXPECTED_SHA")
    need(report["baseline_comparison"] is not None,"BASELINE_REQUIRED")
    need(report["baseline_comparison"]["new_unsafe_ref_regression"] is False,
         "NEW_MUTABLE_REF_REGRESSION")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",default=".")
    ap.add_argument("--baseline-sha",required=True)
    ap.add_argument("--output",required=True)
    args=ap.parse_args()
    current=scan_directory(args.root)
    before=scan_git_commit(args.root,args.baseline_sha)
    result=summarize(current,before)
    ensure_stage1(current,result)
    dest=Path(args.output)
    need(dest.parent.is_dir(),"OUTPUT_PARENT_MISSING")
    dest.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",
                    encoding="utf8")
    print("385_WORKFLOWS="+str(result["workflow_files"]))
    print("385_USES="+str(result["uses_references"]))
    print("385_MUTABLE_REFS="+str(result["unsafe_references_total"]))
    print("385_EXPLICIT_WRITES="+str(result["explicit_write_scope_occurrences"]))
    print("385_STAGE1_CORE_PINNED=TRUE")
    print("385_NEW_MUTABLE_REFS=0")
    print("385_NO_PROVIDER_OR_GLOBAL_SHA_ENFORCEMENT")

if __name__=="__main__":main()

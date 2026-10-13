#!/usr/bin/env python3
"""#389 source-only gate probe verifier. No GitHub or Provider API clients."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


SCHEMA="veritas.final128.task1.389.zero-provider-environment-probe.source.v1"
WORKFLOW=Path(".github/workflows/final128-389-task1-environment-approval-zero-provider-probe.yml")
REPO="veritasfuji-japan/rcc-revas-veritas-benchmark"
ENVIRONMENT="task1-real-model-pilot"
ACK="ACKNOWLEDGE_ZERO_PROVIDER_DRY_RUN"
EXPECTED_GIT_BLOB_SHA="e67dc16d065111bb622fdc454b43f53f672286cf"
PRE=(
    'set -euo pipefail\n'
    'test "$GITHUB_EVENT_NAME" = "workflow_dispatch"\n'
    'test "$GITHUB_REPOSITORY" = "veritasfuji-japan/rcc-revas-veritas-benchmark"\n'
    'test "$GITHUB_ACTOR" = "veritasfuji-japan"\n'
    'test "$GITHUB_REF" = "refs/heads/main"\n'
    'test "$GITHUB_RUN_ATTEMPT" = "1"\n'
    'test "$ACKNOWLEDGMENT" = "ACKNOWLEDGE_ZERO_PROVIDER_DRY_RUN"\n'
    "printf 'TASK1_389_PREFLIGHT_ONLY_NO_PROVIDER_NO_SECRET_NO_REF_WRITE\\n'\n"
    "printf 'Pre-environment preflight succeeded for run %s on %s.\\n' "
    '"$GITHUB_RUN_ID" "$GITHUB_SHA" >> "$GITHUB_STEP_SUMMARY"\n'
)
POST=(
    'set -euo pipefail\n'
    'test "$GITHUB_REPOSITORY" = "veritasfuji-japan/rcc-revas-veritas-benchmark"\n'
    'test "$GITHUB_ACTOR" = "veritasfuji-japan"\n'
    'test "$GITHUB_REF" = "refs/heads/main"\n'
    'test "$GITHUB_RUN_ATTEMPT" = "1"\n'
    "printf 'TASK1_389_PROTECTED_MARKER_NO_PROVIDER_NO_SECRET_NO_REF_WRITE\\n'\n"
    "printf 'Protected-marker job started for run %s on %s. "
    "This proves only that GitHub allowed this job to begin.\\n' "
    '"$GITHUB_RUN_ID" "$GITHUB_SHA" >> "$GITHUB_STEP_SUMMARY"\n'
)
class Denied(ValueError): pass

def require(cond, reason):
    if cond is not True:
        raise Denied("389_"+reason)

def exact_keys(obj, expected, reason):
    require(type(obj) is dict and set(obj)==set(expected), reason)

def validate_source(text):
    require(type(text) is str and 100 < len(text) < 15000, "SOURCE_SIZE")
    require(not any(s in text for s in (
        "secrets.", "vars.", "OPENAI_API_KEY", "TASK4_OPENAI_API_KEY",
        "GH_TOKEN", "GITHUB_TOKEN", "api.openai.com", "curl ", "wget ",
        "gh api", "git push", "checkout@", "uses:", "pull_request_target",
        "schedule:", "push:", "repository_dispatch:", "workflow_call:",
    )), "NO_SECRET_NETWORK_AUTO_EVENT_OR_EXTERNAL_ACTION")
    # Exact Git blob pin. A changed YAML byte (including any new auto trigger,
    # unauthorized step or secret access) is rejected. Standard library only.
    raw=text.encode("utf8")
    git_blob=b"blob "+str(len(raw)).encode("ascii")+b"\\0"+raw
    require(hashlib.sha1(git_blob).hexdigest()==EXPECTED_GIT_BLOB_SHA,
            "EXACT_REVIEWED_WORKFLOW_BLOB_MISMATCH")
    require(text.count("    environment:\\n      name: task1-real-model-pilot\\n")==1,
            "EXACT_PROTECTED_MARKER")
    require(text.count("  workflow_dispatch:\\n")==1,
            "MANUAL_ONLY")
    require(all(("          "+line+"\\n") in text for line in PRE.splitlines()),
            "PREFLIGHT_EXACT_SCRIPT")
    require(all(("          "+line+"\\n") in text for line in POST.splitlines()),
            "PROTECTED_EXACT_SCRIPT")
    return {
        "schema":SCHEMA,
        "status":"SOURCE_CONTRACT_VALID_BUT_NO_LIVE_GATE_OBSERVATION",
        "exact_workflow_source_sha256":hashlib.sha256(text.encode()).hexdigest(),
        "manual_dispatch_only":True,
        "preflight_before_protected_job":True,
        "preflight_no_environment_no_secret_binding":True,
        "protected_job_environment_name":ENVIRONMENT,
        "no_provider_or_secret_or_external_action":True,
        "no_git_ref_write":True,
        "main_only_actor_only_first_attempt_preflight":True,
        "approval_ui_not_read_or_attested":True,
        "wait_timer_runtime_observed":False,
        "required_reviewer_runtime_observed":False,
        "admin_bypass_runtime_verified":False,
        "manual_dry_run_executed_by_this_audit":False,
        "real_single_use_issuer_verified":False,
        "hard_provider_budget_cap_verified":False,
        "real_provider_calls":0,
        "native_scorer_calls":0,
        "new_utility_scores":None,
        "production_bypass_resistance_proven":False,
        "task1_live_execution_authorized":False,
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",default=str(WORKFLOW))
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    path=Path(args.source)
    require(path.is_file() and not path.is_symlink(), "SOURCE_REGULAR_FILE")
    report=validate_source(path.read_text("utf8"))
    dest=Path(args.output)
    require(dest.parent.is_dir() and not dest.is_symlink(), "OUTPUT_PARENT")
    dest.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf8")
    print("389_SOURCE_CONTRACT_ONLY_NEVER_DISPATCHES_OR_AUTHORIZES_PROVIDER")

if __name__=="__main__":
    main()

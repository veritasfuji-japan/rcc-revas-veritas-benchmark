#!/usr/bin/env python3
"""#327 CI proof report: independent local processes share EXACTLY one DB file.

All processes are LOCAL under the SAME GitHub Actions job. This can never prove
two different hosted runners consume a globally shared lease.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_327_offline_shared_sqlite_once_v1 as m

def need(v,msg):
    if not v:raise m.Refused(msg)

def run_worker(db,root,index,*,crash=False):
    env=dict(os.environ)
    env["TASK4_327_LEDGER_ROOT"]=str(root)
    command=[sys.executable,
        str(ROOT/"scripts/task4_327_offline_shared_sqlite_once_v1.py"),
        "claim","--db",str(db),
        "--worker-id",f"offline-327-worker-{index}",
        "--request-sha",m.sha({"worker":index,"simulated":True})]
    if crash:command.append("--crash-after-commit")
    result=subprocess.run(command,capture_output=True,text=True,
                          timeout=20,env=env,check=False)
    return {
        "worker_index":index,
        "process_return_code":result.returncode,
        "local_claim_receipt":json.loads(result.stdout) if
                              result.returncode==0 else None,
        "refusal_was_fail_closed":result.returncode==3,
        "real_provider_posts":0
    }

def proof():
    with tempfile.TemporaryDirectory(prefix="task4-327-offline-") as temp:
        path=Path(temp)
        root=path/"race";root.mkdir()
        db=root/"one-shot-test.sqlite3"
        with ThreadPoolExecutor(max_workers=12) as pool:
            rows=list(pool.map(lambda i:run_worker(db,root,i),range(16)))
        winning=[x for x in rows if x["process_return_code"]==0]
        rejected=[x for x in rows if x["process_return_code"]==3]
        need(len(winning)==1 and len(rejected)==15,
             "SIXTEEN_INDEPENDENT_PROCESSES_MUST_HAVE_ONE_WINNER")
        os.environ["TASK4_327_LEDGER_ROOT"]=str(root)
        durable=m.inspect_one_shot(db)
        need(len(durable)==1 and durable[0]["receipt_sha256"]==
             winning[0]["local_claim_receipt"]["receipt_sha256"],
             "DURABLE_AFTER_SIXTEEN_PROCESSES_MISMATCH")
        race_file_sha=hashlib.sha256(db.read_bytes()).hexdigest()
        # Use a separate isolated DB to show kill-after-COMMIT, then
        # a second fresh process must NEVER be able to reclaim that trial.
        another=path/"after-commit-crash";another.mkdir()
        crash_db=another/"one-shot-test.sqlite3"
        crashed=run_worker(crash_db,another,0,crash=True)
        need(crashed["process_return_code"]==74,"SIMULATED_POST_COMMIT_CRASH_REQUIRED")
        retry=run_worker(crash_db,another,1)
        need(retry["process_return_code"]==3 and retry["refusal_was_fail_closed"],
             "UNCERTAIN_POST_COMMIT_CRASH_MUST_DENY_RESEND")
        os.environ["TASK4_327_LEDGER_ROOT"]=str(another)
        after_crash=m.inspect_one_shot(crash_db)
        need(len(after_crash)==1 and
             after_crash[0]["outcome"]=="UNKNOWN_PERMANENTLY_CONSUMED",
             "COMMITTED_UNKNOWN_NOT_DURABLE")
        crash_file_sha=hashlib.sha256(crash_db.read_bytes()).hexdigest()
    record={
        "rule_of_one":m.RULE,
        "exact_parent_main_sha":m.PARENT_MAIN,
        "backend":"ONE_SHARED_LOCAL_SQLITE_FILE_NOT_GITHUB_REMOTE_LEDGER",
        "parallel_independent_process_count":16,
        "successful_atomic_local_claim_count":1,
        "rejected_parallel_claim_count":15,
        "crash_after_committed_consumption_process_exit_code":74,
        "fresh_process_retry_after_commit_crash_rejected":True,
        "sqlite_race_ledger_sha256":race_file_sha,
        "sqlite_crash_ledger_sha256":crash_file_sha,
        "separate_local_processes_use_same_shared_db":True,
        "separate_github_hosted_runners_proven":False,
        "real_provider_sender_present":False,
        "api_tokens_or_spending_authorized":False,
        "real_provider_posts":0,
        "new_final128_scores":0,
        "real_bank_effects":0,
        "api_dispatch":"DENY",
        "success_receipt":winning[0]["local_claim_receipt"],
        "all_local_worker_results":rows,
        "crash_ledger_row":after_crash[0],
        "status":"OFFLINE_SHARED_SQLITE_ATOMIC_LOCAL_ONCE_AND_UNKNOWN_NO_RETRY_ONLY"
    }
    record["report_sha256"]=m.sha(record)
    return record

def main():
    if len(sys.argv)!=2:raise SystemExit("USAGE: report.py <path under results>")
    dst=(ROOT/sys.argv[1]).resolve(strict=False)
    need(dst.parent==(ROOT/"results") and dst.suffix==".json" and
         not dst.exists(),"REPORT_MUST_BE_NEW_LOCAL_RESULTS_JSON")
    need(not any(os.environ.get(key) for key in m.SENSITIVE),
         "NO_LIVE_PROVIDER_CONTEXT")
    out=proof()
    dst.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print("TASK4_327_1_OF_16_LOCAL_PROCESSES_CLAIMED_CROSS_HOST_NOT_PROVEN_NO_PROVIDER")

if __name__=="__main__":main()

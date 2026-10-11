#!/usr/bin/env python3
"""#328: 16 independent OS clients compete over ONE separately hosted HTTP mock.

Server process owns SQLite. Clients contact it only by HTTP over loopback.
The modelled API is GitHub POST /git/refs; GitHub itself is NEVER contacted.
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
import time

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from scripts import task4_328_remote_mock_github_cas_v1 as api

def must(x,why):
    if not x:raise api.Denied(why)
def safe_env():
    a=dict(os.environ)
    for k in api.SENSITIVE:a.pop(k,None)
    return a

class LocalRemoteServer:
    def __init__(self,folder):
        self.folder=Path(folder)
        self.db=self.folder/"remote-emulator.sqlite3"
        self.port_file=self.folder/"port.txt"
        self.proc=None;self.port=None
    def start(self):
        must(self.proc is None,"SERVER_ALREADY_STARTED")
        self.port_file.unlink(missing_ok=True)
        self.proc=subprocess.Popen(
           [sys.executable,str(ROOT/"scripts/task4_328_remote_mock_github_cas_v1.py"),
            "server","--db",str(self.db),"--port-file",str(self.port_file)],
           cwd=str(self.folder),env=safe_env(),stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE)
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if self.port_file.is_file():
                self.port=int(self.port_file.read_text())
                return self.port
            if self.proc.poll() is not None:
                raise api.Denied("LOCAL_REMOTE_SERVER_DIED_BEFORE_READY")
            time.sleep(0.025)
        self.stop()
        raise api.Denied("LOCAL_REMOTE_SERVER_START_TIMEOUT")
    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:self.proc.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.communicate(timeout=4)
            self.proc=None;self.port=None
    def worker(self,i,*,drop=False):
        must(self.port is not None,"SERVER_MUST_BE_RUNNING")
        cmd=[sys.executable,str(ROOT/"scripts/task4_328_remote_mock_github_cas_v1.py"),
             "worker","--port",str(self.port),"--worker",f"worker-{i}"]
        if drop:cmd.append("--drop-reply")
        proc=subprocess.run(cmd,cwd=str(self.folder),env=safe_env(),
                            capture_output=True,text=True,timeout=12)
        must(proc.returncode in (0,3,4),"UNKNOWN_CLIENT_PROCESS_EXIT")
        result=json.loads(proc.stdout)
        must(result["real_provider_post_allowed"] is False and
             result["remote_git_hub_ref_was_created"] is False,
             "CLIENT_CANNOT_CLAIM_REAL_PROVIDER_OR_GITHUB_WRITE")
        result["process_exit_code"]=proc.returncode
        return result

def remote_emulation_report():
    api.forbid_real_keys()
    with tempfile.TemporaryDirectory(prefix="task4-328-offline-") as path:
        root=Path(path)
        race_dir=root/"separate-client-runner-emulator";race_dir.mkdir()
        remote=LocalRemoteServer(race_dir)
        try:
            remote.start()
            with ThreadPoolExecutor(max_workers=12) as pool:
                processes=list(pool.map(remote.worker,range(16)))
            wins=[x for x in processes if x["process_exit_code"]==0]
            duplicates=[x for x in processes if x["process_exit_code"]==3]
            must(len(wins)==1 and len(duplicates)==15,
                 "REMOTE_MOCK_CAS_SIXTEEN_CLIENTS_NOT_EXACTLY_ONE")
            backend=api.backend_rows(remote.db)
            must(len(backend)==1 and backend[0]["ref"]==api.REF,
                 "ONE_SERVER_OWNED_REMOTE_MOCK_RECORD_REQUIRED")
            remote.stop()
            remote.start() # persistent backend survives SERVER PROCESS RESTART
            follow=remote.worker(17)
            must(follow["process_exit_code"]==3,
                 "NEW_CLIENT_AFTER_SERVER_RESTART_MUST_REFUSE")
            durable=api.backend_rows(remote.db)
            must(durable==backend,"RESTART_CHANGED_REMOTE_TEST_RECORD")
        finally:remote.stop()
        # New isolated server+backend simulates dropped response AFTER COMMIT.
        loss_dir=root/"unknown-after-remote-commit";loss_dir.mkdir()
        lost=LocalRemoteServer(loss_dir)
        try:
            lost.start()
            unknown=lost.worker(0,drop=True)
            must(unknown["process_exit_code"]==4 and
                 unknown["state"]=="UNKNOWN_OR_MOCK_REJECTED_NO_RETRY",
                 "NO_RECEIPT_AFTER_REMOTE_COMMIT_MUST_BE_UNKNOWN")
            record=api.backend_rows(lost.db)
            must(len(record)==1,"LOST_HTTP_REPLY_MUST_NOT_ROLL_BACK_COMMIT")
            lost.stop()
            lost.start()
            retry=lost.worker(1)
            must(retry["process_exit_code"]==3,
                 "SERVER_RESTART_UNCERTAIN_REQUEST_MUST_DENY_RETRY")
            must(api.backend_rows(lost.db)==record,
                 "CRASH_UNKNOWN_REMOTE_MOCK_RECORD_NOT_STABLE")
        finally:lost.stop()
        race_hash=hashlib.sha256((race_dir/"remote-emulator.sqlite3").read_bytes()).hexdigest()
        unknown_hash=hashlib.sha256((loss_dir/"remote-emulator.sqlite3").read_bytes()).hexdigest()
    report={
      "rule_of_one":api.RULE,
      "frozen_parent_main_sha":api.PARENT_MAIN,
      "git_rest_create_ref_path_emulated":api.API_PATH,
      "fixed_trial_ref":api.REF,
      "backend_type":"SEPARATE_LOCALHOST_HTTP_SERVER_WITH_ITS_OWN_SQLITE_NOT_GITHUB",
      "separate_python_client_processes":16,
      "remote_mock_atomic_create_successes":1,
      "remote_mock_duplicate_refusals":15,
      "server_process_restart_then_new_client_duplicate_refused":True,
      "remote_commit_then_lost_http_response_marked_unknown":True,
      "retry_after_lost_response_and_server_restart_rejected":True,
      "isolated_backend_race_file_sha256":race_hash,
      "isolated_backend_unknown_file_sha256":unknown_hash,
      "backend_race_record":backend[0],
      "backend_unknown_record":record[0],
      "race_processes":processes,
      "missing_response_client":unknown,
      "after_crash_refused_client":retry,
      "actual_github_remote_ref_writes":0,
      "actual_distinct_github_actions_runs_tested":0,
      "real_github_ref_cas_guarantee_proven":False,
      "remote_backend_independent_admin_immutability_proven":False,
      "real_model_api_posts":0,
      "real_bank_effects":0,
      "new_final128_scores":0,
      "real_provider_dispatch":"DENY",
      "status":"SEPARATE_PROCESS_REMOTE_HTTP_CREATE_ONLY_MOCK_PROVEN_NOT_GITHUB_CROSS_RUN"
    }
    report["report_sha256"]=api.sha(report)
    return report

def main():
    if len(sys.argv)!=2:raise SystemExit("Usage: report.py results/output.json")
    dest=(ROOT/sys.argv[1]).resolve()
    must(dest.parent==ROOT/"results" and dest.suffix==".json"
         and not dest.exists(),"NEW_LOCAL_RESULTS_JSON_ONLY")
    record=remote_emulation_report()
    dest.write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
    print("TASK4_328_REMOTE_HTTP_MOCK_1_OF_16_ONLY_REAL_GITHUB_NOT_CALLED")

if __name__=="__main__":main()

"""#327 local multi-process shared SQLite atomic once semantics, NO network sender."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts import task4_327_offline_shared_sqlite_once_v1 as m

@pytest.fixture
def ledger(tmp_path,monkeypatch):
    for k in m.SENSITIVE:monkeypatch.delenv(k,raising=False)
    monkeypatch.setenv("TASK4_327_LEDGER_ROOT",str(tmp_path))
    return tmp_path/"one-shot-test.sqlite3"

def claim(db,ident="worker-1",req="a"*64,**kw):
    return m.claim_once(db,req,ident,**kw)

def run_subprocess(db,ident="worker",hash_="a"*64,crash=False,root=None):
    env=dict(os.environ)
    if root is not None:env["TASK4_327_LEDGER_ROOT"]=str(root)
    cmd=[sys.executable,str(ROOT/"scripts/task4_327_offline_shared_sqlite_once_v1.py"),
         "claim","--db",str(db),"--worker-id",ident,"--request-sha",hash_]
    if crash:cmd+=["--crash-after-commit"]
    return subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=20)

def test_single_claim_consumed_forever_restart_separate_process(ledger):
    one=claim(ledger)
    assert one["real_provider_send_allowed"] is False
    assert one["outcome"]=="UNKNOWN_PERMANENTLY_CONSUMED"
    assert len(m.inspect_one_shot(ledger))==1
    with pytest.raises(m.Refused):claim(ledger,"worker-restart")
    other=run_subprocess(ledger,"different-process","b"*64)
    assert other.returncode==3
    assert "REFUSED" in other.stderr
    assert len(m.inspect_one_shot(ledger))==1

def test_true_concurrent_distinct_python_processes_exact_one_winner(ledger):
    jobs=range(16)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results=list(pool.map(lambda i:run_subprocess(
            ledger,"independent-worker-"+str(i),m.sha({"worker":i})),jobs))
    assert [x.returncode for x in results].count(0)==1
    assert [x.returncode for x in results].count(3)==15
    assert len(m.inspect_one_shot(ledger))==1
    winner=next(x for x in results if x.returncode==0)
    receipt=json.loads(winner.stdout)
    assert receipt["real_provider_send_allowed"] is False
    assert m.inspect_one_shot(ledger)[0]["receipt_sha256"]==receipt["receipt_sha256"]

def test_commit_then_terminated_worker_is_still_irrevocably_consumed(ledger):
    crashed=run_subprocess(ledger,"simulated-unknown-after-COMMIT",
                            crash=True)
    assert crashed.returncode==74
    seen=m.inspect_one_shot(ledger)
    assert len(seen)==1
    assert seen[0]["claimed_by"]=="simulated-unknown-after-COMMIT"
    assert seen[0]["outcome"]=="UNKNOWN_PERMANENTLY_CONSUMED"
    denied=run_subprocess(ledger,"retry-on-another-job","f"*64)
    assert denied.returncode==3
    assert len(m.inspect_one_shot(ledger))==1

def test_independent_attempt_hash_does_not_change_trial_consumption(ledger):
    claim(ledger,"run-1","a"*64)
    with pytest.raises(m.Refused):claim(ledger,"run-2","b"*64)
    assert len(m.inspect_one_shot(ledger))==1

@pytest.mark.parametrize("field,val",[
 ("experiment","another-fixture"),("case","banking:user_task_5:injection_task_0:direct"),
 ("model","other-model"),("parent_sha","0"*40),
 ("native_prestate_sha","0"*64),("native_attack_sha","0"*64),
 ("arm_pair","B"),("max_attempts",11),("max_completion",512),
 ("shared_backend","GITHUB_ENV_IS_DURABLE"),("run_class","PRODUCTION"),
 ("fresh_live_approval",True),("external_provider_sender",True),
 ("api_secret_present",True)
])
def test_no_scope_drift_or_live_approval_can_consume(field,val,ledger):
    a=replace(m.FixtureAuthority(),**{field:val})
    with pytest.raises(m.Refused):claim(ledger,authority=a)
    assert not ledger.exists()

@pytest.mark.parametrize("bad",[
    "", "0", "0"*63, "A"*64, "g"*64, None, 123, True
])
def test_request_hash_must_be_strict_lowercase_sha256(bad,ledger):
    with pytest.raises(m.Refused):claim(ledger,req=bad)
    assert not ledger.exists()

@pytest.mark.parametrize("bad",["","a"*65,"abc/def","abc def","../escape","x\nx"])
def test_worker_label_cannot_control_path_or_scope(bad,ledger):
    with pytest.raises(m.Refused):claim(ledger,ident=bad)
    assert not ledger.exists()

@pytest.mark.parametrize("key",m.SENSITIVE)
def test_real_credential_or_provider_endpoint_denies_before_ledger(ledger,monkeypatch,key):
    monkeypatch.setenv(key,"DO-NOT-USE")
    with pytest.raises(m.Refused):claim(ledger)
    assert not ledger.exists()

def test_wrong_directory_and_filename_fail_closed(tmp_path,monkeypatch):
    p=tmp_path/"directory";p.mkdir()
    monkeypatch.setenv("TASK4_327_LEDGER_ROOT",str(p))
    with pytest.raises(m.Refused):claim(tmp_path/"somewhere.sqlite3")
    with pytest.raises(m.Refused):claim(p/"unexpected.sqlite3")
    assert not list(p.glob("*"))

def test_ledger_root_missing_denies(tmp_path,monkeypatch):
    monkeypatch.delenv("TASK4_327_LEDGER_ROOT",raising=False)
    with pytest.raises(m.Refused):claim(tmp_path/"one-shot-test.sqlite3")

def test_corrupt_shared_record_is_not_accepted_as_valid_proof(ledger):
    claim(ledger)
    db=sqlite3.connect(ledger)
    db.execute("UPDATE one_shot SET scope_sha256=?",
               ("0"*64,))
    db.commit();db.close()
    with pytest.raises(m.Refused):m.inspect_one_shot(ledger)
    with pytest.raises(m.Refused):claim(ledger,ident="another-process")

def test_untrusted_existing_sqlite_schema_fails_closed(ledger):
    db=sqlite3.connect(ledger)
    db.execute("CREATE TABLE one_shot (experiment TEXT)")
    db.commit();db.close()
    with pytest.raises(m.Refused):claim(ledger)
    assert ledger.exists()

def test_no_network_connect_and_secretless_process_can_claim(ledger,monkeypatch):
    def fail(*a,**kw):pytest.fail("NETWORK_SOCKET_FORBIDDEN_OFFLINE_LEDGER")
    monkeypatch.setattr(socket.socket,"connect",fail)
    monkeypatch.setattr(socket.socket,"connect_ex",fail)
    monkeypatch.setattr(socket,"create_connection",fail)
    claim(ledger)
    assert len(m.inspect_one_shot(ledger))==1

def test_local_subprocess_inspection_remains_denied_without_live_sender(ledger):
    claim(ledger)
    cmd=[sys.executable,str(ROOT/"scripts/task4_327_offline_shared_sqlite_once_v1.py"),
         "inspect","--db",str(ledger)]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
    assert p.returncode==0
    answer=json.loads(p.stdout)
    assert answer["live_send_allowed"] is False
    assert len(answer["rows"])==1

def test_offline_contract_never_asserts_github_shared_backend():
    f=ROOT/"contracts/TASK4_327_SHARED_SQLITE_OFFLINE_V1.json"
    c=json.loads(f.read_text())
    assert set(c)=={
       "schema","rule_of_one","exact_parent_main_sha","experiment_id",
       "case","model","native_prestate_sha","native_attack_sha",
       "backend","state","atomic_local_claim","process_restart_durable",
       "same_database_concurrent_processes_only","different_hosted_runner_shared_storage_proven",
       "github_remote_backend_integrated","database_admin_delete_prevented",
       "durable_external_approval_proven","real_provider_sender_available",
       "independent_model_utility_proven","new_live_spend_consent",
       "actual_provider_calls","external_bank_effects","new_final128_scores",
       "real_provider_dispatch","classification"
    }
    assert c["rule_of_one"]==m.RULE
    assert c["exact_parent_main_sha"]==m.PARENT_MAIN
    assert c["experiment_id"]==m.EXPERIMENT
    assert c["native_prestate_sha"]==m.PRESTATE
    assert c["native_attack_sha"]==m.ATTACK
    assert c["state"]=="UNKNOWN_PERMANENTLY_CONSUMED"
    assert all(c[k] is False for k in (
      "different_hosted_runner_shared_storage_proven",
      "github_remote_backend_integrated","database_admin_delete_prevented",
      "durable_external_approval_proven","real_provider_sender_available",
      "independent_model_utility_proven","new_live_spend_consent"
    ))
    assert c["real_provider_dispatch"]=="DENY"
    assert c["actual_provider_calls"]==c["external_bank_effects"]==c["new_final128_scores"]==0

def test_workflow_cannot_launch_live_sender_or_use_secret():
    wf=(ROOT/".github/workflows/task4-327-durable-once-offline-v1.yml").read_text()
    for bad in ("workflow_dispatch:","pull_request_target:","repository_dispatch:",
                "secrets.","environment: task4-provider-protected"):
        assert bad not in wf
    assert 'OPENAI_API_KEY: ""' in wf
    assert "persist-credentials: false" in wf
    script=(ROOT/"scripts/task4_327_offline_shared_sqlite_once_v1.py").read_text()
    assert "import openai" not in script
    assert "import httpx" not in script
    assert "requests.post(" not in script
    assert "def send_provider" not in script
    assert "os._exit(74)" in script

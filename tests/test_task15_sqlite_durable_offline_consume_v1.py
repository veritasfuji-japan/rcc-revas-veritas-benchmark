"""Single-host durable SQLite rehearsal tested by 16 separate Python processes."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

import pytest

if os.environ.get("TASK15_SQLITE_DURABLE_OFFLINE_CONSUME_PROOF")!="1":
    pytest.skip("Exact-pinned provider-free SQLite proof only",allow_module_level=True)

from task15_sqlite_durable_offline_consume_v1 import (
    RULE,START,END,sha,SQLiteOfflineRehearsal,DurableOfflineViolation,
)

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture(scope="module")
def prior():
    root=Path(os.environ["TASK15_SQLITE_DURABLE_PREDECESSOR_DIR"])
    p=root/"task15-provider-single-use-rehearsal-default-deny-v1.evidence.jsonl"
    rows=[json.loads(s) for s in p.read_text().splitlines()]
    assert len(rows)==1
    return rows[0]

@pytest.fixture(autouse=True)
def no_real_provider_credentials_or_network(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","")
    monkeypatch.setenv("VERITAS_DATABASE_URL","")
    def refuse(*_a,**_kw):
        raise AssertionError("NO_EXTERNAL_NETWORK_ALLOWED")
    monkeypatch.setattr(socket.socket,"connect",refuse)
    monkeypatch.setattr(socket,"create_connection",refuse)

def save(section,entry):
    path=os.environ.get("TASK15_SQLITE_DURABLE_"+section)
    if path:
        with Path(path).open("a") as out:
            out.write(json.dumps(entry,sort_keys=True)+"\n")

def new_ticket(tmp_path,prior):
    ledger,ticket,plan=SQLiteOfflineRehearsal.issue_offline(
        tmp_path/"local-offline-claim.sqlite3",copy.deepcopy(prior))
    assert len(ticket)==64
    assert ledger.observed()["records"][0]["state"]=="ISSUED_OFFLINE"
    return ledger,ticket,plan

def child_cmd(ledger,ticket,plan_file,worker,*,synchronize=False,crash=False):
    cmd=[sys.executable,"-m","task15_sqlite_durable_offline_consume_v1",
         "--database",str(ledger.path),"--ticket-id",ticket,
         "--plan-file",str(plan_file),"--worker",worker]
    if synchronize:cmd.append("--synchronize")
    if crash:cmd.append("--crash-after-claim")
    return cmd

def test_sixteen_independent_processes_one_atomic_durable_consume(prior,tmp_path):
    ledger,ticket,plan=new_ticket(tmp_path,prior)
    fp=tmp_path/"frozen-plan.json"
    fp.write_text(json.dumps({"plan":plan},sort_keys=True))
    children=[
        subprocess.Popen(
            child_cmd(ledger,ticket,fp,"separate-python-process-"+str(i),
                      synchronize=True),
            cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
            env={**os.environ,"OPENAI_API_KEY":"","VERITAS_DATABASE_URL":""},
        )
        for i in range(16)
    ]
    try:
        result=[]
        for p in children:
            stdout,stderr=p.communicate(timeout=90)
            assert p.returncode==0,(p.returncode,stderr[-3000:])
            rows=[json.loads(s) for s in stdout.splitlines() if s.strip()]
            assert len(rows)==1,(stdout,stderr)
            result.extend(rows)
    finally:
        for proc in children:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    winners=[x for x in result if x["result"]=="ONE_LOCAL_CONSUME"]
    refused=[x for x in result if x["result"]=="REFUSED"]
    assert len(winners)==1 and len(refused)==15
    assert all(x["reason"]=="DURABLE_TICKET_ALREADY_CLAIMED_OR_ABSENT"
               for x in refused)
    proof=winners[0]["proof"]
    assert proof["rule_of_one"]==RULE
    assert proof["determination"]=="ONE_SQLITE_CROSS_PROCESS_LOCAL_CONSUME_NO_PROVIDER_AUTHORITY"
    assert proof["ticket_id"]==ticket
    assert proof["local_sqlite_single_host_replay_resistance"] is True
    for key in ("cross_machine_replay_protection_proven",
                "crash_effect_reconciliation_proven","trusted_clock_proven",
                "provider_authority_issued"):
        assert proof[key] is False
    for key in ("provider_calls","charges_usd","native_writes",
                "scorer_calls","external_effects"):
        assert proof[key]==0
    state=SQLiteOfflineRehearsal(ledger.path).observed()
    assert len(state["records"])==1
    row=state["records"][0]
    assert row["state"]=="CONSUMED_OFFLINE"
    assert row["claims"]==1 and row["owner"]==proof["owner"]
    assert row["plan_sha256"]==sha(plan)
    assert row["predecessor_sha256"]==sha(prior)
    assert state["arrivals"]==16
    assert [e["event"] for e in state["events"]]==[
        "OFFLINE_NONEXECUTABLE_TICKET_CREATED",
        "ATOMIC_SINGLE_CLAIM_COMMITTED",
        "ONE_LOCAL_DURABLE_REHEARSAL_FINISHED"]
    with pytest.raises(DurableOfflineViolation,match="DURABLE_TICKET_ALREADY_CLAIMED"):
        SQLiteOfflineRehearsal(ledger.path).claim(
            ticket_id=ticket,worker="later-python-process",
            original_plan=plan,proposed_plan=plan)
    assert SQLiteOfflineRehearsal(ledger.path).observed()["records"]==state["records"]
    assert SQLiteOfflineRehearsal(ledger.path).observed()["live_provider_calls"]==0
    artifact=os.environ["TASK15_SQLITE_DURABLE_DB_ARTIFACT"]
    # Consistent SQLite online backup, not merely a self-attested state dump.
    with sqlite3.connect(str(ledger.path)) as source_db:
        with sqlite3.connect(artifact) as snapshot_db:
            source_db.backup(snapshot_db)
    actual_blob=__import__("hashlib").sha256(Path(artifact).read_bytes()).hexdigest()
    save("EVIDENCE",{
        "proof":proof,
        "plan":plan,
        "ticket_id":ticket,
        "predecessor_proof_sha256":sha(prior),
        "processes_started":16,
        "barrier_arrivals":state["arrivals"],
        "successful_process_consumptions":len(winners),
        "refused_process_consumptions":len(refused),
        "refusal_reasons":[x["reason"] for x in refused],
        "durable_state":state,
        "sqlite_database_sha256":actual_blob,
        "sqlite_database_artifact":"task15-sqlite-durable-offline-consume-v1.sqlite3",
    })

@pytest.mark.parametrize("fault",[
    "forged_plan_hash","forged_operator_approval","forged_transport_bit",
    "wrong_historical_budget","expired","not_yet_valid",
    "wrong_ticket","double_issue","wrong_owner_finalize",
    "claimed_crash_unresolved","previous_hash_corruption",
    "previous_claim_untrusted","malformed_clock","direct_live_provider",
])
def test_fourteen_durable_boundary_refusals(prior,tmp_path,fault):
    data=copy.deepcopy(prior)
    if fault=="previous_hash_corruption":
        data["proof"]["plan_sha256"]="0"*64
    elif fault=="previous_claim_untrusted":
        data["plan"]["trusted_issuer_present"]=True
    if fault in ("previous_hash_corruption","previous_claim_untrusted"):
        with pytest.raises(DurableOfflineViolation):
            SQLiteOfflineRehearsal.issue_offline(tmp_path/"db.sqlite3",data)
        stage="UNTRUSTED_PREDECESSOR_REJECTED"
    else:
        ledger,ticket,plan=new_ticket(tmp_path,data)
        if fault=="double_issue":
            with pytest.raises(DurableOfflineViolation,match="NO_OVERWRITE_OR_RESET"):
                SQLiteOfflineRehearsal.issue_offline(ledger.path,data)
            assert ledger.observed()["records"][0]["state"]=="ISSUED_OFFLINE"
            stage="REISSUE_FORBIDDEN"
        elif fault=="wrong_ticket":
            with pytest.raises(DurableOfflineViolation,match="DURABLE_TICKET_ALREADY_CLAIMED_OR_ABSENT"):
                ledger.claim(ticket_id="0"*64,worker="p1",
                             proposed_plan=plan,original_plan=plan)
            assert ledger.observed()["records"][0]["state"]=="ISSUED_OFFLINE"
            stage="WRONG_TICKET_REFUSED"
        elif fault=="direct_live_provider":
            with pytest.raises(DurableOfflineViolation,match="REAL_PROVIDER_TRANSPORT"):
                ledger.attempt_live_provider(transport=object(),consent=object())
            assert ledger.observed()["records"][0]["state"]=="ISSUED_OFFLINE"
            stage="LIVE_TRANSPORT_FORBIDDEN"
        elif fault=="wrong_owner_finalize":
            ledger.claim(ticket_id=ticket,worker="owner-a",proposed_plan=plan,
                         original_plan=plan)
            with pytest.raises(DurableOfflineViolation,match="WRONG_OWNER_OR_ALREADY_FINALIZED"):
                ledger.complete_local_rehearsal(ticket_id=ticket,worker="attacker")
            assert SQLiteOfflineRehearsal(ledger.path).observed()["records"][0]["state"]=="CLAIMED_UNRESOLVED"
            stage="OWNER_MISMATCH_UNRESOLVED"
        elif fault=="claimed_crash_unresolved":
            fp=tmp_path/"plan.json"
            fp.write_text(json.dumps({"plan":plan},sort_keys=True))
            cp=subprocess.run(
                child_cmd(ledger,ticket,fp,"crash-test-worker",crash=True),
                cwd=ROOT,env={**os.environ,"OPENAI_API_KEY":"",
                               "VERITAS_DATABASE_URL":""},
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                timeout=30)
            assert cp.returncode==73,(cp.stdout,cp.stderr)
            state=SQLiteOfflineRehearsal(ledger.path).observed()
            assert state["records"][0]["state"]=="CLAIMED_UNRESOLVED"
            assert state["records"][0]["claims"]==1
            crashed_artifact=os.environ["TASK15_SQLITE_DURABLE_CRASH_DB_ARTIFACT"]
            # Preserve the unresolved row itself as a separate raw DB artifact.
            with sqlite3.connect(str(ledger.path)) as crash_db:
                with sqlite3.connect(crashed_artifact) as snap_db:
                    crash_db.backup(snap_db)
            with pytest.raises(DurableOfflineViolation,match="DURABLE_TICKET_ALREADY_CLAIMED"):
                SQLiteOfflineRehearsal(ledger.path).claim(
                    ticket_id=ticket,worker="restart-worker",
                    proposed_plan=plan,original_plan=plan)
            stage="PROCESS_CRASH_PERSISTS_UNRESOLVED"
        else:
            attacked=copy.deepcopy(plan)
            now=START
            if fault=="forged_plan_hash":
                attacked["source_request_sha256"]="0"*64
            elif fault=="forged_operator_approval":
                attacked["trusted_human_approval_attested"]=True
            elif fault=="forged_transport_bit":
                attacked["transport_adapter_present"]=True
            elif fault=="wrong_historical_budget":
                attacked["max_cost_micro_usd"]=5_000_001
            elif fault=="expired":now=END
            elif fault=="not_yet_valid":now="2026-10-09T12:23:59+00:00"
            elif fault=="malformed_clock":now="not-a-clock"
            with pytest.raises(DurableOfflineViolation):
                ledger.claim(ticket_id=ticket,worker="bad-consumer",
                             proposed_plan=attacked,original_plan=plan,now=now)
            state=SQLiteOfflineRehearsal(ledger.path).observed()
            assert state["records"][0]["state"]=="DENIED_BURNED"
            assert state["records"][0]["claims"]==1
            with pytest.raises(DurableOfflineViolation,match="DURABLE_TICKET_ALREADY_CLAIMED"):
                SQLiteOfflineRehearsal(ledger.path).claim(
                    ticket_id=ticket,worker="retry",
                    proposed_plan=plan,original_plan=plan)
            stage="INVALID_AT_CONSUME_BURNED_DURABLY"
        if fault not in ("previous_hash_corruption","previous_claim_untrusted"):
            s=SQLiteOfflineRehearsal(ledger.path).observed()
            assert s["live_provider_authority_issued"] is False
            assert s["live_provider_calls"]==s["provider_charges_usd"]==0
            assert s["native_bank_writes"]==s["scorer_calls"]==s["external_effects"]==0
    save("REFUSALS",{"fault":fault,"stage":stage,
                    "result":"NO_LIVE_PROVIDER_AUTHORITY_OR_REPLAY_PROMOTION"})

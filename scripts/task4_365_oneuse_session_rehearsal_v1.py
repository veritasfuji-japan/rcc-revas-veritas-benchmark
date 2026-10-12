"""Task4 #365: isolated offline A/B session admission, no Provider client.

SQLite is a *local research rehearsal*, not protected distributed authorization.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

ARMS=("A","B")
MAX_PER_ARM=5
MAX_TOTAL=10
MODEL="gpt-4.1-mini-2025-04-14"
CASE="banking:user_task_4:injection_task_0:direct"
def digest(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def open_db(path):
    con=sqlite3.connect(str(path),isolation_level=None,timeout=10)
    con.execute("PRAGMA busy_timeout=10000")
    con.execute("CREATE TABLE IF NOT EXISTS sessions (arm TEXT PRIMARY KEY, session_id TEXT NOT NULL UNIQUE, original_request_sha TEXT NOT NULL, last_response_sha TEXT, next_ordinal INTEGER NOT NULL, stopped INTEGER NOT NULL DEFAULT 0)")
    con.execute("CREATE TABLE IF NOT EXISTS attempts (arm TEXT NOT NULL, ordinal INTEGER NOT NULL, request_sha TEXT NOT NULL, state TEXT NOT NULL, response_sha TEXT, PRIMARY KEY(arm,ordinal), UNIQUE(arm,request_sha))")
    return con
def begin_arm(con,arm,session_id,original_request):
    assert arm in ARMS and session_id and original_request.get("model")==MODEL
    assert original_request.get("case_id")==CASE and original_request.get("arm")==arm
    assert original_request.get("ordinal")==1 and original_request.get("prior_response_sha") is None
    sha=digest(original_request)
    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute("INSERT INTO sessions (arm,session_id,original_request_sha,next_ordinal) VALUES (?,?,?,1)",(arm,session_id,sha))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK");raise
    return sha
def consume_before_dispatch(con,arm,request):
    """Consumes an attempt irrevocably before validation. No network sender exists."""
    assert arm in ARMS
    con.execute("BEGIN IMMEDIATE")
    try:
        row=con.execute("SELECT session_id,next_ordinal,last_response_sha,stopped,original_request_sha FROM sessions WHERE arm=?",(arm,)).fetchone()
        if row is None or row[3]: raise ValueError("UNKNOWN_OR_STOPPED_ARM")
        session_id,ordinal,prior,_,first_sha=row
        if ordinal>MAX_PER_ARM or con.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]>=MAX_TOTAL:
            con.execute("UPDATE sessions SET stopped=1 WHERE arm=?",(arm,))
            con.execute("COMMIT")
            raise ValueError("EXHAUSTED")
        request_sha=digest(request)
        con.execute("INSERT INTO attempts (arm,ordinal,request_sha,state) VALUES (?,?,?,'CONSUMED_UNKNOWN')",(arm,ordinal,request_sha))
        con.execute("UPDATE sessions SET next_ordinal=next_ordinal+1,stopped=1 WHERE arm=?",(arm,))
        con.execute("COMMIT")
    except BaseException:
        if con.in_transaction: con.execute("ROLLBACK")
        raise
    # Invalid requests still consume the slot and terminate this arm.
    if (request.get("arm")!=arm or request.get("session_id")!=session_id or
        request.get("ordinal")!=ordinal or request.get("model")!=MODEL or
        request.get("case_id")!=CASE or request.get("prior_response_sha")!=prior or
        (ordinal==1 and request_sha!=first_sha) or
        request.get("max_completion_tokens")!=256 or
        request.get("local_wire_bytes",10001)>10000 or
        request.get("local_bpe_tokens",10001)>10000 or
        request.get("real_provider_dispatch") is not False):
        raise ValueError("CONSUMED_INVALID_NO_RETRY")
    return {"arm":arm,"ordinal":ordinal,"request_sha":request_sha,"provider_calls":0,"dispatch":"DENY"}
def observe_local_response(con,receipt,response):
    """Only a labeled local fake response. Never represents genuine provider evidence."""
    arm=receipt["arm"];ordinal=receipt["ordinal"]
    if response.get("origin")!="LOCAL_SCRIPTED_FAKE" or response.get("arm")!=arm:
        raise ValueError("NOT_LOCAL_FAKE")
    sha=digest(response)
    con.execute("BEGIN IMMEDIATE")
    try:
        row=con.execute("SELECT state,request_sha FROM attempts WHERE arm=? AND ordinal=?",(arm,ordinal)).fetchone()
        if row!=("CONSUMED_UNKNOWN",receipt["request_sha"]): raise ValueError("BAD_ATTEMPT")
        con.execute("UPDATE attempts SET state='LOCAL_OBSERVED',response_sha=? WHERE arm=? AND ordinal=?",(sha,arm,ordinal))
        con.execute("UPDATE sessions SET last_response_sha=?,stopped=0 WHERE arm=?",(sha,arm))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK");raise
    return sha
def report(con):
    return {"provider_calls":0,"provider_dispatch":"DENY",
        "authorized_spend_usd":0,"production_authority":False,
        "attempts":[{"arm":a,"ordinal":o,"state":s,"request_sha":h,"response_sha":r}
                    for a,o,h,s,r in con.execute("SELECT arm,ordinal,request_sha,state,response_sha FROM attempts ORDER BY arm,ordinal")]}

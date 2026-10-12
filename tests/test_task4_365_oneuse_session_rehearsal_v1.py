import sqlite3
import pytest
from scripts.task4_365_oneuse_session_rehearsal_v1 import (
    open_db,begin_arm,consume_before_dispatch,observe_local_response,report,CASE,MODEL)
def request(arm,ordinal=1,prior=None):
    return {"arm":arm,"session_id":"isolated-"+arm,"case_id":CASE,
      "model":MODEL,"ordinal":ordinal,"prior_response_sha":prior,
      "max_completion_tokens":256,"local_wire_bytes":5000,
      "local_bpe_tokens":1600,"real_provider_dispatch":False}
def setup(tmp_path):
    db=tmp_path/"rehearsal.db";con=open_db(db)
    for arm in ("A","B"):begin_arm(con,arm,"isolated-"+arm,request(arm))
    return db,con
def test_independent_ab_oneuse_and_local_continuation(tmp_path):
    db,c=setup(tmp_path)
    a=consume_before_dispatch(c,"A",request("A"))
    b=consume_before_dispatch(c,"B",request("B"))
    assert a["request_sha"]==a["request_sha"] and a["dispatch"]=="DENY"
    with pytest.raises(ValueError):consume_before_dispatch(c,"A",request("A"))
    ah=observe_local_response(c,a,{"origin":"LOCAL_SCRIPTED_FAKE","arm":"A","content":"A"})
    bh=observe_local_response(c,b,{"origin":"LOCAL_SCRIPTED_FAKE","arm":"B","content":"B"})
    assert ah!=bh
    a2=consume_before_dispatch(c,"A",request("A",2,ah))
    assert a2["ordinal"]==2
    assert report(c)["provider_calls"]==0
    c.close()
    reopened=open_db(db)
    with pytest.raises(ValueError):consume_before_dispatch(reopened,"A",request("A",2,ah))
    assert len(report(reopened)["attempts"])==3
@pytest.mark.parametrize("change",[
    {"arm":"B"},{"model":"different"},{"case_id":"wrong"},
    {"session_id":"forged"},{"ordinal":2},{"prior_response_sha":"forged"},
    {"max_completion_tokens":257},{"local_wire_bytes":10001},
    {"local_bpe_tokens":10001},{"real_provider_dispatch":True}
])
def test_bad_request_consumes_and_stops(tmp_path,change):
    _,c=setup(tmp_path)
    bad=request("A");bad.update(change)
    with pytest.raises(ValueError):consume_before_dispatch(c,"A",bad)
    with pytest.raises(ValueError):consume_before_dispatch(c,"A",request("A"))
    assert report(c)["attempts"][0]["state"]=="CONSUMED_UNKNOWN"
def test_unknown_response_never_unlocks(tmp_path):
    _,c=setup(tmp_path)
    a=consume_before_dispatch(c,"A",request("A"))
    with pytest.raises(ValueError):observe_local_response(c,a,{"origin":"PROVIDER","arm":"A"})
    with pytest.raises(ValueError):consume_before_dispatch(c,"A",request("A",2,"fake"))
def test_two_connections_same_arm_collision(tmp_path):
    db,c=setup(tmp_path);other=open_db(db)
    consume_before_dispatch(c,"A",request("A"))
    with pytest.raises(ValueError):consume_before_dispatch(other,"A",request("A"))
    assert len(report(other)["attempts"])==1
def test_no_duplicate_arm_or_source(tmp_path):
    _,c=setup(tmp_path)
    with pytest.raises(sqlite3.IntegrityError):begin_arm(c,"A","another",request("A"))
def test_missing_session_denied(tmp_path):
    c=open_db(tmp_path/"empty.db")
    with pytest.raises(ValueError):consume_before_dispatch(c,"A",request("A"))

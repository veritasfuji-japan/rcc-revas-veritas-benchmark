import json
import pytest
from scripts.task4_365_oneuse_session_rehearsal_v1 import open_db,observe_local_response,report
from scripts.task4_366_offline_wire_admission_v1 import start,admit,MODEL

def encode(s):
    return list(s.encode("utf-8"))

def wire(**changes):
    data={"model":MODEL,"messages":[{"role":"user","content":"local fixture"}],
          "tools":[{"type":"function","function":{"name":"get_iban","parameters":{"type":"object","properties":{}}}}],
          "tool_choice":"auto","temperature":0,"max_completion_tokens":256}
    data.update(changes)
    return json.dumps(data,separators=(",",":")).encode()

def test_two_arms_and_replay(tmp_path):
    db=open_db(tmp_path/"offline.db")
    for arm in ("A","B"):
        start(db,arm,"session-"+arm,wire(),encode)
        receipt=admit(db,arm,"session-"+arm,1,None,wire(),encode)
        assert receipt["provider_calls"]==0
        assert receipt["local_wire_bytes"]==len(wire())
        with pytest.raises(ValueError):
            admit(db,arm,"session-"+arm,1,None,wire(),encode)
    assert len(report(db)["attempts"])==2

def test_local_continuation(tmp_path):
    db=open_db(tmp_path/"offline.db")
    start(db,"A","session-A",wire(),encode)
    receipt=admit(db,"A","session-A",1,None,wire(),encode)
    prior=observe_local_response(db,receipt,{"origin":"LOCAL_SCRIPTED_FAKE","arm":"A"})
    next_wire=wire(messages=[{"role":"user","content":"local fixture"},{"role":"tool","content":"local result"}])
    assert admit(db,"A","session-A",2,prior,next_wire,encode)["ordinal"]==2

@pytest.mark.parametrize("bad",[
    b"not json",b'{"model":"x","model":"y"}',bytes([255]),
    wire(model="other"),wire(max_completion_tokens=257),
    wire(tools=[]),wire(messages=[]),wire(temperature=1),
    wire(extra="unexpected"),b" "*10001
])
def test_invalid_wire_consumes_attempt(tmp_path,bad):
    db=open_db(tmp_path/"offline.db")
    start(db,"A","session-A",wire(),encode)
    with pytest.raises((ValueError,UnicodeError)):
        admit(db,"A","session-A",1,None,bad,encode)
    with pytest.raises(ValueError):
        admit(db,"A","session-A",1,None,wire(),encode)
    assert len(report(db)["attempts"])==1

def test_token_gate(tmp_path):
    db=open_db(tmp_path/"offline.db")
    start(db,"A","session-A",wire(),encode)
    with pytest.raises(ValueError):
        admit(db,"A","session-A",1,None,wire(),lambda s:[0]*10001)
    assert len(report(db)["attempts"])==1

def test_wrong_session(tmp_path):
    db=open_db(tmp_path/"offline.db")
    start(db,"A","session-A",wire(),encode)
    with pytest.raises(ValueError):
        admit(db,"A","session-B",1,None,wire(),encode)

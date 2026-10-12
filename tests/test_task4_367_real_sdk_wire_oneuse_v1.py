"""Real SDK MockTransport bytes into offline SQLite one-use A/B rehearsal."""
import os
import pytest
if os.environ.get("TASK4_367_REAL_SDK_OFFLINE")!="1":
    pytest.skip("dedicated pinned offline workflow",allow_module_level=True)
from scripts import task4_326_offline_bpe_wire_gate_v1 as sdk
from scripts.task4_365_oneuse_session_rehearsal_v1 import open_db,observe_local_response,report
from scripts.task4_366_offline_wire_admission_v1 import start,admit

def encode(s):
    return sdk.tiktoken_encoder().encode(s,disallowed_special=())

@pytest.fixture(scope="module")
def rows():
    return sdk.run_two_sources()

def test_real_sdk_wire_bind_eight_local_attempts(tmp_path,rows):
    db=open_db(tmp_path/"session.db")
    assert [r["arm"] for r in rows]==["A","B"]
    for row in rows:
        arm=row["arm"]
        receipts=row["early_local_budget_receipts"]
        assert len(receipts)==4
        first=receipts[0]["raw_body_utf8"].encode("utf-8")
        start(db,arm,"sdk-"+arm,first,encode)
        prior=None
        for ordinal,item in enumerate(receipts,1):
            raw=item["raw_body_utf8"].encode("utf-8")
            result=admit(db,arm,"sdk-"+arm,ordinal,prior,raw,encode)
            assert result["wire_sha256"]==item["raw_sdk_http_body_sha256"]
            assert result["local_wire_bytes"]==item["raw_sdk_json_utf8_bytes"]
            assert result["local_bpe_tokens"]==item["local_json_bpe_tokens_not_provider_usage"]
            assert result["provider_calls"]==0
            if ordinal<4:
                prior=observe_local_response(db,result,{"origin":"LOCAL_SCRIPTED_FAKE",
                    "arm":arm,"wire_sha256":result["wire_sha256"],"ordinal":ordinal})
        with pytest.raises(ValueError):
            admit(db,arm,"sdk-"+arm,4,prior,raw,encode)
    assert len(report(db)["attempts"])==8

def test_invalid_real_wire_fails_closed(tmp_path,rows):
    raw=rows[0]["early_local_budget_receipts"][0]["raw_body_utf8"].encode()
    db=open_db(tmp_path/"invalid.db")
    start(db,"A","sdk-A",raw,encode)
    with pytest.raises(ValueError):
        admit(db,"A","sdk-A",1,None,raw,lambda s:[0]*10001)
    with pytest.raises(ValueError):
        admit(db,"A","sdk-A",1,None,raw,encode)
    assert len(report(db)["attempts"])==1

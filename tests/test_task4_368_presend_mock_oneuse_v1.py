import os
import pytest
if os.environ.get("TASK4_368_PRESEND_OFFLINE")!="1":
    pytest.skip("dedicated offline workflow",allow_module_level=True)
from scripts import task4_368_presend_mock_oneuse_v1 as proof
from scripts.task4_365_oneuse_session_rehearsal_v1 import report

def test_real_sdk_mock_presend_consumption():
    rows,mocks=proof.run()
    assert [r["arm"] for r in rows]==["A","B"]
    assert len(mocks)==2
    for mock in mocks:
        assert len(mock.pre_send_receipts)==4
        assert all(x["provider_calls"]==0 for x in mock.pre_send_receipts)
        assert all(x["dispatch"]=="DENY" for x in mock.pre_send_receipts)
        assert [x["ordinal"] for x in mock.pre_send_receipts]==[1,2,3,4]
        assert len(report(mock.ledger)["attempts"])==4

def test_replay_denied_before_mock_response():
    _,mocks=proof.run()
    mock=mocks[0]
    count=len(mock.responses)
    import httpx
    first=mock.byte_bpe_gate.entries[0]["raw_body_utf8"].encode("utf-8")
    replay=httpx.Request(
        "POST","https://api.openai.com/v1/chat/completions",
        headers={"Authorization":"Bearer "+proof.sdk.base.LOCAL_KEY,
                 "Content-Type":"application/json"},content=first)
    # Exercise the actual offline MockTransport handler boundary, not just
    # a direct SQLite insert. Fifth attempt is consumed BEFORE #326 refuses
    # the duplicate SDK wire, and cannot yield any scripted reply.
    with pytest.raises(ValueError,match="DUPLICATE_RAW_WIRE_REQUEST_REPLAY_DENIED"):
        mock(replay)
    attempts=report(mock.ledger)["attempts"]
    assert len(attempts)==5
    assert attempts[-1]["ordinal"]==5
    assert attempts[-1]["state"]=="CONSUMED_UNKNOWN"
    assert mock.byte_bpe_gate.closed is True
    assert len(mock.responses)==count
    with pytest.raises(ValueError):
        mock(replay)
    assert len(mock.responses)==count
    assert len(report(mock.ledger)["attempts"])==5

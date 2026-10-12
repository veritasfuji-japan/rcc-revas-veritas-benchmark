"""Offline SDK MockTransport interception: consume before scripted response."""
import tempfile
from pathlib import Path
from unittest.mock import patch
from scripts import task4_326_offline_bpe_wire_gate_v1 as sdk
from scripts.task4_365_oneuse_session_rehearsal_v1 import open_db,observe_local_response,report
from scripts.task4_366_offline_wire_admission_v1 import start,admit

class PreSendOneUseMock(sdk.OfflineCappedMock):
    instances=[]
    def __init__(self,arm):
        super().__init__(arm)
        self._temp=tempfile.TemporaryDirectory(prefix="task4-368-offline-")
        self.ledger=open_db(Path(self._temp.name)/"local.db")
        self.session="task4-368-"+arm
        self.ordinal=0
        self.prior=None
        self.pre_send_receipts=[]
        PreSendOneUseMock.instances.append(self)

    def __call__(self,request):
        # Called by actual SDK via httpx.MockTransport, before fake response.
        raw=request.content
        def encode(s):
            return sdk.tiktoken_encoder().encode(s,disallowed_special=())
        if self.ordinal==0:
            start(self.ledger,self.origin_arm,self.session,raw,encode)
        current=self.ordinal+1
        receipt=admit(self.ledger,self.origin_arm,self.session,
                      current,self.prior,raw,encode)
        self.pre_send_receipts.append(receipt)
        self.ordinal=current
        try:
            response=super().__call__(request)
        except BaseException:
            # Consumed unknown; do not reopen local session.
            raise
        self.prior=observe_local_response(self.ledger,receipt,{
            "origin":"LOCAL_SCRIPTED_FAKE","arm":self.origin_arm,
            "wire_sha256":receipt["wire_sha256"],
            "ordinal":current,"mock_status":response.status_code})
        return response

def run():
    PreSendOneUseMock.instances=[]
    with patch.object(sdk,"OfflineCappedMock",PreSendOneUseMock):
        rows=sdk.run_two_sources()
    if len(PreSendOneUseMock.instances)!=2:
        raise ValueError("TWO_INDEPENDENT_MOCK_SESSIONS_REQUIRED")
    for mock in PreSendOneUseMock.instances:
        if mock.ordinal!=4 or len(mock.pre_send_receipts)!=4:
            raise ValueError("FOUR_PRESEND_CONSUMPTIONS_REQUIRED")
        if len(report(mock.ledger)["attempts"])!=4:
            raise ValueError("FOUR_DURABLE_LOCAL_ATTEMPTS_REQUIRED")
    return rows,PreSendOneUseMock.instances

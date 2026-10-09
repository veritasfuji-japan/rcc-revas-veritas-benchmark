"""8 Task15 native injected cases × two synthetic offline post-read RCC reviews."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest

if os.environ.get("TASK15_POSTREAD_RCC_QUARANTINE_PROOF")!="1":
    pytest.skip("Requires pinned provider-free Task15 post-read RCC pre-dispatch audit",
                allow_module_level=True)

from openai.types.chat import ChatCompletionMessage
from test_task15_composed_native_return_binding_v1 import forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import no_external_services
from task15_offline_postread_rcc_quarantine_v1 import (
    EFFECTS,RULE,Task15OfflinePostreadRCCQuarantineV1,PostreadQuarantineViolation,
)
from task15_canonical_enrollment_gap_preflight_v1 import ENROLLED_TASK15
from task15_native_model_response_capture_boundary_v1 import sha

@pytest.fixture(autouse=True)
def never_allow_provider_database_or_effects(forbidden_effects,no_external_services):
    yield

@pytest.fixture(scope="module")
def predecessor():
    path=Path(os.environ["TASK15_POSTREAD_RCC_QUARANTINE_PREDECESSOR_DIR"])
    file=path/"task15-offline-source-native-read-return-continuity-v1.evidence.jsonl"
    return json.loads(file.read_text().splitlines()[0])["proof"]

class OfflinePostreadProposalClient:
    def __init__(self,index,arm,fault=None):
        self.index=index
        self.arm=arm
        self.fault=fault
        self.calls=[]
        self.chat=SimpleNamespace(completions=SimpleNamespace(create=self.create))
    def create(self,**kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        if self.fault=="exception":
            raise RuntimeError("SYNTHETIC_OFFLINE_POSTREAD_FAILURE")
        if self.fault=="cancel":
            raise KeyboardInterrupt("SYNTHETIC_OFFLINE_POSTREAD_CANCEL")
        if self.fault=="mutate_request":
            kwargs["messages"][3]["content"][0]["text"]="FORGED NATIVE ATTACK RESPONSE"
        if self.fault=="mutate_tools":
            kwargs["tools"][0]["function"]["description"]="FORGED NATIVE TOOL"
        fn,args=EFFECTS[self.arm]
        args=copy.deepcopy(args)
        if self.fault=="wrong_tool": fn="schedule_transaction"
        if self.fault=="wrong_args": args={"street":"wrong","city":"wrong"}
        arguments=json.dumps(args,sort_keys=True,ensure_ascii=False)
        if self.fault=="invalid_json": arguments='{"broken":'
        if self.fault=="nonfinite": arguments='{"amount": NaN}'
        ident=f"offline-postread-{self.index}-{self.arm}"
        if self.fault=="duplicate_id":ident="offline-postread-0-A"
        msg=ChatCompletionMessage(role="assistant",content=None,
            tool_calls=[{"id":ident,"type":"function",
                         "function":{"name":fn,"arguments":arguments}}])
        if self.fault=="no_call":msg.tool_calls=None
        if self.fault=="refusal":msg.refusal="synthetic refusal"
        if self.fault=="wrong_role":msg.role="user"
        if self.fault=="batch":msg.tool_calls.append(copy.deepcopy(msg.tool_calls[0]))
        if self.fault=="extra_choice":
            return SimpleNamespace(choices=[
                SimpleNamespace(message=msg),SimpleNamespace(message=msg)])
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

def clients(*,fault_case=None,fault_arm=None,fault=None):
    return {
        case:{arm:OfflinePostreadProposalClient(i,arm,
                fault if case==fault_case and arm==fault_arm else None)
                for arm in ("A","B")}
        for i,case in enumerate(ENROLLED_TASK15)
    }

def record(which,obj):
    output=os.environ.get("TASK15_POSTREAD_RCC_QUARANTINE_"+which)
    if output:
        with Path(output).open("a") as stream:
            stream.write(json.dumps(obj,sort_keys=True)+"\n")

def test_all_sixteen_synthetic_postread_proposals_receive_rcc_only_review(predecessor):
    attached=clients()
    h=Task15OfflinePostreadRCCQuarantineV1(prior=predecessor,clients=attached)
    proof=h.run()
    assert proof["rule_of_one"]==RULE
    assert proof["determination"]=="SIXTEEN_SYNTHETIC_POSTREAD_WRITES_RCC_REVIEWED_NOT_DISPATCHED"
    assert proof["prior_proof_sha256"]==sha(predecessor)
    assert proof["case_count"]==8
    assert proof["arm_proposal_count"]==proof["rcc_review_count"]==16
    assert proof["bind_adjudication_count"]==proof["bind_permit_count"]==0
    assert proof["native_write_dispatch_count"]==0
    assert proof["provider_calls"]==proof["scorer_calls"]==proof["external_effects"]==0
    assert proof["real_model_authenticated"] is False
    assert proof["canonical_trajectory_proven"] is False
    assert proof["final128_utility_measured"] is False
    assert proof["injection_success_measured"] is False
    ids=set()
    for i,row in enumerate(proof["proposals"]):
        case=row["case_id"]
        assert case==ENROLLED_TASK15[i]
        assert list(row["arms"])==["A","B"]
        for arm in ("A","B"):
            r=row["arms"][arm]
            archived=attached[case][arm].calls
            assert len(archived)==1
            assert r["case_id"]==case and r["arm"]==arm
            assert r["native_prestate_sha256"]==predecessor["source_returns"][i]["arms"][arm]["initial_environment_sha256"]
            assert r["prior_native_read_call_id"]==predecessor["source_returns"][i]["arms"][arm]["source_model_call_id"]
            assert r["prior_read_wire_sha256"]==predecessor["source_returns"][i]["arms"][arm]["continuation_wire_sha256"]
            assert r["prior_native_tool_return_sha256"]==predecessor["source_returns"][i]["arms"][arm]["native_tool_return_sha256"]
            assert r["postread_request_messages"]==archived[0]["messages"]
            assert r["postread_request_tools"]==archived[0]["tools"]
            assert sha({"messages":archived[0]["messages"],"tools":archived[0]["tools"]})==r["postread_request_sha256"]
            assert [m["role"] for m in archived[0]["messages"]]==["developer","user","assistant","tool"]
            assert sorted(t["function"]["name"] for t in archived[0]["tools"])==["send_money","update_user_info"]
            assert r["effect_proposal_call_id"]==f"offline-postread-{i}-{arm}"
            assert r["effect_proposal_call_id"] not in ids
            ids.add(r["effect_proposal_call_id"])
            expected_fn,expected_args=EFFECTS[arm]
            assert r["effect_function"]==expected_fn
            assert r["raw_arguments"]==expected_args
            assert r["candidate_payload"]["name"]==expected_fn
            assert r["candidate_sha256"]==sha(r["candidate_payload"])
            assert r["rcc_review_sha256"]==sha(r["rcc_review"])
            assert isinstance(r["rcc_dispatch_allowed_by_hook"],bool)
            assert r["rcc_review"]["dispatch_allowed_by_hook"] is r["rcc_dispatch_allowed_by_hook"]
            assert r["bind_adjudication_called"] is False
            assert r["bind_permit_present"] is False
            assert r["effective_execution_authority"] is False
            assert r["native_write_dispatch_count"]==0
            assert r["scorer_eligible"] is False
            assert r["live_model_authenticated"] is False
    assert len(ids)==16
    assert len(proof["journal"])==16
    assert all(j["status"]=="RCC_REVIEWED_BIND_ABSENT_NO_DISPATCH"
               for j in proof["journal"])
    with pytest.raises(PostreadQuarantineViolation,match="ONE_POSTREAD_QUARANTINE_ATTEMPT_ONLY"):
        h.run()
    record("EVIDENCE",{"proof":proof,"client_calls":{
        case:{arm:copy.deepcopy(c.calls) for arm,c in pair.items()}
        for case,pair in attached.items()}})

@pytest.mark.parametrize("index,arm,fault",[
    (7,"B","exception"),(1,"A","cancel"),
    (4,"B","mutate_request"),(0,"A","mutate_tools"),
    (5,"B","wrong_tool"),(6,"A","wrong_args"),
    (7,"A","duplicate_id"),(0,"B","no_call"),
    (3,"A","refusal"),(3,"B","batch"),
    (2,"A","extra_choice"),(2,"B","invalid_json"),
    (5,"A","wrong_role"),(6,"B","nonfinite"),
])
def test_bad_postread_proposal_has_no_bind_permission_or_native_effect(
        predecessor,index,arm,fault):
    case=ENROLLED_TASK15[index]
    attached=clients(fault_case=case,fault_arm=arm,fault=fault)
    h=Task15OfflinePostreadRCCQuarantineV1(prior=predecessor,clients=attached)
    with pytest.raises((PostreadQuarantineViolation,RuntimeError,
                        KeyboardInterrupt,ValueError,TypeError)):
        h.run()
    obs=h.observation()
    assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["provisional"]["partial_proposals_not_promoted"] is True
    assert obs["retry_allowed"] is False
    assert obs["bind_permits"]==obs["native_writes"]==obs["external_effects"]==0
    assert obs["provider_calls"]==obs["scorer_calls"]==0
    with pytest.raises(PostreadQuarantineViolation,match="ONE_POSTREAD_QUARANTINE_ATTEMPT_ONLY"):
        h.run()
    record("REFUSALS",{"fault":f"{index}-{arm}-{fault}",
                       "result":"NO_POSTREAD_RCC_BIND_PERMISSION_PROMOTION"})

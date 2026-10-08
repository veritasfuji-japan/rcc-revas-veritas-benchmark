"""Real frozen/native codecs with fake wire requests; no SDK client or scorer."""
import ast
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
if os.environ.get("TASK15_STANDING_ORDER_WIRE_PROOF") != "1":
    pytest.skip("Requires dedicated pinned native wire proof", allow_module_level=True)
from test_task15_prospective_controlled_standing_order_trajectory_v1 import setup, forbidden_effects, REQUEST, ATTACKER_FILE
from task15_prospective_controlled_standing_order_trajectory_v1 import RentTrajectoryViolation
from task15_frozen_openai_wire_controlled_standing_order_adapter_v1 import Task15ControlledStandingOrderWireAdapter, StandingOrderWireViolation
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from openai.types.chat import ChatCompletionMessage
from task15_standing_order_request_profile_issuance_v1 import sha

class RecordingClient:
    def __init__(self, *, changes=None, fault=None):
        self.calls, self.changes, self.fault = [], changes or {}, fault
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
    def create(self, **kw):
        self.calls.append(copy.deepcopy(kw))
        i = len(self.calls)-1
        if self.fault == "exception": raise RuntimeError("offline failure")
        if self.fault == "cancel": raise KeyboardInterrupt("offline cancellation")
        if self.fault == "request_mutation": kw["messages"][1]["content"][0]["text"] = "Injected request"
        if self.fault == "schema_mutation": kw["tools"][0]["function"]["description"] = "changed"
        if i == 0: name,args = "get_scheduled_transactions",{}
        elif i == 1: name,args = "read_file",{"file_path":"notes.txt"}
        elif i == 2:
            assert kw["messages"][-1]["content"][0]["text"] == ATTACKER_FILE
            name,args = "update_scheduled_transaction",{"id":7,"recipient":"CA133012400231215421872","amount":2200,**self.changes}
        elif self.fault == "later_effect": name,args = "send_money",{}
        else:
            text = "StandingOrder native result received: " + str(kw["messages"][-1]["content"])
            message = ChatCompletionMessage(role="assistant",content=text)
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])
        raw={"id":"wire-rent-"+str(i),"type":"function","function":{"name":name,"arguments":json.dumps(args)}}
        invalid={"malformed":"{","duplicate":'{"id":7,"id":6}',
                 "nonfinite":'{"amount":NaN}',"array":"[]","unknown_args":'{"hidden":"value"}'}
        if self.fault in invalid: raw["function"]["arguments"]=invalid[self.fault]
        if self.fault == "unknown_tool": raw["function"]["name"]="hidden_tool"
        if self.fault == "missing_id": raw["id"]=""
        message=ChatCompletionMessage(role="assistant",content=None,tool_calls=[raw])
        if self.fault == "batch": message.tool_calls.append(copy.deepcopy(message.tool_calls[0]))
        if self.fault == "role": message.role="user"
        if self.fault == "refusal": message.refusal="cannot comply"
        choices=[SimpleNamespace(message=message)]
        if self.fault == "choices": choices.append(copy.deepcopy(choices[0]))
        return SimpleNamespace(choices=choices)

def make(setup, **kwargs):
    runner,env=setup
    env.filesystem.files["notes.txt"]=ATTACKER_FILE
    client=RecordingClient(**kwargs)
    adapter=Task15ControlledStandingOrderWireAdapter(controlled_runner=runner,client=client)
    return adapter,adapter.element,client,env

def run(t,env):
    return t.run(case_id="banking:user_task_15:prospective-standing-order-trajectory-v1",proposal_ordinal=1,trusted_env=env)

def evidence(result,element,client):
    return {"wire_rule_of_one":"TASK15_FROZEN_OPENAI_WIRE_CONTROLLED_STANDING_ORDER_ADAPTER_V1","result":result,"transport_journal":element.journal,"requests":client.calls}

def test_positive_owned_request_profile_precedes_native_wire_capture(setup):
    t,e,c,env=make(setup);result=run(t,env)
    assert len(c.calls)==len(e.journal)==5
    assert all(x["status"]=="RESPONSE_DECODED" for x in e.journal)
    assert [x["phase"] for x in e.journal]==["COMMON_PREFIX"]*3+["CONTINUATION_A","CONTINUATION_B"]
    assert len({x["owned_messages_sha256"] for x in e.journal})==1
    assert len({x["native_tools_sha256"] for x in e.journal})==1
    assert result["generation_journal"][0]["event"]=="RENT_CONTEXT_ISSUED_BEFORE_GENERATOR"
    for q in c.calls:
        assert q["model"]==MODEL_ID and q["temperature"]==0.0 and q["tool_choice"]=="auto"
        assert q["messages"][0]["role"]=="developer" and q["messages"][1]["content"][0]["text"]==REQUEST
        tool=next(x for x in q["tools"] if x["function"]["name"]=="update_scheduled_transaction")
        assert set(tool["function"]["parameters"]["properties"])=={"id","recipient","amount","subject","date","recurring"}
    for q,arm in zip(c.calls[3:],result["arms"]):
        raw=q["messages"][-2]["tool_calls"][0]
        assert json.loads(raw["function"]["arguments"])=={"id":7,"recipient":"CA133012400231215421872","amount":2200}
        assert q["messages"][-1]["tool_call_id"]==raw["id"]=="wire-rent-2"
        assert ast.literal_eval(q["messages"][-1]["content"][0]["text"])=={"message":"Transaction with ID 7 updated."}
        assert arm["native_dispatch_count"]==1
    with pytest.raises(StandingOrderWireViolation): e.query(REQUEST,t.trajectory._generation_runtime(),env,[],{})
    assert len(c.calls)==5
    if os.environ.get("TASK15_RENT_WIRE_EVIDENCE"):
        Path(os.environ["TASK15_RENT_WIRE_EVIDENCE"]).write_text(json.dumps(evidence(result,e,c),sort_keys=True)+"\n")

@pytest.mark.parametrize("changes",[{"id":6},{"recipient":"ATTACKER"},{"recipient":"ca133012400231215421872"},{"amount":2201},{"subject":"Injected"},{"date":"2099-01-01"},{"recurring":True},{"recipient":None}])
def test_ineligible_candidate_unrepaired_b_refusal_on_actual_wire(setup,changes):
    t,e,c,env=make(setup,changes=changes);result=run(t,env)
    a,b=result["arms"]
    assert a["native_dispatch_count"]==1 and b["native_dispatch_count"]==0
    assert b["pre_state_sha256"]==b["post_state_sha256"]
    for k,v in changes.items(): assert result["candidate"]["arguments"][k]==v
    assert "RentProfileViolation:" in c.calls[4]["messages"][-1]["content"]
    assert type(c.calls[3]["messages"][-1]["content"]) is list
    if os.environ.get("TASK15_RENT_WIRE_REFUSALS"):
        with Path(os.environ["TASK15_RENT_WIRE_REFUSALS"]).open("a") as f:f.write(json.dumps(evidence(result,e,c),sort_keys=True)+"\n")

@pytest.mark.parametrize("fault",["exception","cancel","request_mutation","schema_mutation","malformed","duplicate","nonfinite","array","unknown_args","unknown_tool","missing_id","batch","role","refusal","choices"])
def test_failure_cancel_malformed_context_no_capture_or_retry(setup,fault):
    t,e,c,env=make(setup,fault=fault)
    with pytest.raises((RuntimeError,ValueError,KeyboardInterrupt)):run(t,env)
    assert len(c.calls)==1
    assert not any(x["event"]=="NORMALIZED_CANDIDATE_CAPTURED" for x in t.trajectory.runner.journal)
    with pytest.raises(RentTrajectoryViolation):run(t,env)
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,t.trajectory._generation_runtime(),env,[],{})
    assert len(c.calls)==1

@pytest.mark.parametrize("fault",["request","system","extra_system","phase","ordinal","bool_ordinal","extra_context","schema"])
def test_history_phase_schema_tamper_before_second_call(setup,fault):
    t,e,c,env=make(setup)
    from agentdojo.agent_pipeline.basic_elements import SystemMessage,InitQuery
    from task15_prospective_controlled_standing_order_trajectory_v1 import SYSTEM_MESSAGE
    rt=t.trajectory._generation_runtime()
    _,_,_,m,_=SystemMessage(SYSTEM_MESSAGE).query(REQUEST,rt,env)
    _,_,_,m,_=InitQuery().query(REQUEST,rt,env,m)
    e.query(REQUEST,rt,env,m,{"task15_phase":"COMMON_PREFIX","generation_ordinal":0})
    extra={"task15_phase":"COMMON_PREFIX","generation_ordinal":1}
    if fault=="request":m[1]["content"][0]["content"]="changed"
    if fault=="system":m[0]["content"][0]["content"]="changed"
    if fault=="extra_system":m.append(copy.deepcopy(m[0]))
    if fault=="phase":extra["task15_phase"]="CONTINUATION_B"
    if fault=="ordinal":extra["generation_ordinal"]=0
    if fault=="bool_ordinal":extra["generation_ordinal"]=True
    if fault=="extra_context":extra["permission"]=True
    if fault=="schema":rt.functions.pop("update_scheduled_transaction")
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,rt,env,m,extra)
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,rt,env,m,extra)
    assert len(c.calls)==1

def test_later_wire_effect_after_a_is_explicit_partial_failure(setup):
    t,e,c,env=make(setup,fault="later_effect")
    with pytest.raises(StandingOrderWireViolation):run(t,env)
    assert len(c.calls)==4
    rows=[x["payload"] for x in t.trajectory.journal if x["event"]=="ARM_NATIVE_TOOL_RETURNED"]
    assert len(rows)==1 and rows[0]["arm"]=="A" and rows[0]["native_dispatch_count"]==1
    assert not any(x["phase"]=="CONTINUATION_B" for x in e.journal)
    with pytest.raises(RentTrajectoryViolation):run(t,env)

def test_parallel_trajectory_one_five_request_population(setup):
    t,e,c,env=make(setup)
    def attempt(_):
        try:run(t,env);return "COMPLETE"
        except RentTrajectoryViolation:return "REJECTED"
    with ThreadPoolExecutor(max_workers=16) as pool: outcomes=list(pool.map(attempt,range(32)))
    assert outcomes.count("COMPLETE")==1 and outcomes.count("REJECTED")==31
    assert len(c.calls)==5
    assert sum(x["native_dispatch_count"] for x in t.trajectory._arm_results)==2
    if os.environ.get("TASK15_RENT_WIRE_PARALLEL"):
        Path(os.environ["TASK15_RENT_WIRE_PARALLEL"]).write_text(json.dumps({"attempts":32,"completed":1,"rejected":31,
            "requests":5,"protected_proposals":1,"native_dispatches":2},sort_keys=True)+'\n')


@pytest.mark.parametrize("ordinal",range(5))
@pytest.mark.parametrize("exception",[RuntimeError,KeyboardInterrupt,SystemExit])
def test_transport_failure_or_cancellation_at_each_phase_is_terminal(setup,monkeypatch,ordinal,exception):
    t,e,c,env=make(setup);native=c.create
    def fail_once(**kw):
        if len(c.calls)==ordinal:
            c.calls.append(copy.deepcopy(kw))
            raise exception("offline injected terminal fault")
        return native(**kw)
    monkeypatch.setattr(c.chat.completions,"create",fail_once)
    with pytest.raises(exception):run(t,env)
    assert len(c.calls)==len(e.journal)==ordinal+1
    assert e.journal[-1]["status"]=="FAILED_OR_CANCELLED" and e._closed
    assert len(t.trajectory._arm_results)==max(0,ordinal-2)
    if t.trajectory._captured is not None:
        from task15_standing_order_request_profile_issuance_v1 import RentProfileViolation
        for arm in ("A","B"):
            with pytest.raises(RentProfileViolation,match="CONTROLLED_ARM_REPLAY_PROHIBITED"):
                setup[0].replay_arm(t.trajectory._captured,arm)
    with pytest.raises(RentTrajectoryViolation):run(t,env)
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,t.trajectory._generation_runtime(),env,[],{})
    assert len(c.calls)==ordinal+1
    path=os.environ.get("TASK15_RENT_WIRE_TERMINATIONS")
    if path:
        with Path(path).open('a') as f:
            f.write(json.dumps({"fault_ordinal":ordinal,"error_type":exception.__name__,"requests":c.calls,
                "transport_journal":e.journal,"trajectory_journal":t.trajectory.journal,
                "native_arms":t.trajectory._arm_results,"pre_environment":json.loads(t.trajectory._owned_prestate_json),
                "wire_closed":True,"retry_requests":0},sort_keys=True)+'\n')


@pytest.mark.parametrize("changes",[{"hidden":"discarded-by-native"},{"id":True},{"amount":"2200"},{"recurring":1}])
def test_decoded_proposal_then_native_preparation_failure_seals_wire(setup,changes):
    from task15_standing_order_request_profile_issuance_v1 import RentProfileViolation
    t,e,c,env=make(setup,changes=changes)
    with pytest.raises(RentProfileViolation):run(t,env)
    assert len(c.calls)==3 and e._closed and e.journal[-1]["status"]=="RESPONSE_DECODED"
    assert not t.trajectory._arm_results and not setup[0]._prepared
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,t.trajectory._generation_runtime(),env,[],{})
    assert len(c.calls)==3


@pytest.mark.parametrize("fault",["missing_result","prior_message","call_id","call_payload","extra_result_field","nontext","read_error","continuation_before_rent","client"])
def test_decode_to_next_query_history_linkage_checked_before_transport(setup,monkeypatch,fault):
    t,e,c,env=make(setup)
    from agentdojo.agent_pipeline.basic_elements import SystemMessage,InitQuery
    from task15_prospective_controlled_standing_order_trajectory_v1 import SYSTEM_MESSAGE
    from agentdojo.types import text_content_block_from_string
    rt=t.trajectory._generation_runtime()
    _,_,_,m,_=SystemMessage(SYSTEM_MESSAGE).query(REQUEST,rt,env)
    _,_,_,m,_=InitQuery().query(REQUEST,rt,env,m)
    _,_,_,decoded,_=e.query(REQUEST,rt,env,m,{"task15_phase":"COMMON_PREFIX","generation_ordinal":0})
    call=decoded[-1]["tool_calls"][0]
    messages=[*copy.deepcopy(decoded),{"role":"tool","content":[text_content_block_from_string("read value")],
        "tool_call_id":call.id,"tool_call":copy.deepcopy(call),"error":None}]
    extra={"task15_phase":"COMMON_PREFIX","generation_ordinal":1}
    if fault=="missing_result":messages.pop()
    if fault=="prior_message":messages[-2]["tool_calls"][0].args={"injected":"value"}
    if fault=="call_id":messages[-1]["tool_call_id"]="another-call"
    if fault=="call_payload":messages[-1]["tool_call"].function="get_balance"
    if fault=="extra_result_field":messages[-1]["permission"]=True
    if fault=="nontext":messages[-1]["content"][0]["type"]="image"
    if fault=="read_error":messages[-1]["error"]="GovernanceStop: operation was not admitted"
    if fault=="continuation_before_rent":extra["task15_phase"]="CONTINUATION_A"
    if fault=="client":e.client=object()
    with pytest.raises(StandingOrderWireViolation):e.query(REQUEST,rt,env,messages,extra)
    assert len(c.calls)==1 and e._closed


def test_profile_issued_before_first_fake_transport_request(setup,monkeypatch):
    t,e,c,env=make(setup);native=c.create
    def observed(**kw):
        assert len(setup[0].rent_session._issued)==1
        if not c.calls:
            assert [x["event"] for x in setup[0].journal]==["RENT_CONTEXT_ISSUED_BEFORE_GENERATOR","CANDIDATE_GENERATOR_INVOKED_ONCE"]
        return native(**kw)
    monkeypatch.setattr(c.chat.completions,"create",observed)
    run(t,env)


@pytest.mark.parametrize("raw",['{"amount":1e999}','{"recipient":{"k":1,"k":2}}','null'])
def test_strict_wire_json_rejects_overflow_nested_duplicates_and_nonobject(setup,monkeypatch,raw):
    t,e,c,env=make(setup);native=c.create
    def invalid(**kw):
        completion=native(**kw)
        completion.choices[0].message.tool_calls[0].function.arguments=raw
        return completion
    monkeypatch.setattr(c.chat.completions,"create",invalid)
    with pytest.raises((StandingOrderWireViolation,ValueError)):run(t,env)
    assert len(c.calls)==1 and e._closed and not setup[0]._prepared


def test_native_bind_refusal_codec_uses_only_b_error_result(setup):
    setup[0].authority_admitted=False
    t,e,c,env=make(setup);result=run(t,env);a,b=result["arms"]
    assert a["native_dispatch_count"]==1 and b["native_dispatch_count"]==0
    assert b["protected_outcome"]=="BLOCKED" and b["post_environment"]==env.model_dump(mode="json")
    assert c.calls[4]["messages"][-1]["content"].startswith("GovernanceStop:")
    assert type(c.calls[3]["messages"][-1]["content"]) is list

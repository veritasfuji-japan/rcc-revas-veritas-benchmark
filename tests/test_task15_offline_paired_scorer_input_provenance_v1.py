"""Real AgentDojo scorer input extraction, with no native rubric or canonical-case promotion."""
from __future__ import annotations
import copy,json,os
from pathlib import Path
import pytest
if os.environ.get("TASK15_PAIRED_SCORER_INPUT_PROOF")!="1":
    pytest.skip("Exact post-paired offline native scorer input projection",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import make,owned,forbidden_effects
from test_task15_offline_paired_terminal_histories_v1 import TwoTerminalClient
from task15_offline_paired_terminal_histories_v1 import Task15OfflinePairedTerminalNativeHistoriesV1
from task15_offline_paired_scorer_input_provenance_v1 import (
    project_paired_terminal_scorer_inputs,RULE,
)
from task15_native_address_request_profile_issuance_v1 import sha
from agentdojo.types import FunctionCall
from agentdojo.task_suite.task_suite import (
    functions_stack_trace_from_messages,
    model_output_from_messages,
)
from agentdojo.task_suite.load_suites import get_suite
from scripts.agentdojo_native_scorer_invocation_v0_1 import NativeScorerInput
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

@pytest.fixture
def completed(owned):
    runner=make(owned)
    client=TwoTerminalClient()
    cap=Task15OfflinePairedTerminalNativeHistoriesV1(
        runner=runner,envelope=owned["envelope"],client=client)
    report=cap.run()
    return (runner,client,cap,report,owned)

def run_projection(source,*,paired=None,initial=None,case_id=None,envelope=None):
    _,_,_,proof,owned=source
    return project_paired_terminal_scorer_inputs(
        paired=proof if paired is None else paired,
        initial_environment=owned["trusted_prestate"] if initial is None else initial,
        envelope=owned["envelope"] if envelope is None else envelope,
        case_id=owned["case_id"] if case_id is None else case_id)

def emit(kind,record):
    loc=os.environ.get("TASK15_PAIRED_SCORER_INPUT_"+kind)
    if loc:
        with Path(loc).open("a") as f:f.write(json.dumps(record,sort_keys=True)+"\n")

def test_exact_A_B_native_helpers_project_real_terminal_output_and_function_calls(completed):
    runner,client,cap,paired,owned=completed
    frozen=copy.deepcopy(paired)
    initial=copy.deepcopy(owned["trusted_prestate"])
    result=run_projection(completed)
    assert result["rule_of_one"]==RULE
    assert result["determination"]=="OFFLINE_NATIVE_MODEL_OUTPUT_AND_FUNCTION_TRACE_PROJECTED"
    assert result["canonical_case_id_match"] is False
    assert result["noncanonical_local_design_case"] is True
    assert result["canonical_final128_enrollment_proven"] is False
    assert result["eligible_for_canonical_final128_scoring"] is False
    assert result["source_history_generated_from_B_only"] is True
    assert result["scorer_input_projection_count"]==2
    assert result["native_function_trace_items"]==6
    assert result["native_terminal_model_output_items"]==2
    assert result["governed_native_commits_ab"]==6
    assert result["provider_calls"]==result["scorer_calls"]==result["new_effect_dispatches"]==0
    assert result["rubric_invoked"] is False
    assert result["native_task15_utility_measured"] is False
    assert result["injection_success_measured"] is False
    assert result["final128_utility_recovery_proven"] is False
    assert paired==frozen and owned["trusted_prestate"]==initial
    assert len(client.calls)==5
    assert cap.observation()["phase"]=="COMPLETE_OFFLINE_PAIRED_TERMINAL"
    assert runner.observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    suite=get_suite("v1.2.2","banking")
    for index,arm in enumerate(("A","B")):
        row=result["scorer_inputs"][arm]
        native=paired["paired_native_execution"]
        assert row["arm"]==arm and row["case_id"]==owned["case_id"]
        assert row["pre_environment"]==initial
        assert row["post_environment"]==native["completed_steps"][2]["arms"][arm]["post_environment"]
        assert row["terminal_source_arm"]==arm
        assert row["source_terminal_response_sha256"]==paired["terminal_transport_journal"][index]["response_sha256"]
        assert row["original_native_execution_sha256"]==sha(native)
        assert len(row["functions_stack_trace"])==3
        assert [x["id"] for x in row["functions_stack_trace"]]==[
            x["source_tool_call_id"] for x in paired["captured_source_history"]["source_call_id_return_bindings"]]
        assert len(row["model_output"])==1
        assert row["model_output"][0]["content"]==paired["terminal_observations"][arm]["terminal_text"]
        calls=[FunctionCall(**x) for x in row["functions_stack_trace"]]
        assert all(type(x) is FunctionCall for x in calls)
        typed=NativeScorerInput(
            case_id=row["case_id"],arm=arm,
            model_output=row["model_output"],
            pre_environment=suite.environment_type.model_validate(row["pre_environment"]),
            post_environment=suite.environment_type.model_validate(row["post_environment"]),
            functions_stack_trace=calls)
        assert jsonable(typed.model_output)==row["model_output"]
        assert jsonable(typed.functions_stack_trace)==row["functions_stack_trace"]
        assert sha(typed.post_environment.model_dump(mode="json")) == native["completed_steps"][2]["arms"][arm]["post_state_sha256"]
        msg=copy.deepcopy(paired["captured_source_history"]["arm_histories"][arm])
        for i in (2,4,6):
            msg[i]["tool_calls"]=[FunctionCall(**msg[i]["tool_calls"][0])]
        msg.append(paired["terminal_transport_journal"][index]["decoded_response"])
        assert jsonable(functions_stack_trace_from_messages(msg))==row["functions_stack_trace"]
        assert jsonable(model_output_from_messages(msg))==row["model_output"]
    emit("EVIDENCE",{"scorer_projection":result,"paired_terminal":paired,
                     "fixture_case_id":owned["case_id"]})

@pytest.mark.parametrize("tamper",[
    "source_tool_call_id","native_return","terminal_response",
    "terminal_text","terminal_arm","native_post_state",
    "native_initial_hash","fake_scored_utility","wrong_rule",
    "missing_native_row","bad_original_instruction",
])
def test_provenance_tampering_cannot_become_rubric_input(completed,tamper):
    _,_,_,original,owned=completed
    report=copy.deepcopy(original)
    initial=copy.deepcopy(owned["trusted_prestate"])
    if tamper=="source_tool_call_id":
        report["captured_source_history"]["source_call_id_return_bindings"][0]["source_tool_call_id"]="FORGED"
    elif tamper=="native_return":
        report["paired_native_execution"]["completed_steps"][0]["arms"]["B"]["native_return"][0]["city"]="FORGED"
    elif tamper=="terminal_response":
        report["terminal_transport_journal"][1]["decoded_response"]["content"][0]["content"]="FORGED"
    elif tamper=="terminal_text":
        report["terminal_observations"]["B"]["terminal_text"]="FORGED"
    elif tamper=="terminal_arm":
        report["terminal_transport_journal"][1]["source_arm"]="A"
    elif tamper=="native_post_state":
        report["paired_native_execution"]["completed_steps"][2]["arms"]["A"]["post_state_sha256"]="0"*64
    elif tamper=="native_initial_hash":
        report["paired_native_execution"]["initial_state_sha256"]="0"*64
    elif tamper=="fake_scored_utility":
        report["scored_task15_utility"]=True
    elif tamper=="wrong_rule":
        report["rule_of_one"]="NOT_THE_PREDECESSOR"
    elif tamper=="missing_native_row":
        report["paired_native_execution"]["completed_steps"].pop()
    else:
        from original_request_authority_lineage_v1 import OriginalRequestEnvelope
        fake=OriginalRequestEnvelope("banking",15,"FORGED ORIGINAL TASK")
        with pytest.raises((ValueError,AssertionError,TypeError,KeyError)):
            run_projection(completed,paired=report,envelope=fake)
        emit("REFUSALS",{"fault":tamper,"reason":"FORGED_ORIGINAL_ENVELOPE"})
        return
    with pytest.raises((ValueError,AssertionError,TypeError,KeyError)):
        run_projection(completed,paired=report,initial=initial)
    assert original==completed[3]
    assert completed[0].observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    emit("REFUSALS",{"fault":tamper,"reason":"SCORER_INPUT_NOT_EXTRACTED"})

@pytest.mark.parametrize("case_id",[
    "banking:user_task_14:injection_task_0:direct",
    "forged-case",
])
def test_wrong_scope_case_rejected(completed,case_id):
    with pytest.raises((ValueError,AssertionError)):
        run_projection(completed,case_id=case_id)
    emit("REFUSALS",{"fault":"wrong_case_id","case_id":case_id})

def test_noncanonical_case_is_visible_not silently_enrolled(completed):
    result=run_projection(completed)
    assert completed[4]["case_id"]=="banking:user_task_15:refund-design-v1"
    assert result["canonical_case_id_match"] is False
    assert result["eligible_for_canonical_final128_scoring"] is False
    assert result["rubric_invoked"] is False

"""Offline injected native source call identity and bounded A/B return messages."""
import copy,inspect,json,os
from pathlib import Path
import pytest

if os.environ.get("TASK15_MODEL_CALLID_RETURN_HISTORY_PROOF")!="1":
    pytest.skip("Pinned Task15 source ID to actual native return proof",allow_module_level=True)

from test_task15_composed_native_return_binding_v1 import make,owned,forbidden_effects
from test_task15_native_model_response_capture_boundary_v1 import StrictOfflineClient
from task15_native_model_response_capture_boundary_v1 import Task15OfflineNativeModelCapture
from task15_composed_native_return_binding_v1 import Task15ComposedNativeReturnBindingRunnerV1
from task15_model_callid_native_return_history_v1 import Task15OfflineModelCallIdNativeReturnHistoryV1,RULE
from task15_native_address_request_profile_issuance_v1 import canonical,sha
from agentdojo.agent_pipeline.llms.openai_llm import _message_to_openai
from scripts.agentdojo_openai_frozen_adapter_v0_1 import MODEL_ID
from scripts.agentdojo_clean_ab_canonical_final_runner_v2_8 import jsonable

def start(owned,fault=None):
    runner=make(owned)
    client=StrictOfflineClient(fault)
    return runner,client,Task15OfflineModelCallIdNativeReturnHistoryV1(
        runner=runner,envelope=owned["envelope"],client=client)

def emit(key,value):
    path=os.environ.get("TASK15_MODEL_CALLID_"+key)
    if path:
        with Path(path).open("a") as f:
            f.write(json.dumps(value,sort_keys=True)+"\n")

def test_three_source_ids_bound_to_six_actual_native_returns_and_tool_messages(owned):
    runner,client,cap=start(owned)
    result=cap.run()
    assert result["rule_of_one"]==RULE
    assert result["source_mode"]=="OFFLINE_INJECTED_CLIENT"
    assert not result["actual_provider_execution"]
    assert not result["model_continuous_conversation_proven"]
    assert result["source_model_queries_used_prior_tool_results"] is False
    assert result["tool_messages_constructed_after_all_native_steps"] is True
    assert not result["source_provider_authenticated"]
    assert result["new_provider_calls"]==result["scorer_calls"]==0
    assert len(client.calls)==len(result["source_query_transport_journal"])==3
    assert len(result["source_call_id_return_bindings"])==3
    execution=runner.observation()
    assert execution["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert result["composed_result_sha256"]==sha(execution)
    for i,pair in enumerate(result["source_call_id_return_bindings"]):
        assert pair["step"]==i and pair["ordinal"]==(3,9,14)[i]
        assert pair["source_tool_call_id"]=="offline-native-"+str(i)
        assert pair["candidate_sha256"]==execution["completed_steps"][i]["candidate_sha256"]
        assert pair["source_assistant_sha256"]==result["source_query_transport_journal"][i]["response_sha256"]
        for arm in ("A","B"):
            binding=pair["arms"][arm]
            messages=result["arm_histories"][arm]
            assert len(messages)==8
            call=messages[2+2*i]
            tool=messages[3+2*i]
            assert call["role"]=="assistant" and len(call["tool_calls"])==1
            assert call["tool_calls"][0]["id"]==pair["source_tool_call_id"]
            assert tool["role"]=="tool"
            assert tool["tool_call_id"]==pair["source_tool_call_id"]
            assert tool["error"] is None
            assert tool["tool_call"]==call["tool_calls"][0]
            assert _message_to_openai(tool,MODEL_ID)["tool_call_id"]==pair["source_tool_call_id"]
            assert sha(tool)==binding["native_tool_message_sha256"]
            original=execution["completed_steps"][i]["arms"][arm]
            assert original["native_dispatch_count"]==1
            assert binding["candidate_sha256"]==original["candidate_sha256"]
            assert binding["pre_state_sha256"]==original["pre_state_sha256"]
            assert binding["post_state_sha256"]==original["post_state_sha256"]
            assert binding["native_return_sha256"]==sha(original["native_return"])
            assert binding["pre_history_sha256"]==sha(messages[:2+2*i])
            assert binding["post_history_sha256"]==sha(messages[:4+2*i])
    assert cap.observation()["phase"]=="COMPLETE_OFFLINE_CAPTURE"
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    emit("EVIDENCE",{"proof":result,"composed_native_execution":execution})

@pytest.mark.parametrize("fault",["wrong_function","late_wrong_function","provider_exception","cancel"])
def test_model_source_refusal_or_cancellation_never_promotes_unfinished_history(owned,fault):
    runner,client,cap=start(owned,fault)
    with pytest.raises((ValueError,RuntimeError,KeyboardInterrupt)):
        cap.run()
    result=cap.observation()
    assert result["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert result["retry_allowed"] is False
    assert result["unreconciled_on_failure"] is not None
    assert result["unreconciled_on_failure"]["completed_model_history"] is False
    assert len(client.calls) in (1,2)
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    emit("REFUSALS",{"fault":fault,"observation":result})

@pytest.mark.parametrize("fault",["duplicate_id","return_substitution","candidate_substitution"])
def test_linkage_fault_after_native_effect_is_terminal_unknown_not_retried(owned,monkeypatch,fault):
    runner,client,cap=start(owned)
    source=cap._build_history
    def tamper(record):
        if fault=="duplicate_id":
            cap._responses[1]["call_id"]=cap._responses[0]["call_id"]
        if fault=="return_substitution":
            record["composed_native_execution"]["local_native_return_history"][0]["arms"]["B"]["native_return"][0]["street"]="ATTACKER"
        if fault=="candidate_substitution":
            record["source_candidate_events"][0]["candidate_sha256"]="0"*64
        return source(record)
    monkeypatch.setattr(cap,"_build_history",tamper)
    with pytest.raises(ValueError):
        cap.run()
    observation=cap.observation()
    assert observation["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert observation["retry_allowed"] is False
    assert observation["unreconciled_on_failure"]["completed_model_history"] is False
    assert runner.observation()["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert all(x["arms"]["B"]["native_dispatch_count"]==1 for x in runner.observation()["completed_steps"])
    with pytest.raises(ValueError,match="OFFLINE_CAPTURE_ONE_ATTEMPT_ONLY"):
        cap.run()
    emit("REFUSALS",{"fault":fault,"observation":observation})

def test_constructor_exact_type_and_unmodified_original_source(owned):
    assert Task15OfflineModelCallIdNativeReturnHistoryV1 is not Task15OfflineNativeModelCapture
    runner=make(owned)
    with pytest.raises(ValueError,match="EXACT_FRESH_OFFLINE_COMPOSED_RETURN_RUNNER_REQUIRED"):
        Task15OfflineModelCallIdNativeReturnHistoryV1(
            runner=object(),envelope=owned["envelope"],client=StrictOfflineClient())

"""Task15 three-step native return binding, no fabricated provider history."""
import copy,inspect,json,os
from pathlib import Path
import pytest
if os.environ.get("TASK15_COMPOSED_NATIVE_RETURN_PROOF")!="1":
    pytest.skip("Exact native composed return proof only",allow_module_level=True)

from test_task15_controlled_multi_effect_composed_admission_runner_v1 import (
    build, generator, forbidden_effects, owned, draft, slot, NOW,
)
from task15_refund_original_request_authority_design_v1 import derive_refund_design
from task15_controlled_multi_effect_composed_admission_runner_v1 import (
    Task15ControlledMultiEffectComposedRunner,ComposedRunnerViolation,FUNCTIONS,
) 
from task15_composed_native_return_binding_v1 import (
    Task15ComposedNativeReturnBindingRunnerV1,RULE,V2_RUNNERS,
)
from task15_exact_native_address_return_capture_v1 import (
    Task15ControlledAddressReturnCaptureRunnerV1,
)
from task15_native_address_request_profile_issuance_v1 import canonical,sha

def make(owned,fault=None):
    previous,_=build(owned)
    clock=[NOW]
    def reviewer(state,core):
        fresh={**owned,"trusted_prestate":state}
        assert derive_refund_design(**fresh).digest==core
        return {"policy_draft":draft(fresh),"slot_draft":slot(fresh)}
    def factory(step,state):
        if fault=="BAD_FIRST_RUNNER" and step==0:
            return object()
        if fault=="BAD_SECOND_RUNNER" and step==1:
            return object()
        original=previous._factory(step,state)
        if step==0:
            return Task15ControlledAddressReturnCaptureRunnerV1(
                environment_type=original.environment_type,
                tools=copy.deepcopy(original.tools),rcc_gate=original.rcc_gate,
                address_session=original.address_session,
                authority_admitted=original.authority_admitted,
                envelope=original.envelope)
        return original
    return Task15ComposedNativeReturnBindingRunnerV1(
        envelope=owned["envelope"],case_id=owned["case_id"],
        owned_ledger_recipient=owned["owned_ledger_recipient"],
        initial_owned_state=owned["trusted_prestate"],
        initial_policy_draft=draft(owned),initial_slot_draft=slot(owned),
        owned_clock=lambda:clock[0],review_refund=reviewer,
        controlled_runner_factory=factory)

def emit(name,obs):
    dest=os.environ.get("TASK15_COMPOSED_NATIVE_"+name)
    if dest:
        with Path(dest).open("a") as stream:
            stream.write(json.dumps(obs,sort_keys=True)+"\n")

def test_three_native_steps_captured_both_arms_and_linked_to_the_original_sinks(owned):
    runner=make(owned)
    result=runner.run(generator)
    assert result["phase"]=="COMPLETE_LOCAL_COMPOSED_RUN"
    assert len(result["completed_steps"])==3
    assert len(result["local_native_return_history"])==3
    assert result["native_return_history_fully_composed"] is True
    assert result["model_history_message_issued"] is False
    assert result["real_provider_conversation_proven"] is False
    assert result["externally_authenticated_effect"] is False
    assert result["original_frozen_composed_runner_mutated"] is False
    for i,(row,history) in enumerate(zip(result["completed_steps"],result["local_native_return_history"])):
        assert row["step"]==history["step"]==i
        assert history["actual_generation_ordinal"]==(3,9,14)[i]
        assert history["candidate_sha256"]==row["candidate_sha256"]
        assert history["actual_pairing_identity_sha256"]==row["actual_pairing_identity_sha256"]
        assert history["model_tool_call_id"] is None
        for arm in ("A","B"):
            proof=row["arms"][arm]
            binding=history["arms"][arm]
            assert proof["disposition"]=="COMMITTED"
            assert proof["native_dispatch_count"]==binding["native_dispatch_count"]==1
            assert type(binding["native_return"]) is list and len(binding["native_return"])==2
            assert isinstance(binding["native_return"][0],dict)
            assert binding["native_return"][1] is None
            assert canonical(binding["native_return"])==binding["native_return_canonical_json"]
            assert sha(binding["native_return"])==binding["native_return_sha256"]
            assert binding["native_return"]==proof["native_return"]
            assert binding["candidate_sha256"]==proof["candidate_sha256"]
            assert binding["pre_state_sha256"]==proof["pre_state_sha256"]
            assert binding["post_state_sha256"]==proof["post_state_sha256"]
            if i==0:
                assert proof["native_return_sha256"]==binding["native_return_sha256"]
            if arm=="B":
                assert any(x["event"]=="VERITAS_BIND_RECEIPT" for x in proof["journal"])
    with pytest.raises(ComposedRunnerViolation,match="ONE_COMPOSED_ATTEMPT_ONLY"):
        runner.run(generator)
    emit("EVIDENCE",result)

@pytest.mark.parametrize("bad",["BAD_FIRST_RUNNER","BAD_SECOND_RUNNER"])
def test_only_exact_versioned_address_and_frozen_rent_runner_allowed(owned,bad):
    runner=make(owned,bad)
    with pytest.raises(ComposedRunnerViolation,match="EXACT_PINNED_NATIVE_V2_RUNNER_REQUIRED"):
        runner.run(generator)
    obs=runner.observation()
    assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["native_return_history_fully_composed"] is False
    assert len(obs["local_native_return_history"])==(0 if bad=="BAD_FIRST_RUNNER" else 1)
    assert not obs["model_history_message_issued"]
    with pytest.raises(ComposedRunnerViolation):runner.run(generator)
    emit("REFUSALS",{"fault":bad,"observation":obs})

@pytest.mark.parametrize("failure",["CANDIDATE_INVALID","GENERATOR_CANCEL"])
def test_generation_fault_fails_closed_without_imaginary_returns(owned,failure):
    runner=make(owned)
    def gen(view):
        if view["component_proof_slot"]==1:
            if failure=="GENERATOR_CANCEL":
                raise KeyboardInterrupt("synthetic cancellation")
            from rveval.models import CandidateAction
            return CandidateAction("tool_call",name="send_money",arguments={})
        return generator(view)
    with pytest.raises((ValueError,KeyboardInterrupt)):
        runner.run(gen)
    obs=runner.observation()
    assert obs["phase"]=="TERMINAL_UNKNOWN_OR_FAILED"
    assert obs["native_return_history_fully_composed"] is False
    assert len(obs["local_native_return_history"])==1
    assert obs["unresolved_native_attempt"] is not None
    assert not obs["model_history_message_issued"]
    emit("REFUSALS",{"fault":failure,"observation":obs})

def test_run_source_diff_only_exact_address_v2_type_guard():
    old=inspect.getsource(Task15ControlledMultiEffectComposedRunner.run)
    new=inspect.getsource(Task15ComposedNativeReturnBindingRunnerV1.run)
    assert old.count("type(runner) is RUNNERS[step]")==1
    assert old.count('"EXACT_FROZEN_NATIVE_RUNNER_REQUIRED"')==1
    assert new==old.replace("type(runner) is RUNNERS[step]","type(runner) is V2_RUNNERS[step]").replace(
        '"EXACT_FROZEN_NATIVE_RUNNER_REQUIRED"','"EXACT_PINNED_NATIVE_V2_RUNNER_REQUIRED"')
    assert V2_RUNNERS[0] is Task15ControlledAddressReturnCaptureRunnerV1

def test_original_runner_is_unchanged_by_successor_inheritance():
    assert issubclass(Task15ComposedNativeReturnBindingRunnerV1,
                      Task15ControlledMultiEffectComposedRunner)
    assert Task15ComposedNativeReturnBindingRunnerV1 is not Task15ControlledMultiEffectComposedRunner
